use std::net::IpAddr;
use std::time::Duration;

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use hiveguard_core::models::{Action, BanSource, DetectionSignal};
use hiveguard_plugin_api::prelude::*;

pub const PLUGIN_ID: &str = "scoring.default";
pub const PLUGIN_VERSION: &str = "0.1.0";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Config {
    #[serde(default = "default_window")]
    accumulation_window_secs: u64,
    #[serde(default = "default_threshold")]
    ban_severity_threshold: u32,
    #[serde(default = "default_ban_duration")]
    default_ban_duration_secs: u64,
}

fn default_window() -> u64 { 1800 }
fn default_threshold() -> u32 { 100 }
fn default_ban_duration() -> u64 { 86_400 }

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SnapshotSignal {
    signal: DetectionSignal,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SnapshotState {
    config: Config,
    by_ip: Vec<(IpAddr, Vec<SnapshotSignal>)>,
}

pub struct DefaultScoringPlugin {
    manifest: PluginManifest,
    config: Config,
    signals: DashMap<IpAddr, Vec<DetectionSignal>>,
}

impl DefaultScoringPlugin {
    pub fn manifest_fn() -> PluginManifest {
        PluginManifest {
            id: PLUGIN_ID,
            version: PLUGIN_VERSION,
            description: "Default weighted sliding-window scoring engine.",
            kind: PluginKind::ScoringEngine,
            author: "HiveGuard",
            docs_url: Some("https://github.com/anthropics/hiveguard/blob/main/plugins/scoring-default/README.md"),
        }
    }

    pub fn create(
        ctx: PluginContext,
        cfg: serde_json::Value,
    ) -> BoxFuture<'static, PluginResult<Box<dyn ScoringEnginePlugin>>> {
        Box::pin(async move {
            let mut plugin = DefaultScoringPlugin {
                manifest: Self::manifest_fn(),
                config: Config {
                    accumulation_window_secs: default_window(),
                    ban_severity_threshold: default_threshold(),
                    default_ban_duration_secs: default_ban_duration(),
                },
                signals: DashMap::new(),
            };
            <DefaultScoringPlugin as Plugin>::init(&mut plugin, cfg).await?;
            let _ = ctx;
            Ok(Box::new(plugin) as Box<dyn ScoringEnginePlugin>)
        })
    }

    fn prune_signals(&self, ip: IpAddr, now: DateTime<Utc>) {
        if let Some(mut bucket) = self.signals.get_mut(&ip) {
            let cutoff = now
                - chrono::Duration::from_std(Duration::from_secs(self.config.accumulation_window_secs))
                    .unwrap_or(chrono::Duration::zero());
            bucket.retain(|s| s.timestamp >= cutoff);
            if bucket.is_empty() {
                drop(bucket);
                self.signals.remove(&ip);
            }
        }
    }
}

#[async_trait]
impl Plugin for DefaultScoringPlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    async fn init(&mut self, cfg: serde_json::Value) -> PluginResult<()> {
        self.config = serde_json::from_value(cfg)
            .map_err(|e| PluginError::ConfigValidation(e.to_string()))?;
        self.signals.clear();
        Ok(())
    }
}

#[async_trait]
impl ScoringEnginePlugin for DefaultScoringPlugin {
    fn record(&self, signal: DetectionSignal) {
        let ip = signal.source_ip.addr();
        self.signals.entry(ip).or_default().push(signal);
    }

    fn evaluate(&self, ip: IpAddr) -> Option<BanDecision> {
        let now = Utc::now();
        self.prune_signals(ip, now);

        let mut bucket = self.signals.get_mut(&ip)?;
        if bucket.is_empty() {
            return None;
        }

        let total_severity: u32 = bucket
            .iter()
            .map(|s| (s.severity as f32 * s.confidence) as u32)
            .sum();

        if total_severity < self.config.ban_severity_threshold {
            return None;
        }

        let ban_duration = bucket
            .iter()
            .filter_map(|s| match s.suggested_action {
                Action::Ban(d) => Some(d),
                Action::Observe => None,
                Action::Escalate => None,
            })
            .max()
            .unwrap_or_else(|| Duration::from_secs(self.config.default_ban_duration_secs));

        let best_signal = bucket
            .iter()
            .max_by_key(|s| s.severity)
            .cloned()?;

        // Preserve the broadest subnet scope requested by any accumulated
        // signal. Detectors such as `distributed_slow` emit a subnet (e.g. a
        // /24) as their `source_ip`; collapsing to the host `/32` here would
        // ban only the network address and let the rest of the subnet through.
        // Pick the smallest prefix length (widest network) so a subnet ban
        // wins over per-host bans that share the same bucket key.
        let subject = bucket
            .iter()
            .map(|s| s.source_ip)
            .min_by_key(|net| net.prefix_len())
            .unwrap_or_else(|| ip_to_net(ip));

        let reason = format!(
            "Accumulated severity {} (threshold {}) for {}",
            total_severity, self.config.ban_severity_threshold, subject
        );

        let source = BanSource::LocalDetector(best_signal.detector_name.clone());
        bucket.clear();

        Some(BanDecision {
            subject,
            duration: ban_duration,
            reason,
            severity: total_severity.min(255) as u8,
            evidence_hash: best_signal.evidence_hash,
            source,
            timestamp: now,
        })
    }

    fn decay(&self) {
        let now = Utc::now();
        let keys: Vec<IpAddr> = self.signals.iter().map(|entry| *entry.key()).collect();
        for ip in keys {
            self.prune_signals(ip, now);
        }
    }

    fn snapshot(&self) -> serde_json::Value {
        let by_ip = self
            .signals
            .iter()
            .map(|entry| {
                let ip = *entry.key();
                let signals = entry
                    .value()
                    .iter()
                    .cloned()
                    .map(|signal| SnapshotSignal { signal })
                    .collect::<Vec<_>>();
                (ip, signals)
            })
            .collect::<Vec<_>>();

        serde_json::to_value(SnapshotState {
            config: self.config.clone(),
            by_ip,
        })
        .unwrap_or_else(|_| serde_json::json!({}))
    }

    fn restore(&self, state: serde_json::Value) -> PluginResult<()> {
        let parsed: SnapshotState = serde_json::from_value(state)
            .map_err(|e| PluginError::ConfigValidation(e.to_string()))?;

        self.signals.clear();
        for (ip, signals) in parsed.by_ip {
            self.signals.insert(
                ip,
                signals
                    .into_iter()
                    .map(|s| s.signal)
                    .collect::<Vec<_>>(),
            );
        }

        Ok(())
    }
}

fn ip_to_net(ip: IpAddr) -> IpNet {
    match ip {
        IpAddr::V4(v4) => IpNet::V4(ipnet::Ipv4Net::new(v4, 32).expect("valid /32")),
        IpAddr::V6(v6) => IpNet::V6(ipnet::Ipv6Net::new(v6, 128).expect("valid /128")),
    }
}

inventory::submit! {
    PluginDescriptor {
        id: PLUGIN_ID,
        kind: PluginKind::ScoringEngine,
        api_version: API_VERSION,
        manifest: DefaultScoringPlugin::manifest_fn,
        config_schema: include_str!("../schema.json"),
        factory: PluginFactory::ScoringEngine(DefaultScoringPlugin::create),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use hiveguard_plugin_api::context::parking_lot_compat::RegistryHandle;
    use hiveguard_plugin_api::secrets::SecretResolver;

    fn test_ctx() -> PluginContext {
        PluginContext::new(
            PLUGIN_ID.to_string(),
            std::env::temp_dir(),
            Arc::new(SecretResolver::new()),
            PluginMetrics {
                registry: Arc::new(RegistryHandle::default()),
                plugin_id: PLUGIN_ID.to_string(),
            },
            CancellationToken::new(),
        )
    }

    fn make_signal(ip: &str, severity: u8) -> DetectionSignal {
        let ip_addr: IpAddr = ip.parse().expect("valid ip");
        let source_ip = ip_to_net(ip_addr);
        make_signal_net(source_ip, severity)
    }

    fn make_signal_net(source_ip: IpNet, severity: u8) -> DetectionSignal {
        DetectionSignal {
            source_ip,
            severity,
            confidence: 1.0,
            reason: "test".into(),
            evidence_hash: [7u8; 32],
            suggested_action: Action::Ban(Duration::from_secs(60)),
            detector_name: "unit".into(),
            timestamp: Utc::now(),
        }
    }

    #[tokio::test]
    async fn factory_accepts_defaults() {
        let plugin = DefaultScoringPlugin::create(test_ctx(), serde_json::json!({}))
            .await
            .unwrap();
        assert_eq!(plugin.manifest().id, PLUGIN_ID);
    }

    #[tokio::test]
    async fn evaluate_returns_ban_when_threshold_crossed() {
        let plugin = DefaultScoringPlugin::create(test_ctx(), serde_json::json!({
            "ban_severity_threshold": 100
        }))
        .await
        .unwrap();

        plugin.record(make_signal("1.2.3.4", 60));
        plugin.record(make_signal("1.2.3.4", 60));
        let decision = plugin.evaluate("1.2.3.4".parse().unwrap());
        assert!(decision.is_some());
    }

    #[tokio::test]
    async fn subnet_signal_produces_subnet_ban() {
        // A distributed_slow-style signal carries a /24 as its source_ip.
        // The resulting ban must target the /24, not the network host /32.
        let plugin = DefaultScoringPlugin::create(
            test_ctx(),
            serde_json::json!({ "ban_severity_threshold": 100 }),
        )
        .await
        .unwrap();

        let subnet: IpNet = "202.46.62.0/24".parse().unwrap();
        plugin.record(make_signal_net(subnet, 180));

        // Pipeline evaluates by the signal's host addr (network address of /24).
        let decision = plugin
            .evaluate("202.46.62.0".parse().unwrap())
            .expect("threshold crossed");
        assert_eq!(decision.subject.to_string(), "202.46.62.0/24");
        assert!(decision.reason.contains("202.46.62.0/24"));
    }

    #[tokio::test]
    async fn broadest_scope_wins_over_host_ban() {
        // When a bucket mixes a /32 host signal and a /24 subnet signal,
        // the broader /24 must win so the whole subnet is banned.
        let plugin = DefaultScoringPlugin::create(
            test_ctx(),
            serde_json::json!({ "ban_severity_threshold": 100 }),
        )
        .await
        .unwrap();

        let host: IpNet = "10.0.5.0/32".parse().unwrap();
        let subnet: IpNet = "10.0.5.0/24".parse().unwrap();
        plugin.record(make_signal_net(host, 60));
        plugin.record(make_signal_net(subnet, 60));

        let decision = plugin
            .evaluate("10.0.5.0".parse().unwrap())
            .expect("threshold crossed");
        assert_eq!(decision.subject.to_string(), "10.0.5.0/24");
    }

    #[tokio::test]
    async fn snapshot_restore_roundtrip() {
        let first = DefaultScoringPlugin::create(
            test_ctx(),
            serde_json::json!({ "ban_severity_threshold": 100 }),
        )
        .await
        .unwrap();

        first.record(make_signal("1.2.3.5", 60));
        first.record(make_signal("1.2.3.5", 60));

        let snapshot = first.snapshot();

        let second = DefaultScoringPlugin::create(
            test_ctx(),
            serde_json::json!({ "ban_severity_threshold": 100 }),
        )
        .await
        .unwrap();
        second.restore(snapshot).unwrap();

        let first_decision = first.evaluate("1.2.3.5".parse().unwrap());
        let restored_decision = second.evaluate("1.2.3.5".parse().unwrap());
        assert!(first_decision.is_some());
        assert!(restored_decision.is_some());
        assert_eq!(
            first_decision.unwrap().severity,
            restored_decision.unwrap().severity
        );
    }
}
