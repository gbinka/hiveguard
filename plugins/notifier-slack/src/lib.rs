//! Slack incoming-webhook notifier.

use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;
use tokio::sync::RwLock;
use tracing::warn;

use hiveguard_plugin_api::prelude::*;
use hiveguard_plugin_utils::http;

pub const PLUGIN_ID: &str = "notifier.slack";
const PLUGIN_VERSION: &str = "0.1.0";

#[derive(Debug, Clone, Deserialize)]
struct Config {
    webhook_url: String,
    #[serde(default = "default_timeout")]
    timeout_secs: u64,
    #[serde(default)]
    channel: Option<String>,
    #[serde(default = "default_username")]
    username: String,
    #[serde(default = "default_icon")]
    icon_emoji: String,
}

fn default_timeout() -> u64 { 10 }
fn default_username() -> String { "HiveGuard".into() }
fn default_icon() -> String { ":no_entry:".into() }

pub struct SlackPlugin {
    manifest: PluginManifest,
    state: RwLock<Option<State>>,
}

struct State {
    cfg: Config,
    client: reqwest::Client,
}

impl SlackPlugin {
    pub fn manifest_fn() -> PluginManifest {
        PluginManifest {
            id: PLUGIN_ID,
            version: PLUGIN_VERSION,
            description: "Slack incoming-webhook notifier (mrkdwn format).",
            kind: PluginKind::Notifier,
            author: "HiveGuard",
            docs_url: Some(
                "https://github.com/anthropics/hiveguard/blob/main/plugins/notifier-slack/README.md",
            ),
        }
    }

    pub fn create(
        _ctx: PluginContext,
        cfg: serde_json::Value,
    ) -> BoxFuture<'static, PluginResult<Box<dyn NotifierPlugin>>> {
        Box::pin(async move {
            let mut plugin = SlackPlugin {
                manifest: Self::manifest_fn(),
                state: RwLock::new(None),
            };
            <SlackPlugin as Plugin>::init(&mut plugin, cfg).await?;
            Ok(Box::new(plugin) as Box<dyn NotifierPlugin>)
        })
    }

    fn format(event: &AlertEvent) -> String {
        match event {
            AlertEvent::IpBanned { ip, severity, reason, .. } => {
                format!(":no_entry: *Banned* `{ip}` (severity {severity})\n> {reason}")
            }
            AlertEvent::SubnetBanned { subnet, ip_count, reason } => {
                format!(":no_entry_sign: *Subnet ban* `{subnet}` ({ip_count} IPs)\n> {reason}")
            }
            AlertEvent::HoneypotHit { ip, path } => {
                format!(":honeybee: *Honeypot triggered* `{path}` from `{ip}`")
            }
            AlertEvent::HighThreatDetected { ip, score, top_detectors } => {
                format!(":warning: *High threat* `{ip}` (score {score:.1})\n> {}", top_detectors.join(", "))
            }
            AlertEvent::PeerDown { node_id, address } => {
                format!(":satellite: *Peer down* `{node_id}` ({address})")
            }
            AlertEvent::PeerQuarantined { node_id, reason } => {
                format!(":no_entry: *Peer quarantined* `{node_id}`\n> {reason}")
            }
            AlertEvent::BanRateAnomaly { bans_per_minute, threshold } => {
                format!(":chart_with_upwards_trend: *Ban rate anomaly* {bans_per_minute}/min (threshold {threshold})")
            }
        }
    }
}

#[async_trait]
impl Plugin for SlackPlugin {
    fn manifest(&self) -> &PluginManifest { &self.manifest }

    async fn init(&mut self, cfg: serde_json::Value) -> PluginResult<()> {
        let parsed: Config = serde_json::from_value(cfg)
            .map_err(|e| PluginError::ConfigValidation(e.to_string()))?;
        let client = http::build_client(Duration::from_secs(parsed.timeout_secs))?;
        *self.state.write().await = Some(State { cfg: parsed, client });
        Ok(())
    }
}

#[async_trait]
impl NotifierPlugin for SlackPlugin {
    async fn notify(&self, event: &AlertEvent) -> PluginResult<()> {
        let guard = self.state.read().await;
        let state = guard.as_ref()
            .ok_or_else(|| PluginError::Runtime("slack notifier used before init".into()))?;

        let text = Self::format(event);
        let mut payload = serde_json::json!({
            "text": text,
            "username": state.cfg.username,
            "icon_emoji": state.cfg.icon_emoji,
        });
        if let Some(ref ch) = state.cfg.channel {
            payload["channel"] = serde_json::json!(format!("#{ch}"));
        }

        let resp = state.client.post(&state.cfg.webhook_url)
            .json(&payload)
            .send()
            .await
            .map_err(|e| PluginError::Runtime(format!("HTTP: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            warn!(plugin = PLUGIN_ID, status = %status, "Slack webhook returned non-2xx");
            return Err(PluginError::Runtime(format!("Slack HTTP {status}")));
        }
        Ok(())
    }
}

inventory::submit! {
    PluginDescriptor {
        id: PLUGIN_ID,
        kind: PluginKind::Notifier,
        api_version: API_VERSION,
        manifest: SlackPlugin::manifest_fn,
        config_schema: include_str!("../schema.json"),
        factory: PluginFactory::Notifier(SlackPlugin::create),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hiveguard_plugin_api::context::parking_lot_compat::RegistryHandle;
    use hiveguard_plugin_api::secrets::SecretResolver;
    use ipnet::IpNet;

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

    #[test]
    fn manifest_correct() {
        let m = SlackPlugin::manifest_fn();
        assert_eq!(m.id, PLUGIN_ID);
        assert_eq!(m.kind, PluginKind::Notifier);
    }

    #[tokio::test]
    async fn factory_accepts_minimal() {
        let cfg = serde_json::json!({ "webhook_url": "https://example.com/x" });
        let _p = SlackPlugin::create(test_ctx(), cfg).await.unwrap();
    }

    #[tokio::test]
    async fn factory_rejects_missing_url() {
        match SlackPlugin::create(test_ctx(), serde_json::json!({})).await {
            Err(PluginError::ConfigValidation(_)) => {}
            Err(other) => panic!("expected ConfigValidation, got {other:?}"),
            Ok(_) => panic!("expected error"),
        }
    }

    #[test]
    fn format_renders_ip_ban() {
        let event = AlertEvent::IpBanned {
            ip: "1.2.3.4/32".parse::<IpNet>().unwrap(),
            severity: 200,
            reason: "test".into(),
            geo: None,
        };
        let out = SlackPlugin::format(&event);
        assert!(out.contains("1.2.3.4"));
        assert!(out.contains("severity 200"));
    }
}
