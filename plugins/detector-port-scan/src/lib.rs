use std::collections::HashMap;
use std::time::Duration;

use chrono::Utc;
use hiveguard_core::Detector;
use hiveguard_core::detectors::netkey::{
    validate_ipv6_prefix, validate_v4_subnet_prefix, DEFAULT_IPV6_PREFIX,
};
use hiveguard_core::detectors::port_scan::{
    DEFAULT_LONG_BAN_SECS, DEFAULT_LONG_SUBNET_MIN_IPS, DEFAULT_LONG_SUBNET_THRESHOLD,
    DEFAULT_LONG_THRESHOLD, DEFAULT_LONG_WINDOW_SECS, DEFAULT_MAX_TRACKED_IPS,
};
use hiveguard_core::detectors::PortScanDetector;
use hiveguard_core::models::{EventType, NormalizedEvent};
use hiveguard_plugin_api::prelude::*;
use serde::Deserialize;

pub const PLUGIN_ID: &str = "detector.port_scan";
pub const PLUGIN_VERSION: &str = "0.1.0";

#[derive(Debug, Deserialize, Default)]
struct Config {
    window_secs: Option<u64>,
    threshold: Option<usize>,
    ban_duration_secs: Option<u64>,
    /// Long-window ("slow scan") tier; `long_threshold: 0` disables it.
    long_window_secs: Option<u64>,
    long_threshold: Option<usize>,
    long_ban_duration_secs: Option<u64>,
    max_tracked_ips: Option<usize>,
    /// IPv6 sources counted/banned per this prefix (0/128 = per address).
    ipv6_prefix: Option<u8>,
    /// Distributed slow tier over IPv4 subnets (prefix 0 = off).
    long_subnet_v4_prefix: Option<u8>,
    long_subnet_threshold: Option<usize>,
    long_subnet_min_ips: Option<usize>,
}

pub struct PortScanPlugin {
    manifest: PluginManifest,
    detector: PortScanDetector,
}

impl PortScanPlugin {
    pub fn manifest_fn() -> PluginManifest {
        PluginManifest {
            id: PLUGIN_ID,
            version: PLUGIN_VERSION,
            description: "Port scan detector.",
            kind: PluginKind::Detector,
            author: "HiveGuard",
            docs_url: Some("https://github.com/anthropics/hiveguard/blob/main/plugins/detector-port-scan/README.md"),
        }
    }

    pub fn create(
        ctx: PluginContext,
        cfg: serde_json::Value,
    ) -> BoxFuture<'static, PluginResult<Box<dyn DetectorPlugin>>> {
        Box::pin(async move {
            let mut plugin = PortScanPlugin {
                manifest: Self::manifest_fn(),
                detector: PortScanDetector::new(),
            };
            <PortScanPlugin as Plugin>::init(&mut plugin, cfg).await?;
            let _ = ctx;
            Ok(Box::new(plugin) as Box<dyn DetectorPlugin>)
        })
    }

    fn from_config(cfg: Config) -> PortScanDetector {
        PortScanDetector::with_config(
            Duration::from_secs(cfg.window_secs.unwrap_or(600)),
            cfg.threshold.unwrap_or(6),
            Duration::from_secs(cfg.ban_duration_secs.unwrap_or(172_800)),
        )
        .with_long_tier(
            Duration::from_secs(cfg.long_window_secs.unwrap_or(DEFAULT_LONG_WINDOW_SECS)),
            cfg.long_threshold.unwrap_or(DEFAULT_LONG_THRESHOLD),
            Duration::from_secs(cfg.long_ban_duration_secs.unwrap_or(DEFAULT_LONG_BAN_SECS)),
        )
        .with_max_tracked_ips(cfg.max_tracked_ips.unwrap_or(DEFAULT_MAX_TRACKED_IPS))
        .with_ipv6_prefix(cfg.ipv6_prefix.unwrap_or(DEFAULT_IPV6_PREFIX))
        .with_long_subnet_tier(
            cfg.long_subnet_v4_prefix.unwrap_or(0),
            cfg.long_subnet_threshold.unwrap_or(DEFAULT_LONG_SUBNET_THRESHOLD),
            cfg.long_subnet_min_ips.unwrap_or(DEFAULT_LONG_SUBNET_MIN_IPS),
        )
    }
}

#[async_trait]
impl Plugin for PortScanPlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    async fn init(&mut self, cfg: serde_json::Value) -> PluginResult<()> {
        let cfg: Config = serde_json::from_value(cfg)
            .map_err(|e| PluginError::ConfigValidation(e.to_string()))?;
        validate_ipv6_prefix("ipv6_prefix", cfg.ipv6_prefix.unwrap_or(DEFAULT_IPV6_PREFIX))
            .map_err(PluginError::ConfigValidation)?;
        validate_v4_subnet_prefix("long_subnet_v4_prefix", cfg.long_subnet_v4_prefix.unwrap_or(0))
            .map_err(PluginError::ConfigValidation)?;
        self.detector = Self::from_config(cfg);
        Ok(())
    }
}

impl DetectorPlugin for PortScanPlugin {
    fn process(&self, event: &NormalizedEvent) -> Option<DetectionSignal> {
        self.detector.process(event)
    }
}

inventory::submit! {
    PluginDescriptor {
        id: PLUGIN_ID,
        kind: PluginKind::Detector,
        api_version: API_VERSION,
        manifest: PortScanPlugin::manifest_fn,
        config_schema: include_str!("../schema.json"),
        factory: PluginFactory::Detector(PortScanPlugin::create),
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

    fn unrelated_event() -> NormalizedEvent {
        NormalizedEvent {
            timestamp: Utc::now(),
            source_ip: "10.0.0.1".parse().unwrap(),
            event_type: EventType::AuthSuccess,
            source_name: "ssh".into(),
            raw_line: "ok".into(),
            metadata: HashMap::new(),
        }
    }

    #[test]
    fn manifest_has_correct_id_and_kind() {
        let p = PortScanPlugin {
            manifest: PortScanPlugin::manifest_fn(),
            detector: PortScanDetector::new(),
        };
        assert_eq!(p.manifest().id, PLUGIN_ID);
        assert_eq!(p.manifest().kind, PluginKind::Detector);
    }

    #[tokio::test]
    async fn factory_accepts_defaults() {
        let p = PortScanPlugin::create(test_ctx(), serde_json::json!({})).await;
        assert!(p.is_ok());
    }

    #[tokio::test]
    async fn factory_accepts_full_config() {
        let p = PortScanPlugin::create(
            test_ctx(),
            serde_json::json!({
                "window_secs": 45,
                "threshold": 15,
                "ban_duration_secs": 3600,
                "long_window_secs": 86400,
                "long_threshold": 40,
                "long_ban_duration_secs": 604800,
                "max_tracked_ips": 20000,
                "ipv6_prefix": 64,
                "long_subnet_v4_prefix": 24,
                "long_subnet_threshold": 40,
                "long_subnet_min_ips": 3
            }),
        )
        .await;
        assert!(p.is_ok());
    }

    #[tokio::test]
    async fn schema_is_strict_and_lists_new_keys() {
        let schema: serde_json::Value = serde_json::from_str(include_str!("../schema.json")).unwrap();
        assert_eq!(schema["additionalProperties"], serde_json::json!(false));
        for k in [
            "long_window_secs", "long_threshold", "long_ban_duration_secs", "max_tracked_ips",
            "ipv6_prefix", "long_subnet_v4_prefix", "long_subnet_threshold", "long_subnet_min_ips",
        ] {
            assert!(schema["properties"].get(k).is_some(), "{k} missing from schema");
        }
    }

    #[tokio::test]
    async fn slow_scan_fires_through_plugin() {
        let p = PortScanPlugin::create(
            test_ctx(),
            serde_json::json!({"window_secs": 30, "threshold": 20, "long_window_secs": 3600, "long_threshold": 5}),
        )
        .await
        .unwrap();
        let base = Utc::now();
        let mut fired = None;
        for i in 0..5u16 {
            let mut metadata = HashMap::new();
            metadata.insert("port".to_string(), (100 + i).to_string());
            let ev = NormalizedEvent {
                timestamp: base + chrono::Duration::minutes(10 * i as i64),
                source_ip: "100.64.112.16".parse().unwrap(),
                event_type: EventType::PortAccess,
                source_name: "firewall".into(),
                raw_line: String::new(),
                metadata,
            };
            fired = p.process(&ev);
        }
        assert_eq!(fired.unwrap().detector_name, "port_scan_slow");
    }

    #[tokio::test]
    async fn process_returns_none_for_unrelated_event() {
        let p = PortScanPlugin::create(test_ctx(), serde_json::json!({}))
            .await
            .unwrap();
        assert!(p.process(&unrelated_event()).is_none());
    }

    fn port_event(ip: &str, port: u16) -> NormalizedEvent {
        let mut metadata = HashMap::new();
        metadata.insert("port".to_string(), port.to_string());
        NormalizedEvent {
            timestamp: Utc::now(),
            source_ip: ip.parse().unwrap(),
            event_type: EventType::PortAccess,
            source_name: "firewall".into(),
            raw_line: String::new(),
            metadata,
        }
    }

    #[tokio::test]
    async fn default_ipv6_prefix_aggregates_rotation() {
        let p = PortScanPlugin::create(test_ctx(), serde_json::json!({})).await.unwrap();
        let mut fired = None;
        for i in 1..=6u16 {
            fired = p.process(&port_event(&format!("2001:db8:4880:8000::{i:x}"), 100 + i));
        }
        assert_eq!(fired.expect("rotation caught").source_ip.to_string(), "2001:db8:4880:8000::/64");
    }

    #[tokio::test]
    async fn factory_rejects_bad_prefixes() {
        for cfg in [
            serde_json::json!({"ipv6_prefix": 16}),
            serde_json::json!({"long_subnet_v4_prefix": 8}),
        ] {
            assert!(PortScanPlugin::create(test_ctx(), cfg).await.is_err());
        }
    }
}
