use std::collections::HashMap;
use std::time::Duration;

use chrono::Utc;
use hiveguard_core::Detector;
use hiveguard_core::detectors::http_login_bruteforce::{
    HttpLoginBruteforceDetector, DEFAULT_SUBNET_MIN_DISTINCT_IPS, DEFAULT_SUBNET_THRESHOLD,
};
use hiveguard_core::detectors::netkey::{validate_ipv6_prefix, validate_v4_subnet_prefix};
use hiveguard_core::models::{EventType, NormalizedEvent};
use hiveguard_plugin_api::prelude::*;
use serde::Deserialize;

pub const PLUGIN_ID: &str = "detector.http_login_bruteforce";
pub const PLUGIN_VERSION: &str = "0.1.0";

#[derive(Debug, Deserialize, Default)]
struct Config {
    paths: Option<Vec<String>>,
    threshold: Option<u32>,
    window_secs: Option<u64>,
    ban_duration_secs: Option<u64>,
    /// Subnet aggregation (0 = off per family).
    subnet_v4_prefix: Option<u8>,
    subnet_v6_prefix: Option<u8>,
    subnet_threshold: Option<u32>,
    subnet_min_distinct_ips: Option<usize>,
}

pub struct HttpLoginBruteforcePlugin {
    manifest: PluginManifest,
    detector: HttpLoginBruteforceDetector,
}

impl HttpLoginBruteforcePlugin {
    pub fn manifest_fn() -> PluginManifest {
        PluginManifest {
            id: PLUGIN_ID,
            version: PLUGIN_VERSION,
            description: "HTTP login brute-force detector.",
            kind: PluginKind::Detector,
            author: "HiveGuard",
            docs_url: Some("https://github.com/anthropics/hiveguard/blob/main/plugins/detector-http-login-bruteforce/README.md"),
        }
    }

    pub fn create(
        ctx: PluginContext,
        cfg: serde_json::Value,
    ) -> BoxFuture<'static, PluginResult<Box<dyn DetectorPlugin>>> {
        Box::pin(async move {
            let mut plugin = HttpLoginBruteforcePlugin {
                manifest: Self::manifest_fn(),
                detector: HttpLoginBruteforceDetector::new(),
            };
            <HttpLoginBruteforcePlugin as Plugin>::init(&mut plugin, cfg).await?;
            let _ = ctx;
            Ok(Box::new(plugin) as Box<dyn DetectorPlugin>)
        })
    }

    fn from_config(cfg: Config) -> HttpLoginBruteforceDetector {
        let paths = cfg.paths.unwrap_or_else(|| vec!["/wp-login.php".into(), "/xmlrpc.php".into()]);
        let threshold = cfg.threshold.unwrap_or(5);
        let window = Duration::from_secs(cfg.window_secs.unwrap_or(600));
        let ban_duration = Duration::from_secs(cfg.ban_duration_secs.unwrap_or(86_400));
        HttpLoginBruteforceDetector::with_config(paths, threshold, window, ban_duration)
            .with_subnet_aggregation(
                cfg.subnet_v4_prefix.unwrap_or(0),
                cfg.subnet_v6_prefix.unwrap_or(0),
                cfg.subnet_threshold.unwrap_or(DEFAULT_SUBNET_THRESHOLD),
                cfg.subnet_min_distinct_ips.unwrap_or(DEFAULT_SUBNET_MIN_DISTINCT_IPS),
            )
    }
}

#[async_trait]
impl Plugin for HttpLoginBruteforcePlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    async fn init(&mut self, cfg: serde_json::Value) -> PluginResult<()> {
        let cfg: Config = serde_json::from_value(cfg)
            .map_err(|e| PluginError::ConfigValidation(e.to_string()))?;
        validate_v4_subnet_prefix("subnet_v4_prefix", cfg.subnet_v4_prefix.unwrap_or(0))
            .map_err(PluginError::ConfigValidation)?;
        validate_ipv6_prefix("subnet_v6_prefix", cfg.subnet_v6_prefix.unwrap_or(0))
            .map_err(PluginError::ConfigValidation)?;
        self.detector = Self::from_config(cfg);
        Ok(())
    }
}

impl DetectorPlugin for HttpLoginBruteforcePlugin {
    fn process(&self, event: &NormalizedEvent) -> Option<DetectionSignal> {
        self.detector.process(event)
    }
}

inventory::submit! {
    PluginDescriptor {
        id: PLUGIN_ID,
        kind: PluginKind::Detector,
        api_version: API_VERSION,
        manifest: HttpLoginBruteforcePlugin::manifest_fn,
        config_schema: include_str!("../schema.json"),
        factory: PluginFactory::Detector(HttpLoginBruteforcePlugin::create),
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
        let p = HttpLoginBruteforcePlugin {
            manifest: HttpLoginBruteforcePlugin::manifest_fn(),
            detector: HttpLoginBruteforceDetector::new(),
        };
        assert_eq!(p.manifest().id, PLUGIN_ID);
        assert_eq!(p.manifest().kind, PluginKind::Detector);
    }

    #[tokio::test]
    async fn factory_accepts_defaults() {
        let p = HttpLoginBruteforcePlugin::create(test_ctx(), serde_json::json!({})).await;
        assert!(p.is_ok());
    }

    #[tokio::test]
    async fn factory_accepts_full_config() {
        let p = HttpLoginBruteforcePlugin::create(
            test_ctx(),
            serde_json::json!({
                "paths": ["/wp-login.php", "/xmlrpc.php"],
                "threshold": 8,
                "window_secs": 900,
                "ban_duration_secs": 7200
            }),
        )
        .await;
        assert!(p.is_ok());
    }

    #[tokio::test]
    async fn process_returns_none_for_unrelated_event() {
        let p = HttpLoginBruteforcePlugin::create(test_ctx(), serde_json::json!({}))
            .await
            .unwrap();
        assert!(p.process(&unrelated_event()).is_none());
    }

    fn wp_post(ip: &str) -> NormalizedEvent {
        let mut metadata = HashMap::new();
        metadata.insert("path".to_string(), "/wp-login.php".to_string());
        metadata.insert("method".to_string(), "POST".to_string());
        metadata.insert("status_code".to_string(), "200".to_string());
        NormalizedEvent {
            timestamp: Utc::now(),
            source_ip: ip.parse().unwrap(),
            event_type: EventType::HttpRequest,
            source_name: "nginx".into(),
            raw_line: String::new(),
            metadata,
        }
    }

    #[tokio::test]
    async fn subnet_keys_enable_subnet_ban() {
        let p = HttpLoginBruteforcePlugin::create(
            test_ctx(),
            serde_json::json!({
                "subnet_v4_prefix": 24,
                "subnet_v6_prefix": 64,
                "subnet_threshold": 10,
                "subnet_min_distinct_ips": 5
            }),
        )
        .await
        .unwrap();
        let mut last = None;
        for i in 1..=10 {
            last = p.process(&wp_post(&format!("100.64.53.{i}")));
        }
        assert_eq!(last.expect("subnet signal").source_ip.to_string(), "100.64.53.0/24");
    }

    #[tokio::test]
    async fn defaults_keep_per_ip_behaviour() {
        let p = HttpLoginBruteforcePlugin::create(test_ctx(), serde_json::json!({})).await.unwrap();
        for i in 1..=50 {
            assert!(p.process(&wp_post(&format!("100.64.53.{i}"))).is_none());
        }
    }

    #[tokio::test]
    async fn factory_rejects_too_wide_subnet() {
        for cfg in [serde_json::json!({"subnet_v4_prefix": 8}), serde_json::json!({"subnet_v6_prefix": 32})] {
            assert!(HttpLoginBruteforcePlugin::create(test_ctx(), cfg).await.is_err());
        }
    }
}
