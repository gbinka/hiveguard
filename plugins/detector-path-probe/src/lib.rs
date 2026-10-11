use std::time::Duration;

use chrono::Utc;
use hiveguard_core::Detector;
use hiveguard_core::detectors::netkey::validate_ipv6_prefix;
use hiveguard_core::detectors::path_probe::{
    default_exact_paths, default_probe_paths, default_query_patterns, default_segment_paths,
};
use hiveguard_core::detectors::PathProbeDetector;
use hiveguard_core::models::EventType;
use hiveguard_plugin_api::prelude::*;
use serde::Deserialize;

pub const PLUGIN_ID: &str = "detector.path_probe";
pub const PLUGIN_VERSION: &str = "0.1.0";

#[derive(Debug, Deserialize, Default)]
struct Config {
    paths: Option<Vec<String>>,
    ban_duration_secs: Option<u64>,
    /// Segment patterns anywhere in the path (default list; `[]` = off).
    segment_paths: Option<Vec<String>>,
    /// Query substrings after ≤ 2 percent-decodes (default list; `[]` = off).
    query_patterns: Option<Vec<String>>,
    /// Exact paths (default MCP/LLM recon list; `[]` = off).
    exact_paths: Option<Vec<String>>,
    /// IPv6 ban prefix (default 128 = per address).
    ipv6_prefix: Option<u8>,
}

pub struct PathProbePlugin {
    manifest: PluginManifest,
    detector: PathProbeDetector,
}

impl PathProbePlugin {
    pub fn manifest_fn() -> PluginManifest {
        PluginManifest {
            id: PLUGIN_ID,
            version: PLUGIN_VERSION,
            description: "HTTP path probe detector.",
            kind: PluginKind::Detector,
            author: "HiveGuard",
            docs_url: Some("https://github.com/anthropics/hiveguard/blob/main/plugins/detector-path-probe/README.md"),
        }
    }

    pub fn create(
        ctx: PluginContext,
        cfg: serde_json::Value,
    ) -> BoxFuture<'static, PluginResult<Box<dyn DetectorPlugin>>> {
        Box::pin(async move {
            let mut plugin = PathProbePlugin {
                manifest: Self::manifest_fn(),
                detector: PathProbeDetector::new(),
            };
            <PathProbePlugin as Plugin>::init(&mut plugin, cfg).await?;
            let _ = ctx;
            Ok(Box::new(plugin) as Box<dyn DetectorPlugin>)
        })
    }

    fn from_config(cfg: Config) -> PathProbeDetector {
        let paths = cfg.paths.unwrap_or_else(default_probe_paths);
        let ban_duration = Duration::from_secs(cfg.ban_duration_secs.unwrap_or(259_200));
        PathProbeDetector::with_config(paths, ban_duration)
            .with_extended_matching(
                cfg.segment_paths.unwrap_or_else(default_segment_paths),
                cfg.query_patterns.unwrap_or_else(default_query_patterns),
                cfg.exact_paths.unwrap_or_else(default_exact_paths),
            )
            .with_ipv6_prefix(cfg.ipv6_prefix.unwrap_or(128))
    }
}

#[async_trait]
impl Plugin for PathProbePlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    async fn init(&mut self, cfg: serde_json::Value) -> PluginResult<()> {
        let cfg: Config = serde_json::from_value(cfg)
            .map_err(|e| PluginError::ConfigValidation(e.to_string()))?;
        validate_ipv6_prefix("ipv6_prefix", cfg.ipv6_prefix.unwrap_or(128))
            .map_err(PluginError::ConfigValidation)?;
        self.detector = Self::from_config(cfg);
        Ok(())
    }
}

impl DetectorPlugin for PathProbePlugin {
    fn process(&self, event: &NormalizedEvent) -> Option<DetectionSignal> {
        self.detector.process(event)
    }
}

inventory::submit! {
    PluginDescriptor {
        id: PLUGIN_ID,
        kind: PluginKind::Detector,
        api_version: API_VERSION,
        manifest: PathProbePlugin::manifest_fn,
        config_schema: include_str!("../schema.json"),
        factory: PluginFactory::Detector(PathProbePlugin::create),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
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

    fn path_probe_event(ip: &str, path: &str) -> NormalizedEvent {
        let mut metadata = HashMap::new();
        metadata.insert("path".to_string(), path.to_string());
        NormalizedEvent {
            timestamp: Utc::now(),
            source_ip: ip.parse().unwrap(),
            event_type: EventType::Http4xx,
            source_name: "nginx".into(),
            raw_line: format!("GET {}", path),
            metadata,
        }
    }

    #[test]
    fn manifest_has_correct_id_and_kind() {
        let p = PathProbePlugin {
            manifest: PathProbePlugin::manifest_fn(),
            detector: PathProbeDetector::new(),
        };
        assert_eq!(p.manifest().id, PLUGIN_ID);
        assert_eq!(p.manifest().kind, PluginKind::Detector);
    }

    #[tokio::test]
    async fn factory_accepts_defaults() {
        let plugin = PathProbePlugin::create(test_ctx(), serde_json::json!({}))
            .await
            .unwrap();
        assert_eq!(plugin.manifest().id, PLUGIN_ID);
    }

    #[tokio::test]
    async fn factory_accepts_full_config() {
        let plugin = PathProbePlugin::create(
            test_ctx(),
            serde_json::json!({
                "paths": ["/wp-login.php", "/xmlrpc.php", "/.env"],
                "ban_duration_secs": 7200
            }),
        )
        .await;
        assert!(plugin.is_ok());
    }

    #[tokio::test]
    async fn process_returns_none_for_unrelated_event() {
        let plugin = PathProbePlugin::create(test_ctx(), serde_json::json!({}))
            .await
            .unwrap();
        assert!(plugin.process(&unrelated_event()).is_none());
    }

    #[tokio::test]
    async fn process_emits_signal_when_triggered() {
        let plugin = PathProbePlugin::create(
            test_ctx(),
            serde_json::json!({ "paths": ["/wp-login.php"] }),
        )
        .await
        .unwrap();
        assert!(plugin
            .process(&path_probe_event("1.2.3.4", "/wp-login.php"))
            .is_some());
    }

    #[tokio::test]
    async fn default_extended_matching_is_on_even_with_custom_paths() {
        let plugin = PathProbePlugin::create(test_ctx(), serde_json::json!({ "paths": ["/secret"] }))
            .await
            .unwrap();
        for p in [
            "/kontakt/.git/config",
            "/?pagename=templates%252f%252e%252e%252fusr/lib/php/peclcmd",
            "/mcp",
        ] {
            assert!(plugin.process(&path_probe_event("100.64.0.5", p)).is_some(), "{p}");
        }
        assert!(plugin.process(&path_probe_event("100.64.0.5", "/llms.txt")).is_none());
        assert!(plugin.process(&path_probe_event("100.64.0.5", "/wp-json/batch/v1")).is_none());
    }

    #[tokio::test]
    async fn empty_lists_disable_extended_matching() {
        let plugin = PathProbePlugin::create(
            test_ctx(),
            serde_json::json!({
                "paths": ["/secret"],
                "segment_paths": [],
                "query_patterns": [],
                "exact_paths": [],
                "ipv6_prefix": 64,
                "ban_duration_secs": 3600
            }),
        )
        .await
        .unwrap();
        assert!(plugin.process(&path_probe_event("100.64.0.5", "/kontakt/.git/config")).is_none());
        assert!(plugin.process(&path_probe_event("100.64.0.5", "/x?f=/etc/passwd")).is_none());
        assert!(plugin.process(&path_probe_event("100.64.0.5", "/mcp")).is_none());
        let s = plugin.process(&path_probe_event("2001:db8:5::9", "/secret")).unwrap();
        assert_eq!(s.source_ip.to_string(), "2001:db8:5::/64");
    }

    #[tokio::test]
    async fn rejects_too_wide_ipv6_prefix() {
        assert!(PathProbePlugin::create(test_ctx(), serde_json::json!({ "ipv6_prefix": 8 }))
            .await
            .is_err());
    }
}
