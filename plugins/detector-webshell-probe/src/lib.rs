//! `detector.webshell_probe` — webshell / backdoor filename probing detector.
//! Logic: `hiveguard_core::detectors::webshell_probe`.

use std::time::Duration;

use hiveguard_core::detectors::webshell_probe::{WebshellProbeConfig, WebshellProbeDetector};
use hiveguard_core::models::NormalizedEvent;
use hiveguard_core::Detector;
use hiveguard_plugin_api::prelude::*;
use serde::Deserialize;

pub const PLUGIN_ID: &str = "detector.webshell_probe";
pub const PLUGIN_VERSION: &str = "0.1.0";

#[derive(Debug, Deserialize, Default)]
struct Config {
    window_secs: Option<u64>,
    min_distinct_paths: Option<usize>,
    score_threshold: Option<f32>,
    ban_duration_secs: Option<u64>,
    legit_paths: Option<Vec<String>>,
    #[serde(default)]
    extra_legit_paths: Vec<String>,
    ignore_user_agents: Option<Vec<String>>,
    #[serde(default)]
    extra_ignore_user_agents: Vec<String>,
    ignore_vhosts: Option<Vec<String>>,
    shared_path_min_ips: Option<usize>,
    max_tracked_ips: Option<usize>,
    max_tracked_paths: Option<usize>,
    /// IPv6 counting/ban prefix (default 64; 0/128 = per address).
    ipv6_prefix: Option<u8>,
}

pub struct WebshellProbePlugin {
    manifest: PluginManifest,
    detector: WebshellProbeDetector,
}

impl WebshellProbePlugin {
    pub fn manifest_fn() -> PluginManifest {
        PluginManifest {
            id: PLUGIN_ID,
            version: PLUGIN_VERSION,
            description: "Webshell / backdoor PHP filename probing detector (status-code independent).",
            kind: PluginKind::Detector,
            author: "HiveGuard",
            docs_url: Some("https://github.com/anthropics/hiveguard/blob/main/plugins/detector-webshell-probe/README.md"),
        }
    }

    pub fn create(
        ctx: PluginContext,
        cfg: serde_json::Value,
    ) -> BoxFuture<'static, PluginResult<Box<dyn DetectorPlugin>>> {
        Box::pin(async move {
            let mut plugin = WebshellProbePlugin {
                manifest: Self::manifest_fn(),
                detector: WebshellProbeDetector::new(),
            };
            <WebshellProbePlugin as Plugin>::init(&mut plugin, cfg).await?;
            let _ = ctx;
            Ok(Box::new(plugin) as Box<dyn DetectorPlugin>)
        })
    }

    fn from_config(cfg: Config) -> WebshellProbeDetector {
        let d = WebshellProbeConfig::default();
        let mut legit = cfg.legit_paths.unwrap_or(d.legit_paths);
        legit.extend(cfg.extra_legit_paths);
        let mut ignore_ua = cfg.ignore_user_agents.unwrap_or(d.ignore_user_agents);
        ignore_ua.extend(cfg.extra_ignore_user_agents);
        WebshellProbeDetector::with_config(WebshellProbeConfig {
            window: cfg.window_secs.map(Duration::from_secs).unwrap_or(d.window),
            min_distinct_paths: cfg.min_distinct_paths.unwrap_or(d.min_distinct_paths),
            score_threshold: cfg.score_threshold.unwrap_or(d.score_threshold),
            ban_duration: cfg
                .ban_duration_secs
                .map(Duration::from_secs)
                .unwrap_or(d.ban_duration),
            legit_paths: legit,
            ignore_user_agents: ignore_ua,
            ignore_vhosts: cfg.ignore_vhosts.unwrap_or(d.ignore_vhosts),
            shared_path_min_ips: cfg.shared_path_min_ips.unwrap_or(d.shared_path_min_ips),
            max_tracked_ips: cfg.max_tracked_ips.unwrap_or(d.max_tracked_ips),
            max_tracked_paths: cfg.max_tracked_paths.unwrap_or(d.max_tracked_paths),
            ipv6_prefix: cfg.ipv6_prefix.unwrap_or(d.ipv6_prefix),
        })
    }
}

#[async_trait]
impl Plugin for WebshellProbePlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    async fn init(&mut self, cfg: serde_json::Value) -> PluginResult<()> {
        let cfg: Config = serde_json::from_value(cfg)
            .map_err(|e| PluginError::ConfigValidation(e.to_string()))?;
        hiveguard_core::detectors::netkey::validate_ipv6_prefix(
            "ipv6_prefix",
            cfg.ipv6_prefix.unwrap_or(hiveguard_core::detectors::netkey::DEFAULT_IPV6_PREFIX),
        )
        .map_err(PluginError::ConfigValidation)?;
        if cfg
            .score_threshold
            .is_some_and(|s| !s.is_finite() || s <= 0.0)
        {
            return Err(PluginError::ConfigValidation(
                "score_threshold must be > 0".into(),
            ));
        }
        self.detector = Self::from_config(cfg);
        Ok(())
    }
}

impl DetectorPlugin for WebshellProbePlugin {
    fn process(&self, event: &NormalizedEvent) -> Option<DetectionSignal> {
        self.detector.process(event)
    }
}

inventory::submit! {
    PluginDescriptor {
        id: PLUGIN_ID,
        kind: PluginKind::Detector,
        api_version: API_VERSION,
        manifest: WebshellProbePlugin::manifest_fn,
        config_schema: include_str!("../schema.json"),
        factory: PluginFactory::Detector(WebshellProbePlugin::create),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Arc;

    use chrono::Utc;
    use hiveguard_core::models::EventType;
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

    fn get(path: &str, status: u16) -> NormalizedEvent {
        let mut metadata = HashMap::new();
        metadata.insert("method".into(), "GET".into());
        metadata.insert("path".into(), path.into());
        metadata.insert("user_agent".into(), "-".into());
        metadata.insert("status_code".into(), status.to_string());
        metadata.insert("vhost".into(), "shop.example.org".into());
        NormalizedEvent {
            timestamp: Utc::now(),
            source_ip: "20.219.160.77".parse().unwrap(),
            event_type: if status >= 400 {
                EventType::Http4xx
            } else {
                EventType::HttpRequest
            },
            source_name: "nginx".into(),
            raw_line: String::new(),
            metadata,
        }
    }

    #[test]
    fn manifest_has_correct_id_and_kind() {
        let m = WebshellProbePlugin::manifest_fn();
        assert_eq!(m.id, PLUGIN_ID);
        assert_eq!(m.kind, PluginKind::Detector);
    }

    #[tokio::test]
    async fn factory_accepts_defaults_and_full_config() {
        assert!(
            WebshellProbePlugin::create(test_ctx(), serde_json::json!({}))
                .await
                .is_ok()
        );
        let p = WebshellProbePlugin::create(
            test_ctx(),
            serde_json::json!({
                "window_secs": 21600,
                "min_distinct_paths": 6,
                "score_threshold": 12.0,
                "ban_duration_secs": 259200,
                "extra_legit_paths": ["/stats/awstats.php"],
                "ignore_user_agents": ["Googlebot", "bingbot"],
                "extra_ignore_user_agents": ["site-monitor"],
                "ignore_vhosts": ["legacy.example"],
                "shared_path_min_ips": 3,
                "max_tracked_ips": 50000,
                "max_tracked_paths": 20000
            }),
        )
        .await;
        assert!(p.is_ok());
    }

    #[tokio::test]
    async fn rejects_bad_config() {
        assert!(
            WebshellProbePlugin::create(test_ctx(), serde_json::json!({"score_threshold": 0}))
                .await
                .is_err()
        );
        assert!(
            WebshellProbePlugin::create(test_ctx(), serde_json::json!({"window_secs": -1}))
                .await
                .is_err()
        );
        let schema: serde_json::Value =
            serde_json::from_str(include_str!("../schema.json")).unwrap();
        assert_eq!(schema["additionalProperties"], serde_json::json!(false));
    }

    #[tokio::test]
    async fn detects_probe_and_respects_extra_legit() {
        let p = WebshellProbePlugin::create(
            test_ctx(),
            serde_json::json!({"extra_legit_paths": ["/h.php"]}),
        )
        .await
        .unwrap();
        assert!(p.process(&get("/h.php", 502)).is_none());
        let mut fired = false;
        for path in [
            "/0.php",
            "/bro.php",
            "/222.php",
            "/file52.php",
            "/wp-freya.php",
            "/scx.php7",
        ] {
            fired |= p.process(&get(path, 404)).is_some();
        }
        assert!(fired);
    }
}
