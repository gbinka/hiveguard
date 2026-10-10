//! `detector.campaign` — cross-IP login campaign detector (distributed
//! low-and-slow credential stuffing). Logic: `hiveguard_core::detectors::campaign`.

use std::time::Duration;

use hiveguard_core::detectors::campaign::{CampaignConfig, CampaignDetector};
use hiveguard_core::models::NormalizedEvent;
use hiveguard_core::Detector;
use hiveguard_plugin_api::prelude::*;
use serde::Deserialize;

pub const PLUGIN_ID: &str = "detector.campaign";
pub const PLUGIN_VERSION: &str = "0.1.0";

#[derive(Debug, Deserialize, Default)]
struct Config {
    paths: Option<Vec<String>>,
    methods: Option<Vec<String>>,
    window_secs: Option<u64>,
    min_distinct_ips: Option<usize>,
    min_requests: Option<usize>,
    hot_secs: Option<u64>,
    ban_duration_secs: Option<u64>,
    ignore_user_agents: Option<Vec<String>>,
    #[serde(default)]
    extra_ignore_user_agents: Vec<String>,
    ignore_vhosts: Option<Vec<String>>,
    ignore_redirects: Option<bool>,
    vhost_min_distinct_ips: Option<usize>,
    retro_ban: Option<bool>,
    max_retro_bans: Option<usize>,
    retro_batch: Option<usize>,
    max_keys: Option<usize>,
    max_hits_per_key: Option<usize>,
}

pub struct CampaignPlugin {
    manifest: PluginManifest,
    detector: CampaignDetector,
}

impl CampaignPlugin {
    pub fn manifest_fn() -> PluginManifest {
        PluginManifest {
            id: PLUGIN_ID,
            version: PLUGIN_VERSION,
            description: "Cross-IP login campaign detector (distributed credential stuffing).",
            kind: PluginKind::Detector,
            author: "HiveGuard",
            docs_url: Some("https://github.com/anthropics/hiveguard/blob/main/plugins/detector-campaign/README.md"),
        }
    }

    pub fn create(
        ctx: PluginContext,
        cfg: serde_json::Value,
    ) -> BoxFuture<'static, PluginResult<Box<dyn DetectorPlugin>>> {
        Box::pin(async move {
            let mut plugin = CampaignPlugin {
                manifest: Self::manifest_fn(),
                detector: CampaignDetector::new(),
            };
            <CampaignPlugin as Plugin>::init(&mut plugin, cfg).await?;
            let _ = ctx;
            Ok(Box::new(plugin) as Box<dyn DetectorPlugin>)
        })
    }

    fn from_config(cfg: Config) -> CampaignDetector {
        let d = CampaignConfig::default();
        let mut ignore = cfg.ignore_user_agents.unwrap_or(d.ignore_user_agents);
        ignore.extend(cfg.extra_ignore_user_agents);
        CampaignDetector::with_config(CampaignConfig {
            paths: cfg.paths.unwrap_or(d.paths),
            methods: cfg.methods.unwrap_or(d.methods),
            window: cfg.window_secs.map(Duration::from_secs).unwrap_or(d.window),
            min_distinct_ips: cfg.min_distinct_ips.unwrap_or(d.min_distinct_ips),
            min_requests: cfg.min_requests.unwrap_or(d.min_requests),
            hot_duration: cfg
                .hot_secs
                .map(Duration::from_secs)
                .unwrap_or(d.hot_duration),
            ban_duration: cfg
                .ban_duration_secs
                .map(Duration::from_secs)
                .unwrap_or(d.ban_duration),
            ignore_user_agents: ignore,
            ignore_vhosts: cfg.ignore_vhosts.unwrap_or(d.ignore_vhosts),
            ignore_redirects: cfg.ignore_redirects.unwrap_or(d.ignore_redirects),
            vhost_min_distinct_ips: cfg
                .vhost_min_distinct_ips
                .unwrap_or(d.vhost_min_distinct_ips),
            retro_ban: cfg.retro_ban.unwrap_or(d.retro_ban),
            max_retro_bans: cfg.max_retro_bans.unwrap_or(d.max_retro_bans),
            retro_batch: cfg.retro_batch.unwrap_or(d.retro_batch),
            max_keys: cfg.max_keys.unwrap_or(d.max_keys),
            max_hits_per_key: cfg.max_hits_per_key.unwrap_or(d.max_hits_per_key),
        })
    }
}

#[async_trait]
impl Plugin for CampaignPlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    async fn init(&mut self, cfg: serde_json::Value) -> PluginResult<()> {
        let cfg: Config = serde_json::from_value(cfg)
            .map_err(|e| PluginError::ConfigValidation(e.to_string()))?;
        if cfg.paths.as_ref().is_some_and(|p| p.is_empty()) {
            return Err(PluginError::ConfigValidation(
                "paths must not be empty".into(),
            ));
        }
        if cfg.methods.as_ref().is_some_and(|m| m.is_empty()) {
            return Err(PluginError::ConfigValidation(
                "methods must not be empty".into(),
            ));
        }
        self.detector = Self::from_config(cfg);
        Ok(())
    }
}

impl DetectorPlugin for CampaignPlugin {
    fn process(&self, event: &NormalizedEvent) -> Option<DetectionSignal> {
        self.detector.process(event)
    }

    fn process_multi(&self, event: &NormalizedEvent) -> Vec<DetectionSignal> {
        self.detector.process_multi(event)
    }
}

inventory::submit! {
    PluginDescriptor {
        id: PLUGIN_ID,
        kind: PluginKind::Detector,
        api_version: API_VERSION,
        manifest: CampaignPlugin::manifest_fn,
        config_schema: include_str!("../schema.json"),
        factory: PluginFactory::Detector(CampaignPlugin::create),
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

    fn login(i: u32, ua: &str) -> NormalizedEvent {
        let mut metadata = HashMap::new();
        metadata.insert("method".into(), "POST".into());
        metadata.insert("path".into(), "/wp-login.php".into());
        metadata.insert("user_agent".into(), ua.into());
        metadata.insert("status_code".into(), "200".into());
        metadata.insert("vhost".into(), "site-a.example.org".into());
        NormalizedEvent {
            timestamp: Utc::now(),
            source_ip: format!("216.26.{}.{}", 224 + i / 200, i % 200 + 1)
                .parse()
                .unwrap(),
            event_type: EventType::HttpRequest,
            source_name: "nginx".into(),
            raw_line: String::new(),
            metadata,
        }
    }

    #[test]
    fn manifest_has_correct_id_and_kind() {
        let m = CampaignPlugin::manifest_fn();
        assert_eq!(m.id, PLUGIN_ID);
        assert_eq!(m.kind, PluginKind::Detector);
    }

    #[tokio::test]
    async fn factory_accepts_defaults() {
        assert!(CampaignPlugin::create(test_ctx(), serde_json::json!({}))
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn factory_accepts_full_config() {
        let p = CampaignPlugin::create(
            test_ctx(),
            serde_json::json!({
                "paths": ["/wp-login.php", "/xmlrpc.php"],
                "methods": ["POST"],
                "window_secs": 1800,
                "min_distinct_ips": 15,
                "min_requests": 25,
                "hot_secs": 43200,
                "ban_duration_secs": 86400,
                "ignore_user_agents": ["Googlebot"],
                "extra_ignore_user_agents": ["site-monitor"],
                "ignore_vhosts": ["intranet.example"],
                "ignore_redirects": true,
                "vhost_min_distinct_ips": 40,
                "retro_ban": true,
                "max_retro_bans": 2000,
                "retro_batch": 32,
                "max_keys": 5000,
                "max_hits_per_key": 4096
            }),
        )
        .await;
        assert!(p.is_ok());
    }

    #[tokio::test]
    async fn rejects_bad_config() {
        assert!(
            CampaignPlugin::create(test_ctx(), serde_json::json!({"paths": []}))
                .await
                .is_err()
        );
        assert!(
            CampaignPlugin::create(test_ctx(), serde_json::json!({"window_secs": "x"}))
                .await
                .is_err()
        );
        let schema: serde_json::Value =
            serde_json::from_str(include_str!("../schema.json")).unwrap();
        assert_eq!(schema["additionalProperties"], serde_json::json!(false));
    }

    #[tokio::test]
    async fn process_multi_bans_campaign_participants() {
        let p = CampaignPlugin::create(
            test_ctx(),
            serde_json::json!({"min_distinct_ips": 5, "min_requests": 5}),
        )
        .await
        .unwrap();
        let ua = "Goosee-Audit/1.0 (+internal-security-audit)";
        let mut banned = std::collections::HashSet::new();
        for i in 0..10 {
            for s in p.process_multi(&login(i, ua)) {
                banned.insert(s.source_ip);
            }
        }
        assert_eq!(banned.len(), 10);
        // Known-good UA added through extra list is ignored.
        let p = CampaignPlugin::create(
            test_ctx(),
            serde_json::json!({"min_distinct_ips": 2, "min_requests": 2, "extra_ignore_user_agents": ["Goosee"]}),
        )
        .await
        .unwrap();
        for i in 0..10 {
            assert!(p.process_multi(&login(i, ua)).is_empty());
        }
    }
}
