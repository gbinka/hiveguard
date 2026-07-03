use std::time::Duration;

use chrono::Utc;
use hiveguard_core::Detector;
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
        let paths = cfg.paths.unwrap_or_else(|| {
            vec![
                "/wp-login.php".to_string(),
                "/xmlrpc.php".to_string(),
                "/.env".to_string(),
                "/phpmyadmin".to_string(),
                "/wp-admin".to_string(),
            ]
        });
        let ban_duration = Duration::from_secs(cfg.ban_duration_secs.unwrap_or(259_200));
        PathProbeDetector::with_config(paths, ban_duration)
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
}
