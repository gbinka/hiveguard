use std::time::Duration;

use chrono::Utc;
use hiveguard_core::Detector;
use hiveguard_core::detectors::Http4xxFloodDetector;
use hiveguard_core::models::EventType;
use hiveguard_plugin_api::prelude::*;
use serde::Deserialize;

pub const PLUGIN_ID: &str = "detector.http_4xx_flood";
pub const PLUGIN_VERSION: &str = "0.1.0";

#[derive(Debug, Deserialize, Default)]
struct Config {
    threshold: Option<u32>,
    window_secs: Option<u64>,
    ban_duration_secs: Option<u64>,
}

pub struct Http4xxFloodPlugin {
    manifest: PluginManifest,
    detector: Http4xxFloodDetector,
}

impl Http4xxFloodPlugin {
    pub fn manifest_fn() -> PluginManifest {
        PluginManifest {
            id: PLUGIN_ID,
            version: PLUGIN_VERSION,
            description: "HTTP 4xx flood detector.",
            kind: PluginKind::Detector,
            author: "HiveGuard",
            docs_url: Some("https://github.com/anthropics/hiveguard/blob/main/plugins/detector-http-4xx-flood/README.md"),
        }
    }

    pub fn create(
        ctx: PluginContext,
        cfg: serde_json::Value,
    ) -> BoxFuture<'static, PluginResult<Box<dyn DetectorPlugin>>> {
        Box::pin(async move {
            let mut plugin = Http4xxFloodPlugin {
                manifest: Self::manifest_fn(),
                detector: Http4xxFloodDetector::new(),
            };
            <Http4xxFloodPlugin as Plugin>::init(&mut plugin, cfg).await?;
            let _ = ctx;
            Ok(Box::new(plugin) as Box<dyn DetectorPlugin>)
        })
    }

    fn from_config(cfg: Config) -> Http4xxFloodDetector {
        let threshold = cfg.threshold.unwrap_or(50);
        let window = Duration::from_secs(cfg.window_secs.unwrap_or(60));
        let ban = Duration::from_secs(cfg.ban_duration_secs.unwrap_or(3_600));
        Http4xxFloodDetector::with_config(threshold, window, ban)
    }
}

#[async_trait]
impl Plugin for Http4xxFloodPlugin {
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

impl DetectorPlugin for Http4xxFloodPlugin {
    fn process(&self, event: &NormalizedEvent) -> Option<DetectionSignal> {
        self.detector.process(event)
    }
}

inventory::submit! {
    PluginDescriptor {
        id: PLUGIN_ID,
        kind: PluginKind::Detector,
        api_version: API_VERSION,
        manifest: Http4xxFloodPlugin::manifest_fn,
        config_schema: include_str!("../schema.json"),
        factory: PluginFactory::Detector(Http4xxFloodPlugin::create),
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

    #[test]
    fn manifest_has_correct_id_and_kind() {
        let p = Http4xxFloodPlugin {
            manifest: Http4xxFloodPlugin::manifest_fn(),
            detector: Http4xxFloodDetector::new(),
        };
        assert_eq!(p.manifest().id, PLUGIN_ID);
        assert_eq!(p.manifest().kind, PluginKind::Detector);
    }

    #[tokio::test]
    async fn factory_accepts_defaults() {
        let plugin = Http4xxFloodPlugin::create(test_ctx(), serde_json::json!({}))
            .await
            .unwrap();
        assert_eq!(plugin.manifest().id, PLUGIN_ID);
    }

    #[tokio::test]
    async fn factory_accepts_full_config() {
        let plugin = Http4xxFloodPlugin::create(
            test_ctx(),
            serde_json::json!({
                "threshold": 75,
                "window_secs": 120,
                "ban_duration_secs": 7200
            }),
        )
        .await;
        assert!(plugin.is_ok());
    }

    #[tokio::test]
    async fn process_returns_none_for_unrelated_event() {
        let plugin = Http4xxFloodPlugin::create(test_ctx(), serde_json::json!({}))
            .await
            .unwrap();
        assert!(plugin.process(&unrelated_event()).is_none());
    }
}
