use std::time::Duration;

use hiveguard_core::Detector;
use hiveguard_core::detectors::HttpFloodDetector;
use hiveguard_core::models::NormalizedEvent;
use hiveguard_plugin_api::prelude::*;
use serde::Deserialize;

pub const PLUGIN_ID: &str = "detector.http_flood";
pub const PLUGIN_VERSION: &str = "0.1.0";

#[derive(Debug, Deserialize, Default)]
struct Config {
    window_secs: Option<u64>,
    ip_threshold: Option<u64>,
    subnet_threshold: Option<u64>,
    ban_duration_secs: Option<u64>,
    ignore_extensions: Option<Vec<String>>,
}

pub struct HttpFloodPlugin {
    manifest: PluginManifest,
    detector: HttpFloodDetector,
}

impl HttpFloodPlugin {
    pub fn manifest_fn() -> PluginManifest {
        PluginManifest {
            id: PLUGIN_ID,
            version: PLUGIN_VERSION,
            description: "Volumetric HTTP flood detector (rate per IP and per subnet, any status).",
            kind: PluginKind::Detector,
            author: "HiveGuard",
            docs_url: Some("https://github.com/anthropics/hiveguard/blob/main/plugins/detector-http-flood/README.md"),
        }
    }

    pub fn create(
        ctx: PluginContext,
        cfg: serde_json::Value,
    ) -> BoxFuture<'static, PluginResult<Box<dyn DetectorPlugin>>> {
        Box::pin(async move {
            let mut plugin = HttpFloodPlugin {
                manifest: Self::manifest_fn(),
                detector: HttpFloodDetector::new(),
            };
            <HttpFloodPlugin as Plugin>::init(&mut plugin, cfg).await?;
            let _ = ctx;
            Ok(Box::new(plugin) as Box<dyn DetectorPlugin>)
        })
    }

    fn from_config(cfg: Config) -> HttpFloodDetector {
        HttpFloodDetector::with_config(
            Duration::from_secs(cfg.window_secs.unwrap_or(60)),
            cfg.ip_threshold.unwrap_or(600),
            cfg.subnet_threshold.unwrap_or(2400),
            Duration::from_secs(cfg.ban_duration_secs.unwrap_or(43_200)),
            cfg.ignore_extensions
                .unwrap_or_else(hiveguard_core::detectors::http_flood::default_ignore_extensions),
        )
    }
}

#[async_trait]
impl Plugin for HttpFloodPlugin {
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

impl DetectorPlugin for HttpFloodPlugin {
    fn process(&self, event: &NormalizedEvent) -> Option<DetectionSignal> {
        self.detector.process(event)
    }
}

inventory::submit! {
    PluginDescriptor {
        id: PLUGIN_ID,
        kind: PluginKind::Detector,
        api_version: API_VERSION,
        manifest: HttpFloodPlugin::manifest_fn,
        config_schema: include_str!("../schema.json"),
        factory: PluginFactory::Detector(HttpFloodPlugin::create),
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

    fn http_event(ip: &str) -> NormalizedEvent {
        let mut metadata = HashMap::new();
        metadata.insert("path".to_string(), "/katalog/obuwie".to_string());
        metadata.insert("status_code".to_string(), "200".to_string());
        NormalizedEvent {
            timestamp: Utc::now(),
            source_ip: ip.parse().unwrap(),
            event_type: EventType::HttpRequest,
            source_name: "nginx".into(),
            raw_line: "GET /katalog/obuwie 200".into(),
            metadata,
        }
    }

    #[test]
    fn manifest_has_correct_id_and_kind() {
        let p = HttpFloodPlugin {
            manifest: HttpFloodPlugin::manifest_fn(),
            detector: HttpFloodDetector::new(),
        };
        assert_eq!(p.manifest().id, PLUGIN_ID);
        assert_eq!(p.manifest().kind, PluginKind::Detector);
    }

    #[tokio::test]
    async fn factory_accepts_defaults() {
        let p = HttpFloodPlugin::create(test_ctx(), serde_json::json!({})).await;
        assert!(p.is_ok());
    }

    #[tokio::test]
    async fn factory_accepts_full_config() {
        let p = HttpFloodPlugin::create(
            test_ctx(),
            serde_json::json!({
                "window_secs": 60,
                "ip_threshold": 600,
                "subnet_threshold": 2400,
                "ban_duration_secs": 43200,
                "ignore_extensions": [".css", ".js"]
            }),
        )
        .await;
        assert!(p.is_ok());
    }

    #[tokio::test]
    async fn factory_rejects_malformed_config() {
        let p = HttpFloodPlugin::create(test_ctx(), serde_json::json!({"window_secs": "abc"})).await;
        assert!(p.is_err());
    }

    #[tokio::test]
    async fn low_threshold_config_fires_on_flood() {
        let p = HttpFloodPlugin::create(
            test_ctx(),
            serde_json::json!({ "window_secs": 60, "ip_threshold": 3, "subnet_threshold": 0 }),
        )
        .await
        .unwrap();

        assert!(p.process(&http_event("203.0.113.9")).is_none());
        assert!(p.process(&http_event("203.0.113.9")).is_none());
        let signal = p.process(&http_event("203.0.113.9"));
        assert!(signal.is_some());
        assert_eq!(signal.unwrap().source_ip.to_string(), "203.0.113.9/32");
    }
}
