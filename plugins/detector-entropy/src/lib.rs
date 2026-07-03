use std::collections::HashMap;
use chrono::Utc;
use hiveguard_core::Detector;
use hiveguard_core::detectors::EntropyDetector;
use hiveguard_core::models::{EventType, NormalizedEvent};
use hiveguard_plugin_api::prelude::*;
use serde::Deserialize;

pub const PLUGIN_ID: &str = "detector.entropy";
pub const PLUGIN_VERSION: &str = "0.1.0";

#[derive(Debug, Deserialize, Default)]
struct Config {
    score_threshold: Option<f64>,
    benign_penalty: Option<f64>,
    error_response_multiplier: Option<f64>,
    min_entropy: Option<f64>,
    max_entropy: Option<f64>,
}

pub struct EntropyPlugin {
    manifest: PluginManifest,
    detector: EntropyDetector,
}

impl EntropyPlugin {
    pub fn manifest_fn() -> PluginManifest {
        PluginManifest {
            id: PLUGIN_ID,
            version: PLUGIN_VERSION,
            description: "Entropy anomaly detector.",
            kind: PluginKind::Detector,
            author: "HiveGuard",
            docs_url: Some("https://github.com/anthropics/hiveguard/blob/main/plugins/detector-entropy/README.md"),
        }
    }

    pub fn create(
        ctx: PluginContext,
        cfg: serde_json::Value,
    ) -> BoxFuture<'static, PluginResult<Box<dyn DetectorPlugin>>> {
        Box::pin(async move {
            let mut plugin = EntropyPlugin {
                manifest: Self::manifest_fn(),
                detector: EntropyDetector::new(),
            };
            <EntropyPlugin as Plugin>::init(&mut plugin, cfg).await?;
            let _ = ctx;
            Ok(Box::new(plugin) as Box<dyn DetectorPlugin>)
        })
    }

    fn from_config(cfg: Config) -> EntropyDetector {
        EntropyDetector::from_config(
            cfg.score_threshold.unwrap_or(25.0),
            cfg.benign_penalty.unwrap_or(30.0),
            cfg.error_response_multiplier.unwrap_or(1.5),
        )
    }
}

#[async_trait]
impl Plugin for EntropyPlugin {
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

impl DetectorPlugin for EntropyPlugin {
    fn process(&self, event: &NormalizedEvent) -> Option<DetectionSignal> {
        self.detector.process(event)
    }
}

inventory::submit! {
    PluginDescriptor {
        id: PLUGIN_ID,
        kind: PluginKind::Detector,
        api_version: API_VERSION,
        manifest: EntropyPlugin::manifest_fn,
        config_schema: include_str!("../schema.json"),
        factory: PluginFactory::Detector(EntropyPlugin::create),
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
        let p = EntropyPlugin {
            manifest: EntropyPlugin::manifest_fn(),
            detector: EntropyDetector::new(),
        };
        assert_eq!(p.manifest().id, PLUGIN_ID);
        assert_eq!(p.manifest().kind, PluginKind::Detector);
    }

    #[tokio::test]
    async fn factory_accepts_defaults() {
        let p = EntropyPlugin::create(test_ctx(), serde_json::json!({})).await;
        assert!(p.is_ok());
    }

    #[tokio::test]
    async fn factory_accepts_full_config() {
        let p = EntropyPlugin::create(
            test_ctx(),
            serde_json::json!({
                "score_threshold": 20.0,
                "benign_penalty": 25.0,
                "error_response_multiplier": 1.3,
                "min_entropy": 5.0,
                "max_entropy": 7.5
            }),
        )
        .await;
        assert!(p.is_ok());
    }

    #[tokio::test]
    async fn process_returns_none_for_unrelated_event() {
        let p = EntropyPlugin::create(test_ctx(), serde_json::json!({}))
            .await
            .unwrap();
        assert!(p.process(&unrelated_event()).is_none());
    }
}
