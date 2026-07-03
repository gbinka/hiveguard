use std::collections::HashMap;
use std::time::Duration;

use chrono::Utc;
use hiveguard_core::Detector;
use hiveguard_core::detectors::TimingDetector;
use hiveguard_core::models::{EventType, NormalizedEvent};
use hiveguard_plugin_api::prelude::*;
use serde::Deserialize;

pub const PLUGIN_ID: &str = "detector.timing";
pub const PLUGIN_VERSION: &str = "0.1.0";

#[derive(Debug, Deserialize, Default)]
struct Config {
    window_secs: Option<u64>,
    min_samples: Option<usize>,
    stddev_threshold_ms: Option<f64>,
}

pub struct TimingPlugin {
    manifest: PluginManifest,
    detector: TimingDetector,
}

impl TimingPlugin {
    pub fn manifest_fn() -> PluginManifest {
        PluginManifest {
            id: PLUGIN_ID,
            version: PLUGIN_VERSION,
            description: "Request timing detector.",
            kind: PluginKind::Detector,
            author: "HiveGuard",
            docs_url: Some("https://github.com/anthropics/hiveguard/blob/main/plugins/detector-timing/README.md"),
        }
    }

    pub fn create(
        ctx: PluginContext,
        cfg: serde_json::Value,
    ) -> BoxFuture<'static, PluginResult<Box<dyn DetectorPlugin>>> {
        Box::pin(async move {
            let mut plugin = TimingPlugin {
                manifest: Self::manifest_fn(),
                detector: TimingDetector::new(),
            };
            <TimingPlugin as Plugin>::init(&mut plugin, cfg).await?;
            let _ = ctx;
            Ok(Box::new(plugin) as Box<dyn DetectorPlugin>)
        })
    }

    fn from_config(cfg: Config) -> TimingDetector {
        TimingDetector::with_config(
            Duration::from_secs(cfg.window_secs.unwrap_or(60)),
            cfg.min_samples.unwrap_or(10),
            cfg.stddev_threshold_ms.unwrap_or(50.0),
        )
    }
}

#[async_trait]
impl Plugin for TimingPlugin {
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

impl DetectorPlugin for TimingPlugin {
    fn process(&self, event: &NormalizedEvent) -> Option<DetectionSignal> {
        self.detector.process(event)
    }
}

inventory::submit! {
    PluginDescriptor {
        id: PLUGIN_ID,
        kind: PluginKind::Detector,
        api_version: API_VERSION,
        manifest: TimingPlugin::manifest_fn,
        config_schema: include_str!("../schema.json"),
        factory: PluginFactory::Detector(TimingPlugin::create),
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
        let p = TimingPlugin {
            manifest: TimingPlugin::manifest_fn(),
            detector: TimingDetector::new(),
        };
        assert_eq!(p.manifest().id, PLUGIN_ID);
        assert_eq!(p.manifest().kind, PluginKind::Detector);
    }

    #[tokio::test]
    async fn factory_accepts_defaults() {
        let p = TimingPlugin::create(test_ctx(), serde_json::json!({})).await;
        assert!(p.is_ok());
    }

    #[tokio::test]
    async fn factory_accepts_full_config() {
        let p = TimingPlugin::create(
            test_ctx(),
            serde_json::json!({
                "window_secs": 120,
                "min_samples": 12,
                "stddev_threshold_ms": 40.0
            }),
        )
        .await;
        assert!(p.is_ok());
    }

    #[tokio::test]
    async fn process_returns_none_for_unrelated_event() {
        let p = TimingPlugin::create(test_ctx(), serde_json::json!({}))
            .await
            .unwrap();
        assert!(p.process(&unrelated_event()).is_none());
    }
}
