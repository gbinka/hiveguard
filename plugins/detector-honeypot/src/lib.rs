use std::collections::HashMap;
use std::time::Duration;

use chrono::Utc;
use hiveguard_core::Detector;
use hiveguard_core::detectors::HoneypotDetector;
use hiveguard_core::models::{EventType, NormalizedEvent};
use hiveguard_plugin_api::prelude::*;
use serde::Deserialize;

pub const PLUGIN_ID: &str = "detector.honeypot";
pub const PLUGIN_VERSION: &str = "0.1.0";

#[derive(Debug, Deserialize, Default)]
struct Config {
    paths: Option<Vec<String>>,
    ban_duration_secs: Option<u64>,
    severity: Option<u8>,
}

pub struct HoneypotPlugin {
    manifest: PluginManifest,
    detector: HoneypotDetector,
}

impl HoneypotPlugin {
    pub fn manifest_fn() -> PluginManifest {
        PluginManifest {
            id: PLUGIN_ID,
            version: PLUGIN_VERSION,
            description: "Honeypot path detector.",
            kind: PluginKind::Detector,
            author: "HiveGuard",
            docs_url: Some("https://github.com/anthropics/hiveguard/blob/main/plugins/detector-honeypot/README.md"),
        }
    }

    pub fn create(
        ctx: PluginContext,
        cfg: serde_json::Value,
    ) -> BoxFuture<'static, PluginResult<Box<dyn DetectorPlugin>>> {
        Box::pin(async move {
            let mut plugin = HoneypotPlugin {
                manifest: Self::manifest_fn(),
                detector: HoneypotDetector::new(),
            };
            <HoneypotPlugin as Plugin>::init(&mut plugin, cfg).await?;
            let _ = ctx;
            Ok(Box::new(plugin) as Box<dyn DetectorPlugin>)
        })
    }

    fn from_config(cfg: Config) -> HoneypotDetector {
        let paths = cfg.paths.unwrap_or_else(|| {
            vec![
                "/backup.sql".into(),
                "/db-dump.sql".into(),
                "/admin-panel-secret".into(),
                "/admin-backup-2024.zip".into(),
            ]
        });
        let ban_duration = cfg.ban_duration_secs.map(Duration::from_secs);
        let severity = cfg.severity.unwrap_or(250);
        HoneypotDetector::with_config(paths, ban_duration, severity)
    }
}

#[async_trait]
impl Plugin for HoneypotPlugin {
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

impl DetectorPlugin for HoneypotPlugin {
    fn process(&self, event: &NormalizedEvent) -> Option<DetectionSignal> {
        self.detector.process(event)
    }
}

inventory::submit! {
    PluginDescriptor {
        id: PLUGIN_ID,
        kind: PluginKind::Detector,
        api_version: API_VERSION,
        manifest: HoneypotPlugin::manifest_fn,
        config_schema: include_str!("../schema.json"),
        factory: PluginFactory::Detector(HoneypotPlugin::create),
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
        let p = HoneypotPlugin {
            manifest: HoneypotPlugin::manifest_fn(),
            detector: HoneypotDetector::new(),
        };
        assert_eq!(p.manifest().id, PLUGIN_ID);
        assert_eq!(p.manifest().kind, PluginKind::Detector);
    }

    #[tokio::test]
    async fn factory_accepts_defaults() {
        let p = HoneypotPlugin::create(test_ctx(), serde_json::json!({})).await;
        assert!(p.is_ok());
    }

    #[tokio::test]
    async fn factory_accepts_full_config() {
        let p = HoneypotPlugin::create(
            test_ctx(),
            serde_json::json!({
                "paths": ["/backup.sql", "/db-dump.sql"],
                "ban_duration_secs": 3600,
                "severity": 251
            }),
        )
        .await;
        assert!(p.is_ok());
    }

    #[tokio::test]
    async fn process_returns_none_for_unrelated_event() {
        let p = HoneypotPlugin::create(test_ctx(), serde_json::json!({}))
            .await
            .unwrap();
        assert!(p.process(&unrelated_event()).is_none());
    }

    #[tokio::test]
    async fn process_emits_signal_when_triggered() {
        let p = HoneypotPlugin::create(
            test_ctx(),
            serde_json::json!({ "paths": ["/trap"] }),
        )
        .await
        .unwrap();

        let mut metadata = HashMap::new();
        metadata.insert("path".to_string(), "/trap".to_string());
        let event = NormalizedEvent {
            timestamp: Utc::now(),
            source_ip: "10.10.10.10".parse().unwrap(),
            event_type: EventType::HttpRequest,
            source_name: "nginx".into(),
            raw_line: "GET /trap".into(),
            metadata,
        };

        let signal = p.process(&event);
        assert!(signal.is_some());
        assert!(signal.unwrap().severity >= 250);
    }
}
