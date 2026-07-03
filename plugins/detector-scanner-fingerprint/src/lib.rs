use std::collections::HashMap;
use std::time::Duration;

use chrono::Utc;
use hiveguard_core::Detector;
use hiveguard_core::detectors::ScannerFingerprintDetector;
use hiveguard_core::models::{EventType, NormalizedEvent};
use hiveguard_plugin_api::prelude::*;
use serde::Deserialize;

pub const PLUGIN_ID: &str = "detector.scanner_fingerprint";
pub const PLUGIN_VERSION: &str = "0.1.0";

#[derive(Debug, Deserialize, Default)]
struct Config {
    scanners: Option<Vec<String>>,
    ban_duration_secs: Option<u64>,
}

pub struct ScannerFingerprintPlugin {
    manifest: PluginManifest,
    detector: ScannerFingerprintDetector,
}

impl ScannerFingerprintPlugin {
    pub fn manifest_fn() -> PluginManifest {
        PluginManifest {
            id: PLUGIN_ID,
            version: PLUGIN_VERSION,
            description: "Scanner fingerprint detector.",
            kind: PluginKind::Detector,
            author: "HiveGuard",
            docs_url: Some("https://github.com/anthropics/hiveguard/blob/main/plugins/detector-scanner-fingerprint/README.md"),
        }
    }

    pub fn create(
        ctx: PluginContext,
        cfg: serde_json::Value,
    ) -> BoxFuture<'static, PluginResult<Box<dyn DetectorPlugin>>> {
        Box::pin(async move {
            let mut plugin = ScannerFingerprintPlugin {
                manifest: Self::manifest_fn(),
                detector: ScannerFingerprintDetector::new(),
            };
            <ScannerFingerprintPlugin as Plugin>::init(&mut plugin, cfg).await?;
            let _ = ctx;
            Ok(Box::new(plugin) as Box<dyn DetectorPlugin>)
        })
    }

    fn from_config(cfg: Config) -> ScannerFingerprintDetector {
        let scanners = cfg.scanners.unwrap_or_else(|| {
            vec![
                "nikto".into(), "sqlmap".into(), "nuclei".into(), "nessus".into(),
                "openvas".into(), "w3af".into(), "skipfish".into(), "wpscan".into(),
                "dirbuster".into(), "gobuster".into(), "masscan".into(), "zgrab".into(),
            ]
        });
        let ban_duration = Duration::from_secs(cfg.ban_duration_secs.unwrap_or(259_200));
        ScannerFingerprintDetector::with_config(scanners, ban_duration)
    }
}

#[async_trait]
impl Plugin for ScannerFingerprintPlugin {
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

impl DetectorPlugin for ScannerFingerprintPlugin {
    fn process(&self, event: &NormalizedEvent) -> Option<DetectionSignal> {
        self.detector.process(event)
    }
}

inventory::submit! {
    PluginDescriptor {
        id: PLUGIN_ID,
        kind: PluginKind::Detector,
        api_version: API_VERSION,
        manifest: ScannerFingerprintPlugin::manifest_fn,
        config_schema: include_str!("../schema.json"),
        factory: PluginFactory::Detector(ScannerFingerprintPlugin::create),
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
        let p = ScannerFingerprintPlugin {
            manifest: ScannerFingerprintPlugin::manifest_fn(),
            detector: ScannerFingerprintDetector::new(),
        };
        assert_eq!(p.manifest().id, PLUGIN_ID);
        assert_eq!(p.manifest().kind, PluginKind::Detector);
    }

    #[tokio::test]
    async fn factory_accepts_defaults() {
        let p = ScannerFingerprintPlugin::create(test_ctx(), serde_json::json!({})).await;
        assert!(p.is_ok());
    }

    #[tokio::test]
    async fn factory_accepts_full_config() {
        let p = ScannerFingerprintPlugin::create(
            test_ctx(),
            serde_json::json!({
                "scanners": ["nikto", "sqlmap", "nuclei"],
                "ban_duration_secs": 7200
            }),
        )
        .await;
        assert!(p.is_ok());
    }

    #[tokio::test]
    async fn process_returns_none_for_unrelated_event() {
        let p = ScannerFingerprintPlugin::create(test_ctx(), serde_json::json!({}))
            .await
            .unwrap();
        assert!(p.process(&unrelated_event()).is_none());
    }
}
