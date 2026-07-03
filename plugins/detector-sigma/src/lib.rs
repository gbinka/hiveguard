use std::path::PathBuf;

use serde::Deserialize;
use tokio::sync::watch;
use tokio::task::JoinHandle;

use hiveguard_core::detector::Detector as LegacyDetector;
use hiveguard_plugin_api::prelude::*;
use hiveguard_sigma::{load_rules_from_dir, spawn_hot_reload_watcher, FieldMapper, SigmaDetector};

const PLUGIN_ID: &str = "detector.sigma";
const PLUGIN_VERSION: &str = "0.1.0";

#[derive(Debug, Deserialize)]
struct Config {
    rules_dir: PathBuf,
    #[serde(default = "default_hot_reload")]
    hot_reload: bool,
}

fn default_hot_reload() -> bool { true }

pub struct SigmaPlugin {
    manifest: PluginManifest,
    // SigmaDetector::process is now `&self` (interior mutability via
    // Arc<Mutex<HashMap>> for stats); no outer lock needed.
    detector: Option<SigmaDetector>,
    shutdown_tx: Option<watch::Sender<bool>>,
    watcher: Option<JoinHandle<()>>,
}

impl SigmaPlugin {
    pub fn manifest_fn() -> PluginManifest {
        PluginManifest {
            id: PLUGIN_ID,
            version: PLUGIN_VERSION,
            description: "Sigma rule detector.",
            kind: PluginKind::Detector,
            author: "HiveGuard",
            docs_url: Some("https://github.com/anthropics/hiveguard/blob/main/plugins/detector-sigma/README.md"),
        }
    }

    pub fn create(
        _ctx: PluginContext,
        cfg: serde_json::Value,
    ) -> BoxFuture<'static, PluginResult<Box<dyn DetectorPlugin>>> {
        Box::pin(async move {
            let mut plugin = SigmaPlugin {
                manifest: Self::manifest_fn(),
                detector: None,
                shutdown_tx: None,
                watcher: None,
            };
            <SigmaPlugin as Plugin>::init(&mut plugin, cfg).await?;
            Ok(Box::new(plugin) as Box<dyn DetectorPlugin>)
        })
    }
}

#[async_trait]
impl Plugin for SigmaPlugin {
    fn manifest(&self) -> &PluginManifest { &self.manifest }

    async fn init(&mut self, cfg: serde_json::Value) -> PluginResult<()> {
        let parsed: Config = serde_json::from_value(cfg)
            .map_err(|e| PluginError::ConfigValidation(e.to_string()))?;

        let rules = load_rules_from_dir(&parsed.rules_dir);
        let detector = SigmaDetector::new(rules, FieldMapper::new());

        let rules_handle = detector.rules_handle();
        self.detector = Some(detector);

        if parsed.hot_reload {
            let (tx, rx) = watch::channel(false);
            let handle = spawn_hot_reload_watcher(parsed.rules_dir, rules_handle, rx);
            self.shutdown_tx = Some(tx);
            self.watcher = Some(handle);
        }

        Ok(())
    }

    async fn shutdown(&mut self) -> PluginResult<()> {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(true);
        }
        if let Some(handle) = self.watcher.take() {
            let _ = handle.await;
        }
        Ok(())
    }
}

impl DetectorPlugin for SigmaPlugin {
    fn process(&self, event: &NormalizedEvent) -> Option<DetectionSignal> {
        self.detector.as_ref()?.process(event)
    }
}

inventory::submit! {
    PluginDescriptor {
        id: PLUGIN_ID,
        kind: PluginKind::Detector,
        api_version: API_VERSION,
        manifest: SigmaPlugin::manifest_fn,
        config_schema: include_str!("../schema.json"),
        factory: PluginFactory::Detector(SigmaPlugin::create),
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

    #[test]
    fn manifest_has_correct_id_and_kind() {
        let manifest = SigmaPlugin::manifest_fn();
        assert_eq!(manifest.id, PLUGIN_ID);
        assert_eq!(manifest.kind, PluginKind::Detector);
    }

    #[tokio::test]
    async fn factory_accepts_valid_config() {
        let rules_dir = std::env::temp_dir().join("hg_sigma_rules_valid");
        std::fs::create_dir_all(&rules_dir).unwrap();
        let cfg = serde_json::json!({
            "rules_dir": rules_dir,
            "hot_reload": false
        });
        let _plugin = SigmaPlugin::create(test_ctx(), cfg).await.unwrap();
    }

    #[tokio::test]
    async fn factory_rejects_invalid_config() {
        let bad_cfg = serde_json::json!({ "hot_reload": true });
        match SigmaPlugin::create(test_ctx(), bad_cfg).await {
            Err(PluginError::ConfigValidation(_)) => {}
            Err(other) => panic!("expected ConfigValidation, got {other:?}"),
            Ok(_) => panic!("expected error"),
        }
    }

    #[tokio::test]
    async fn process_returns_none_for_unrelated_event() {
        let rules_dir = std::env::temp_dir().join("hg_sigma_rules_empty");
        std::fs::create_dir_all(&rules_dir).unwrap();
        let cfg = serde_json::json!({
            "rules_dir": rules_dir,
            "hot_reload": false
        });

        let plugin = SigmaPlugin::create(test_ctx(), cfg).await.unwrap();
        let event = NormalizedEvent {
            timestamp: Utc::now(),
            source_ip: "10.0.0.1".parse().unwrap(),
            event_type: EventType::AuthFailure,
            source_name: "unit-test".to_string(),
            raw_line: "failed login".to_string(),
            metadata: HashMap::new(),
        };

        assert!(plugin.process(&event).is_none());
    }
}
