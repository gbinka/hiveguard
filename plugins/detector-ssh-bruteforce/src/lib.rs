use std::time::Duration;

use chrono::Utc;
use hiveguard_core::Detector;
use hiveguard_core::detectors::SshBruteforceDetector;
use hiveguard_core::models::EventType;
use hiveguard_plugin_api::prelude::*;
use serde::Deserialize;

pub const PLUGIN_ID: &str = "detector.ssh_bruteforce";
pub const PLUGIN_VERSION: &str = "0.1.0";

#[derive(Debug, Deserialize, Default)]
struct Config {
    threshold: Option<u32>,
    window_secs: Option<u64>,
    ban_duration_secs: Option<u64>,
    enum_threshold: Option<u32>,
    enum_window_secs: Option<u64>,
    enum_ban_duration_secs: Option<u64>,
}

pub struct SshBruteforcePlugin {
    manifest: PluginManifest,
    detector: SshBruteforceDetector,
}

impl SshBruteforcePlugin {
    pub fn manifest_fn() -> PluginManifest {
        PluginManifest {
            id: PLUGIN_ID,
            version: PLUGIN_VERSION,
            description: "SSH brute-force and user-enumeration detector.",
            kind: PluginKind::Detector,
            author: "HiveGuard",
            docs_url: Some("https://github.com/anthropics/hiveguard/blob/main/plugins/detector-ssh-bruteforce/README.md"),
        }
    }

    pub fn create(
        ctx: PluginContext,
        cfg: serde_json::Value,
    ) -> BoxFuture<'static, PluginResult<Box<dyn DetectorPlugin>>> {
        Box::pin(async move {
            let mut plugin = SshBruteforcePlugin {
                manifest: Self::manifest_fn(),
                detector: SshBruteforceDetector::new(),
            };
            <SshBruteforcePlugin as Plugin>::init(&mut plugin, cfg).await?;
            let _ = ctx;
            Ok(Box::new(plugin) as Box<dyn DetectorPlugin>)
        })
    }

    fn from_config(cfg: Config) -> SshBruteforceDetector {
        let threshold = cfg.threshold.unwrap_or(5);
        let window = Duration::from_secs(cfg.window_secs.unwrap_or(300));
        let ban = Duration::from_secs(cfg.ban_duration_secs.unwrap_or(86_400));
        let enum_threshold = cfg.enum_threshold.unwrap_or(3);
        let enum_window = Duration::from_secs(cfg.enum_window_secs.unwrap_or(120));
        let enum_ban = Duration::from_secs(cfg.enum_ban_duration_secs.unwrap_or(172_800));

        SshBruteforceDetector::with_config(
            threshold,
            window,
            ban,
            enum_threshold,
            enum_window,
            enum_ban,
        )
    }
}

#[async_trait]
impl Plugin for SshBruteforcePlugin {
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

impl DetectorPlugin for SshBruteforcePlugin {
    fn process(&self, event: &NormalizedEvent) -> Option<DetectionSignal> {
        self.detector.process(event)
    }
}

inventory::submit! {
    PluginDescriptor {
        id: PLUGIN_ID,
        kind: PluginKind::Detector,
        api_version: API_VERSION,
        manifest: SshBruteforcePlugin::manifest_fn,
        config_schema: include_str!("../schema.json"),
        factory: PluginFactory::Detector(SshBruteforcePlugin::create),
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

    fn auth_failure_event(ip: &str) -> NormalizedEvent {
        NormalizedEvent {
            timestamp: Utc::now(),
            source_ip: ip.parse().unwrap(),
            event_type: EventType::AuthFailure,
            source_name: "ssh".into(),
            raw_line: "fail".into(),
            metadata: HashMap::new(),
        }
    }

    #[test]
    fn manifest_has_correct_id_and_kind() {
        let p = SshBruteforcePlugin {
            manifest: SshBruteforcePlugin::manifest_fn(),
            detector: SshBruteforceDetector::new(),
        };
        assert_eq!(p.manifest().id, PLUGIN_ID);
        assert_eq!(p.manifest().kind, PluginKind::Detector);
    }

    #[tokio::test]
    async fn factory_accepts_defaults() {
        let plugin = SshBruteforcePlugin::create(test_ctx(), serde_json::json!({}))
            .await
            .unwrap();
        assert_eq!(plugin.manifest().id, PLUGIN_ID);
    }

    #[tokio::test]
    async fn factory_accepts_full_config() {
        let plugin = SshBruteforcePlugin::create(
            test_ctx(),
            serde_json::json!({
                "threshold": 7,
                "window_secs": 360,
                "ban_duration_secs": 7200,
                "enum_threshold": 4,
                "enum_window_secs": 180,
                "enum_ban_duration_secs": 10800
            }),
        )
        .await;
        assert!(plugin.is_ok());
    }

    #[tokio::test]
    async fn process_returns_none_for_unrelated_event() {
        let plugin = SshBruteforcePlugin::create(test_ctx(), serde_json::json!({}))
            .await
            .unwrap();
        assert!(plugin.process(&unrelated_event()).is_none());
    }

    #[tokio::test]
    async fn process_emits_signal_when_triggered() {
        let plugin = SshBruteforcePlugin::create(
            test_ctx(),
            serde_json::json!({ "threshold": 3, "window_secs": 300 }),
        )
        .await
        .unwrap();

        assert!(plugin.process(&auth_failure_event("1.2.3.4")).is_none());
        assert!(plugin.process(&auth_failure_event("1.2.3.4")).is_none());
        assert!(plugin.process(&auth_failure_event("1.2.3.4")).is_some());
    }
}
