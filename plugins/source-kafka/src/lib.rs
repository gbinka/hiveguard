//! Apache Kafka source plugin — thin wrapper over `hiveguard_queue::KafkaSource`.

use std::sync::Arc;

use tokio::sync::Mutex;
use tracing::info;

use hiveguard_core::config::KafkaSourceConfig;
use hiveguard_ingest::source::LogSource as LegacyLogSource;
use hiveguard_plugin_api::prelude::*;
use hiveguard_queue::KafkaSource;

pub const PLUGIN_ID: &str = "source.kafka";
const PLUGIN_VERSION: &str = "0.1.0";

pub struct KafkaPlugin {
    manifest: PluginManifest,
    inner: Arc<Mutex<Option<KafkaSource>>>,
}

impl KafkaPlugin {
    pub fn manifest_fn() -> PluginManifest {
        PluginManifest {
            id: PLUGIN_ID,
            version: PLUGIN_VERSION,
            description: "Apache Kafka consumer log source.",
            kind: PluginKind::LogSource,
            author: "HiveGuard",
            docs_url: Some(
                "https://github.com/anthropics/hiveguard/blob/main/plugins/source-kafka/README.md",
            ),
        }
    }

    pub fn create(
        _ctx: PluginContext,
        cfg: serde_json::Value,
    ) -> BoxFuture<'static, PluginResult<Box<dyn LogSourcePlugin>>> {
        Box::pin(async move {
            let mut plugin = KafkaPlugin {
                manifest: Self::manifest_fn(),
                inner: Arc::new(Mutex::new(None)),
            };
            <KafkaPlugin as Plugin>::init(&mut plugin, cfg).await?;
            Ok(Box::new(plugin) as Box<dyn LogSourcePlugin>)
        })
    }
}

#[async_trait]
impl Plugin for KafkaPlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    async fn init(&mut self, cfg: serde_json::Value) -> PluginResult<()> {
        let parsed: KafkaSourceConfig = serde_json::from_value(cfg)
            .map_err(|e| PluginError::ConfigValidation(e.to_string()))?;
        *self.inner.lock().await = Some(KafkaSource::new(parsed));
        Ok(())
    }

    async fn shutdown(&mut self) -> PluginResult<()> {
        if let Some(mut src) = self.inner.lock().await.take() {
            let _ = src.stop().await;
        }
        Ok(())
    }
}

#[async_trait]
impl LogSourcePlugin for KafkaPlugin {
    async fn run(
        &mut self,
        sink: EventSink,
        shutdown: CancellationToken,
    ) -> PluginResult<()> {
        // Legacy `start` spawns the consumer task and returns; we then wait
        // for the cancellation token, call `stop` to drain, and return.
        {
            let mut guard = self.inner.lock().await;
            let src = guard
                .as_mut()
                .ok_or_else(|| PluginError::Runtime("kafka source used before init".into()))?;
            src.start(sink)
                .await
                .map_err(|e| PluginError::Runtime(e.to_string()))?;
        }
        info!(plugin = PLUGIN_ID, "kafka consumer started");

        shutdown.cancelled().await;

        if let Some(mut src) = self.inner.lock().await.take() {
            src.stop()
                .await
                .map_err(|e| PluginError::Runtime(e.to_string()))?;
        }
        info!(plugin = PLUGIN_ID, "kafka consumer stopped");
        Ok(())
    }
}

inventory::submit! {
    PluginDescriptor {
        id: PLUGIN_ID,
        kind: PluginKind::LogSource,
        api_version: API_VERSION,
        manifest: KafkaPlugin::manifest_fn,
        config_schema: include_str!("../schema.json"),
        factory: PluginFactory::LogSource(KafkaPlugin::create),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
        let m = KafkaPlugin::manifest_fn();
        assert_eq!(m.id, PLUGIN_ID);
        assert_eq!(m.kind, PluginKind::LogSource);
    }

    #[tokio::test]
    async fn factory_accepts_minimal_config() {
        let cfg = serde_json::json!({
            "brokers": ["localhost:9092"],
            "topics": [{"name": "logs", "format": "syslog", "parser": "auto"}],
            "group_id": "test-group",
        });
        let _plugin = KafkaPlugin::create(test_ctx(), cfg).await.unwrap();
    }

    #[tokio::test]
    async fn factory_rejects_missing_brokers() {
        let cfg = serde_json::json!({});
        match KafkaPlugin::create(test_ctx(), cfg).await {
            Err(PluginError::ConfigValidation(_)) => {}
            Err(other) => panic!("expected ConfigValidation, got {other:?}"),
            Ok(_) => panic!("expected error"),
        }
    }
}
