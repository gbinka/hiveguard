use std::net::IpAddr;
use std::time::Duration;

use serde::Deserialize;

use hiveguard_cti::tor::TorProvider;
use hiveguard_cti::CtiProvider as LegacyCtiProvider;
use hiveguard_plugin_api::prelude::*;

const PLUGIN_ID: &str = "cti.tor";
const PLUGIN_VERSION: &str = "0.1.0";

#[derive(Debug, Deserialize)]
struct Config {
    #[serde(default = "default_refresh")]
    refresh_interval_secs: u64,
    #[serde(default)]
    ban_on_first_hit: bool,
}

fn default_refresh() -> u64 { 3600 }

pub struct TorPlugin {
    manifest: PluginManifest,
    provider: Option<TorProvider>,
    ban_on_first_hit: bool,
}

impl TorPlugin {
    pub fn manifest_fn() -> PluginManifest {
        PluginManifest {
            id: PLUGIN_ID,
            version: PLUGIN_VERSION,
            description: "Tor exit list provider.",
            kind: PluginKind::CtiProvider,
            author: "HiveGuard",
            docs_url: Some("https://github.com/anthropics/hiveguard/blob/main/plugins/cti-tor/README.md"),
        }
    }

    pub fn create(
        _ctx: PluginContext,
        cfg: serde_json::Value,
    ) -> BoxFuture<'static, PluginResult<Box<dyn CtiProviderPlugin>>> {
        Box::pin(async move {
            let mut plugin = TorPlugin {
                manifest: Self::manifest_fn(),
                provider: None,
                ban_on_first_hit: false,
            };
            <TorPlugin as Plugin>::init(&mut plugin, cfg).await?;
            Ok(Box::new(plugin) as Box<dyn CtiProviderPlugin>)
        })
    }

    fn provider_ref(&self) -> PluginResult<&TorProvider> {
        self.provider
            .as_ref()
            .ok_or_else(|| PluginError::Runtime("plugin used before init".into()))
    }
}

#[async_trait]
impl Plugin for TorPlugin {
    fn manifest(&self) -> &PluginManifest { &self.manifest }

    async fn init(&mut self, cfg: serde_json::Value) -> PluginResult<()> {
        let parsed: Config = serde_json::from_value(cfg)
            .map_err(|e| PluginError::ConfigValidation(e.to_string()))?;
        self.ban_on_first_hit = parsed.ban_on_first_hit;

        let client = reqwest::Client::builder()
            .build()
            .map_err(|e| PluginError::Runtime(e.to_string()))?;
        let provider = TorProvider::new(client, Duration::from_secs(parsed.refresh_interval_secs)).await;
        self.provider = Some(provider);
        Ok(())
    }
}

#[async_trait]
impl CtiProviderPlugin for TorPlugin {
    async fn lookup(&self, ip: IpAddr) -> PluginResult<Option<CtiVerdict>> {
        let (signal, _stats) = self.provider_ref()?.check(ip).await;
        Ok(signal.map(|s| CtiVerdict {
            provider: s.provider.to_string(),
            confidence: Some(s.confidence_score),
            reason: Some(s.description),
            recommend_ban: self.ban_on_first_hit && s.confidence_score >= 90,
        }))
    }
}

inventory::submit! {
    PluginDescriptor {
        id: PLUGIN_ID,
        kind: PluginKind::CtiProvider,
        api_version: API_VERSION,
        manifest: TorPlugin::manifest_fn,
        config_schema: include_str!("../schema.json"),
        factory: PluginFactory::CtiProvider(TorPlugin::create),
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

    #[test]
    fn manifest_has_correct_id_and_kind() {
        let manifest = TorPlugin::manifest_fn();
        assert_eq!(manifest.id, PLUGIN_ID);
        assert_eq!(manifest.kind, PluginKind::CtiProvider);
    }

    #[tokio::test]
    async fn factory_accepts_valid_config() {
        let cfg = serde_json::json!({ "refresh_interval_secs": 3600 });
        let _plugin = TorPlugin::create(test_ctx(), cfg).await.unwrap();
    }

    #[tokio::test]
    async fn factory_rejects_invalid_config() {
        let bad_cfg = serde_json::json!({ "refresh_interval_secs": "fast" });
        match TorPlugin::create(test_ctx(), bad_cfg).await {
            Err(PluginError::ConfigValidation(_)) => {}
            Err(other) => panic!("expected ConfigValidation, got {other:?}"),
            Ok(_) => panic!("expected error"),
        }
    }
}
