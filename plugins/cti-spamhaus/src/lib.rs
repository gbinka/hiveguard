use std::net::IpAddr;

use serde::Deserialize;

use hiveguard_cti::spamhaus::SpamhausProvider;
use hiveguard_cti::CtiProvider as LegacyCtiProvider;
use hiveguard_plugin_api::prelude::*;

const PLUGIN_ID: &str = "cti.spamhaus";
const PLUGIN_VERSION: &str = "0.1.0";

#[derive(Debug, Deserialize)]
struct Config {
    #[serde(default)]
    custom_resolver: Option<String>,
    #[serde(default = "default_threshold")]
    confidence_threshold: u8,
    #[serde(default)]
    ban_on_first_hit: bool,
}

fn default_threshold() -> u8 { 50 }

pub struct SpamhausPlugin {
    manifest: PluginManifest,
    provider: Option<SpamhausProvider>,
    ban_on_first_hit: bool,
}

impl SpamhausPlugin {
    pub fn manifest_fn() -> PluginManifest {
        PluginManifest {
            id: PLUGIN_ID,
            version: PLUGIN_VERSION,
            description: "Spamhaus DNSBL provider.",
            kind: PluginKind::CtiProvider,
            author: "HiveGuard",
            docs_url: Some("https://github.com/anthropics/hiveguard/blob/main/plugins/cti-spamhaus/README.md"),
        }
    }

    pub fn create(
        _ctx: PluginContext,
        cfg: serde_json::Value,
    ) -> BoxFuture<'static, PluginResult<Box<dyn CtiProviderPlugin>>> {
        Box::pin(async move {
            let mut plugin = SpamhausPlugin {
                manifest: Self::manifest_fn(),
                provider: None,
                ban_on_first_hit: false,
            };
            <SpamhausPlugin as Plugin>::init(&mut plugin, cfg).await?;
            Ok(Box::new(plugin) as Box<dyn CtiProviderPlugin>)
        })
    }

    fn provider_ref(&self) -> PluginResult<&SpamhausProvider> {
        self.provider
            .as_ref()
            .ok_or_else(|| PluginError::Runtime("plugin used before init".into()))
    }
}

#[async_trait]
impl Plugin for SpamhausPlugin {
    fn manifest(&self) -> &PluginManifest { &self.manifest }

    async fn init(&mut self, cfg: serde_json::Value) -> PluginResult<()> {
        let parsed: Config = serde_json::from_value(cfg)
            .map_err(|e| PluginError::ConfigValidation(e.to_string()))?;
        self.ban_on_first_hit = parsed.ban_on_first_hit;

        let provider = if let Some(addr) = parsed.custom_resolver.as_deref() {
            SpamhausProvider::with_custom_resolver(parsed.confidence_threshold, addr)
        } else {
            SpamhausProvider::new(parsed.confidence_threshold)
        };

        self.provider = Some(provider);
        Ok(())
    }
}

#[async_trait]
impl CtiProviderPlugin for SpamhausPlugin {
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
        manifest: SpamhausPlugin::manifest_fn,
        config_schema: include_str!("../schema.json"),
        factory: PluginFactory::CtiProvider(SpamhausPlugin::create),
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
        let manifest = SpamhausPlugin::manifest_fn();
        assert_eq!(manifest.id, PLUGIN_ID);
        assert_eq!(manifest.kind, PluginKind::CtiProvider);
    }

    #[tokio::test]
    async fn factory_accepts_valid_config() {
        let cfg = serde_json::json!({ "confidence_threshold": 50 });
        let _plugin = SpamhausPlugin::create(test_ctx(), cfg).await.unwrap();
    }

    #[tokio::test]
    async fn factory_rejects_invalid_config() {
        let bad_cfg = serde_json::json!({ "confidence_threshold": "high" });
        match SpamhausPlugin::create(test_ctx(), bad_cfg).await {
            Err(PluginError::ConfigValidation(_)) => {}
            Err(other) => panic!("expected ConfigValidation, got {other:?}"),
            Ok(_) => panic!("expected error"),
        }
    }
}
