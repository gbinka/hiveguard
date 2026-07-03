use std::net::IpAddr;
use std::time::Duration;

use serde::Deserialize;

use hiveguard_cti::abuseipdb::AbuseIpDbClient;
use hiveguard_cti::{AbuseIpDbProvider, CtiProvider as LegacyCtiProvider};
use hiveguard_plugin_api::prelude::*;

const PLUGIN_ID: &str = "cti.abuseipdb";
const PLUGIN_VERSION: &str = "0.1.0";

#[derive(Debug, Deserialize)]
struct Config {
    api_key: String,
    #[serde(default = "default_threshold")]
    confidence_threshold: u8,
    #[serde(default)]
    ban_on_first_hit: bool,
    #[serde(default = "default_cache_ttl_hours")]
    cache_ttl_hours: u32,
    #[serde(default = "default_max_cache_entries")]
    max_cache_entries: usize,
}

fn default_threshold() -> u8 { 75 }
fn default_cache_ttl_hours() -> u32 { 6 }
fn default_max_cache_entries() -> usize { 100_000 }

pub struct AbuseIpDbPlugin {
    manifest: PluginManifest,
    provider: Option<AbuseIpDbProvider>,
    data_dir: std::path::PathBuf,
    ban_on_first_hit: bool,
}

impl AbuseIpDbPlugin {
    pub fn manifest_fn() -> PluginManifest {
        PluginManifest {
            id: PLUGIN_ID,
            version: PLUGIN_VERSION,
            description: "AbuseIPDB reputation provider.",
            kind: PluginKind::CtiProvider,
            author: "HiveGuard",
            docs_url: Some("https://github.com/anthropics/hiveguard/blob/main/plugins/cti-abuseipdb/README.md"),
        }
    }

    pub fn create(
        ctx: PluginContext,
        cfg: serde_json::Value,
    ) -> BoxFuture<'static, PluginResult<Box<dyn CtiProviderPlugin>>> {
        Box::pin(async move {
            let mut plugin = AbuseIpDbPlugin {
                manifest: Self::manifest_fn(),
                provider: None,
                data_dir: ctx.data_dir,
                ban_on_first_hit: false,
            };
            <AbuseIpDbPlugin as Plugin>::init(&mut plugin, cfg).await?;
            Ok(Box::new(plugin) as Box<dyn CtiProviderPlugin>)
        })
    }

    fn provider_ref(&self) -> PluginResult<&AbuseIpDbProvider> {
        self.provider
            .as_ref()
            .ok_or_else(|| PluginError::Runtime("plugin used before init".into()))
    }
}

#[async_trait]
impl Plugin for AbuseIpDbPlugin {
    fn manifest(&self) -> &PluginManifest { &self.manifest }

    async fn init(&mut self, cfg: serde_json::Value) -> PluginResult<()> {
        let parsed: Config = serde_json::from_value(cfg)
            .map_err(|e| PluginError::ConfigValidation(e.to_string()))?;
        self.ban_on_first_hit = parsed.ban_on_first_hit;

        let client = AbuseIpDbClient::new(parsed.api_key);
        self.provider = Some(AbuseIpDbProvider::new(
            self.data_dir.as_path(),
            client,
            parsed.confidence_threshold,
            parsed.ban_on_first_hit,
            Duration::from_secs((parsed.cache_ttl_hours as u64) * 3600),
            parsed.max_cache_entries,
        ));

        Ok(())
    }
}

#[async_trait]
impl CtiProviderPlugin for AbuseIpDbPlugin {
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
        manifest: AbuseIpDbPlugin::manifest_fn,
        config_schema: include_str!("../schema.json"),
        factory: PluginFactory::CtiProvider(AbuseIpDbPlugin::create),
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
        let manifest = AbuseIpDbPlugin::manifest_fn();
        assert_eq!(manifest.id, PLUGIN_ID);
        assert_eq!(manifest.kind, PluginKind::CtiProvider);
    }

    #[tokio::test]
    async fn factory_accepts_valid_config() {
        let cfg = serde_json::json!({ "api_key": "dummy-key" });
        let _plugin = AbuseIpDbPlugin::create(test_ctx(), cfg).await.unwrap();
    }

    #[tokio::test]
    async fn factory_rejects_invalid_config() {
        let bad_cfg = serde_json::json!({});
        match AbuseIpDbPlugin::create(test_ctx(), bad_cfg).await {
            Err(PluginError::ConfigValidation(_)) => {}
            Err(other) => panic!("expected ConfigValidation, got {other:?}"),
            Ok(_) => panic!("expected error"),
        }
    }
}
