use serde::Deserialize;

use hiveguard_core::config::{CloudflareConfig, CloudflareZoneConfig};
use hiveguard_enforce::cloudflare::CloudflareEnforcer;
use hiveguard_enforce::enforcer::Enforcer as LegacyEnforcer;
use hiveguard_plugin_api::prelude::*;

const PLUGIN_ID: &str = "enforcer.cloudflare";
const PLUGIN_VERSION: &str = "0.1.0";

#[derive(Debug, Deserialize)]
struct Config {
    api_token: String,
    zone_id: String,
    account_id: String,
    #[serde(default = "default_list_name")]
    list_name: String,
    #[serde(default = "default_min_severity")]
    min_severity: u8,
    #[serde(default)]
    zones: Vec<Zone>,
}

#[derive(Debug, Deserialize)]
struct Zone {
    id: String,
}

fn default_list_name() -> String {
    "hiveguard-blocklist".to_string()
}

fn default_min_severity() -> u8 {
    60
}

pub struct CloudflarePlugin {
    manifest: PluginManifest,
    inner: Option<CloudflareEnforcer>,
}

impl CloudflarePlugin {
    pub fn manifest_fn() -> PluginManifest {
        PluginManifest {
            id: PLUGIN_ID,
            version: PLUGIN_VERSION,
            description: "Cloudflare edge enforcement backend.",
            kind: PluginKind::Enforcer,
            author: "HiveGuard",
            docs_url: Some("https://github.com/anthropics/hiveguard/blob/main/plugins/enforcer-cloudflare/README.md"),
        }
    }

    pub fn create(
        _ctx: PluginContext,
        cfg: serde_json::Value,
    ) -> BoxFuture<'static, PluginResult<Box<dyn EnforcerPlugin>>> {
        Box::pin(async move {
            let mut plugin = CloudflarePlugin {
                manifest: Self::manifest_fn(),
                inner: None,
            };
            <CloudflarePlugin as Plugin>::init(&mut plugin, cfg).await?;
            Ok(Box::new(plugin) as Box<dyn EnforcerPlugin>)
        })
    }

    fn inner_mut(&mut self) -> PluginResult<&mut CloudflareEnforcer> {
        self.inner
            .as_mut()
            .ok_or_else(|| PluginError::Runtime("plugin used before init".into()))
    }

    fn inner_ref(&self) -> PluginResult<&CloudflareEnforcer> {
        self.inner
            .as_ref()
            .ok_or_else(|| PluginError::Runtime("plugin used before init".into()))
    }
}

#[async_trait]
impl Plugin for CloudflarePlugin {
    fn manifest(&self) -> &PluginManifest { &self.manifest }

    async fn init(&mut self, cfg: serde_json::Value) -> PluginResult<()> {
        let parsed: Config = serde_json::from_value(cfg)
            .map_err(|e| PluginError::ConfigValidation(e.to_string()))?;

        let legacy_cfg = CloudflareConfig {
            enabled: true,
            api_token: parsed.api_token,
            zone_id: parsed.zone_id,
            account_id: parsed.account_id,
            list_name: parsed.list_name,
            min_severity: parsed.min_severity,
            zones: parsed
                .zones
                .into_iter()
                .map(|z| CloudflareZoneConfig { id: z.id, list_id: None })
                .collect(),
        };

        self.inner = Some(CloudflareEnforcer::new(legacy_cfg));
        Ok(())
    }
}

#[async_trait]
impl EnforcerPlugin for CloudflarePlugin {
    async fn setup(&mut self) -> PluginResult<()> {
        self.inner_mut()?.setup().await.map_err(|e| PluginError::Runtime(e.to_string()))
    }

    async fn apply_ban(&mut self, subject: &ipnet::IpNet) -> PluginResult<()> {
        self.inner_mut()?.apply_ban(subject).await.map_err(|e| PluginError::Runtime(e.to_string()))
    }

    async fn remove_ban(&mut self, subject: &ipnet::IpNet) -> PluginResult<()> {
        self.inner_mut()?.remove_ban(subject).await.map_err(|e| PluginError::Runtime(e.to_string()))
    }

    async fn sync_full(&mut self, banned: &[ipnet::IpNet]) -> PluginResult<()> {
        self.inner_mut()?.sync_full(banned).await.map_err(|e| PluginError::Runtime(e.to_string()))
    }

    async fn get_current_bans(&self) -> PluginResult<Vec<ipnet::IpNet>> {
        self.inner_ref()?.get_current_bans().await.map_err(|e| PluginError::Runtime(e.to_string()))
    }
}

inventory::submit! {
    PluginDescriptor {
        id: PLUGIN_ID,
        kind: PluginKind::Enforcer,
        api_version: API_VERSION,
        manifest: CloudflarePlugin::manifest_fn,
        config_schema: include_str!("../schema.json"),
        factory: PluginFactory::Enforcer(CloudflarePlugin::create),
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
        let manifest = CloudflarePlugin::manifest_fn();
        assert_eq!(manifest.id, PLUGIN_ID);
        assert_eq!(manifest.kind, PluginKind::Enforcer);
    }

    #[tokio::test]
    async fn factory_accepts_valid_config() {
        let cfg = serde_json::json!({
            "api_token": "token",
            "zone_id": "zone",
            "account_id": "account"
        });
        let _plugin = CloudflarePlugin::create(test_ctx(), cfg).await.unwrap();
    }

    #[tokio::test]
    async fn factory_rejects_invalid_config() {
        let bad_cfg = serde_json::json!({ "api_token": "token" });
        match CloudflarePlugin::create(test_ctx(), bad_cfg).await {
            Err(PluginError::ConfigValidation(_)) => {}
            Err(other) => panic!("expected ConfigValidation, got {other:?}"),
            Ok(_) => panic!("expected error"),
        }
    }
}
