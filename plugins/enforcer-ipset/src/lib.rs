use serde::Deserialize;

use hiveguard_plugin_api::prelude::*;

const PLUGIN_ID: &str = "enforcer.ipset";
const PLUGIN_VERSION: &str = "0.1.0";

#[derive(Debug, Deserialize)]
struct Config {
    #[serde(default = "default_set_name")]
    set_name: String,
}

fn default_set_name() -> String {
    "hiveguard_blocklist".to_string()
}

pub struct IpsetEnforcerPlugin {
    manifest: PluginManifest,
}

impl IpsetEnforcerPlugin {
    pub fn manifest_fn() -> PluginManifest {
        PluginManifest {
            id: PLUGIN_ID,
            version: PLUGIN_VERSION,
            description: "IPSet enforcer migration scaffold (observe-only fallback).",
            kind: PluginKind::Enforcer,
            author: "HiveGuard",
            docs_url: Some("https://github.com/anthropics/hiveguard/blob/main/plugins/enforcer-ipset/README.md"),
        }
    }

    pub fn create(
        _ctx: PluginContext,
        cfg: serde_json::Value,
    ) -> BoxFuture<'static, PluginResult<Box<dyn EnforcerPlugin>>> {
        Box::pin(async move {
            let _parsed: Config = serde_json::from_value(cfg.clone())
                .map_err(|e| PluginError::ConfigValidation(e.to_string()))?;
            let _ = _parsed.set_name;
            let mut plugin = IpsetEnforcerPlugin {
                manifest: Self::manifest_fn(),
            };
            <IpsetEnforcerPlugin as Plugin>::init(&mut plugin, cfg).await?;
            Ok(Box::new(plugin) as Box<dyn EnforcerPlugin>)
        })
    }
}

#[async_trait]
impl Plugin for IpsetEnforcerPlugin {
    fn manifest(&self) -> &PluginManifest { &self.manifest }

    async fn init(&mut self, _cfg: serde_json::Value) -> PluginResult<()> {
        Err(PluginError::Init(
            "enforcer.ipset backend not yet implemented. Use enforcer.nftables instead, or set enforcement to observe-only via enforcer.observe. Tracked in REFACTOR_PROGRESS.md (Otwarte elementy A2).".into(),
        ))
    }
}

#[async_trait]
impl EnforcerPlugin for IpsetEnforcerPlugin {
    async fn apply_ban(&mut self, _subject: &ipnet::IpNet) -> PluginResult<()> {
        Err(PluginError::Runtime("enforcer.ipset backend not implemented".into()))
    }

    async fn remove_ban(&mut self, _subject: &ipnet::IpNet) -> PluginResult<()> {
        Err(PluginError::Runtime("enforcer.ipset backend not implemented".into()))
    }

    async fn sync_full(&mut self, _banned: &[ipnet::IpNet]) -> PluginResult<()> {
        Err(PluginError::Runtime("enforcer.ipset backend not implemented".into()))
    }

    async fn get_current_bans(&self) -> PluginResult<Vec<ipnet::IpNet>> {
        Err(PluginError::Runtime("enforcer.ipset backend not implemented".into()))
    }
}

inventory::submit! {
    PluginDescriptor {
        id: PLUGIN_ID,
        kind: PluginKind::Enforcer,
        api_version: API_VERSION,
        manifest: IpsetEnforcerPlugin::manifest_fn,
        config_schema: include_str!("../schema.json"),
        factory: PluginFactory::Enforcer(IpsetEnforcerPlugin::create),
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
        let manifest = IpsetEnforcerPlugin::manifest_fn();
        assert_eq!(manifest.id, PLUGIN_ID);
        assert_eq!(manifest.kind, PluginKind::Enforcer);
    }

    #[tokio::test]
    async fn factory_returns_init_error_until_implemented() {
        let cfg = serde_json::json!({ "set_name": "hiveguard_blocklist" });
        match IpsetEnforcerPlugin::create(test_ctx(), cfg).await {
            Err(PluginError::Init(msg)) => assert!(msg.contains("not yet implemented")),
            Err(other) => panic!("expected Init, got {other:?}"),
            Ok(_) => panic!("expected error"),
        }
    }

    #[tokio::test]
    async fn factory_rejects_invalid_config() {
        let bad_cfg = serde_json::json!("not-an-object");
        match IpsetEnforcerPlugin::create(test_ctx(), bad_cfg).await {
            Err(PluginError::ConfigValidation(_)) => {}
            Err(other) => panic!("expected ConfigValidation, got {other:?}"),
            Ok(_) => panic!("expected error"),
        }
    }
}
