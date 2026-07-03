use hiveguard_enforce::enforcer::Enforcer as LegacyEnforcer;
use hiveguard_enforce::ObserveOnlyEnforcer;
use hiveguard_plugin_api::prelude::*;
use serde::Deserialize;

const PLUGIN_ID: &str = "enforcer.observe";
const PLUGIN_VERSION: &str = "0.1.0";

#[derive(Debug, Deserialize)]
struct Config {}

pub struct ObserveEnforcerPlugin {
    manifest: PluginManifest,
    inner: Option<ObserveOnlyEnforcer>,
}

impl ObserveEnforcerPlugin {
    pub fn manifest_fn() -> PluginManifest {
        PluginManifest {
            id: PLUGIN_ID,
            version: PLUGIN_VERSION,
            description: "No-op enforcer for dry-run mode.",
            kind: PluginKind::Enforcer,
            author: "HiveGuard",
            docs_url: Some("https://github.com/anthropics/hiveguard/blob/main/plugins/enforcer-observe/README.md"),
        }
    }

    pub fn create(
        _ctx: PluginContext,
        cfg: serde_json::Value,
    ) -> BoxFuture<'static, PluginResult<Box<dyn EnforcerPlugin>>> {
        Box::pin(async move {
            let mut plugin = ObserveEnforcerPlugin {
                manifest: Self::manifest_fn(),
                inner: None,
            };
            <ObserveEnforcerPlugin as Plugin>::init(&mut plugin, cfg).await?;
            Ok(Box::new(plugin) as Box<dyn EnforcerPlugin>)
        })
    }

    fn inner_mut(&mut self) -> PluginResult<&mut ObserveOnlyEnforcer> {
        self.inner
            .as_mut()
            .ok_or_else(|| PluginError::Runtime("plugin used before init".into()))
    }

    fn inner_ref(&self) -> PluginResult<&ObserveOnlyEnforcer> {
        self.inner
            .as_ref()
            .ok_or_else(|| PluginError::Runtime("plugin used before init".into()))
    }
}

#[async_trait]
impl Plugin for ObserveEnforcerPlugin {
    fn manifest(&self) -> &PluginManifest { &self.manifest }

    async fn init(&mut self, cfg: serde_json::Value) -> PluginResult<()> {
        let _parsed: Config = serde_json::from_value(cfg)
            .map_err(|e| PluginError::ConfigValidation(e.to_string()))?;
        self.inner = Some(ObserveOnlyEnforcer::new());
        Ok(())
    }
}

#[async_trait]
impl EnforcerPlugin for ObserveEnforcerPlugin {
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
        manifest: ObserveEnforcerPlugin::manifest_fn,
        config_schema: include_str!("../schema.json"),
        factory: PluginFactory::Enforcer(ObserveEnforcerPlugin::create),
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
        let manifest = ObserveEnforcerPlugin::manifest_fn();
        assert_eq!(manifest.id, PLUGIN_ID);
        assert_eq!(manifest.kind, PluginKind::Enforcer);
    }

    #[tokio::test]
    async fn factory_accepts_valid_config() {
        let cfg = serde_json::json!({});
        let _plugin = ObserveEnforcerPlugin::create(test_ctx(), cfg).await.unwrap();
    }

    #[tokio::test]
    async fn factory_rejects_invalid_config() {
        let bad_cfg = serde_json::json!(42);
        match ObserveEnforcerPlugin::create(test_ctx(), bad_cfg).await {
            Err(PluginError::ConfigValidation(_)) => {}
            Err(other) => panic!("expected ConfigValidation, got {other:?}"),
            Ok(_) => panic!("expected error"),
        }
    }
}
