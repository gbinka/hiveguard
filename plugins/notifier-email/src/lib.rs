//! Email notifier — fail-loud scaffold.

use hiveguard_plugin_api::prelude::*;

pub const PLUGIN_ID: &str = "notifier.email";
const PLUGIN_VERSION: &str = "0.1.0";

pub struct EmailPlugin { manifest: PluginManifest }

impl EmailPlugin {
    pub fn manifest_fn() -> PluginManifest {
        PluginManifest {
            id: PLUGIN_ID,
            version: PLUGIN_VERSION,
            description: "Email notifier — NOT IMPLEMENTED YET.",
            kind: PluginKind::Notifier,
            author: "HiveGuard",
            docs_url: Some("https://github.com/anthropics/hiveguard/blob/main/plugins/notifier-email/README.md"),
        }
    }
    pub fn create(_ctx: PluginContext, cfg: serde_json::Value)
        -> BoxFuture<'static, PluginResult<Box<dyn NotifierPlugin>>>
    {
        Box::pin(async move {
            let mut plugin = EmailPlugin { manifest: Self::manifest_fn() };
            <EmailPlugin as Plugin>::init(&mut plugin, cfg).await?;
            Ok(Box::new(plugin) as Box<dyn NotifierPlugin>)
        })
    }
}

#[async_trait]
impl Plugin for EmailPlugin {
    fn manifest(&self) -> &PluginManifest { &self.manifest }
    async fn init(&mut self, _cfg: serde_json::Value) -> PluginResult<()> {
        Err(PluginError::Init(
            "notifier.email is not yet implemented. Use notifier.webhook with a              custom template until this scaffold is fleshed out.".into(),
        ))
    }
}

#[async_trait]
impl NotifierPlugin for EmailPlugin {
    async fn notify(&self, _event: &AlertEvent) -> PluginResult<()> {
        Err(PluginError::Runtime("notifier.email not implemented".into()))
    }
}

inventory::submit! {
    PluginDescriptor {
        id: PLUGIN_ID,
        kind: PluginKind::Notifier,
        api_version: API_VERSION,
        manifest: EmailPlugin::manifest_fn,
        config_schema: include_str!("../schema.json"),
        factory: PluginFactory::Notifier(EmailPlugin::create),
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
    fn manifest_correct() {
        let m = EmailPlugin::manifest_fn();
        assert_eq!(m.id, PLUGIN_ID);
        assert_eq!(m.kind, PluginKind::Notifier);
    }

    #[tokio::test]
    async fn fails_with_init_error() {
        match EmailPlugin::create(test_ctx(), serde_json::json!({})).await {
            Err(PluginError::Init(msg)) => assert!(msg.contains("not yet implemented")),
            Err(other) => panic!("expected Init, got {other:?}"),
            Ok(_) => panic!("expected error"),
        }
    }
}
