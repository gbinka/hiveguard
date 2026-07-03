//! Native side of the `hiveguard-ui-web` plugin.
//!
//! Registers the `ui.web` plugin with the host. Phase-5 scaffold: `init`
//! returns `PluginError::Init` so operators don't accidentally configure a
//! no-op UI. The eventual implementation will:
//!
//! 1. On `init`, validate config (bind addr, TLS cert paths, SPA dist
//!    directory).
//! 2. On `run`, start an Axum server that:
//!    - Serves static files from `dist/` (the Trunk-built SPA bundle).
//!    - Exposes `/api/...` REST endpoints proxied to `UiApiHandle`.
//!    - Exposes `/api/stream` as a WebSocket pushing `Msg`-encoded JSON
//!      to subscribed clients (model deltas + threat / ban events).
//! 3. On `shutdown` (`CancellationToken`), drain in-flight requests and
//!    return.
//!
//! See `plugins/ui-rest/` for the REST endpoint surface (when that scaffold
//! is filled in too — both UI plugins consume the same `UiApiHandle`).

use hiveguard_plugin_api::prelude::*;
use std::sync::Arc;

pub const PLUGIN_ID: &str = "ui.web";
const PLUGIN_VERSION: &str = "0.1.0";

pub struct WebPlugin {
    manifest: PluginManifest,
}

impl WebPlugin {
    pub fn manifest_fn() -> PluginManifest {
        PluginManifest {
            id: PLUGIN_ID,
            version: PLUGIN_VERSION,
            description: "UI Web renderer (Leptos SPA) — PHASE 5 SCAFFOLD.",
            kind: PluginKind::UiServer,
            author: "HiveGuard",
            docs_url: Some(
                "https://github.com/anthropics/hiveguard/blob/main/plugins/ui-web/README.md",
            ),
        }
    }

    pub fn create(
        _ctx: PluginContext,
        cfg: serde_json::Value,
    ) -> BoxFuture<'static, PluginResult<Box<dyn UiServerPlugin>>> {
        Box::pin(async move {
            let mut plugin = WebPlugin {
                manifest: Self::manifest_fn(),
            };
            <WebPlugin as Plugin>::init(&mut plugin, cfg).await?;
            Ok(Box::new(plugin) as Box<dyn UiServerPlugin>)
        })
    }
}

#[async_trait]
impl Plugin for WebPlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    async fn init(&mut self, _cfg: serde_json::Value) -> PluginResult<()> {
        // TODO(phase-5): parse config (bind addr, dist_dir, tls), verify
        // that `dist/index.html` exists, build Axum router. For now we
        // fail loud so the host won't silently advertise a broken UI.
        Err(PluginError::Init(
            "ui.web is a Phase 5 scaffold: the Leptos SPA compiles via \
             `trunk build`, but the host-side server is not wired up yet. \
             Serve the standalone React panel (../hiveguard-web) via ui.rest \
             `static_dir` until Phase 5 completes."
                .into(),
        ))
    }
}

#[async_trait]
impl UiServerPlugin for WebPlugin {
    async fn run(
        &mut self,
        _api: Arc<dyn UiApiHandle>,
        _shutdown: CancellationToken,
    ) -> PluginResult<()> {
        // TODO(phase-5): spawn Axum server, serve `dist/`, wire `/api/stream`
        // WebSocket to the host's event bus, push `Msg::Connected{...}`
        // followed by streaming threats/bans.
        Err(PluginError::Runtime("ui.web not implemented".into()))
    }
}

inventory::submit! {
    PluginDescriptor {
        id: PLUGIN_ID,
        kind: PluginKind::UiServer,
        api_version: API_VERSION,
        manifest: WebPlugin::manifest_fn,
        config_schema: include_str!("../schema.json"),
        factory: PluginFactory::UiServer(WebPlugin::create),
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
    fn manifest_correct() {
        let m = WebPlugin::manifest_fn();
        assert_eq!(m.id, PLUGIN_ID);
        assert_eq!(m.kind, PluginKind::UiServer);
    }

    #[tokio::test]
    async fn fails_with_init_error() {
        match WebPlugin::create(test_ctx(), serde_json::json!({})).await {
            Err(PluginError::Init(msg)) => assert!(msg.contains("Phase 5 scaffold")),
            Err(other) => panic!("expected Init, got {other:?}"),
            Ok(_) => panic!("expected error"),
        }
    }
}
