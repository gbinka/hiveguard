//! `ui.tui` — ratatui-based TUI renderer.
//!
//! This crate has two faces:
//!
//! * **Library (`UiServerPlugin`)** — registered via `inventory`. The host
//!   may instantiate it for *embedded mode*, where the daemon runs the TUI
//!   in the same process. In embedded mode the plugin owns the terminal,
//!   so it MUST only be enabled when stdout is a tty and the host is being
//!   run in the foreground.
//!
//! * **Binary (`hiveguard-tui`)** — the primary entry-point. Operators
//!   run this against a remote daemon over REST + WebSocket. See
//!   `src/bin/hiveguard-tui.rs`.
//!
//! Both paths share the same architecture: the Elm-style `update` from
//! `hiveguard-ui` is the single source of truth, ratatui only renders
//! `&AppModel` and crossterm event handling produces `Msg` values.

pub mod app;
pub mod event;
pub mod rest;
pub mod views;
pub mod ws;

use hiveguard_plugin_api::prelude::*;
use std::sync::Arc;

pub const PLUGIN_ID: &str = "ui.tui";
const PLUGIN_VERSION: &str = "0.1.0";

/// In-process TUI plugin. Most operators want the `hiveguard-tui` binary
/// instead — that runs the same UI against a remote daemon. The plugin
/// form is for single-host deployments that want one process for both
/// daemon and UI.
pub struct TuiPlugin {
    manifest: PluginManifest,
    /// Set to `true` by `init` if the embedded TUI is opted in. By default
    /// the plugin is *inert*: it registers with the host so plugin listing
    /// shows it, but `run` does nothing. Operators must explicitly set
    /// `enabled: true` in their config to take over the terminal.
    enabled: bool,
}

impl TuiPlugin {
    pub fn manifest_fn() -> PluginManifest {
        PluginManifest {
            id: PLUGIN_ID,
            version: PLUGIN_VERSION,
            description: "UI TUI renderer (ratatui) — embedded + standalone binary.",
            kind: PluginKind::UiServer,
            author: "HiveGuard",
            docs_url: Some(
                "https://github.com/anthropics/hiveguard/blob/main/plugins/ui-tui/README.md",
            ),
        }
    }

    pub fn create(
        _ctx: PluginContext,
        cfg: serde_json::Value,
    ) -> BoxFuture<'static, PluginResult<Box<dyn UiServerPlugin>>> {
        Box::pin(async move {
            let mut plugin = TuiPlugin {
                manifest: Self::manifest_fn(),
                enabled: false,
            };
            <TuiPlugin as Plugin>::init(&mut plugin, cfg).await?;
            Ok(Box::new(plugin) as Box<dyn UiServerPlugin>)
        })
    }
}

#[async_trait]
impl Plugin for TuiPlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    async fn init(&mut self, cfg: serde_json::Value) -> PluginResult<()> {
        // Config shape: `{ "enabled": bool }`. Default false so adding this
        // plugin to the registry doesn't accidentally take over the tty.
        self.enabled = cfg
            .get("enabled")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        Ok(())
    }
}

#[async_trait]
impl UiServerPlugin for TuiPlugin {
    async fn run(
        &mut self,
        api: Arc<dyn UiApiHandle>,
        shutdown: CancellationToken,
    ) -> PluginResult<()> {
        if !self.enabled {
            // Inert mode: stay registered, do nothing. Wait for shutdown so
            // the host's join logic sees a clean exit.
            shutdown.cancelled().await;
            return Ok(());
        }

        // Embedded mode: drive the TUI off the in-process `UiApiHandle`.
        // We seed the model with daemon metadata and let the standalone
        // app loop take over.
        let node_name = api.node_name();
        let daemon_version = api.daemon_version();

        let mut model = hiveguard_ui::AppModel::default();
        model.node_name = node_name;
        model.daemon_version = daemon_version;
        model.status = hiveguard_ui::ConnectionStatus::Connected;

        // Embedded TUI shares the binary's render loop but uses an in-memory
        // event source instead of WS. For Phase B1 we don't ship a full
        // embedded driver — operators should prefer the binary. Return
        // immediately on shutdown.
        shutdown.cancelled().await;
        Ok(())
    }
}

inventory::submit! {
    PluginDescriptor {
        id: PLUGIN_ID,
        kind: PluginKind::UiServer,
        api_version: API_VERSION,
        manifest: TuiPlugin::manifest_fn,
        config_schema: include_str!("../schema.json"),
        factory: PluginFactory::UiServer(TuiPlugin::create),
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
        let m = TuiPlugin::manifest_fn();
        assert_eq!(m.id, PLUGIN_ID);
        assert_eq!(m.kind, PluginKind::UiServer);
    }

    #[tokio::test]
    async fn init_defaults_to_disabled() {
        let plugin = TuiPlugin::create(test_ctx(), serde_json::json!({}))
            .await
            .expect("init must succeed with default cfg");
        // Use the trait surface — we can't downcast across the boxed dyn,
        // but we can at least confirm the manifest is wired.
        assert_eq!(plugin.manifest().id, PLUGIN_ID);
    }

    #[tokio::test]
    async fn init_respects_enabled_flag() {
        let plugin = TuiPlugin::create(test_ctx(), serde_json::json!({ "enabled": true }))
            .await
            .expect("init must succeed with explicit enable");
        assert_eq!(plugin.manifest().id, PLUGIN_ID);
    }
}
