//! `ui.rest` — REST + WebSocket UI backend plugin.
//!
//! Serves a small JSON API and a live WebSocket stream backed by
//! [`UiApiHandle`]. Optionally serves a SPA (e.g. `plugins/ui-web/dist/`)
//! from a local directory with `index.html` fallback so client-side routing
//! works out of the box.
//!
//! See `README.md` for endpoint and config documentation.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use hiveguard_plugin_api::prelude::*;
use serde::Deserialize;
use tokio::net::TcpListener;
use tracing::{error, info};

pub mod auth;
pub mod routes;
pub mod state;
pub mod ws;

pub use routes::build_router;
pub use state::AppState;

pub const PLUGIN_ID: &str = "ui.rest";
const PLUGIN_VERSION: &str = "0.1.0";

/// Plugin entry point.
pub struct RestPlugin {
    manifest: PluginManifest,
    config: Option<RestConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RestConfig {
    #[serde(default = "default_bind_addr")]
    pub bind_addr: String,
    pub auth_token: String,
    #[serde(default)]
    pub static_dir: Option<PathBuf>,
    #[serde(default)]
    pub cors_origins: Vec<String>,
    #[serde(default = "default_tick_interval")]
    pub tick_interval_secs: u64,
    /// Optional HTTP-push log ingest receiver (`POST /api/ingest/logs`).
    /// Migrated from legacy `api.http_push` (REFACTOR 2.5). Disabled unless
    /// present with `enabled: true`.
    #[serde(default)]
    pub ingest: Option<IngestConfig>,
}

/// Configuration for the `POST /api/ingest/logs` HTTP-push receiver.
#[derive(Debug, Clone, Deserialize)]
pub struct IngestConfig {
    /// Mount the ingest route. When `false`, `/api/ingest/logs` returns 404.
    #[serde(default)]
    pub enabled: bool,
    /// Bearer token for the ingest endpoint. Falls back to `auth_token` when
    /// omitted.
    #[serde(default)]
    pub token: Option<String>,
    /// Parser to apply to each line: `ssh`, `nginx`, `postfix`, or `auto`.
    #[serde(default = "default_parser")]
    pub parser: String,
    /// Maximum accepted requests per second (per-process sliding window).
    #[serde(default = "default_rate_limit_per_sec")]
    pub rate_limit_per_sec: u32,
    /// Maximum request body size, in megabytes.
    #[serde(default = "default_max_request_size_mb")]
    pub max_request_size_mb: usize,
}

fn default_bind_addr() -> String {
    "127.0.0.1:8443".to_string()
}

fn default_tick_interval() -> u64 {
    30
}

fn default_parser() -> String {
    "auto".to_string()
}

fn default_rate_limit_per_sec() -> u32 {
    100
}

fn default_max_request_size_mb() -> usize {
    4
}

impl RestPlugin {
    pub fn manifest_fn() -> PluginManifest {
        PluginManifest {
            id: PLUGIN_ID,
            version: PLUGIN_VERSION,
            description: "REST + WebSocket UI backend.",
            kind: PluginKind::UiServer,
            author: "HiveGuard",
            docs_url: Some(
                "https://github.com/anthropics/hiveguard/blob/main/plugins/ui-rest/README.md",
            ),
        }
    }

    pub fn create(
        _ctx: PluginContext,
        cfg: serde_json::Value,
    ) -> BoxFuture<'static, PluginResult<Box<dyn UiServerPlugin>>> {
        Box::pin(async move {
            let mut plugin = RestPlugin {
                manifest: Self::manifest_fn(),
                config: None,
            };
            <RestPlugin as Plugin>::init(&mut plugin, cfg).await?;
            Ok(Box::new(plugin) as Box<dyn UiServerPlugin>)
        })
    }
}

#[async_trait]
impl Plugin for RestPlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    async fn init(&mut self, cfg: serde_json::Value) -> PluginResult<()> {
        let parsed: RestConfig = serde_json::from_value(cfg).map_err(|e| {
            PluginError::ConfigValidation(format!("invalid ui.rest config: {e}"))
        })?;

        if parsed.auth_token.trim().is_empty() {
            return Err(PluginError::ConfigValidation(
                "auth_token must be a non-empty string".into(),
            ));
        }

        parsed.bind_addr.parse::<SocketAddr>().map_err(|e| {
            PluginError::ConfigValidation(format!(
                "bind_addr '{}' is not a valid socket address: {e}",
                parsed.bind_addr
            ))
        })?;

        if parsed.tick_interval_secs == 0 {
            return Err(PluginError::ConfigValidation(
                "tick_interval_secs must be >= 1".into(),
            ));
        }

        if let Some(dir) = &parsed.static_dir {
            if !dir.exists() {
                return Err(PluginError::ConfigValidation(format!(
                    "static_dir '{}' does not exist",
                    dir.display()
                )));
            }
        }

        self.config = Some(parsed);
        Ok(())
    }
}

#[async_trait]
impl UiServerPlugin for RestPlugin {
    async fn run(
        &mut self,
        api: Arc<dyn UiApiHandle>,
        shutdown: CancellationToken,
    ) -> PluginResult<()> {
        let cfg = self
            .config
            .as_ref()
            .ok_or_else(|| PluginError::Runtime("ui.rest run() before init()".into()))?
            .clone();

        let addr: SocketAddr = cfg.bind_addr.parse().map_err(|e| {
            PluginError::Runtime(format!("bind_addr parse failed at run(): {e}"))
        })?;

        let ingest = match &cfg.ingest {
            Some(ic) if ic.enabled => state::IngestState {
                enabled: true,
                // Dedicated token, or fall back to the main auth token.
                token: Some(ic.token.clone().unwrap_or_else(|| cfg.auth_token.clone())),
                parser: ic.parser.clone(),
                rate_limit_per_sec: ic.rate_limit_per_sec,
                max_request_bytes: ic.max_request_size_mb.saturating_mul(1024 * 1024),
                rate_limiter: std::sync::Mutex::new((Instant::now(), 0)),
            },
            _ => state::IngestState::default(),
        };

        let state = Arc::new(AppState {
            api,
            auth_token: cfg.auth_token.clone(),
            started_at: Instant::now(),
            tick_interval: Duration::from_secs(cfg.tick_interval_secs),
            shutdown: shutdown.clone(),
            ingest,
        });

        let router = build_router(state, cfg.static_dir.clone(), &cfg.cors_origins);

        let listener = TcpListener::bind(addr)
            .await
            .map_err(|e| PluginError::Runtime(format!("bind {addr} failed: {e}")))?;
        info!("ui.rest: listening on http://{addr}");

        let serve_fut = axum::serve(listener, router.into_make_service());
        let shutdown_signal = async move {
            shutdown.cancelled().await;
        };

        match serve_fut.with_graceful_shutdown(shutdown_signal).await {
            Ok(()) => {
                info!("ui.rest: shut down cleanly");
                Ok(())
            }
            Err(e) => {
                error!("ui.rest: serve error: {e}");
                Err(PluginError::Runtime(format!("axum serve: {e}")))
            }
        }
    }
}

inventory::submit! {
    PluginDescriptor {
        id: PLUGIN_ID,
        kind: PluginKind::UiServer,
        api_version: API_VERSION,
        manifest: RestPlugin::manifest_fn,
        config_schema: include_str!("../schema.json"),
        factory: PluginFactory::UiServer(RestPlugin::create),
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
        let m = RestPlugin::manifest_fn();
        assert_eq!(m.id, PLUGIN_ID);
        assert_eq!(m.kind, PluginKind::UiServer);
        assert_eq!(m.version, PLUGIN_VERSION);
    }

    #[tokio::test]
    async fn init_with_valid_config_succeeds() {
        let mut plugin = RestPlugin {
            manifest: RestPlugin::manifest_fn(),
            config: None,
        };
        let cfg = serde_json::json!({
            "bind_addr": "127.0.0.1:18443",
            "auth_token": "test-token",
        });
        <RestPlugin as Plugin>::init(&mut plugin, cfg)
            .await
            .expect("init should succeed");
        assert!(plugin.config.is_some());
        let stored = plugin.config.unwrap();
        assert_eq!(stored.bind_addr, "127.0.0.1:18443");
        assert_eq!(stored.auth_token, "test-token");
        assert_eq!(stored.tick_interval_secs, 30);
    }

    #[tokio::test]
    async fn init_rejects_missing_auth_token() {
        let cfg = serde_json::json!({ "bind_addr": "127.0.0.1:18443" });
        let result = RestPlugin::create(test_ctx(), cfg).await;
        match result {
            Err(PluginError::ConfigValidation(msg)) => {
                assert!(
                    msg.contains("auth_token") || msg.contains("missing"),
                    "unexpected message: {msg}"
                );
            }
            Err(other) => panic!("expected ConfigValidation, got {other:?}"),
            Ok(_) => panic!("expected error, got Ok(_)"),
        }
    }

    #[tokio::test]
    async fn init_rejects_empty_auth_token() {
        let mut plugin = RestPlugin {
            manifest: RestPlugin::manifest_fn(),
            config: None,
        };
        let cfg = serde_json::json!({
            "bind_addr": "127.0.0.1:18443",
            "auth_token": "   ",
        });
        let err = <RestPlugin as Plugin>::init(&mut plugin, cfg)
            .await
            .unwrap_err();
        match err {
            PluginError::ConfigValidation(msg) => {
                assert!(msg.contains("non-empty"));
            }
            other => panic!("expected ConfigValidation, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn init_rejects_invalid_bind_addr() {
        let mut plugin = RestPlugin {
            manifest: RestPlugin::manifest_fn(),
            config: None,
        };
        let cfg = serde_json::json!({
            "bind_addr": "not-an-address",
            "auth_token": "test-token",
        });
        let err = <RestPlugin as Plugin>::init(&mut plugin, cfg)
            .await
            .unwrap_err();
        assert!(matches!(err, PluginError::ConfigValidation(_)));
    }
}
