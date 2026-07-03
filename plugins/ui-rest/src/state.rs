//! Shared application state passed to all Axum handlers.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hiveguard_plugin_api::prelude::UiApiHandle;
use tokio_util::sync::CancellationToken;

/// State shared with every handler via `axum::extract::State`.
pub struct AppState {
    /// Daemon-facing API the plugin queries for snapshots and mutations.
    pub api: Arc<dyn UiApiHandle>,
    /// Bearer token clients must present.
    pub auth_token: String,
    /// Instant the plugin started serving — used for uptime in `/api/health`.
    pub started_at: Instant,
    /// Interval at which the WebSocket task emits keepalive `UiEvent::Tick`.
    pub tick_interval: Duration,
    /// Shared cancellation token — fires when the plugin host shuts the
    /// plugin down. Long-lived WebSocket tasks check this to terminate
    /// gracefully.
    pub shutdown: CancellationToken,
    /// HTTP-push log ingest settings (`POST /api/ingest/logs`).
    pub ingest: IngestState,
}

/// Resolved ingest configuration + runtime rate-limiter state.
pub struct IngestState {
    /// Whether the ingest route is mounted at all.
    pub enabled: bool,
    /// Bearer token required by the ingest endpoint (already resolved to the
    /// plugin `auth_token` when no dedicated token was configured).
    pub token: Option<String>,
    /// Parser name forwarded to `UiApiHandle::ingest_logs`.
    pub parser: String,
    /// Maximum accepted requests per second.
    pub rate_limit_per_sec: u32,
    /// Maximum request body size, in bytes (enforced by `DefaultBodyLimit`).
    pub max_request_bytes: usize,
    /// Per-second sliding window: `(window_start, count_in_window)`.
    pub rate_limiter: Mutex<(Instant, u32)>,
}

impl Default for IngestState {
    fn default() -> Self {
        Self {
            enabled: false,
            token: None,
            parser: "auto".to_string(),
            rate_limit_per_sec: 100,
            max_request_bytes: 4 * 1024 * 1024,
            rate_limiter: Mutex::new((Instant::now(), 0)),
        }
    }
}
