//! `/api/agent/*` — the AI-agent / analyst analysis surface.
//!
//! Thin HTTP plumbing over the `agent_*` methods of [`UiApiHandle`]; the
//! shapes are documented in `docs/AGENT_API.md`. Everything here is JSON in /
//! JSON out except [`sse_handler`], which streams incremental
//! [`AgentEvent`]s as Server-Sent Events.

use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{
        sse::{Event, KeepAlive, Sse},
        IntoResponse, Json, Response,
    },
    routing::{get, post},
    Router,
};
use futures_util::stream::{self, Stream};
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::sync::broadcast::error::RecvError;
use tracing::{debug, warn};

use hiveguard_plugin_api::prelude::{AgentEvent, PluginError};

use crate::auth::ct_eq;
use crate::state::AppState;

/// Interval of SSE keep-alive comments.
const SSE_KEEPALIVE: Duration = Duration::from_secs(15);

/// Authenticated agent routes (mounted behind `require_auth`).
pub fn agent_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/agent/overview", get(get_overview))
        .route("/api/agent/bans", get(get_bans))
        .route("/api/agent/threats", get(get_threats))
        .route("/api/agent/logs/sources", get(get_log_sources))
        .route("/api/agent/logs/query", post(post_log_query))
        .route("/api/agent/logs/stats", post(post_log_stats))
        .route("/api/agent/ip", post(post_ip_profile))
        .route("/api/agent/journal", get(get_journal))
        .route("/api/agent/detectors", get(get_detectors))
        .route("/api/agent/catalog", get(get_catalog))
        .route("/api/agent/config/validate", post(post_config_validate))
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn get_overview(State(state): State<Arc<AppState>>) -> Response {
    respond(state.api.agent_overview().await)
}

async fn get_bans(
    State(state): State<Arc<AppState>>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    respond(state.api.agent_bans(params_to_value(params)).await)
}

async fn get_threats(
    State(state): State<Arc<AppState>>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    respond(state.api.agent_threats(params_to_value(params)).await)
}

async fn get_log_sources(State(state): State<Arc<AppState>>) -> Response {
    respond(state.api.agent_log_sources().await)
}

async fn post_log_query(State(state): State<Arc<AppState>>, Json(body): Json<Value>) -> Response {
    respond(state.api.agent_log_query(body).await)
}

async fn post_log_stats(State(state): State<Arc<AppState>>, Json(body): Json<Value>) -> Response {
    respond(state.api.agent_log_stats(body).await)
}

async fn post_ip_profile(State(state): State<Arc<AppState>>, Json(body): Json<Value>) -> Response {
    respond(state.api.agent_ip_profile(body).await)
}

async fn get_journal(
    State(state): State<Arc<AppState>>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    respond(state.api.agent_journal(params_to_value(params)).await)
}

async fn get_detectors(State(state): State<Arc<AppState>>) -> Response {
    respond(state.api.agent_detectors().await)
}

#[derive(Debug, Deserialize)]
struct CatalogQuery {
    kind: Option<String>,
}

async fn get_catalog(
    State(state): State<Arc<AppState>>,
    Query(q): Query<CatalogQuery>,
) -> Response {
    respond(state.api.agent_catalog(q.kind).await)
}

#[derive(Debug, Deserialize)]
struct ValidateRequest {
    content: String,
}

async fn post_config_validate(
    State(state): State<Arc<AppState>>,
    Json(body): Json<ValidateRequest>,
) -> Response {
    respond(state.api.agent_config_validate(body.content).await)
}

// ---------------------------------------------------------------------------
// SSE stream — public route with its own token check (header or `?token=`),
// mirroring the WebSocket endpoint so browser `EventSource` clients work.
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct StreamQuery {
    token: Option<String>,
    /// Comma-separated subset of `signal,ban_added,ban_removed`.
    types: Option<String>,
}

/// Axum handler for `GET /api/agent/stream`.
pub async fn sse_handler(
    State(state): State<Arc<AppState>>,
    Query(q): Query<StreamQuery>,
    headers: HeaderMap,
) -> Response {
    let header_token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::to_owned);
    let token = match header_token.or(q.token) {
        Some(t) => t,
        None => return unauthorized("missing token"),
    };
    if !ct_eq(token.as_bytes(), state.auth_token.as_bytes()) {
        return unauthorized("invalid token");
    }

    let Some(rx) = state.api.subscribe_agent() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "error": "agent event stream not available on this daemon" })),
        )
            .into_response();
    };

    let wanted: Option<Vec<String>> = q.types.map(|t| {
        t.split(',')
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty())
            .collect()
    });

    debug!("ui.rest: agent SSE client connected");
    let shutdown = state.shutdown.clone();
    let events = agent_event_stream(rx, wanted, shutdown);
    Sse::new(events)
        .keep_alive(KeepAlive::new().interval(SSE_KEEPALIVE).text("keep-alive"))
        .into_response()
}

/// Turn a broadcast receiver into an SSE event stream. Lagged frames are
/// skipped (and reported as a `lagged` event) rather than terminating the
/// connection; the stream ends on shutdown or when the sender is dropped.
fn agent_event_stream(
    rx: tokio::sync::broadcast::Receiver<AgentEvent>,
    wanted: Option<Vec<String>>,
    shutdown: tokio_util::sync::CancellationToken,
) -> impl Stream<Item = Result<Event, Infallible>> + Send + 'static {
    stream::unfold((rx, wanted, shutdown), |(mut rx, wanted, shutdown)| async move {
        loop {
            tokio::select! {
                biased;
                _ = shutdown.cancelled() => return None,
                recv = rx.recv() => match recv {
                    Ok(ev) => {
                        let kind = ev.kind();
                        if let Some(ref w) = wanted {
                            if !w.iter().any(|k| k == kind) {
                                continue;
                            }
                        }
                        let data = match &ev {
                            AgentEvent::Signal(t) => serde_json::to_string(t),
                            AgentEvent::BanAdded(b) => serde_json::to_string(b),
                            AgentEvent::BanRemoved { subject } => {
                                serde_json::to_string(&json!({ "subject": subject }))
                            }
                        };
                        let data = match data {
                            Ok(d) => d,
                            Err(e) => {
                                warn!("ui.rest: agent event serialisation failed: {e}");
                                continue;
                            }
                        };
                        let event = Event::default().event(kind).data(data);
                        return Some((Ok(event), (rx, wanted, shutdown)));
                    }
                    Err(RecvError::Lagged(n)) => {
                        let event = Event::default()
                            .event("lagged")
                            .data(json!({ "skipped": n }).to_string());
                        return Some((Ok(event), (rx, wanted, shutdown)));
                    }
                    Err(RecvError::Closed) => return None,
                },
            }
        }
    })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn params_to_value(params: HashMap<String, String>) -> Value {
    Value::Object(params.into_iter().map(|(k, v)| (k, Value::String(v))).collect())
}

/// `ConfigValidation`/`MissingConfig` → 400, `NotFound` → 404, everything
/// else → 503 (unsupported subsystem or runtime failure).
fn respond(result: Result<Value, PluginError>) -> Response {
    match result {
        Ok(v) => Json(v).into_response(),
        Err(err) => {
            let status = match &err {
                PluginError::ConfigValidation(_) | PluginError::MissingConfig(_) => {
                    StatusCode::BAD_REQUEST
                }
                PluginError::NotFound(_) => StatusCode::NOT_FOUND,
                _ => StatusCode::SERVICE_UNAVAILABLE,
            };
            (status, Json(json!({ "error": err.to_string() }))).into_response()
        }
    }
}

fn unauthorized(msg: &'static str) -> Response {
    (StatusCode::UNAUTHORIZED, Json(json!({ "error": msg }))).into_response()
}
