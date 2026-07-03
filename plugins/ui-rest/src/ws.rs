//! WebSocket endpoint for live UI updates.
//!
//! Authentication accepts the bearer token via the
//! `Sec-WebSocket-Protocol: bearer.<token>` subprotocol header (preferred —
//! browsers can set it natively) or, as a fallback, via a `?token=...`
//! query parameter.
//!
//! On upgrade the handler emits an initial snapshot burst
//! (`Connected`, `BansSnapshot`, `ThreatsSnapshot`, `PluginsSnapshot`), then
//! forwards every `UiEvent` published by `UiApiHandle::subscribe()` until
//! the client disconnects or the daemon shuts down.

use std::collections::HashMap;
use std::sync::Arc;

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Query, State,
    },
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use futures_util::{SinkExt, StreamExt};
use subtle::ConstantTimeEq;
use tokio::sync::broadcast::error::RecvError;
use tokio::time::interval;
use tracing::{debug, info, warn};

use hiveguard_plugin_api::prelude::UiEvent;

use crate::state::AppState;

/// Sec-WebSocket-Protocol value prefix used to carry the bearer token.
///
/// Example header: `Sec-WebSocket-Protocol: bearer.abc123`.
const BEARER_PROTOCOL_PREFIX: &str = "bearer.";

/// Axum handler for `GET /api/stream`.
pub async fn ws_handler(
    State(state): State<Arc<AppState>>,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    // Prefer the `Sec-WebSocket-Protocol: bearer.<token>` header — it's
    // marginally safer than a query parameter because it doesn't get logged
    // by access logs / proxies the way a URL does.
    let (token, via_protocol) = match extract_protocol_token(&headers) {
        Some(t) => (t, true),
        None => match params.get("token").cloned() {
            Some(t) => (t, false),
            None => return (StatusCode::UNAUTHORIZED, "missing token").into_response(),
        },
    };

    let expected = state.auth_token.as_bytes();
    let token_bytes = token.as_bytes();
    let length_ok = token_bytes.len() == expected.len();
    let content_ok: bool = token_bytes.ct_eq(expected).into();
    if !(length_ok && content_ok) {
        return (StatusCode::UNAUTHORIZED, "invalid token").into_response();
    }

    // If the client requested the `bearer.<token>` subprotocol, echo it
    // back — RFC 6455 requires the server to respond with one of the
    // offered subprotocols, otherwise some clients close the connection.
    if via_protocol {
        let echo = format!("{BEARER_PROTOCOL_PREFIX}{token}");
        ws.protocols([echo])
            .on_upgrade(move |socket| run_ws(socket, state))
    } else {
        ws.on_upgrade(move |socket| run_ws(socket, state))
    }
}

fn extract_protocol_token(headers: &HeaderMap) -> Option<String> {
    let raw = headers
        .get(axum::http::header::SEC_WEBSOCKET_PROTOCOL)?
        .to_str()
        .ok()?;
    // Header may carry a comma-separated list of offered subprotocols.
    for part in raw.split(',') {
        let trimmed = part.trim();
        if let Some(rest) = trimmed.strip_prefix(BEARER_PROTOCOL_PREFIX) {
            if !rest.is_empty() {
                return Some(rest.to_string());
            }
        }
    }
    None
}

/// Per-connection event loop.
async fn run_ws(socket: WebSocket, state: Arc<AppState>) {
    info!("ui.rest: websocket client connected");
    let (mut tx, mut rx) = socket.split();

    // ---- Initial snapshot burst ----
    let initial = vec![
        UiEvent::Connected(state.api.node_info().await),
        UiEvent::BansSnapshot(state.api.list_bans().await),
        UiEvent::ThreatsSnapshot(state.api.list_threats().await),
        UiEvent::PluginsSnapshot(state.api.list_plugins().await),
    ];
    for ev in initial {
        if let Err(e) = send_event(&mut tx, &ev).await {
            warn!("ui.rest: initial snapshot send failed: {e}");
            return;
        }
    }

    let mut sub = state.api.subscribe();
    let mut ticks = interval(state.tick_interval);
    // Skip the immediate first tick so we don't double-fire right after the
    // snapshot burst.
    ticks.tick().await;
    let shutdown = state.shutdown.clone();

    loop {
        tokio::select! {
            biased;
            _ = shutdown.cancelled() => {
                debug!("ui.rest: websocket terminating due to shutdown signal");
                let _ = tx.send(Message::Close(None)).await;
                return;
            }
            recv = sub.recv() => match recv {
                Ok(ev) => {
                    if let Err(e) = send_event(&mut tx, &ev).await {
                        warn!("ui.rest: ws send failed: {e}");
                        return;
                    }
                }
                Err(RecvError::Lagged(skipped)) => {
                    warn!("ui.rest: ws subscriber lagged, skipped {skipped} events");
                    // Snapshots are idempotent — client will catch up on the
                    // next broadcast. Nothing to do here.
                }
                Err(RecvError::Closed) => {
                    debug!("ui.rest: broadcast channel closed");
                    return;
                }
            },
            _ = ticks.tick() => {
                if let Err(e) = send_event(&mut tx, &UiEvent::Tick).await {
                    warn!("ui.rest: ws tick failed: {e}");
                    return;
                }
            }
            msg = rx.next() => match msg {
                Some(Ok(Message::Close(_))) | None => {
                    debug!("ui.rest: ws client closed");
                    return;
                }
                Some(Ok(_)) => {
                    // TODO(Phase 7): handle user actions sent from the
                    // client (e.g. unban requests, filter selections).
                }
                Some(Err(e)) => {
                    warn!("ui.rest: ws recv error: {e}");
                    return;
                }
            }
        }
    }
}

/// Serialise a `UiEvent` and send it as a text frame.
async fn send_event<S>(tx: &mut S, ev: &UiEvent) -> Result<(), String>
where
    S: SinkExt<Message, Error = axum::Error> + Unpin,
{
    let body = serde_json::to_string(ev).map_err(|e| format!("json: {e}"))?;
    tx.send(Message::Text(body.into()))
        .await
        .map_err(|e| format!("send: {e}"))
}
