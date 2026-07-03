//! WebSocket client for the daemon's `/api/stream` endpoint.
//!
//! Phase 5 wire format:
//!
//! * Inbound frames are JSON objects shaped as `{"type": "...", "data": ...}`.
//!   The `type` field selects a `Msg` variant; `data` is the payload.
//!   Recognised envelopes:
//!     - `connected`         → `Msg::Connected { node_name, version }`
//!     - `bans_snapshot`     → `Msg::BansLoaded(Vec<BanRow>)`
//!     - `threats_snapshot`  → `Msg::ThreatsLoaded(Vec<ThreatRow>)`
//!     - `plugins_snapshot`  → `Msg::PluginsLoaded(Vec<PluginStatus>)`
//! * The bare-enum JSON encoding of `Msg` is also accepted so the daemon
//!   can stream raw `Msg` values once `ui-rest` stabilises.
//!
//! TODO(phase-6):
//! * Outbound channel (user actions: ban request, filter syncs) — currently
//!   only inbound is wired.
//! * Re-auth flow if the daemon rejects the upgrade with 401.
//! * Streaming compression / batching once message volume warrants it.
//! * Real-time event subscriptions (per-view backpressure, server-side
//!   filtering, etc.).
//! * Persist filter state across reconnects via `localStorage`.

use futures::stream::StreamExt;
use gloo_net::websocket::{futures::WebSocket, Message};
use gloo_timers::future::TimeoutFuture;
use hiveguard_ui::{BanRow, Msg, PluginStatus, ThreatRow};
use serde::Deserialize;
use wasm_bindgen_futures::spawn_local;

use crate::state::AppState;

/// Default URL the SPA connects to. The host should serve us from the same
/// origin, but during `trunk serve` development we hit the daemon directly.
/// TODO(phase-6): derive from `window.location` + config endpoint.
const DEFAULT_WS_URL: &str = "ws://localhost:8443/api/stream";

/// Envelope wrapper accepted by the parser. The daemon side either uses
/// the bare-enum JSON form (already covered by `serde_json::from_str::<Msg>`)
/// or the structured envelope below.
#[derive(Debug, Deserialize)]
struct Envelope {
    #[serde(rename = "type")]
    ty: String,
    #[serde(default)]
    data: serde_json::Value,
}

/// Start the (re)connecting WebSocket loop. Runs forever as a spawned task.
pub fn connect_loop(state: AppState) {
    spawn_local(async move {
        // Exponential backoff bounded at 30s. Resets on a successful connect.
        let mut backoff_ms: u32 = 500;

        loop {
            state.dispatch(Msg::Connecting);
            log("ui-web: connecting to ", DEFAULT_WS_URL);

            match WebSocket::open(DEFAULT_WS_URL) {
                Ok(ws) => {
                    backoff_ms = 500; // reset on successful open
                    run_session(ws, state).await;
                }
                Err(e) => {
                    let reason = format!("open failed: {e}");
                    state.dispatch(Msg::ConnectionFailed(reason));
                }
            }

            // Wait then retry.
            TimeoutFuture::new(backoff_ms).await;
            backoff_ms = (backoff_ms * 2).min(30_000);
        }
    });
}

/// Drive a single WS session until it closes. Returns control to the
/// reconnect loop on close / error.
async fn run_session(ws: WebSocket, state: AppState) {
    let (_sink, mut stream) = ws.split();
    // TODO(phase-6): retain `sink` and expose an outbound sender so user
    // actions can be pushed to the daemon. Currently we drop it.

    while let Some(msg) = stream.next().await {
        match msg {
            Ok(Message::Text(text)) => {
                if let Some(parsed) = parse_frame(&text) {
                    state.dispatch(parsed);
                } else {
                    log("ui-web: dropped unrecognised frame:", &text);
                }
            }
            Ok(Message::Bytes(_)) => {
                // TODO(phase-6): binary protocol (msgpack / bincode) once
                // throughput needs warrant it. For now we ignore.
            }
            Err(e) => {
                state.dispatch(Msg::ConnectionFailed(format!("ws error: {e}")));
                return;
            }
        }
    }

    state.dispatch(Msg::ConnectionFailed("socket closed".into()));
}

/// Decode a WebSocket text frame into a `Msg`.
///
/// Tries the structured envelope first (the format `ui-rest` is expected to
/// emit). Falls back to the bare-enum JSON form so we can interoperate with
/// any tooling that just serialises `Msg` directly.
fn parse_frame(text: &str) -> Option<Msg> {
    // Try the typed envelope first.
    if let Ok(env) = serde_json::from_str::<Envelope>(text) {
        match env.ty.as_str() {
            "connected" => {
                #[derive(Deserialize)]
                struct ConnectedPayload {
                    node_name: String,
                    version: String,
                }
                if let Ok(p) = serde_json::from_value::<ConnectedPayload>(env.data) {
                    return Some(Msg::Connected {
                        node_name: p.node_name,
                        version: p.version,
                    });
                }
                return None;
            }
            "bans_snapshot" => {
                if let Ok(rows) = serde_json::from_value::<Vec<BanRow>>(env.data) {
                    return Some(Msg::BansLoaded(rows));
                }
                return None;
            }
            "threats_snapshot" => {
                if let Ok(rows) = serde_json::from_value::<Vec<ThreatRow>>(env.data) {
                    return Some(Msg::ThreatsLoaded(rows));
                }
                return None;
            }
            "plugins_snapshot" => {
                if let Ok(rows) = serde_json::from_value::<Vec<PluginStatus>>(env.data) {
                    return Some(Msg::PluginsLoaded(rows));
                }
                return None;
            }
            _ => {
                // Unknown envelope type — fall through to bare-enum parse.
            }
        }
    }

    // Bare-enum `Msg` form, e.g. `{"BansLoaded":[...]}`.
    serde_json::from_str::<Msg>(text).ok()
}

/// Tiny `console.log` helper that doesn't drag in the `log` / `tracing`
/// ecosystem for a scaffold. Replace with `tracing-wasm` in Phase 6.
fn log(prefix: &str, body: &str) {
    web_sys::console::log_1(&format!("{prefix} {body}").into());
}
