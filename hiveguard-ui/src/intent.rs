//! User intents — messages that drive `update(model, msg) -> (model, cmds)`.
//!
//! Each `Msg` represents either a user action (button click, key press) or
//! an API response. The TUI and the Web renderer both emit `Msg` and route
//! them through the same `update` function.

use serde::{Deserialize, Serialize};

use crate::model::{BanRow, PluginStatus, ThreatRow, ViewKind};

/// All user intents and API events that flow through the UI.
///
/// `#[serde(tag = "type", content = "data")]` would be nicer ergonomically
/// (matches the WebSocket envelope `{"type": "...", "data": ...}`) but we
/// keep the default representation here so the existing TUI / tests don't
/// have to change. The web `ws.rs` layer translates the envelope form into
/// `Msg` variants before dispatching.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Msg {
    // --- Navigation ---
    NavigateTo(ViewKind),

    // --- Connection lifecycle ---
    Connecting,
    Connected { node_name: String, version: String },
    ConnectionFailed(String),

    // --- Periodic / heartbeat ---
    Tick,

    // --- Snapshots pushed by the daemon ---
    BansLoaded(Vec<BanRow>),
    ThreatsLoaded(Vec<ThreatRow>),
    PluginsLoaded(Vec<PluginStatus>),

    // --- User actions on bans ---
    /// Unban the given CIDR subject.
    UnbanRequested(String),
    /// Create a ban. `duration_secs == 0` means permanent.
    BanRequested {
        subject: String,
        duration_secs: u64,
        reason: String,
    },

    // --- Filter state changes ---
    FilterBansSeverity(u8),
    FilterBansSearch(String),
    FilterThreatsDetector(String),
    FilterThreatsSeverity(u8),

    // --- Dev-only convenience ---
    /// Populate the model with deterministic fake data so the layout can be
    /// exercised without a live backend. Wired to a Dashboard button.
    LoadSampleData,
}
