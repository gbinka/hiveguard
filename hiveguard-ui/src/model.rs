//! Application state model. Single source of truth for what the UI displays.

use serde::{Deserialize, Serialize};

/// Top-level UI state. Cloned cheap; immutable updates via [`crate::update`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AppModel {
    pub view: ViewKind,
    pub status: ConnectionStatus,
    pub node_name: String,
    pub daemon_version: String,
    /// Active bans (snapshot pushed by the daemon).
    pub bans: Vec<BanRow>,
    /// Recent threat detections.
    pub threats: Vec<ThreatRow>,
    /// Plugin health snapshot.
    pub plugins_status: Vec<PluginStatus>,
    /// User-facing filter / search state for the Bans and Threats views.
    pub filters: FilterState,
}

/// Which top-level view is currently rendered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum ViewKind {
    #[default]
    Dashboard,
    Bans,
    Threats,
    Plugins,
    Config,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum ConnectionStatus {
    #[default]
    Disconnected,
    Connecting,
    Connected,
    Failed(String),
}

/// One row in the Bans view.
///
/// `subject` is a CIDR string (`"10.0.0.1/32"`, `"2001:db8::/32"`), matching
/// how the daemon's enforce plugin records ban scopes. `expires_at` is an
/// ISO-8601 string (or `None` for permanent bans).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct BanRow {
    pub subject: String,
    pub severity: u8,
    pub reason: String,
    pub expires_at: Option<String>,
    pub source: String,
}

/// One row in the Threats view.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ThreatRow {
    pub ip: String,
    pub severity: u8,
    pub confidence: u8,
    pub detector: String,
    pub reason: String,
    pub timestamp: String,
}

/// One row in the Plugins view.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct PluginStatus {
    pub id: String,
    pub kind: String,
    pub health: String,
    pub version: String,
}

/// View-level filters applied client-side over the snapshots above.
///
/// Filters are *not* persisted across page reloads in Phase 5 (TODO: stash
/// in `localStorage` once we have a serde-stable shape we're happy with).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct FilterState {
    pub bans_severity_min: u8,
    pub bans_search: String,
    pub threats_detector: String,
    pub threats_severity_min: u8,
}
