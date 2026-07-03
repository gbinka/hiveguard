//! UI server contract — REST/WebSocket/TUI plugins consume a shared
//! [`UiApiHandle`] that the host (`hiveguard-daemon`) implements over its
//! live state. The shape is intentionally narrow: read methods return owned
//! snapshots, mutations are explicit, and live updates flow through a
//! single `subscribe()` broadcast channel.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;

use crate::error::{PluginError, PluginResult};
use crate::manifest::PluginKind;
use crate::traits::Plugin;

// ---------------------------------------------------------------------------
// Wire types — shared between daemon (`UiApiHandle` impl) and UI plugins.
// These match `hiveguard-ui`'s `BanRow` / `ThreatRow` / `PluginStatus` field
// shapes exactly so JSON round-trips losslessly through the WebSocket.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BanInfo {
    /// CIDR (e.g. `1.2.3.4/32` or `1.2.3.0/24`).
    pub subject: String,
    pub severity: u8,
    pub reason: String,
    /// ISO 8601 timestamp; `None` for permanent bans.
    pub expires_at: Option<String>,
    /// `"detector:ssh_bruteforce"`, `"peer:node-2"`, or `"admin"`.
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ThreatInfo {
    pub ip: String,
    pub severity: u8,
    /// 0..=100 confidence.
    pub confidence: u8,
    pub detector: String,
    pub reason: String,
    /// ISO 8601 timestamp of the signal.
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PluginInfo {
    pub id: String,
    /// `"Source"`, `"Detector"`, `"Enforcer"`, `"Notifier"`, `"SiemSink"`,
    /// `"Cti"`, `"ScoringEngine"`, `"UiServer"`.
    pub kind: String,
    /// `"Healthy"`, `"Degraded"`, or `"Failed"`.
    pub health: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeInfo {
    pub node_name: String,
    pub daemon_version: String,
    /// Seconds since the daemon started.
    pub uptime_secs: u64,
    pub total_bans: usize,
}

/// Frame pushed over the WebSocket. Variants mirror `Msg` in `hiveguard-ui`
/// closely so the renderer can route them with minimal translation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum UiEvent {
    /// Initial handshake — sent once per connection right after auth.
    Connected(NodeInfo),
    /// Full snapshot of currently active bans.
    BansSnapshot(Vec<BanInfo>),
    /// Full snapshot of recent threats (sliding window).
    ThreatsSnapshot(Vec<ThreatInfo>),
    /// Full snapshot of loaded plugins.
    PluginsSnapshot(Vec<PluginInfo>),
    /// Heartbeat — keepalive every ~30s. Renderer can ignore.
    Tick,
}

/// Ban request from the UI (operator clicks "Ban" in the form).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BanRequest {
    pub subject: IpNet,
    pub duration: Duration,
    pub reason: String,
}

// ---------------------------------------------------------------------------
// Management wire types — used by the consolidated REST surface (`ui.rest`).
// Shapes mirror the legacy `rest_api.rs` responses 1:1 so existing clients
// keep round-tripping. Defined here (not pulled from `hiveguard-sigma` /
// `hiveguard-queue`) to keep those crates out of the plugin dependency graph.
// ---------------------------------------------------------------------------

/// Daemon-wide counters — backs `GET /api/stats`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StatsInfo {
    pub uptime_secs: u64,
    pub total_bans: usize,
    pub total_whitelisted: usize,
    pub version: String,
}

/// One federation peer — backs `GET /api/peers`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PeerInfo {
    pub node_id: String,
    pub address: String,
    pub trust_score: f64,
    pub state: String,
}

/// Sigma log-source specifier (lightweight mirror of `hiveguard_sigma::SigmaLogSource`).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct SigmaLogSource {
    pub category: Option<String>,
    pub product: Option<String>,
    pub service: Option<String>,
}

/// One row in `GET /api/sigma/rules`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SigmaRuleSummary {
    pub id: Option<String>,
    pub title: String,
    pub status: String,
    pub level: String,
    pub tags: Vec<String>,
    pub hit_count: u64,
}

/// Full rule detail for `GET /api/sigma/rules/{id}`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SigmaRuleDetail {
    pub id: Option<String>,
    pub title: String,
    pub status: String,
    pub level: String,
    pub description: Option<String>,
    pub author: Option<String>,
    pub date: Option<String>,
    pub tags: Vec<String>,
    pub references: Vec<String>,
    pub logsource: SigmaLogSource,
    pub condition: String,
    pub hit_count: u64,
}

/// Aggregate Sigma stats — backs `GET /api/sigma/stats`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct SigmaStatsInfo {
    pub total_rules: usize,
    pub hit_counts: HashMap<String, u64>,
}

/// One fail2ban ban row — backs `GET /api/fail2ban/preview`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Fail2banBanInfo {
    pub jail: String,
    pub ip: String,
    pub banned_at: String,
    pub expires_at: Option<String>,
}

/// Outcome of `POST /api/fail2ban/import`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Fail2banImportInfo {
    pub imported: usize,
    pub skipped: usize,
    pub errors: Vec<String>,
}

// ---------------------------------------------------------------------------
// UiApiHandle — read/write surface a UI plugin sees.
// ---------------------------------------------------------------------------

/// What the daemon exposes to UI plugins. The host implements this over its
/// live state (ban store, recent-threats ring buffer, plugin registry). UI
/// plugins receive `Arc<dyn UiApiHandle>` and call read methods on demand or
/// subscribe to push updates.
///
/// All read methods are cheap snapshot copies — the daemon's locks are held
/// only long enough to materialise the return value. Mutations are async
/// because they may need to await the enforcer / persistence layer.
#[async_trait]
pub trait UiApiHandle: Send + Sync + 'static {
    // --- Metadata ---
    fn daemon_version(&self) -> String;
    fn node_name(&self) -> String;
    fn uptime(&self) -> Duration;

    // --- Read snapshots ---
    async fn node_info(&self) -> NodeInfo;
    async fn list_bans(&self) -> Vec<BanInfo>;
    async fn list_threats(&self) -> Vec<ThreatInfo>;
    async fn list_plugins(&self) -> Vec<PluginInfo>;

    // --- Mutations ---
    async fn add_ban(&self, req: BanRequest) -> PluginResult<()>;
    async fn remove_ban(&self, subject: IpNet) -> PluginResult<()>;

    // -----------------------------------------------------------------------
    // Extended management surface (REFACTOR 2.5 — legacy `/api/v1` migration).
    //
    // Every method below ships a default implementation so that UI plugins
    // and test doubles (`MockUiApi`, ui-tui, ui-web) compile unchanged — only
    // `DaemonUiApi` overrides them. Infallible reads default to an empty
    // snapshot; everything else defaults to "not supported" (`Err`/`None`),
    // which the REST layer maps to `503 Service Unavailable`.
    // -----------------------------------------------------------------------

    // --- Extended reads ---

    /// Daemon-wide counters. Defaults to deriving from [`node_info`].
    async fn stats(&self) -> StatsInfo {
        let n = self.node_info().await;
        StatsInfo {
            uptime_secs: n.uptime_secs,
            total_bans: n.total_bans,
            total_whitelisted: 0,
            version: n.daemon_version,
        }
    }

    /// CIDR strings currently whitelisted.
    async fn list_whitelist(&self) -> Vec<String> {
        Vec::new()
    }

    /// Known federation peers (empty until a `PeerManager` is wired in).
    async fn list_peers(&self) -> Vec<PeerInfo> {
        Vec::new()
    }

    /// Known bots + runtime stats as a JSON document.
    async fn list_bots(&self) -> PluginResult<Value> {
        Err(unsupported())
    }

    /// Raw config file contents (YAML).
    async fn get_config(&self) -> PluginResult<String> {
        Err(unsupported())
    }

    /// Effective detector configuration as JSON.
    async fn get_detectors(&self) -> PluginResult<Value> {
        Err(unsupported())
    }

    /// Loaded Sigma rules with hit counts.
    async fn list_sigma_rules(&self) -> PluginResult<Vec<SigmaRuleSummary>> {
        Err(unsupported())
    }

    /// Full detail for a single Sigma rule by id (or title fallback).
    /// `Ok(None)` → 404; `Err` → engine unavailable.
    async fn get_sigma_rule(&self, _id: String) -> PluginResult<Option<SigmaRuleDetail>> {
        Err(unsupported())
    }

    /// Aggregate Sigma hit statistics.
    async fn sigma_stats(&self) -> PluginResult<SigmaStatsInfo> {
        Err(unsupported())
    }

    /// Preview bans present in a fail2ban SQLite database without importing.
    async fn fail2ban_preview(
        &self,
        _db: Option<String>,
        _jail: Option<String>,
    ) -> PluginResult<Vec<Fail2banBanInfo>> {
        Err(unsupported())
    }

    /// Prometheus exposition text for `GET /metrics` (no auth). `None` → 503.
    async fn render_metrics(&self) -> Option<String> {
        None
    }

    // --- Extended mutations ---

    /// Add a CIDR to the whitelist.
    async fn add_whitelist(&self, _cidr: IpNet) -> PluginResult<()> {
        Err(unsupported())
    }

    /// Remove a CIDR from the whitelist.
    async fn remove_whitelist(&self, _cidr: IpNet) -> PluginResult<()> {
        Err(unsupported())
    }

    /// Replace the on-disk config file (validated by the daemon).
    async fn put_config(&self, _content: String) -> PluginResult<()> {
        Err(unsupported())
    }

    /// Replace the detector configuration block.
    async fn put_detectors(&self, _detectors: Value) -> PluginResult<()> {
        Err(unsupported())
    }

    /// Add or replace a Sigma rule from YAML; returns the effective rule id.
    async fn upsert_sigma_rule(&self, _yaml: String) -> PluginResult<String> {
        Err(unsupported())
    }

    /// Delete a Sigma rule by id.
    async fn delete_sigma_rule(&self, _id: String) -> PluginResult<()> {
        Err(unsupported())
    }

    /// Import bans from a fail2ban database into the ban store.
    async fn fail2ban_import(
        &self,
        _db: Option<String>,
        _jail: Option<String>,
    ) -> PluginResult<Fail2banImportInfo> {
        Err(unsupported())
    }

    /// Set the policy (`allow`/`block`/`monitor`) for a known bot by name.
    async fn set_bot_policy(&self, _name: String, _policy: String) -> PluginResult<()> {
        Err(unsupported())
    }

    /// Ingest raw log lines through the message router. Returns
    /// `(accepted, rejected)`. `parser` is a parser name or `"auto"`.
    async fn ingest_logs(&self, _lines: Vec<String>, _parser: String) -> PluginResult<(usize, usize)> {
        Err(unsupported())
    }

    // --- Live updates ---
    /// Subscribe to push events. The returned receiver fans out from a single
    /// broadcast channel; lagging consumers may miss messages (this is fine
    /// for snapshots because the next snapshot supersedes the missed one).
    fn subscribe(&self) -> broadcast::Receiver<UiEvent>;
}

// ---------------------------------------------------------------------------
// Plugin trait
// ---------------------------------------------------------------------------

/// UI server — REST API, embedded SPA, TUI, gRPC frontend, …
///
/// UI plugins all consume the same `UiApiHandle`, so a deployment can run
/// TUI + Web simultaneously without code duplication.
#[async_trait]
pub trait UiServerPlugin: Plugin {
    /// Run until `shutdown` fires. The handle is shared and clone-cheap.
    async fn run(
        &mut self,
        api: Arc<dyn UiApiHandle>,
        shutdown: CancellationToken,
    ) -> PluginResult<()>;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// The error returned by the default management-method implementations: the
/// host (or test double) does not back this operation. The REST layer maps it
/// to `503 Service Unavailable`, matching legacy `rest_api.rs` behaviour for
/// disabled subsystems.
fn unsupported() -> PluginError {
    PluginError::Runtime("operation not supported by this UiApiHandle".to_string())
}

/// Convert a `PluginKind` to the stable string used in `PluginInfo::kind`.
pub fn plugin_kind_name(kind: PluginKind) -> &'static str {
    match kind {
        PluginKind::LogSource => "Source",
        PluginKind::Detector => "Detector",
        PluginKind::Enforcer => "Enforcer",
        PluginKind::Notifier => "Notifier",
        PluginKind::SiemSink => "SiemSink",
        PluginKind::CtiProvider => "Cti",
        PluginKind::ScoringEngine => "ScoringEngine",
        PluginKind::UiServer => "UiServer",
    }
}
