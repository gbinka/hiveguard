use serde::{Deserialize, Serialize};

/// Coarse-grained category. The host uses this to route plugins into the
/// correct collection (sources, notifiers, enforcers, …).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PluginKind {
    LogSource,
    Notifier,
    Enforcer,
    CtiProvider,
    SiemSink,
    Detector,
    ScoringEngine,
    UiServer,
}

impl PluginKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            PluginKind::LogSource => "log_source",
            PluginKind::Notifier => "notifier",
            PluginKind::Enforcer => "enforcer",
            PluginKind::CtiProvider => "cti_provider",
            PluginKind::SiemSink => "siem_sink",
            PluginKind::Detector => "detector",
            PluginKind::ScoringEngine => "scoring_engine",
            PluginKind::UiServer => "ui_server",
        }
    }
}

/// Self-description of a plugin instance.
///
/// Returned by `Plugin::manifest()`. Exposed on `GET /api/v1/plugins` so
/// the UI can render plugin status and version information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginManifest {
    /// Stable identifier — e.g. `"notifier.slack"`. Must match the
    /// `PluginDescriptor::id` registered via `inventory::submit!`.
    pub id: &'static str,

    /// SemVer of the plugin implementation. Independent of `core` version.
    pub version: &'static str,

    /// Free-form human-readable description.
    pub description: &'static str,

    /// Plugin category — drives dispatch logic in the host.
    pub kind: PluginKind,

    /// Author or maintainer string.
    pub author: &'static str,

    /// Optional documentation URL.
    pub docs_url: Option<&'static str>,
}

/// Runtime health of a plugin, polled by the host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", content = "detail")]
pub enum HealthState {
    /// Plugin is operating normally.
    Healthy,
    /// Plugin reports a transient issue but is still running.
    Degraded(String),
    /// Plugin is non-functional; host may restart it.
    Failed(String),
    /// Plugin has not yet finished `init`.
    Initialising,
}

impl HealthState {
    pub fn is_healthy(&self) -> bool {
        matches!(self, HealthState::Healthy)
    }
}
