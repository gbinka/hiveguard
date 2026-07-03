//! # hiveguard-plugin-api
//!
//! Stable contract for HiveGuard plugins. Every plugin crate depends only on
//! this crate (plus `hiveguard-core` for domain types) — never on the daemon
//! or on sibling plugins.
//!
//! ## Categories
//!
//! | Trait                | Purpose                                                |
//! |----------------------|--------------------------------------------------------|
//! | [`LogSourcePlugin`]  | Produce [`NormalizedEvent`]s from files, sockets, MQs  |
//! | [`NotifierPlugin`]   | Push alerts to chat / paging systems                   |
//! | [`EnforcerPlugin`]   | Apply / remove bans at the firewall layer              |
//! | [`CtiProviderPlugin`]| Reputation lookups for IPs                             |
//! | [`SiemSinkPlugin`]   | Ship events to SIEM (Elastic / Splunk / Datadog / …)   |
//! | [`DetectorPlugin`]   | Inspect events, emit [`DetectionSignal`]s              |
//! | [`UiServerPlugin`]   | Serve a UI (REST / TUI / Web)                          |
//!
//! ## Registration
//!
//! Each plugin crate submits one [`PluginDescriptor`] via [`inventory`]:
//!
//! ```ignore
//! use hiveguard_plugin_api::prelude::*;
//!
//! inventory::submit! {
//!     PluginDescriptor {
//!         id: "notifier.slack",
//!         kind: PluginKind::Notifier,
//!         api_version: API_VERSION,
//!         manifest: SlackPlugin::manifest_fn,
//!         config_schema: include_str!("../schema.json"),
//!         factory: PluginFactory::Notifier(SlackPlugin::create),
//!     }
//! }
//! ```
//!
//! The host (`hiveguard-host`) iterates `inventory::iter::<PluginDescriptor>`
//! at startup, filters by the `plugins:` section in YAML, validates each
//! plugin's config against its JSON Schema, and calls the factory.

pub mod context;
pub mod error;
pub mod manifest;
pub mod prelude;
pub mod registry;
pub mod schema;
pub mod secrets;
pub mod traits;

pub use context::{PluginContext, PluginMetrics};
pub use error::{PluginError, PluginResult};
pub use manifest::{HealthState, PluginKind, PluginManifest};
pub use registry::{PluginDescriptor, PluginFactory, API_VERSION};
pub use schema::validate_against_schema;
pub use secrets::SecretResolver;

pub use traits::{
    cti_provider::{CtiProviderPlugin, CtiVerdict},
    detector::DetectorPlugin,
    enforcer::EnforcerPlugin,
    log_source::{EventSink, LogSourcePlugin},
    notifier::{AlertEvent, AlertKind, NotifierPlugin},
    scoring_engine::{BanDecision, ScoringEnginePlugin},
    siem_sink::{SiemBatch, SiemSinkPlugin},
    ui_server::{
        plugin_kind_name, BanInfo, BanRequest, Fail2banBanInfo, Fail2banImportInfo, NodeInfo,
        PeerInfo, PluginInfo, SigmaLogSource, SigmaRuleDetail, SigmaRuleSummary, SigmaStatsInfo,
        StatsInfo, ThreatInfo, UiApiHandle, UiEvent, UiServerPlugin,
    },
    Plugin,
};

// Re-export inventory so plugins don't need to depend on it directly.
pub use inventory;
pub use tokio_util::sync::CancellationToken;
