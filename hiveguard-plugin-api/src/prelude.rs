//! Convenience re-exports for plugin authors.
//!
//! ```ignore
//! use hiveguard_plugin_api::prelude::*;
//! ```

pub use crate::context::{PluginContext, PluginMetrics};
pub use crate::error::{PluginError, PluginResult};
pub use crate::manifest::{HealthState, PluginKind, PluginManifest};
pub use crate::registry::{BoxFuture, PluginDescriptor, PluginFactory, API_VERSION};
pub use crate::traits::{
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

pub use async_trait::async_trait;
pub use inventory;
pub use serde_json;
pub use tokio_util::sync::CancellationToken;

pub use hiveguard_core::models::{DetectionSignal, NormalizedEvent};
