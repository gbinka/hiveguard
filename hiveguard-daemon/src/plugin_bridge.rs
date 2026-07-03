//! Bridge layer between the new plugin contract and the daemon's existing
//! pipeline code.
//!
//! During INT we wire `hiveguard-host::Loader` into the daemon while keeping
//! `pipeline.rs`, `state_manager`, and friends on their legacy trait signatures.
//! These adapters let an instantiated plugin satisfy the older trait, so the
//! pipeline does not have to be rewritten in this phase.
//!
//! As legacy crates (`hiveguard-enforce`, `hiveguard-ingest`, …) are
//! liquidated in subsequent passes, individual adapters here will be deleted
//! one by one until this module disappears.

use std::net::IpAddr;

use async_trait::async_trait;
use ipnet::IpNet;
use tracing::error;

use hiveguard_core::detector::Detector as LegacyDetector;
use hiveguard_core::errors::HiveGuardError;
use hiveguard_core::models::{BanRecord, DetectionSignal, NormalizedEvent};
use hiveguard_cti::enricher::{CtiSignal, EnrichStats};
use hiveguard_cti::provider::CtiProvider as LegacyCtiProvider;
use hiveguard_enforce::enforcer::Enforcer as LegacyEnforcer;
use hiveguard_plugin_api::traits::scoring_engine::BanDecision;
use hiveguard_plugin_api::{CtiProviderPlugin, DetectorPlugin, EnforcerPlugin};

// ---------------------------------------------------------------------------
// DetectorPlugin → hiveguard_core::Detector
// ---------------------------------------------------------------------------

/// Wraps a `DetectorPlugin` so that pipeline code (which still imports
/// `hiveguard_core::Detector`) can call it without modification.
///
/// Detector contracts already align on `&self` and `process(&NormalizedEvent)`,
/// so this is a thin shim — the only adaptation is exposing `manifest().id`
/// as the legacy `name()` field.
pub struct DetectorPluginAdapter(pub Box<dyn DetectorPlugin>);

impl LegacyDetector for DetectorPluginAdapter {
    fn name(&self) -> &str {
        self.0.manifest().id
    }

    fn process(&self, event: &NormalizedEvent) -> Option<DetectionSignal> {
        self.0.process(event)
    }
}

// ---------------------------------------------------------------------------
// EnforcerPlugin → hiveguard_enforce::Enforcer
// ---------------------------------------------------------------------------

/// Wraps an `EnforcerPlugin` so it can be plugged into the legacy
/// `Arc<Mutex<Box<dyn hiveguard_enforce::Enforcer>>>` slot in the pipeline.
///
/// `PluginError` is mapped to `HiveGuardError::Storage`. The pipeline treats
/// any error as cause to log and continue, so the exact variant does not
/// matter operationally — we use `Storage` because it's the catch-all.
pub struct EnforcerPluginAdapter(pub Box<dyn EnforcerPlugin>);

fn map_err(e: hiveguard_plugin_api::PluginError) -> HiveGuardError {
    HiveGuardError::Storage(format!("plugin: {e}"))
}

#[async_trait]
impl LegacyEnforcer for EnforcerPluginAdapter {
    async fn setup(&mut self) -> Result<(), HiveGuardError> {
        self.0.setup().await.map_err(map_err)
    }

    async fn apply_ban(&mut self, subject: &IpNet) -> Result<(), HiveGuardError> {
        self.0.apply_ban(subject).await.map_err(|e| {
            error!(target: "plugin_bridge", subject = %subject, error = %e, "apply_ban via plugin failed");
            map_err(e)
        })
    }

    async fn remove_ban(&mut self, subject: &IpNet) -> Result<(), HiveGuardError> {
        self.0.remove_ban(subject).await.map_err(map_err)
    }

    async fn sync_full(&mut self, banned: &[IpNet]) -> Result<(), HiveGuardError> {
        self.0.sync_full(banned).await.map_err(map_err)
    }

    async fn get_current_bans(&self) -> Result<Vec<IpNet>, HiveGuardError> {
        self.0.get_current_bans().await.map_err(map_err)
    }
}

// ---------------------------------------------------------------------------
// CtiProviderPlugin → hiveguard_cti::CtiProvider
// ---------------------------------------------------------------------------

/// Wraps a `CtiProviderPlugin` so it can be aggregated into the legacy
/// `hiveguard_cti::CtiEnricher` consumed by the pipeline.
///
/// The plugin's `CtiVerdict` (provider/confidence/reason/recommend_ban) is
/// projected onto the legacy `CtiSignal` (provider/severity/confidence_score/
/// description). Severity is derived heuristically:
///
/// - `recommend_ban: true` → 200 (above default scoring threshold)
/// - otherwise            → 100 (accumulates with other detector signals)
pub struct CtiPluginAdapter(pub Box<dyn CtiProviderPlugin>);

#[async_trait]
impl LegacyCtiProvider for CtiPluginAdapter {
    fn name(&self) -> &'static str {
        self.0.manifest().id
    }

    async fn check(&self, ip: IpAddr) -> (Option<CtiSignal>, EnrichStats) {
        let mut stats = EnrichStats::default();
        stats.api_called = true;
        match self.0.lookup(ip).await {
            Ok(Some(verdict)) => {
                let signal = CtiSignal {
                    provider: self.0.manifest().id,
                    severity: if verdict.recommend_ban { 200 } else { 100 },
                    confidence_score: verdict.confidence.unwrap_or(0),
                    description: verdict
                        .reason
                        .unwrap_or_else(|| "no detail provided".to_owned()),
                };
                (Some(signal), stats)
            }
            Ok(None) => (None, stats),
            Err(e) => {
                stats.api_error = true;
                error!(target: "plugin_bridge", ip = %ip, error = %e, "CTI lookup failed");
                (None, stats)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// BanDecision → BanRecord
// ---------------------------------------------------------------------------

/// Convert a plugin-side [`BanDecision`] into a legacy [`BanRecord`] suitable
/// for the persistence layer and gossip propagation.
///
/// The `BanDecision` carries everything except the absolute `expires_at`
/// timestamp (it has a relative `duration`) and the `geo_info` enrichment
/// (filled in by the pipeline after CTI/GeoIP lookups). Both are added here.
pub fn decision_to_record(decision: BanDecision) -> BanRecord {
    let expires_at = chrono::Duration::from_std(decision.duration)
        .ok()
        .map(|cd| decision.timestamp + cd);

    BanRecord {
        subject: decision.subject,
        created_at: decision.timestamp,
        expires_at,
        severity: decision.severity,
        reason: decision.reason,
        evidence_hash: decision.evidence_hash,
        source: decision.source,
        geo_info: None,
    }
}

// ---------------------------------------------------------------------------
// Conversion helpers — daemon config → loader config
// ---------------------------------------------------------------------------

/// Convert legacy `hiveguard_core::config::HiveGuardConfig` into the lean
/// `hiveguard_config::HiveGuardConfig` consumed by the loader.
///
/// Only the `node`, `scoring`, and `plugins` fields are forwarded — the rest
/// of legacy config (sources, detectors, alerting, …) keeps driving the old
/// code paths in `main.rs` until those subsystems are migrated.
pub fn to_loader_config(
    cfg: &hiveguard_core::config::HiveGuardConfig,
) -> hiveguard_config::HiveGuardConfig {
    hiveguard_config::HiveGuardConfig {
        node: hiveguard_config::NodeConfig {
            name: cfg.node.name.clone(),
            data_dir: cfg.node.data_dir.clone(),
            listen_gossip: if cfg.node.listen_gossip.is_empty() {
                None
            } else {
                Some(cfg.node.listen_gossip.clone())
            },
            seeds: cfg.node.seeds.iter().map(|s| s.address().to_owned()).collect(),
        },
        scoring: hiveguard_config::ScoringConfig {
            // HumanDuration round-trips through its Display impl.
            accumulation_window: format!("{}", cfg.scoring.accumulation_window),
            ban_severity_threshold: cfg.scoring.ban_severity_threshold,
            default_ban_duration: format!("{}", cfg.scoring.default_ban_duration),
        },
        plugins: cfg
            .plugins
            .iter()
            .map(|p| hiveguard_config::PluginEntry {
                id: p.id.clone(),
                name: p.name.clone(),
                config: p.config.clone(),
                optional: p.optional,
            })
            .collect(),
    }
}
