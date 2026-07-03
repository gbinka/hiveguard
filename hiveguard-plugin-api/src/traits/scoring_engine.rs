use std::net::IpAddr;
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use hiveguard_core::models::{BanSource, DetectionSignal};

use crate::error::PluginResult;
use crate::traits::Plugin;

/// Output of a scoring engine — a concrete instruction to issue a ban.
///
/// The pipeline takes this and writes the corresponding [`BanRecord`] into
/// the ban store. The scoring engine does **not** persist bans itself.
///
/// [`BanRecord`]: hiveguard_core::models::BanRecord
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BanDecision {
    /// Target — single IP or CIDR (subnet-level bans for distributed attacks).
    pub subject: IpNet,

    /// Requested ban duration. The pipeline may clamp to per-source minima
    /// configured in the daemon (e.g. `min_ban_duration: 1h`).
    pub duration: Duration,

    /// Human-readable explanation surfaced in alerts and the REST API.
    /// Should reference the detectors that contributed.
    pub reason: String,

    /// Effective severity at the moment of the decision (max across
    /// contributing signals, typically). Used for ranking in the UI.
    pub severity: u8,

    /// Stable hash of the contributing evidence — used by CRDT
    /// deduplication when bans propagate across the cluster.
    pub evidence_hash: [u8; 32],

    /// Origin of the ban — typically `BanSource::LocalDetector(name)` where
    /// `name` is the detector that contributed the highest-severity signal.
    pub source: BanSource,

    /// Decision timestamp.
    pub timestamp: DateTime<Utc>,
}

/// Scoring engine — combines detection signals into ban decisions.
///
/// Exactly one scoring engine is active per daemon. The pipeline calls
/// [`ScoringEnginePlugin::record`] for every signal produced by any
/// detector, then [`ScoringEnginePlugin::evaluate`] for the source IP. The
/// engine returns `Some(BanDecision)` when its internal threshold is
/// crossed.
///
/// ## Why a plugin
///
/// The default implementation is a weighted sliding-window accumulator —
/// the same algorithm HiveGuard used before the refactor. But the contract
/// is intentionally narrow (5 methods) and the input/output types are
/// stable, so third parties can ship alternative engines:
///
/// - ML-based (Isolation Forest, gradient boosting on event features).
/// - Bayesian inference over per-detector likelihoods.
/// - Adaptive thresholds based on traffic volume.
/// - Business-rule overlays ("never ban our internal CI/CD egress").
/// - Compliance-driven scoring (PCI / HIPAA / SOC2 specific rules).
///
/// Vendors can sell "HiveGuard Pro Scoring" as a plugin that swaps the
/// default engine — the rest of the system doesn't change.
///
/// ## Concurrency
///
/// Both `record` and `evaluate` take `&self`. The pipeline runs them
/// concurrently across pipeline workers. Use interior mutability
/// (`DashMap`, `RwLock`, atomics) for engine state. **Keep `record`
/// fast** — it's called once per signal and sits in the hot path.
///
/// ## Persistence
///
/// `snapshot` and `restore` round-trip the engine's internal state through
/// the same WAL+snapshot mechanism used for the ban store. The default
/// snapshot interval is 5 minutes; `restore` is called on daemon startup
/// before any signals are processed.
///
/// Implementations MUST guarantee `snapshot ∘ restore = identity` on the
/// observable behaviour (subsequent decisions). The on-disk JSON
/// representation can change between versions, but `restore` must
/// gracefully handle older snapshots (or return `Err` to abort startup).
#[async_trait]
pub trait ScoringEnginePlugin: Plugin {
    /// Record one detection signal. Hot path — keep allocations bounded
    /// and avoid expensive computations. Returns nothing; the pipeline
    /// follows up with `evaluate(ip)` immediately afterward.
    fn record(&self, signal: DetectionSignal);

    /// Evaluate whether `ip` should be banned given the current
    /// accumulated state. `Some(BanDecision)` causes the pipeline to
    /// write the corresponding ban record; `None` keeps the IP alive.
    ///
    /// May be called for an IP that has never been `record`ed against
    /// (e.g. operator-driven check). Implementations should return
    /// `None` quickly in that case.
    fn evaluate(&self, ip: IpAddr) -> Option<BanDecision>;

    /// Periodic housekeeping (~every 30 s). Prune expired entries,
    /// decay aging scores, evict cold entries past the size cap.
    /// Must not block the hot path; use try-lock + skip if needed.
    fn decay(&self);

    /// Serialize the engine's internal state for persistence.
    ///
    /// Called on a timer (default every 5 min) and during graceful
    /// shutdown. The returned `Value` is persisted alongside the ban
    /// store snapshot.
    fn snapshot(&self) -> serde_json::Value;

    /// Restore engine state from a previously taken snapshot. Called
    /// once during startup, before any `record`/`evaluate` calls.
    ///
    /// Implementations should handle older snapshot formats gracefully
    /// — either migrate, or return `Err` with a clear error message
    /// (the daemon will refuse to start, which is the safer outcome
    /// for a security tool).
    fn restore(&self, state: serde_json::Value) -> PluginResult<()>;
}
