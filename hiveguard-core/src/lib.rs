// --- Always-on modules ---------------------------------------------------
pub mod api;
pub mod ban_store;
pub mod bot_registry;
pub mod config;
pub mod crdt;      // Part of persistence v2 format — required even standalone.
pub mod detector;
pub mod detectors;
pub mod errors;
pub mod hlc;       // Used by crdt + persistence — required even standalone.
pub mod models;
pub mod persistence;
// Stage 3 of INT: `scoring` module migrated to the `scoring-default` plugin
// (`plugins/scoring-default/`). Source archived in `obsolete/scoring.rs`.
pub mod whitelist;

// --- Cluster-only modules ------------------------------------------------
//
// These are only meaningful in multi-node deployments. Gated behind the
// `cluster` Cargo feature so `distribution-minimal` (fail2ban-style
// standalone) builds don't pull them in.
#[cfg(feature = "cluster")]
pub mod anti_poison;
#[cfg(feature = "cluster")]
pub mod hashcash;
#[cfg(feature = "cluster")]
pub mod trust;

// --- Re-exports (always available) ---------------------------------------
pub use ban_store::{BanStore, InMemoryBanStore};
pub use bot_registry::{BotRegistry, BotRule, BotPolicy, BotStatsResponse};
pub use config::{HiveGuardConfig, SeedPeer, ClusterMode};
pub use detector::Detector;
pub use detectors::{
    PathProbeDetector, SshBruteforceDetector, Http4xxFloodDetector,
    HttpLoginBruteforceDetector,
    ScannerFingerprintDetector, SmtpBruteforceDetector,
    HoneypotDetector, EntropyDetector, TimingDetector,
    PortScanDetector, DistributedSlowDetector, create_detectors,
};
pub use errors::HiveGuardError;
pub use models::*;
pub use persistence::{StateManager, WalEntry, WalReader, WalWriter};
pub use whitelist::WhitelistManager;
pub use crdt::CrdtBanRecord;
pub use crdt::TOMBSTONE_QUORUM;
pub use hlc::HlcTimestamp;

// --- Cluster-only re-exports ---------------------------------------------
#[cfg(feature = "cluster")]
pub use anti_poison::RateLimiter;
#[cfg(feature = "cluster")]
pub use hashcash::PowStamp;
#[cfg(feature = "cluster")]
pub use trust::TrustManager;
