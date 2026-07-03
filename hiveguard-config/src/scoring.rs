use serde::{Deserialize, Serialize};

/// Scoring engine configuration. Independent of detectors and ban store.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoringConfig {
    /// Sliding window over which severity scores accumulate. Accepts strings
    /// like `"30m"`, `"1h"`. Parsed by the engine, not here.
    #[serde(default = "default_accumulation_window")]
    pub accumulation_window: String,

    /// Weighted-sum threshold at which a ban is issued.
    #[serde(default = "default_threshold")]
    pub ban_severity_threshold: u32,

    /// Default ban duration when a detector does not request a specific one.
    #[serde(default = "default_ban_duration")]
    pub default_ban_duration: String,
}

impl Default for ScoringConfig {
    fn default() -> Self {
        Self {
            accumulation_window: default_accumulation_window(),
            ban_severity_threshold: default_threshold(),
            default_ban_duration: default_ban_duration(),
        }
    }
}

fn default_accumulation_window() -> String {
    "30m".into()
}
fn default_threshold() -> u32 {
    100
}
fn default_ban_duration() -> String {
    "24h".into()
}
