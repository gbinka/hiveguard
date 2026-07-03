//! # hiveguard-config
//!
//! Configuration root for the new plugin-aware HiveGuard.
//!
//! Unlike the legacy `hiveguard-core::config` (2997 LOC monolith), this crate
//! only knows about **core** sections: node identity, scoring engine,
//! persistence, cluster, whitelist. Every plugin owns its own config section
//! under a single uniform `plugins:` list.
//!
//! ```yaml
//! node:
//!   name: web-prod-01
//!   data_dir: /var/lib/hiveguard
//!
//! scoring:
//!   accumulation_window: 30m
//!   ban_severity_threshold: 100
//!
//! plugins:
//!   - id: source.file.ssh
//!     config: { path: /var/log/auth.log }
//!   - id: notifier.slack
//!     config: { webhook_url: "${env:SLACK_WEBHOOK}" }
//! ```

pub mod node;
pub mod plugin_entry;
pub mod scoring;

use std::path::Path;

use serde::{Deserialize, Serialize};

pub use node::NodeConfig;
pub use plugin_entry::PluginEntry;
pub use scoring::ScoringConfig;

#[derive(Debug, Clone, thiserror::Error)]
pub enum ConfigError {
    #[error("io: {0}")]
    Io(String),
    #[error("yaml: {0}")]
    Yaml(String),
}

/// Root configuration object loaded from YAML.
///
/// All plugin-specific config lives inside [`PluginEntry::config`] as a
/// `serde_json::Value` so this crate does not need to be modified when a new
/// plugin is added.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HiveGuardConfig {
    pub node: NodeConfig,

    #[serde(default)]
    pub scoring: ScoringConfig,

    /// Ordered list of plugins to instantiate. Order matters only for UI
    /// plugins (first wins port conflicts) and detectors (signals are emitted
    /// in order). Sources / sinks / notifiers fan out concurrently.
    #[serde(default)]
    pub plugins: Vec<PluginEntry>,
}

impl HiveGuardConfig {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|e| ConfigError::Io(e.to_string()))?;
        serde_yaml::from_str(&text).map_err(|e| ConfigError::Yaml(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
node:
  name: test-node
  data_dir: /tmp/hg
scoring:
  ban_severity_threshold: 50
plugins:
  - id: source.file.ssh
    config:
      path: /var/log/auth.log
  - id: notifier.slack
    config:
      webhook_url: "https://example.com"
"#;

    #[test]
    fn parses_minimal_config() {
        let cfg: HiveGuardConfig = serde_yaml::from_str(SAMPLE).unwrap();
        assert_eq!(cfg.node.name, "test-node");
        assert_eq!(cfg.plugins.len(), 2);
        assert_eq!(cfg.plugins[0].id, "source.file.ssh");
        assert_eq!(cfg.scoring.ban_severity_threshold, 50);
    }

    #[test]
    fn missing_plugins_defaults_to_empty() {
        let cfg: HiveGuardConfig =
            serde_yaml::from_str("node:\n  name: x\n  data_dir: /tmp\n").unwrap();
        assert!(cfg.plugins.is_empty());
    }
}
