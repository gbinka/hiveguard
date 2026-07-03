use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Node-level configuration: identity, data directory, optional cluster
/// gossip listen address.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    pub name: String,
    pub data_dir: PathBuf,

    /// Cluster gossip listen, e.g. `"0.0.0.0:7946"`. Empty / missing = standalone.
    #[serde(default)]
    pub listen_gossip: Option<String>,

    /// Seed peers for SWIM membership.
    #[serde(default)]
    pub seeds: Vec<String>,
}
