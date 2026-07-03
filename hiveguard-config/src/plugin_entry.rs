use serde::{Deserialize, Serialize};

/// One entry from the `plugins:` list.
///
/// The host matches `id` against the static registry, validates `config`
/// against the plugin's JSON Schema, then hands the value to the factory.
/// Unknown ids cause a config error unless `optional` is `true`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginEntry {
    /// Stable plugin id, e.g. `"notifier.slack"`.
    pub id: String,

    /// Optional human-readable instance name when multiple instances of the
    /// same plugin are configured (`"slack-ops"`, `"slack-security"`).
    #[serde(default)]
    pub name: Option<String>,

    /// Plugin-specific configuration. Opaque to this crate.
    #[serde(default = "default_config")]
    pub config: serde_json::Value,

    /// If `true`, missing plugin (not linked into the binary) is a warning,
    /// not an error. Lets users keep a single config across distributions.
    #[serde(default)]
    pub optional: bool,
}

fn default_config() -> serde_json::Value {
    serde_json::Value::Object(serde_json::Map::new())
}
