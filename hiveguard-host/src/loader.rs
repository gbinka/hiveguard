use std::path::PathBuf;
use std::sync::Arc;

use thiserror::Error;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use hiveguard_config::{HiveGuardConfig, PluginEntry};
use hiveguard_plugin_api::context::parking_lot_compat::RegistryHandle;
use hiveguard_plugin_api::context::{PluginContext, PluginMetrics};
use hiveguard_plugin_api::manifest::PluginKind;
use hiveguard_plugin_api::registry::{find_descriptor, PluginDescriptor, PluginFactory, API_VERSION};
use hiveguard_plugin_api::schema::validate_against_schema;
use hiveguard_plugin_api::secrets::SecretResolver;

#[derive(Debug, Error)]
pub enum LoaderError {
    #[error("plugin `{0}` not linked into this binary — recompile with the matching feature")]
    UnknownPlugin(String),

    #[error("plugin `{id}` requires api_version {required}, host provides {host}")]
    ApiVersionMismatch {
        id: String,
        required: u32,
        host: u32,
    },

    #[error("config for plugin `{id}` invalid: {msg}")]
    InvalidConfig { id: String, msg: String },

    #[error("plugin `{id}` failed to initialise: {msg}")]
    InitFailure { id: String, msg: String },
}

/// One instantiated plugin paired with its descriptor. The host keeps
/// these in a vector and dispatches into them via downcasted accessors
/// (added in later phases).
pub struct InstantiatedPlugin {
    pub descriptor: &'static PluginDescriptor,
    pub instance: PluginInstance,
}

/// Erased instance — concrete trait object stored by category. Phase 1+
/// extends this enum with category-specific calling code.
pub enum PluginInstance {
    LogSource(Box<dyn hiveguard_plugin_api::LogSourcePlugin>),
    Notifier(Box<dyn hiveguard_plugin_api::NotifierPlugin>),
    Enforcer(Box<dyn hiveguard_plugin_api::EnforcerPlugin>),
    CtiProvider(Box<dyn hiveguard_plugin_api::CtiProviderPlugin>),
    SiemSink(Box<dyn hiveguard_plugin_api::SiemSinkPlugin>),
    Detector(Box<dyn hiveguard_plugin_api::DetectorPlugin>),
    ScoringEngine(Box<dyn hiveguard_plugin_api::ScoringEnginePlugin>),
    UiServer(Box<dyn hiveguard_plugin_api::UiServerPlugin>),
}

impl PluginInstance {
    pub fn kind(&self) -> PluginKind {
        match self {
            PluginInstance::LogSource(_) => PluginKind::LogSource,
            PluginInstance::Notifier(_) => PluginKind::Notifier,
            PluginInstance::Enforcer(_) => PluginKind::Enforcer,
            PluginInstance::CtiProvider(_) => PluginKind::CtiProvider,
            PluginInstance::SiemSink(_) => PluginKind::SiemSink,
            PluginInstance::Detector(_) => PluginKind::Detector,
            PluginInstance::ScoringEngine(_) => PluginKind::ScoringEngine,
            PluginInstance::UiServer(_) => PluginKind::UiServer,
        }
    }
}

/// Bulk of categorized plugin instances. Returned by [`Loader::load_categorized`]
/// after both `resolve` and `instantiate` succeed for every entry.
#[derive(Default)]
pub struct LoadedPlugins {
    pub log_sources: Vec<Box<dyn hiveguard_plugin_api::LogSourcePlugin>>,
    pub notifiers: Vec<Box<dyn hiveguard_plugin_api::NotifierPlugin>>,
    pub enforcers: Vec<Box<dyn hiveguard_plugin_api::EnforcerPlugin>>,
    pub cti_providers: Vec<Box<dyn hiveguard_plugin_api::CtiProviderPlugin>>,
    pub siem_sinks: Vec<Box<dyn hiveguard_plugin_api::SiemSinkPlugin>>,
    pub detectors: Vec<Box<dyn hiveguard_plugin_api::DetectorPlugin>>,
    pub scoring_engines: Vec<Box<dyn hiveguard_plugin_api::ScoringEnginePlugin>>,
    pub ui_servers: Vec<Box<dyn hiveguard_plugin_api::UiServerPlugin>>,
}

impl LoadedPlugins {
    /// Total number of instantiated plugins.
    pub fn len(&self) -> usize {
        self.log_sources.len()
            + self.notifiers.len()
            + self.enforcers.len()
            + self.cti_providers.len()
            + self.siem_sinks.len()
            + self.detectors.len()
            + self.scoring_engines.len()
            + self.ui_servers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Plugin loader — resolves config entries against the static registry,
/// validates schemas, and instantiates plugins.
pub struct Loader {
    secrets: Arc<SecretResolver>,
    data_dir: PathBuf,
    registry: Arc<RegistryHandle>,
    shutdown: CancellationToken,
}

impl Loader {
    /// Construct a loader. `data_dir` is the daemon's root data directory;
    /// per-plugin context will receive `data_dir/plugins/<id>/`.
    pub fn new(
        secrets: Arc<SecretResolver>,
        data_dir: PathBuf,
        registry: Arc<RegistryHandle>,
        shutdown: CancellationToken,
    ) -> Self {
        Self {
            secrets,
            data_dir,
            registry,
            shutdown,
        }
    }

    /// Convenience constructor for tests / Phase-0 callers that only need
    /// resolution and don't intend to instantiate.
    pub fn resolve_only(secrets: Arc<SecretResolver>) -> Self {
        Self {
            secrets,
            data_dir: PathBuf::from("/tmp"),
            registry: Arc::new(RegistryHandle::default()),
            shutdown: CancellationToken::new(),
        }
    }

    /// Resolve every plugin entry in `cfg` to a descriptor, validating
    /// schemas and api versions along the way. Returns the descriptors in
    /// config order, dropping (with a warning) any entry marked `optional`
    /// whose plugin isn't linked in.
    ///
    /// Instantiation itself is intentionally deferred to a later call —
    /// validating first lets the host surface every config error in one go
    /// rather than failing on the first plugin.
    pub fn resolve<'a>(
        &self,
        cfg: &'a HiveGuardConfig,
    ) -> Result<Vec<ResolvedPlugin<'a>>, LoaderError> {
        let mut out = Vec::with_capacity(cfg.plugins.len());

        for entry in &cfg.plugins {
            match self.resolve_one(entry)? {
                Some(r) => out.push(r),
                None => continue,
            }
        }

        info!(
            requested = cfg.plugins.len(),
            resolved = out.len(),
            "plugin resolution complete"
        );
        Ok(out)
    }

    fn resolve_one<'a>(
        &self,
        entry: &'a PluginEntry,
    ) -> Result<Option<ResolvedPlugin<'a>>, LoaderError> {
        let descriptor = match find_descriptor(&entry.id) {
            Some(d) => d,
            None if entry.optional => {
                warn!(plugin = entry.id, "optional plugin not linked — skipping");
                return Ok(None);
            }
            None => return Err(LoaderError::UnknownPlugin(entry.id.clone())),
        };

        if descriptor.api_version != API_VERSION {
            return Err(LoaderError::ApiVersionMismatch {
                id: entry.id.clone(),
                required: descriptor.api_version,
                host: API_VERSION,
            });
        }

        let resolved_config = self
            .resolve_secrets(&entry.config)
            .map_err(|msg| LoaderError::InvalidConfig {
                id: entry.id.clone(),
                msg,
            })?;

        validate_against_schema(descriptor.config_schema, &resolved_config).map_err(|e| {
            LoaderError::InvalidConfig {
                id: entry.id.clone(),
                msg: e.to_string(),
            }
        })?;

        debug!(plugin = entry.id, kind = ?descriptor.kind, "plugin descriptor resolved");
        Ok(Some(ResolvedPlugin {
            entry,
            descriptor,
            resolved_config,
        }))
    }

    /// Resolve + instantiate every plugin in `cfg`, categorised by kind.
    ///
    /// This is the one-shot entry point most callers want. Returns
    /// [`LoadedPlugins`] with each kind in a separate vec. On any failure,
    /// every plugin instantiated so far is dropped (their `Drop` may run a
    /// `shutdown` task; see individual plugin documentation).
    pub async fn load_categorized(
        &self,
        cfg: &HiveGuardConfig,
    ) -> Result<LoadedPlugins, LoaderError> {
        let resolved = self.resolve(cfg)?;
        let mut out = LoadedPlugins::default();

        for rp in resolved {
            let ctx = self.build_context(rp.descriptor)?;
            self.instantiate_into(rp.descriptor, ctx, rp.resolved_config, &mut out)
                .await?;
        }

        info!(loaded = out.len(), "plugin instantiation complete");
        Ok(out)
    }

    /// Build a [`PluginContext`] for one plugin. Each plugin gets its own
    /// subdirectory under `<data_dir>/plugins/<id>/`, created on demand.
    fn build_context(
        &self,
        descriptor: &PluginDescriptor,
    ) -> Result<PluginContext, LoaderError> {
        let plugin_data_dir = self.data_dir.join("plugins").join(descriptor.id);
        std::fs::create_dir_all(&plugin_data_dir).map_err(|e| LoaderError::InitFailure {
            id: descriptor.id.to_owned(),
            msg: format!("failed to create data_dir: {e}"),
        })?;

        Ok(PluginContext::new(
            descriptor.id.to_owned(),
            plugin_data_dir,
            self.secrets.clone(),
            PluginMetrics {
                registry: self.registry.clone(),
                plugin_id: descriptor.id.to_owned(),
            },
            self.shutdown.clone(),
        ))
    }

    /// Invoke the descriptor's factory and append the result to `out`.
    /// The factory variant is matched against `descriptor.kind` defensively —
    /// a mismatch here means a plugin author broke the `inventory::submit!`
    /// contract and we fail loudly.
    async fn instantiate_into(
        &self,
        descriptor: &PluginDescriptor,
        ctx: PluginContext,
        cfg: serde_json::Value,
        out: &mut LoadedPlugins,
    ) -> Result<(), LoaderError> {
        let id = descriptor.id.to_owned();
        let map_init_err = |msg: String| LoaderError::InitFailure { id: id.clone(), msg };

        match &descriptor.factory {
            PluginFactory::LogSource(f) => {
                let plugin = f(ctx, cfg).await.map_err(|e| map_init_err(e.to_string()))?;
                out.log_sources.push(plugin);
            }
            PluginFactory::Notifier(f) => {
                let plugin = f(ctx, cfg).await.map_err(|e| map_init_err(e.to_string()))?;
                out.notifiers.push(plugin);
            }
            PluginFactory::Enforcer(f) => {
                let plugin = f(ctx, cfg).await.map_err(|e| map_init_err(e.to_string()))?;
                out.enforcers.push(plugin);
            }
            PluginFactory::CtiProvider(f) => {
                let plugin = f(ctx, cfg).await.map_err(|e| map_init_err(e.to_string()))?;
                out.cti_providers.push(plugin);
            }
            PluginFactory::SiemSink(f) => {
                let plugin = f(ctx, cfg).await.map_err(|e| map_init_err(e.to_string()))?;
                out.siem_sinks.push(plugin);
            }
            PluginFactory::Detector(f) => {
                let plugin = f(ctx, cfg).await.map_err(|e| map_init_err(e.to_string()))?;
                out.detectors.push(plugin);
            }
            PluginFactory::ScoringEngine(f) => {
                let plugin = f(ctx, cfg).await.map_err(|e| map_init_err(e.to_string()))?;
                out.scoring_engines.push(plugin);
            }
            PluginFactory::UiServer(f) => {
                let plugin = f(ctx, cfg).await.map_err(|e| map_init_err(e.to_string()))?;
                out.ui_servers.push(plugin);
            }
        }
        Ok(())
    }

    /// Recursively walk a JSON value and resolve every `${...}` placeholder
    /// found in string leaves.
    fn resolve_secrets(&self, value: &serde_json::Value) -> Result<serde_json::Value, String> {
        match value {
            serde_json::Value::String(s) => self
                .secrets
                .resolve(s)
                .map(serde_json::Value::String)
                .map_err(|e| e.to_string()),
            serde_json::Value::Array(arr) => arr
                .iter()
                .map(|v| self.resolve_secrets(v))
                .collect::<Result<Vec<_>, _>>()
                .map(serde_json::Value::Array),
            serde_json::Value::Object(map) => {
                let mut out = serde_json::Map::with_capacity(map.len());
                for (k, v) in map {
                    out.insert(k.clone(), self.resolve_secrets(v)?);
                }
                Ok(serde_json::Value::Object(out))
            }
            other => Ok(other.clone()),
        }
    }
}

/// Successfully resolved (but not yet instantiated) plugin entry.
pub struct ResolvedPlugin<'a> {
    pub entry: &'a PluginEntry,
    pub descriptor: &'static PluginDescriptor,
    pub resolved_config: serde_json::Value,
}

#[cfg(test)]
mod tests {
    use super::*;
    use hiveguard_config::{NodeConfig, PluginEntry, ScoringConfig};

    fn empty_cfg() -> HiveGuardConfig {
        HiveGuardConfig {
            node: NodeConfig {
                name: "t".into(),
                data_dir: std::path::PathBuf::from("/tmp"),
                listen_gossip: None,
                seeds: vec![],
            },
            scoring: ScoringConfig::default(),
            plugins: vec![],
        }
    }

    #[test]
    fn empty_config_resolves_empty_list() {
        let loader = Loader::resolve_only(Arc::new(SecretResolver::new()));
        let cfg = empty_cfg();
        let plugins = loader.resolve(&cfg).unwrap();
        assert!(plugins.is_empty());
    }

    #[test]
    fn unknown_required_plugin_errors() {
        let loader = Loader::resolve_only(Arc::new(SecretResolver::new()));
        let mut cfg = empty_cfg();
        cfg.plugins.push(PluginEntry {
            id: "notifier.nonexistent".into(),
            name: None,
            config: serde_json::json!({}),
            optional: false,
        });
        match loader.resolve(&cfg) {
            Err(LoaderError::UnknownPlugin(id)) => assert_eq!(id, "notifier.nonexistent"),
            Err(other) => panic!("expected UnknownPlugin, got {other:?}"),
            Ok(_) => panic!("expected error, got Ok"),
        }
    }

    #[test]
    fn unknown_optional_plugin_is_skipped() {
        let loader = Loader::resolve_only(Arc::new(SecretResolver::new()));
        let mut cfg = empty_cfg();
        cfg.plugins.push(PluginEntry {
            id: "notifier.nonexistent".into(),
            name: None,
            config: serde_json::json!({}),
            optional: true,
        });
        let resolved = loader.resolve(&cfg).unwrap();
        assert!(resolved.is_empty());
    }

    #[tokio::test]
    async fn load_categorized_empty() {
        let loader = Loader::new(
            Arc::new(SecretResolver::new()),
            std::env::temp_dir(),
            Arc::new(RegistryHandle::default()),
            CancellationToken::new(),
        );
        let cfg = empty_cfg();
        let loaded = loader.load_categorized(&cfg).await.unwrap();
        assert_eq!(loaded.len(), 0);
        assert!(loaded.is_empty());
    }
}
