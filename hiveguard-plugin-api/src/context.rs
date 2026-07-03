use std::path::PathBuf;
use std::sync::Arc;

use crate::secrets::SecretResolver;

/// Per-plugin runtime context handed to `Plugin::init()`.
///
/// Provides everything a plugin needs from the host without coupling the
/// plugin to a concrete host implementation:
///
/// * `plugin_id`     — the descriptor id (e.g. `"notifier.slack"`).
/// * `data_dir`      — writable directory unique to this plugin instance.
/// * `secrets`       — resolver for `${env:VAR}` / `${file:/path}` strings.
/// * `metrics`       — handle for registering per-plugin Prometheus metrics.
/// * `shutdown`      — cancellation token; long-running plugins must respect it.
#[derive(Clone)]
pub struct PluginContext {
    pub plugin_id: String,
    pub data_dir: PathBuf,
    pub secrets: Arc<SecretResolver>,
    pub metrics: PluginMetrics,
    pub shutdown: tokio_util::sync::CancellationToken,
}

impl PluginContext {
    /// Construct a context. Normally only the host calls this; tests can use it
    /// to instantiate plugins in isolation.
    pub fn new(
        plugin_id: impl Into<String>,
        data_dir: PathBuf,
        secrets: Arc<SecretResolver>,
        metrics: PluginMetrics,
        shutdown: tokio_util::sync::CancellationToken,
    ) -> Self {
        Self {
            plugin_id: plugin_id.into(),
            data_dir,
            secrets,
            metrics,
            shutdown,
        }
    }
}

/// Handle that lets a plugin publish Prometheus metrics under a stable prefix.
///
/// All metrics created via this handle are registered with prefix
/// `hiveguard_plugin_{plugin_id}_*` by the host, so plugin authors never
/// pick conflicting names.
#[derive(Clone)]
pub struct PluginMetrics {
    pub registry: Arc<parking_lot_compat::RegistryHandle>,
    pub plugin_id: String,
}

// We expose a thin newtype to keep the public Prometheus client out of the
// public API surface — the host can swap implementations without breaking
// plugins.
pub mod parking_lot_compat {
    use std::sync::Mutex;

    use prometheus_client::registry::Registry;

    /// Thread-safe handle around the Prometheus registry the host owns.
    ///
    /// Plugins acquire the inner `Registry` via `with_registry` to register
    /// counters / gauges / histograms.
    pub struct RegistryHandle {
        inner: Mutex<Registry>,
    }

    impl RegistryHandle {
        pub fn new(registry: Registry) -> Self {
            Self {
                inner: Mutex::new(registry),
            }
        }

        pub fn with_registry<F, R>(&self, f: F) -> R
        where
            F: FnOnce(&mut Registry) -> R,
        {
            let mut guard = self.inner.lock().expect("registry mutex poisoned");
            f(&mut guard)
        }
    }

    impl Default for RegistryHandle {
        fn default() -> Self {
            Self::new(Registry::default())
        }
    }
}
