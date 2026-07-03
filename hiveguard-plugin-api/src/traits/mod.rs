//! Plugin traits — one per category. Every concrete plugin implements
//! [`Plugin`] (lifecycle base) plus exactly one of the specialised traits
//! below.

pub mod cti_provider;
pub mod detector;
pub mod enforcer;
pub mod log_source;
pub mod notifier;
pub mod scoring_engine;
pub mod siem_sink;
pub mod ui_server;

use async_trait::async_trait;

use crate::error::PluginResult;
use crate::manifest::{HealthState, PluginManifest};

/// Lifecycle methods common to every plugin category.
///
/// The host calls `init` exactly once, after validating the config against
/// the JSON Schema declared in the [`crate::registry::PluginDescriptor`].
/// `shutdown` is called during graceful shutdown; plugins must drain
/// outstanding work and release resources within a reasonable timeout
/// (the host enforces a deadline).
#[async_trait]
pub trait Plugin: Send + Sync + 'static {
    /// Static self-description. Returned by reference because manifests are
    /// typically `'static` data populated at compile time.
    fn manifest(&self) -> &PluginManifest;

    /// Apply runtime configuration. Called once, before any category-specific
    /// methods. Plugins should fail fast here if config is invalid beyond what
    /// JSON Schema can express (e.g. live connectivity check to a webhook).
    async fn init(&mut self, cfg: serde_json::Value) -> PluginResult<()>;

    /// Graceful shutdown. Default impl is a no-op — override if you have
    /// background tasks, open connections, or buffered state to flush.
    async fn shutdown(&mut self) -> PluginResult<()> {
        Ok(())
    }

    /// Cheap, non-blocking health probe. Polled by the host periodically and
    /// surfaced on `GET /api/v1/plugins`. Default impl returns `Healthy`.
    fn health(&self) -> HealthState {
        HealthState::Healthy
    }
}
