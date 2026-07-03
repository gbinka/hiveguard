//! # hiveguard-host
//!
//! Plugin runtime for HiveGuard. Bridges the YAML config in
//! [`hiveguard_config`] to the descriptor registry exposed by
//! [`hiveguard_plugin_api`].
//!
//! ## Responsibilities
//!
//! 1. **Discovery** — iterate `inventory::iter::<PluginDescriptor>` and pair
//!    each `PluginEntry` from config with a static descriptor.
//! 2. **Validation** — JSON Schema check + `${env:...}` / `${file:...}`
//!    secret resolution.
//! 3. **Instantiation** — call the descriptor factory, hand the plugin a
//!    fresh [`PluginContext`] with a data dir under
//!    `<data_dir>/plugins/<id>/`.
//! 4. **Lifecycle** — run plugins to completion under a shared
//!    [`CancellationToken`]; restart `Failed` plugins with exponential
//!    back-off; collect health.
//! 5. **Dispatch** — fan out alerts to notifiers, events to sinks, etc.
//!
//! Phase 0 ships skeletons for these modules; full implementations land in
//! Phase 1 (notifiers) onward.

pub mod dispatcher;
pub mod lifecycle;
pub mod loader;
pub mod metrics;

pub use dispatcher::{
    AlertDispatcher, AlertDispatcherConfig, AlertDispatcherHandle,
};
pub use lifecycle::{Lifecycle, RestartPolicy};
pub use loader::{InstantiatedPlugin, LoadedPlugins, Loader, LoaderError, PluginInstance, ResolvedPlugin};
