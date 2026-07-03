use std::sync::Arc;

use hiveguard_plugin_api::context::parking_lot_compat::RegistryHandle;
use hiveguard_plugin_api::context::PluginMetrics;

/// Build a [`PluginMetrics`] handle for the given `plugin_id` backed by the
/// shared host registry.
///
/// All metrics created via the returned handle should be prefixed
/// `hiveguard_plugin_{plugin_id}_*` by convention. The host enforces this
/// indirectly by handing each plugin its own [`PluginMetrics`] — the
/// `plugin_id` is part of the struct so plugin authors can build the prefix
/// themselves when registering metrics.
pub fn build_plugin_metrics(registry: Arc<RegistryHandle>, plugin_id: String) -> PluginMetrics {
    PluginMetrics {
        registry,
        plugin_id,
    }
}
