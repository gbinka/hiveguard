//! Supervisor for plugin lifecycle. Spawns long-running plugins (log sources,
//! UI servers) into Tokio tasks and tracks them so the daemon can wait on
//! them during graceful shutdown.
//!
//! In INT phase this is intentionally minimalist — no restart-with-backoff
//! (Lifecycle policy lives in `hiveguard-host` but is not wired up here yet).
//! Subsequent integration passes will move plugins under full supervision
//! with health checks, restarts, and metrics.

use std::sync::Arc;

use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

use hiveguard_core::models::NormalizedEvent;
use hiveguard_plugin_api::{LogSourcePlugin, NotifierPlugin};

/// Spawn one log source plugin into its own Tokio task. The returned
/// `JoinHandle` resolves when the plugin's `run` loop exits.
pub fn spawn_log_source(
    mut plugin: Box<dyn LogSourcePlugin>,
    sink: tokio::sync::mpsc::Sender<NormalizedEvent>,
    shutdown: CancellationToken,
) -> JoinHandle<()> {
    let plugin_id = plugin.manifest().id.to_owned();
    tokio::spawn(async move {
        info!(plugin = %plugin_id, "log source starting");
        if let Err(e) = plugin.run(sink, shutdown).await {
            error!(plugin = %plugin_id, error = %e, "log source exited with error");
        } else {
            info!(plugin = %plugin_id, "log source stopped cleanly");
        }
    })
}

/// Wrap a vector of notifier plugins behind an `Arc<Mutex<...>>` so the
/// daemon's existing alert dispatcher (legacy `alert_manager.rs`) can pull
/// from it without taking ownership.
///
/// Returns `None` when the input is empty so callers can short-circuit
/// alert plumbing.
pub fn share_notifiers(
    notifiers: Vec<Box<dyn NotifierPlugin>>,
) -> Option<Arc<Mutex<Vec<Box<dyn NotifierPlugin>>>>> {
    if notifiers.is_empty() {
        None
    } else {
        Some(Arc::new(Mutex::new(notifiers)))
    }
}
