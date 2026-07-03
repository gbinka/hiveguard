use async_trait::async_trait;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use hiveguard_core::models::NormalizedEvent;

use crate::error::PluginResult;
use crate::traits::Plugin;

/// Channel handed to a log source for emitting events into the pipeline.
///
/// Plugins should treat back-pressure as a normal signal — `send` may block
/// when the pipeline is saturated. Plugins must NOT spawn background tasks
/// that outlive `run()`; respect the [`CancellationToken`] given to them.
pub type EventSink = mpsc::Sender<NormalizedEvent>;

/// Source that produces [`NormalizedEvent`]s — log files, syslog sockets,
/// message queue consumers, etc.
///
/// Lifecycle: the host calls `init` once, then `run` exactly once. `run` is
/// expected to loop until the cancellation token fires, at which point it
/// returns `Ok(())`. Errors returned from `run` cause the host to mark the
/// plugin as `Failed` and (depending on policy) restart it with backoff.
#[async_trait]
pub trait LogSourcePlugin: Plugin {
    /// Blocking driver loop. Runs until `shutdown` fires or an unrecoverable
    /// error occurs.
    async fn run(&mut self, sink: EventSink, shutdown: CancellationToken) -> PluginResult<()>;
}
