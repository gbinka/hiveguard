use async_trait::async_trait;
use hiveguard_core::models::NormalizedEvent;

use crate::error::PluginResult;
use crate::traits::Plugin;

/// Batch of events ready to be shipped downstream. The host buffers events
/// and hands them off in chunks for amortised throughput.
pub type SiemBatch = Vec<NormalizedEvent>;

/// SIEM / log-shipping destination (Elastic / Splunk / Datadog / syslog
/// forwarder / S3 …).
///
/// Sinks own their own retry + on-disk buffer policy — the host hands them
/// batches and they are responsible for getting them to the wire.
#[async_trait]
pub trait SiemSinkPlugin: Plugin {
    /// Ship a batch. Implementations should be reentrant — the host may call
    /// `send` concurrently if `max_in_flight()` returns > 1.
    async fn send(&self, batch: SiemBatch) -> PluginResult<()>;

    /// Concurrency hint. Default 1 (strict ordering).
    fn max_in_flight(&self) -> usize {
        1
    }

    /// Force flush of any in-memory / on-disk buffer. Called during graceful
    /// shutdown. Default impl is a no-op.
    async fn flush(&self) -> PluginResult<()> {
        Ok(())
    }
}
