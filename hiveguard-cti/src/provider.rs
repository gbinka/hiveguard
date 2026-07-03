//! [`CtiProvider`] trait — unified interface for all CTI reputation providers.
//!
//! Each provider is responsible for:
//! - Its own in-memory caching (with per-provider TTLs).
//! - Returning `None` on transient errors rather than propagating them.
//! - Being cheaply shareable via `Arc`.

use std::net::IpAddr;

use async_trait::async_trait;

use crate::enricher::{CtiSignal, EnrichStats};

/// Unified interface implemented by every CTI reputation provider.
///
/// Implement this trait to add a new intelligence feed.  Providers are
/// collected into a [`crate::enricher::CtiEnricher`] which calls all of them
/// for each event and returns the highest-severity signal.
#[async_trait]
pub trait CtiProvider: Send + Sync {
    /// Stable, machine-readable name used as a Prometheus label.
    fn name(&self) -> &'static str;

    /// Look up the reputation of `ip`.
    ///
    /// Returns `(None, stats)` when the IP is below threshold, not found in
    /// this feed, or when a transient error occurred.
    async fn check(&self, ip: IpAddr) -> (Option<CtiSignal>, EnrichStats);

    /// Flush any in-memory state to persistent storage.
    ///
    /// The default implementation is a no-op.  Override for providers that
    /// maintain a disk-backed cache (e.g. AbuseIPDB bincode cache).
    async fn flush_cache(&self) {}
}
