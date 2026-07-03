//! CTI enrichment aggregator.
//!
//! [`CtiEnricher`] holds a list of [`crate::provider::CtiProvider`]
//! implementations and, for each event IP, calls all of them in order,
//! returning the highest-severity [`CtiSignal`] found.

use std::net::{IpAddr, Ipv6Addr};

use crate::provider::CtiProvider;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Signal emitted by the CTI enricher when an IP is considered malicious.
#[derive(Debug, Clone)]
pub struct CtiSignal {
    /// Human-readable, machine-stable name of the provider (Prometheus label).
    pub provider: &'static str,
    /// Severity injected into the pipeline scoring engine (0–255).
    pub severity: u8,
    /// Raw confidence score from the provider (0–100).
    pub confidence_score: u8,
    /// Short human-readable description of the finding.
    pub description: String,
}

/// Per-enrich call statistics so the pipeline can update Prometheus counters
/// without knowing about provider internals.
#[derive(Debug, Default)]
pub struct EnrichStats {
    /// At least one provider returned a cached result.
    pub cache_hit: bool,
    /// At least one provider made a live API / DNS call.
    pub api_called: bool,
    /// At least one provider encountered an error.
    pub api_error: bool,
}

// ---------------------------------------------------------------------------
// CtiEnricher
// ---------------------------------------------------------------------------

/// Aggregates multiple CTI providers and returns the highest-severity signal.
///
/// Wrap in `Arc<CtiEnricher>` when sharing across async tasks.
pub struct CtiEnricher {
    providers: Vec<Box<dyn CtiProvider>>,
}

impl CtiEnricher {
    /// Create a new enricher from a list of providers.
    ///
    /// Pass an empty `Vec` to create a no-op enricher (useful for testing).
    pub fn new(providers: Vec<Box<dyn CtiProvider>>) -> Self {
        Self { providers }
    }

    /// Look up CTI reputation for `ip` across all configured providers.
    ///
    /// Returns `(Option<CtiSignal>, EnrichStats)`.  The signal is `None` when
    /// all providers are disabled, the IP is non-routable, or all checks came
    /// back below threshold.
    pub async fn enrich(&self, ip: IpAddr) -> (Option<CtiSignal>, EnrichStats) {
        // Skip private / loopback / link-local addresses
        if is_non_routable(ip) {
            return (None, EnrichStats::default());
        }

        let mut best: Option<CtiSignal> = None;
        let mut agg = EnrichStats::default();

        for provider in &self.providers {
            let (sig, stats) = provider.check(ip).await;

            if stats.cache_hit { agg.cache_hit = true; }
            if stats.api_called { agg.api_called = true; }
            if stats.api_error { agg.api_error = true; }

            if let Some(s) = sig {
                let is_better = best.as_ref().map_or(true, |b: &CtiSignal| s.severity > b.severity);
                if is_better {
                    best = Some(s);
                }
            }
        }

        (best, agg)
    }

    /// Flush all provider caches to disk (called on clean shutdown).
    pub async fn flush_caches(&self) {
        for provider in &self.providers {
            provider.flush_cache().await;
        }
    }
}

// ---------------------------------------------------------------------------
// Address helpers (pub(crate) so providers can reuse)
// ---------------------------------------------------------------------------

pub(crate) fn is_non_routable(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_unspecified()
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || is_ipv6_link_local(v6)
                || is_ipv6_unique_local(v6)
        }
    }
}

fn is_ipv6_link_local(v6: Ipv6Addr) -> bool {
    v6.segments()[0] & 0xffc0 == 0xfe80
}

fn is_ipv6_unique_local(v6: Ipv6Addr) -> bool {
    v6.segments()[0] & 0xfe00 == 0xfc00
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn non_routable_returns_none() {
        let enricher = CtiEnricher::new(vec![]);
        let (signal, stats) =
            enricher.enrich(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))).await;
        assert!(signal.is_none());
        assert!(!stats.cache_hit);
        assert!(!stats.api_called);
    }

    #[tokio::test]
    async fn no_providers_returns_none() {
        let enricher = CtiEnricher::new(vec![]);
        let (signal, stats) =
            enricher.enrich(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))).await;
        assert!(signal.is_none());
        assert!(!stats.api_called);
    }

    #[test]
    fn is_non_routable_loopback() {
        assert!(is_non_routable("127.0.0.1".parse().unwrap()));
        assert!(is_non_routable("::1".parse().unwrap()));
    }

    #[test]
    fn is_non_routable_private() {
        assert!(is_non_routable("192.168.1.1".parse().unwrap()));
        assert!(is_non_routable("10.0.0.1".parse().unwrap()));
        assert!(is_non_routable("172.16.0.1".parse().unwrap()));
    }

    #[test]
    fn public_ip_is_routable() {
        assert!(!is_non_routable("1.2.3.4".parse().unwrap()));
        assert!(!is_non_routable("8.8.8.8".parse().unwrap()));
    }
}

