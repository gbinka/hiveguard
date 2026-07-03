//! Tor exit-node CTI provider.
//!
//! Downloads the Tor Project's bulk exit list from
//! `https://check.torproject.org/torbulkexitlist` and keeps it in memory.
//! The list is refreshed periodically (default: every hour).
//!
//! Tor exit nodes are assigned severity 40 — Tor itself is not an attack, but
//! it raises the scoring-engine score for other concurrent detections.

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::RwLock;
use tracing::{debug, warn};

use crate::enricher::{CtiSignal, EnrichStats};
use crate::provider::CtiProvider;

const TOR_BULK_EXIT_URL: &str = "https://check.torproject.org/torbulkexitlist";
/// Severity for Tor exit nodes — low by itself, raises overall score.
const TOR_SEVERITY: u8 = 40;
/// High confidence that the IP *is* a Tor exit node.
const TOR_CONFIDENCE: u8 = 95;

// ---------------------------------------------------------------------------
// TorProvider
// ---------------------------------------------------------------------------

/// Tor exit-node list provider with periodic refresh.
pub struct TorProvider {
    exit_nodes: Arc<RwLock<HashSet<IpAddr>>>,
}

impl TorProvider {
    /// Create and start the provider.
    ///
    /// Performs an initial fetch on construction; if it fails the list is
    /// empty until the next refresh.  `refresh_interval` controls how often
    /// the list is re-downloaded (default: 1 hour).
    pub async fn new(client: reqwest::Client, refresh_interval: Duration) -> Self {
        let exit_nodes: Arc<RwLock<HashSet<IpAddr>>> =
            Arc::new(RwLock::new(HashSet::new()));

        // Initial load
        match fetch_exit_list(&client).await {
            Ok(nodes) => {
                let count = nodes.len();
                *exit_nodes.write().await = nodes;
                debug!(count, "Tor exit node list loaded");
            }
            Err(e) => warn!(error = %e, "Initial Tor exit node fetch failed — list empty"),
        }

        // Background refresh task
        let nodes_bg = exit_nodes.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(refresh_interval);
            ticker.tick().await; // skip initial tick (we already loaded above)
            loop {
                ticker.tick().await;
                match fetch_exit_list(&client).await {
                    Ok(new_nodes) => {
                        let count = new_nodes.len();
                        *nodes_bg.write().await = new_nodes;
                        debug!(count, "Tor exit node list refreshed");
                    }
                    Err(e) => warn!(error = %e, "Tor exit node list refresh failed"),
                }
            }
        });

        Self { exit_nodes }
    }
}

#[async_trait]
impl CtiProvider for TorProvider {
    fn name(&self) -> &'static str {
        "tor"
    }

    async fn check(&self, ip: IpAddr) -> (Option<CtiSignal>, EnrichStats) {
        // In-memory set lookup is O(1) — always a "cache hit".
        let stats = EnrichStats { cache_hit: true, ..Default::default() };

        if self.exit_nodes.read().await.contains(&ip) {
            let sig = CtiSignal {
                provider: "tor",
                severity: TOR_SEVERITY,
                confidence_score: TOR_CONFIDENCE,
                description: "Tor exit node".to_string(),
            };
            return (Some(sig), stats);
        }

        (None, stats)
    }
}

// ---------------------------------------------------------------------------
// HTTP fetch helper
// ---------------------------------------------------------------------------

async fn fetch_exit_list(client: &reqwest::Client) -> Result<HashSet<IpAddr>, reqwest::Error> {
    let text = client
        .get(TOR_BULK_EXIT_URL)
        .timeout(Duration::from_secs(30))
        .send()
        .await?
        .text()
        .await?;

    let nodes: HashSet<IpAddr> = text
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
        .filter_map(|l| l.trim().parse().ok())
        .collect();

    Ok(nodes)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_exit_list_line() {
        let line = "185.220.101.1";
        let ip: IpAddr = line.parse().unwrap();
        assert!(matches!(ip, IpAddr::V4(_)));
    }

    #[test]
    fn skip_comment_lines() {
        // Lines beginning with '#' or empty lines should be ignored
        let text = "# comment\n\n185.220.101.1\n";
        let nodes: HashSet<IpAddr> = text
            .lines()
            .filter(|l| !l.starts_with('#') && !l.is_empty())
            .filter_map(|l| l.trim().parse().ok())
            .collect();
        assert_eq!(nodes.len(), 1);
    }
}
