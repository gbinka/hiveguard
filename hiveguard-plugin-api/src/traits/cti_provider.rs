use std::net::IpAddr;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::error::PluginResult;
use crate::traits::Plugin;

/// Provider verdict for a single IP lookup.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CtiVerdict {
    /// Source identifier (e.g. `"abuseipdb"`, `"spamhaus"`).
    pub provider: String,
    /// 0–100 confidence that the IP is malicious. `None` = no opinion.
    pub confidence: Option<u8>,
    /// Human-readable explanation, e.g. `"AbuseIPDB score=87"`.
    pub reason: Option<String>,
    /// True if this verdict alone is sufficient to ban.
    pub recommend_ban: bool,
}

/// Cyber-Threat-Intelligence reputation source.
///
/// Plugins of this kind enrich pipeline events with external reputation data
/// (AbuseIPDB, Spamhaus, Tor exit list, AlienVault OTX, GeoIP, …).
#[async_trait]
pub trait CtiProviderPlugin: Plugin {
    /// Look up `ip`. Plugins are expected to handle their own caching,
    /// timeouts and rate limits. Returning `Ok(None)` means "no information".
    async fn lookup(&self, ip: IpAddr) -> PluginResult<Option<CtiVerdict>>;
}
