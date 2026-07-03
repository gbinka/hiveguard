//! AlienVault OTX (Open Threat Exchange) CTI provider.
//!
//! Uses the OTX API v1 `indicators/IPv4/{ip}/reputation` endpoint to look up
//! reputation information.  Results are cached for 12 hours.
//!
//! Requires a free OTX API key from `https://otx.alienvault.com/`.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use reqwest::Client;
use serde::Deserialize;
use tokio::sync::Mutex;
use tracing::warn;

use crate::enricher::{CtiSignal, EnrichStats};
use crate::provider::CtiProvider;

const CACHE_TTL: Duration = Duration::from_secs(12 * 3600); // 12 hours
const OTX_BASE: &str = "https://otx.alienvault.com";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

// ---------------------------------------------------------------------------
// API response types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct OtxResponse {
    #[serde(default)]
    reputation: Option<OtxReputation>,
    #[serde(default)]
    pulse_info: Option<OtxPulseInfo>,
}

#[derive(Deserialize)]
struct OtxReputation {
    threat_score: f32,
}

#[derive(Deserialize)]
struct OtxPulseInfo {
    count: u32,
}

// ---------------------------------------------------------------------------
// OtxProvider
// ---------------------------------------------------------------------------

/// Cached per-IP result.
#[derive(Clone)]
struct OtxHit {
    threat_score: f32,
    pulse_count: u32,
}

/// AlienVault OTX reputation provider.
pub struct OtxProvider {
    client: Client,
    api_key: String,
    /// Minimum number of OTX pulses to emit a signal.
    min_pulse_count: u32,
    cache: Mutex<HashMap<IpAddr, (Option<OtxHit>, Instant)>>,
}

impl OtxProvider {
    pub fn new(api_key: String, min_pulse_count: u32) -> Self {
        Self {
            client: Client::new(),
            api_key,
            min_pulse_count,
            cache: Mutex::new(HashMap::new()),
        }
    }

    async fn fetch(&self, ip: IpAddr) -> Result<Option<OtxHit>, reqwest::Error> {
        let url = format!("{OTX_BASE}/api/v1/indicators/IPv4/{ip}/reputation");
        let resp: OtxResponse = self
            .client
            .get(&url)
            .header("X-OTX-API-KEY", &self.api_key)
            .timeout(REQUEST_TIMEOUT)
            .send()
            .await?
            .json()
            .await?;

        let score = resp.reputation.map(|r| r.threat_score).unwrap_or(0.0);
        let pulses = resp.pulse_info.map(|p| p.count).unwrap_or(0);

        if pulses >= self.min_pulse_count || score > 30.0 {
            Ok(Some(OtxHit { threat_score: score, pulse_count: pulses }))
        } else {
            Ok(None)
        }
    }

    fn hit_to_signal(hit: &OtxHit) -> CtiSignal {
        // Normalise OTX threat_score (0–100) with same formula as AbuseIPDB.
        let score_u8 = hit.threat_score.clamp(0.0, 100.0) as u8;
        let severity = 55u8.saturating_add(score_u8 / 4);
        CtiSignal {
            provider: "otx",
            severity,
            confidence_score: score_u8,
            description: format!(
                "OTX: threat_score={:.1}, pulses={}",
                hit.threat_score, hit.pulse_count
            ),
        }
    }
}

#[async_trait]
impl CtiProvider for OtxProvider {
    fn name(&self) -> &'static str {
        "otx"
    }

    async fn check(&self, ip: IpAddr) -> (Option<CtiSignal>, EnrichStats) {
        let mut stats = EnrichStats::default();

        // --- Cache lookup ---
        {
            let cache = self.cache.lock().await;
            if let Some((hit, fetched_at)) = cache.get(&ip) {
                if fetched_at.elapsed() < CACHE_TTL {
                    stats.cache_hit = true;
                    let sig = hit.as_ref().map(Self::hit_to_signal);
                    return (sig, stats);
                }
            }
        }

        // --- API call ---
        stats.api_called = true;
        match self.fetch(ip).await {
            Ok(hit) => {
                let sig = hit.as_ref().map(Self::hit_to_signal);
                self.cache.lock().await.insert(ip, (hit, Instant::now()));
                (sig, stats)
            }
            Err(e) => {
                warn!(ip = %ip, error = %e, "OTX reputation lookup failed");
                stats.api_error = true;
                (None, stats)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hit_to_signal_severity_formula() {
        let hit = OtxHit { threat_score: 80.0, pulse_count: 5 };
        let sig = OtxProvider::hit_to_signal(&hit);
        // 55 + 80/4 = 55 + 20 = 75
        assert_eq!(sig.severity, 75);
        assert_eq!(sig.confidence_score, 80);
        assert_eq!(sig.provider, "otx");
    }

    #[test]
    fn hit_to_signal_low_score() {
        let hit = OtxHit { threat_score: 0.0, pulse_count: 0 };
        let sig = OtxProvider::hit_to_signal(&hit);
        assert_eq!(sig.severity, 55);
        assert_eq!(sig.confidence_score, 0);
    }
}
