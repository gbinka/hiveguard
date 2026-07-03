//! AbuseIPDB API v2 client.
//!
//! Checks IP reputation via <https://www.abuseipdb.com/api.html>.
//! Rate limit headers are respected; the caller is responsible for caching.

use std::net::IpAddr;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Base URL for the AbuseIPDB v2 API.
const API_BASE: &str = "https://api.abuseipdb.com/api/v2";

/// Default request timeout.
const TIMEOUT_SECS: u64 = 3;

/// Number of retry attempts on transient failures (5xx, timeout).
const MAX_RETRIES: u32 = 2;

/// Base backoff delay between retries.
const RETRY_BACKOFF_MS: u64 = 300;

// ---------------------------------------------------------------------------
// Public data types
// ---------------------------------------------------------------------------

/// Result of an AbuseIPDB `/check` query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbuseIpReport {
    /// IP address that was queried.
    pub ip_address: IpAddr,
    /// Confidence score that this IP is abusive, 0–100.
    pub confidence_score: u8,
    /// Total number of reports in the database.
    pub total_reports: u32,
    /// Timestamp of the most recent report, if any.
    #[serde(default)]
    pub last_reported_at: Option<DateTime<Utc>>,
    /// Usage type string (e.g. "Data Center/Web Hosting/Transit").
    #[serde(default)]
    pub usage_type: Option<String>,
    /// Two-letter country code (ISO 3166-1 alpha-2).
    #[serde(default)]
    pub country_code: Option<String>,
    /// Internet service provider name.
    #[serde(default)]
    pub isp: Option<String>,
}

/// Errors returned by [`AbuseIpDbClient`].
#[derive(Debug, Error)]
pub enum AbuseIpDbError {
    #[error("HTTP request failed: {0}")]
    Request(#[from] reqwest::Error),

    /// The API returned an error response (non-2xx).
    #[error("AbuseIPDB API error {status}: {message}")]
    Api { status: u16, message: String },

    /// Rate limit exceeded; contains `Retry-After` seconds if present.
    #[error("AbuseIPDB rate limit exceeded (retry after {0:?}s)")]
    RateLimit(Option<u64>),
}

// ---------------------------------------------------------------------------
// Raw API response shapes (internal serde types)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct ApiResponse {
    data: ApiData,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ApiData {
    ip_address: IpAddr,
    abuse_confidence_score: u8,
    total_reports: u32,
    #[serde(default)]
    last_reported_at: Option<DateTime<Utc>>,
    #[serde(default)]
    usage_type: Option<String>,
    #[serde(default)]
    country_code: Option<String>,
    #[serde(default)]
    isp: Option<String>,
}

#[derive(Deserialize)]
struct ApiErrorResponse {
    errors: Vec<ApiError>,
}

#[derive(Deserialize)]
struct ApiError {
    detail: String,
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

/// Async HTTP client for the AbuseIPDB v2 API.
///
/// # Usage
/// ```rust,no_run
/// # use hiveguard_cti::abuseipdb::AbuseIpDbClient;
/// # async fn example() {
/// let client = AbuseIpDbClient::new("YOUR_API_KEY".to_string());
/// let report = client.check("1.2.3.4".parse().unwrap()).await.unwrap();
/// println!("Score: {}", report.confidence_score);
/// # }
/// ```
pub struct AbuseIpDbClient {
    api_key: String,
    client: reqwest::Client,
    max_age_days: u32,
}

impl AbuseIpDbClient {
    /// Create a new client with the given API key.
    ///
    /// `max_age_days` controls how far back reports are included (default 90).
    pub fn new(api_key: String) -> Self {
        Self::with_max_age(api_key, 90)
    }

    /// Create a client with a custom `maxAgeInDays` parameter.
    pub fn with_max_age(api_key: String, max_age_days: u32) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(TIMEOUT_SECS))
            .user_agent(concat!("HiveGuard/", env!("CARGO_PKG_VERSION")))
            .build()
            .expect("failed to build AbuseIPDB HTTP client");

        Self {
            api_key,
            client,
            max_age_days,
        }
    }

    /// Query AbuseIPDB for the reputation of a single IP address.
    ///
    /// Retries up to [`MAX_RETRIES`] times on transient errors (5xx / timeout)
    /// using exponential backoff.
    pub async fn check(&self, ip: IpAddr) -> Result<AbuseIpReport, AbuseIpDbError> {
        let url = format!("{}/check", API_BASE);
        let ip_str = ip.to_string();

        let mut last_err: Option<AbuseIpDbError> = None;

        for attempt in 0..=MAX_RETRIES {
            if attempt > 0 {
                let delay = Duration::from_millis(RETRY_BACKOFF_MS * (1 << (attempt - 1)));
                tokio::time::sleep(delay).await;
            }

            let result = self
                .client
                .get(&url)
                .header("Key", &self.api_key)
                .header("Accept", "application/json")
                .query(&[
                    ("ipAddress", ip_str.as_str()),
                    (
                        "maxAgeInDays",
                        // SAFETY: safe, value is a u32 displayed inline
                        Box::leak(self.max_age_days.to_string().into_boxed_str()),
                    ),
                    ("verbose", ""),
                ])
                .send()
                .await;

            match result {
                Err(e) => {
                    if e.is_timeout() || e.is_connect() {
                        last_err = Some(AbuseIpDbError::Request(e));
                        continue; // retry
                    }
                    return Err(AbuseIpDbError::Request(e));
                }
                Ok(resp) => {
                    let status = resp.status();

                    // 429 — rate limit
                    if status.as_u16() == 429 {
                        let retry_after = resp
                            .headers()
                            .get("Retry-After")
                            .and_then(|v| v.to_str().ok())
                            .and_then(|s| s.parse::<u64>().ok());
                        return Err(AbuseIpDbError::RateLimit(retry_after));
                    }

                    // 5xx — retry
                    if status.is_server_error() {
                        let msg = resp.text().await.unwrap_or_default();
                        last_err = Some(AbuseIpDbError::Api {
                            status: status.as_u16(),
                            message: msg,
                        });
                        continue;
                    }

                    // 4xx — client error (bad API key, etc.) — don't retry
                    if !status.is_success() {
                        let message = resp
                            .json::<ApiErrorResponse>()
                            .await
                            .ok()
                            .and_then(|e| e.errors.into_iter().next().map(|e| e.detail))
                            .unwrap_or_else(|| status.to_string());
                        return Err(AbuseIpDbError::Api {
                            status: status.as_u16(),
                            message,
                        });
                    }

                    // 200 OK
                    let body: ApiResponse = resp.json().await?;
                    let d = body.data;
                    return Ok(AbuseIpReport {
                        ip_address: d.ip_address,
                        confidence_score: d.abuse_confidence_score,
                        total_reports: d.total_reports,
                        last_reported_at: d.last_reported_at,
                        usage_type: d.usage_type,
                        country_code: d.country_code,
                        isp: d.isp,
                    });
                }
            }
        }

        Err(last_err.unwrap_or_else(|| AbuseIpDbError::Api {
            status: 0,
            message: "max retries exceeded".to_string(),
        }))
    }
}

// ---------------------------------------------------------------------------
// AbuseIpDbProvider — implements CtiProvider
// ---------------------------------------------------------------------------

use std::path::Path;

use async_trait::async_trait;
use tokio::sync::Mutex;

use crate::cache::CtiCache;
use crate::enricher::{CtiSignal, EnrichStats};
use crate::provider::CtiProvider;

/// [`CtiProvider`] wrapper around [`AbuseIpDbClient`] with in-memory + disk cache.
pub struct AbuseIpDbProvider {
    client: AbuseIpDbClient,
    cache: Mutex<CtiCache>,
    /// Minimum confidence score (0–100) to emit a signal.
    threshold: u8,
    /// When `true`, signal severity is 200 (immediate ban).
    ban_on_first_hit: bool,
}

impl AbuseIpDbProvider {
    /// Create a new provider.
    ///
    /// - `data_dir` — daemon data directory (disk cache stored as `cti_cache.bin`)
    /// - `client` — pre-built AbuseIPDB HTTP client
    /// - `threshold` — minimum confidence score (default 75)
    /// - `ban_on_first_hit` — when true, severity is raised to 200
    /// - `cache_ttl` — how long entries are considered fresh
    /// - `max_cache_entries` — eviction threshold
    pub fn new(
        data_dir: &Path,
        client: AbuseIpDbClient,
        threshold: u8,
        ban_on_first_hit: bool,
        cache_ttl: Duration,
        max_cache_entries: usize,
    ) -> Self {
        let mut cache = CtiCache::with_options(data_dir, cache_ttl, max_cache_entries);
        cache.load_from_disk();
        Self {
            client,
            cache: Mutex::new(cache),
            threshold,
            ban_on_first_hit,
        }
    }

    fn report_to_signal(&self, report: &AbuseIpReport) -> Option<CtiSignal> {
        if report.confidence_score < self.threshold {
            return None;
        }
        let base = 60u16 + (report.confidence_score as u16 / 4);
        let severity = if self.ban_on_first_hit { 200 } else { base.min(255) as u8 };

        let mut desc = format!(
            "AbuseIPDB confidence {}/100 ({} reports)",
            report.confidence_score, report.total_reports
        );
        if let Some(ref isp) = report.isp {
            desc.push_str(&format!(", ISP: {isp}"));
        }

        Some(CtiSignal {
            provider: "abuseipdb",
            severity,
            confidence_score: report.confidence_score,
            description: desc,
        })
    }
}

#[async_trait]
impl CtiProvider for AbuseIpDbProvider {
    fn name(&self) -> &'static str {
        "abuseipdb"
    }

    async fn check(&self, ip: IpAddr) -> (Option<CtiSignal>, EnrichStats) {
        let mut stats = EnrichStats::default();

        // --- Cache lookup ---
        {
            let mut cache = self.cache.lock().await;
            if let Some(cached) = cache.get(ip) {
                stats.cache_hit = true;
                let sig = self.report_to_signal(cached);
                return (sig, stats);
            }
        }

        // --- Live API call ---
        stats.api_called = true;
        match self.client.check(ip).await {
            Ok(report) => {
                let sig = self.report_to_signal(&report);
                self.cache.lock().await.insert(ip, report);
                (sig, stats)
            }
            Err(AbuseIpDbError::RateLimit(retry_after)) => {
                tracing::warn!(
                    ip = %ip,
                    retry_after = ?retry_after,
                    "AbuseIPDB rate limit — skipping enrichment"
                );
                stats.api_error = true;
                (None, stats)
            }
            Err(e) => {
                tracing::warn!(ip = %ip, "AbuseIPDB error: {}", e);
                stats.api_error = true;
                (None, stats)
            }
        }
    }

    async fn flush_cache(&self) {
        self.cache.lock().await.flush_to_disk();
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_serialization_roundtrip() {
        let report = AbuseIpReport {
            ip_address: "1.2.3.4".parse().unwrap(),
            confidence_score: 85,
            total_reports: 42,
            last_reported_at: None,
            usage_type: Some("Data Center/Web Hosting/Transit".to_string()),
            country_code: Some("US".to_string()),
            isp: Some("Example ISP".to_string()),
        };

        let json = serde_json::to_string(&report).unwrap();
        let decoded: AbuseIpReport = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.confidence_score, 85);
        assert_eq!(decoded.total_reports, 42);
        assert_eq!(decoded.country_code.as_deref(), Some("US"));
    }

    #[test]
    fn report_bincode_roundtrip() {
        let report = AbuseIpReport {
            ip_address: "2001:db8::1".parse().unwrap(),
            confidence_score: 60,
            total_reports: 5,
            last_reported_at: None,
            usage_type: None,
            country_code: Some("DE".to_string()),
            isp: None,
        };

        let encoded = bincode::serialize(&report).unwrap();
        let decoded: AbuseIpReport = bincode::deserialize(&encoded).unwrap();
        assert_eq!(decoded.confidence_score, 60);
        assert_eq!(decoded.country_code.as_deref(), Some("DE"));
    }

    #[test]
    fn severity_formula_standard() {
        let provider = make_provider(75, false);
        let report = sample_report(80);
        let sig = provider.report_to_signal(&report).unwrap();
        // 60 + 80/4 = 80
        assert_eq!(sig.severity, 80);
        assert_eq!(sig.provider, "abuseipdb");
    }

    #[test]
    fn severity_formula_ban_on_first_hit() {
        let provider = make_provider(75, true);
        let report = sample_report(76);
        let sig = provider.report_to_signal(&report).unwrap();
        assert_eq!(sig.severity, 200);
    }

    #[test]
    fn below_threshold_returns_none() {
        let provider = make_provider(75, false);
        let report = sample_report(40);
        assert!(provider.report_to_signal(&report).is_none());
    }

    fn make_provider(threshold: u8, ban_on_first_hit: bool) -> AbuseIpDbProvider {
        AbuseIpDbProvider {
            client: AbuseIpDbClient::new("dummy".to_string()),
            cache: Mutex::new(CtiCache::new(std::path::Path::new("/tmp"))),
            threshold,
            ban_on_first_hit,
        }
    }

    fn sample_report(score: u8) -> AbuseIpReport {
        AbuseIpReport {
            ip_address: "1.2.3.4".parse().unwrap(),
            confidence_score: score,
            total_reports: 5,
            last_reported_at: None,
            usage_type: None,
            country_code: None,
            isp: None,
        }
    }
}
