//! Spamhaus DNSBL (zen.spamhaus.org) CTI provider.
//!
//! Performs a reverse-DNS lookup against the Spamhaus zen blocklist zone and
//! maps the 127.0.0.x response codes to severity scores.  Results are cached
//! in-memory for 1 hour.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use hickory_resolver::TokioAsyncResolver;
use hickory_resolver::error::ResolveErrorKind;
use tokio::sync::Mutex;
use tracing::warn;

use crate::enricher::{CtiSignal, EnrichStats};
use crate::provider::CtiProvider;

const CACHE_TTL: Duration = Duration::from_secs(3600); // 1 hour
const DNSBL_ZONE: &str = "zen.spamhaus.org";

/// Cached result: `None` means "checked and clean", `Some` means listed.
#[derive(Clone, Copy)]
struct SpamhausHit {
    severity: u8,
    description: &'static str,
}

fn classify(octets: [u8; 4]) -> Option<SpamhausHit> {
    if octets[0] != 127 || octets[1] != 0 || octets[2] != 0 {
        return None;
    }
    Some(match octets[3] {
        2 => SpamhausHit { severity: 85, description: "Spamhaus SBL: confirmed spam source" },
        3 => SpamhausHit { severity: 80, description: "Spamhaus CSS: spam support service" },
        4..=7 => SpamhausHit { severity: 75, description: "Spamhaus XBL: exploited/malware host" },
        9 => SpamhausHit { severity: 90, description: "Spamhaus DROP: hijacked netblock" },
        10 | 11 => SpamhausHit { severity: 50, description: "Spamhaus PBL: dynamic/residential IP" },
        _ => return None,
    })
}

/// Build the DNSBL query hostname for an IP address.
///
/// IPv4: octets reversed, e.g. `1.2.3.4` → `4.3.2.1.zen.spamhaus.org`
/// IPv6: full 32 nibbles reversed, dot-separated (RFC 5782 §2.4)
fn make_query(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, c, d] = v4.octets();
            format!("{d}.{c}.{b}.{a}.{DNSBL_ZONE}")
        }
        IpAddr::V6(v6) => {
            let bytes = v6.octets();
            // Expand to 32 nibbles in MSB-first order, then reverse the sequence.
            let nibbles: Vec<char> = bytes
                .iter()
                .flat_map(|b| {
                    let hi = char::from_digit((b >> 4) as u32, 16).unwrap();
                    let lo = char::from_digit((b & 0xf) as u32, 16).unwrap();
                    [hi, lo]
                })
                .collect();
            let reversed: String = nibbles
                .iter()
                .rev()
                .map(|c| c.to_string())
                .collect::<Vec<_>>()
                .join(".");
            format!("{reversed}.{DNSBL_ZONE}")
        }
    }
}

// ---------------------------------------------------------------------------
// SpamhausProvider
// ---------------------------------------------------------------------------

/// Spamhaus DNSBL provider querying `zen.spamhaus.org`.
pub struct SpamhausProvider {
    resolver: TokioAsyncResolver,
    cache: Mutex<HashMap<IpAddr, (Option<SpamhausHit>, Instant)>>,
    /// Minimum severity to emit a signal (mirrors the roadmap's `confidence_threshold`).
    min_severity: u8,
}

impl SpamhausProvider {
    /// Create using the system DNS resolver (`/etc/resolv.conf`).
    pub fn new(min_severity: u8) -> Self {
        let resolver = TokioAsyncResolver::tokio_from_system_conf().unwrap_or_else(|_| {
            TokioAsyncResolver::tokio(
                hickory_resolver::config::ResolverConfig::default(),
                hickory_resolver::config::ResolverOpts::default(),
            )
        });
        Self {
            resolver,
            cache: Mutex::new(HashMap::new()),
            min_severity,
        }
    }

    /// Create using a specific DNS server address (e.g. `"8.8.8.8:53"`).
    pub fn with_custom_resolver(min_severity: u8, resolver_addr: &str) -> Self {
        use std::net::SocketAddr;
        use hickory_resolver::config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts};

        let mut config = ResolverConfig::new();
        if let Ok(addr) = resolver_addr.parse::<SocketAddr>() {
            config.add_name_server(NameServerConfig::new(addr, Protocol::Udp));
        }
        let resolver = TokioAsyncResolver::tokio(config, ResolverOpts::default());
        Self {
            resolver,
            cache: Mutex::new(HashMap::new()),
            min_severity,
        }
    }
}

#[async_trait]
impl CtiProvider for SpamhausProvider {
    fn name(&self) -> &'static str {
        "spamhaus"
    }

    async fn check(&self, ip: IpAddr) -> (Option<CtiSignal>, EnrichStats) {
        let mut stats = EnrichStats::default();

        // --- Cache lookup ---
        {
            let cache = self.cache.lock().await;
            if let Some((hit, fetched_at)) = cache.get(&ip) {
                if fetched_at.elapsed() < CACHE_TTL {
                    stats.cache_hit = true;
                    let sig = hit
                        .filter(|h| h.severity >= self.min_severity)
                        .map(signal_from_hit);
                    return (sig, stats);
                }
            }
        }

        // --- DNS lookup ---
        stats.api_called = true;
        let query = make_query(ip);

        let hit: Option<SpamhausHit> = match self.resolver.ipv4_lookup(&*query).await {
            Ok(lookup) => {
                let mut best: Option<SpamhausHit> = None;
                for addr in lookup.iter() {
                    if let Some(h) = classify(addr.octets()) {
                        if best.map_or(true, |b| h.severity > b.severity) {
                            best = Some(h);
                        }
                    }
                }
                best
            }
            Err(e) => match e.kind() {
                // NXDOMAIN → IP is clean / not listed
                ResolveErrorKind::NoRecordsFound { .. } => None,
                _ => {
                    warn!(ip = %ip, error = %e, "Spamhaus DNSBL lookup error");
                    stats.api_error = true;
                    return (None, stats);
                }
            },
        };

        // Store result (even clean = None so we don't re-query on every event)
        self.cache.lock().await.insert(ip, (hit, Instant::now()));

        let sig = hit
            .filter(|h| h.severity >= self.min_severity)
            .map(signal_from_hit);

        (sig, stats)
    }
}

fn signal_from_hit(h: SpamhausHit) -> CtiSignal {
    CtiSignal {
        provider: "spamhaus",
        // DNSBL severity maps directly to confidence — no separate score field.
        severity: h.severity,
        confidence_score: h.severity,
        description: h.description.to_string(),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn make_query_ipv4() {
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        assert_eq!(make_query(ip), "4.3.2.1.zen.spamhaus.org");
    }

    #[test]
    fn classify_sbl() {
        let hit = classify([127, 0, 0, 2]).unwrap();
        assert_eq!(hit.severity, 85);
    }

    #[test]
    fn classify_pbl() {
        let hit = classify([127, 0, 0, 10]).unwrap();
        assert_eq!(hit.severity, 50);
    }

    #[test]
    fn classify_drop() {
        let hit = classify([127, 0, 0, 9]).unwrap();
        assert_eq!(hit.severity, 90);
    }

    #[test]
    fn classify_unknown_returns_none() {
        assert!(classify([127, 0, 0, 255]).is_none());
        assert!(classify([1, 2, 3, 4]).is_none());
    }

    #[test]
    fn make_query_ipv6_loopback() {
        let ip: IpAddr = "::1".parse().unwrap();
        let q = make_query(ip);
        // ::1 → 0000:0000:...:0001 → reversed nibbles start with 1.0.0.0...
        assert!(q.starts_with("1.0.0.0"));
        assert!(q.ends_with("zen.spamhaus.org"));
    }
}
