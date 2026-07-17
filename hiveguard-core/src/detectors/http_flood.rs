use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use ipnet::IpNet;

use crate::detector::Detector;
use crate::models::{Action, DetectionSignal, EventType, NormalizedEvent};

/// Sweep stale counters every this many processed events.
const SWEEP_EVERY: u64 = 8192;

/// Volumetric HTTP flood detector — counts request *rate* per source IP and
/// per subnet (/24 for IPv4, /48 for IPv6) regardless of response status.
///
/// Complements `Http4xxFloodDetector` (which only sees 4xx errors) and
/// `DistributedSlowDetector` (which only counts unique IPs, so a small set of
/// hosts hammering valid 200-OK pages stays invisible to both). Requests for
/// static assets (images, CSS, JS, fonts) are excluded so that ordinary page
/// loads don't inflate the counts.
pub struct HttpFloodDetector {
    /// Length of the tumbling counting window.
    window: Duration,
    /// Requests per window from a single IP to trigger a host ban (0 = off).
    ip_threshold: u64,
    /// Requests per window from a whole subnet to trigger a subnet ban (0 = off).
    subnet_threshold: u64,
    /// Ban duration for both host and subnet bans.
    ban_duration: Duration,
    /// Lower-cased path suffixes that never count towards the thresholds.
    ignore_extensions: Vec<String>,
    ip_counters: DashMap<IpAddr, WindowCounter>,
    subnet_counters: DashMap<IpNet, WindowCounter>,
    events_since_sweep: AtomicU64,
}

struct WindowCounter {
    window_start: DateTime<Utc>,
    count: u64,
}

pub fn default_ignore_extensions() -> Vec<String> {
    [
        ".css", ".js", ".mjs", ".map", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".avif",
        ".svg", ".ico", ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".webm", ".pdf",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

impl HttpFloodDetector {
    pub fn new() -> Self {
        Self::with_config(
            Duration::from_secs(60),
            600,
            2400,
            Duration::from_secs(12 * 3600),
            default_ignore_extensions(),
        )
    }

    pub fn with_config(
        window: Duration,
        ip_threshold: u64,
        subnet_threshold: u64,
        ban_duration: Duration,
        ignore_extensions: Vec<String>,
    ) -> Self {
        Self {
            window,
            ip_threshold,
            subnet_threshold,
            ban_duration,
            ignore_extensions: ignore_extensions
                .into_iter()
                .map(|e| e.to_ascii_lowercase())
                .collect(),
            ip_counters: DashMap::new(),
            subnet_counters: DashMap::new(),
            events_since_sweep: AtomicU64::new(0),
        }
    }

    /// Extract /24 subnet from an IPv4 address, or /48 for IPv6.
    fn ip_to_subnet(ip: IpAddr) -> Option<IpNet> {
        match ip {
            IpAddr::V4(v4) => {
                let octets = v4.octets();
                let subnet_ip = std::net::Ipv4Addr::new(octets[0], octets[1], octets[2], 0);
                Some(IpNet::V4(ipnet::Ipv4Net::new(subnet_ip, 24).ok()?))
            }
            IpAddr::V6(v6) => {
                let mut segments = v6.segments();
                for seg in segments[3..].iter_mut() {
                    *seg = 0;
                }
                let subnet_ip = std::net::Ipv6Addr::from(segments);
                Some(IpNet::V6(ipnet::Ipv6Net::new(subnet_ip, 48).ok()?))
            }
        }
    }

    /// True if the request path (query string excluded) ends with an ignored
    /// static-asset extension.
    fn is_ignored_path(&self, path: &str) -> bool {
        let path = path.split(['?', '#']).next().unwrap_or(path);
        let lower = path.to_ascii_lowercase();
        self.ignore_extensions.iter().any(|ext| lower.ends_with(ext))
    }

    /// Increment a tumbling-window counter; returns the new count, or `None`
    /// when this exact event crossed the threshold (fires once per window).
    fn bump(counter: &mut WindowCounter, ts: DateTime<Utc>, window: Duration, threshold: u64) -> bool {
        let window_chrono =
            chrono::Duration::from_std(window).unwrap_or(chrono::Duration::seconds(60));
        if ts.signed_duration_since(counter.window_start) >= window_chrono {
            counter.window_start = ts;
            counter.count = 0;
        }
        counter.count += 1;
        counter.count == threshold
    }

    fn maybe_sweep(&self, now: DateTime<Utc>) {
        if self.events_since_sweep.fetch_add(1, Ordering::Relaxed) % SWEEP_EVERY != SWEEP_EVERY - 1 {
            return;
        }
        let stale = chrono::Duration::from_std(self.window * 4)
            .unwrap_or(chrono::Duration::seconds(240));
        self.ip_counters
            .retain(|_, c| now.signed_duration_since(c.window_start) < stale);
        self.subnet_counters
            .retain(|_, c| now.signed_duration_since(c.window_start) < stale);
    }

    fn signal(&self, target: IpNet, count: u64, ts: DateTime<Utc>, kind: &str) -> DetectionSignal {
        let evidence = format!("{target}:http_flood:{kind}:{count}:{}", ts.timestamp() / 60);
        DetectionSignal {
            source_ip: target,
            severity: 200,
            confidence: 0.85,
            reason: format!(
                "HTTP flood: {count} requests from {target} in {}s",
                self.window.as_secs()
            ),
            evidence_hash: *blake3::hash(evidence.as_bytes()).as_bytes(),
            suggested_action: Action::Ban(self.ban_duration),
            detector_name: "http_flood".into(),
            timestamp: ts,
        }
    }
}

impl Default for HttpFloodDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for HttpFloodDetector {
    fn name(&self) -> &str {
        "http_flood"
    }

    fn process(&self, event: &NormalizedEvent) -> Option<DetectionSignal> {
        match event.event_type {
            EventType::HttpRequest | EventType::Http4xx | EventType::Http5xx => {}
            _ => return None,
        }

        if let Some(path) = event.metadata.get("path") {
            if self.is_ignored_path(path) {
                return None;
            }
        }

        let ts = event.timestamp;
        self.maybe_sweep(ts);

        // Subnet counter first: a subnet-wide ban covers the member IP anyway.
        if self.subnet_threshold > 0 {
            if let Some(subnet) = Self::ip_to_subnet(event.source_ip) {
                let mut entry = self
                    .subnet_counters
                    .entry(subnet)
                    .or_insert_with(|| WindowCounter { window_start: ts, count: 0 });
                if Self::bump(&mut entry, ts, self.window, self.subnet_threshold) {
                    let count = entry.count;
                    drop(entry);
                    return Some(self.signal(subnet, count, ts, "subnet"));
                }
            }
        }

        if self.ip_threshold > 0 {
            let mut entry = self
                .ip_counters
                .entry(event.source_ip)
                .or_insert_with(|| WindowCounter { window_start: ts, count: 0 });
            if Self::bump(&mut entry, ts, self.window, self.ip_threshold) {
                let count = entry.count;
                drop(entry);
                let host_net = IpNet::from(event.source_ip);
                return Some(self.signal(host_net, count, ts, "ip"));
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use std::collections::HashMap;

    fn http_event(ip: &str, path: &str, status: u16, ts: DateTime<Utc>) -> NormalizedEvent {
        let mut metadata = HashMap::new();
        metadata.insert("path".to_string(), path.to_string());
        metadata.insert("status_code".to_string(), status.to_string());
        NormalizedEvent {
            timestamp: ts,
            source_ip: ip.parse().unwrap(),
            event_type: match status {
                400..=499 => EventType::Http4xx,
                500..=599 => EventType::Http5xx,
                _ => EventType::HttpRequest,
            },
            source_name: "nginx".into(),
            raw_line: format!("GET {path} {status}"),
            metadata,
        }
    }

    fn detector(window_secs: u64, ip_thr: u64, subnet_thr: u64) -> HttpFloodDetector {
        HttpFloodDetector::with_config(
            Duration::from_secs(window_secs),
            ip_thr,
            subnet_thr,
            Duration::from_secs(3600),
            default_ignore_extensions(),
        )
    }

    #[test]
    fn single_ip_flood_of_200s_triggers_host_ban() {
        let d = detector(60, 10, 0);
        let base = Utc::now();
        let mut fired = Vec::new();
        for i in 0..15 {
            if let Some(s) = d.process(&http_event("203.0.113.7", "/obuwie/rozmiar/48", 200, base + chrono::Duration::milliseconds(i * 10))) {
                fired.push(s);
            }
        }
        assert_eq!(fired.len(), 1, "fires exactly once per window");
        assert_eq!(fired[0].source_ip.to_string(), "203.0.113.7/32");
        assert_eq!(fired[0].severity, 200);
        assert_eq!(fired[0].suggested_action, Action::Ban(Duration::from_secs(3600)));
    }

    #[test]
    fn subnet_flood_of_200s_triggers_subnet_ban() {
        let d = detector(60, 0, 20);
        let base = Utc::now();
        let mut fired = Vec::new();
        // 4 IPs x 5 requests + a few extra — each individually low-rate.
        for i in 0..25u32 {
            let ip = format!("42.201.192.{}", (i % 4) + 1);
            if let Some(s) = d.process(&http_event(&ip, "/katalog", 200, base + chrono::Duration::milliseconds(i as i64 * 10))) {
                fired.push(s);
            }
        }
        assert_eq!(fired.len(), 1);
        assert_eq!(fired[0].source_ip.to_string(), "42.201.192.0/24");
    }

    #[test]
    fn static_assets_do_not_count() {
        let d = detector(60, 5, 0);
        let base = Utc::now();
        for i in 0..50 {
            let res = d.process(&http_event(
                "203.0.113.7",
                "/media/catalog/product.JPG?width=200",
                200,
                base + chrono::Duration::milliseconds(i * 10),
            ));
            assert!(res.is_none());
        }
    }

    #[test]
    fn window_reset_starts_fresh_count() {
        let d = detector(60, 10, 0);
        let base = Utc::now();
        for i in 0..8 {
            assert!(d.process(&http_event("203.0.113.7", "/a", 200, base + chrono::Duration::seconds(i))).is_none());
        }
        // Next window: 8 old requests must not carry over.
        let later = base + chrono::Duration::seconds(120);
        for i in 0..9 {
            assert!(d.process(&http_event("203.0.113.7", "/a", 200, later + chrono::Duration::seconds(i % 50))).is_none());
        }
        // 10th in the new window fires.
        assert!(d.process(&http_event("203.0.113.7", "/a", 200, later + chrono::Duration::seconds(55))).is_some());
    }

    #[test]
    fn refires_in_next_window_if_flood_continues() {
        let d = detector(60, 10, 0);
        let base = Utc::now();
        let mut fired = 0;
        for w in 0..2i64 {
            for i in 0..12i64 {
                let ts = base + chrono::Duration::seconds(w * 90 + i);
                if d.process(&http_event("203.0.113.7", "/a", 200, ts)).is_some() {
                    fired += 1;
                }
            }
        }
        assert_eq!(fired, 2);
    }

    #[test]
    fn mixed_statuses_all_count() {
        let d = detector(60, 10, 0);
        let base = Utc::now();
        let mut fired = 0;
        for (i, status) in [200, 404, 500, 200, 444, 200, 302, 200, 200, 200].iter().enumerate() {
            if d.process(&http_event("203.0.113.7", "/a", *status, base + chrono::Duration::seconds(i as i64))).is_some() {
                fired += 1;
            }
        }
        assert_eq!(fired, 1);
    }

    #[test]
    fn ignores_non_http_events() {
        let d = detector(60, 1, 1);
        let event = NormalizedEvent {
            timestamp: Utc::now(),
            source_ip: "10.0.0.1".parse().unwrap(),
            event_type: EventType::AuthFailure,
            source_name: "ssh".into(),
            raw_line: "failure".into(),
            metadata: HashMap::new(),
        };
        assert!(d.process(&event).is_none());
    }

    #[test]
    fn zero_thresholds_disable_detection() {
        let d = detector(60, 0, 0);
        let base = Utc::now();
        for i in 0..100 {
            assert!(d.process(&http_event("203.0.113.7", "/a", 200, base + chrono::Duration::milliseconds(i))).is_none());
        }
    }

    #[test]
    fn ipv6_subnet_ban_is_48() {
        let d = detector(60, 0, 5);
        let base = Utc::now();
        let mut fired = Vec::new();
        for i in 0..6i64 {
            let ip = format!("2001:db8:1::{}", i + 1);
            if let Some(s) = d.process(&http_event(&ip, "/a", 200, base + chrono::Duration::seconds(i))) {
                fired.push(s);
            }
        }
        assert_eq!(fired.len(), 1);
        assert_eq!(fired[0].source_ip.to_string(), "2001:db8:1::/48");
    }

    #[test]
    fn distinct_ips_tracked_separately() {
        let d = detector(60, 10, 0);
        let base = Utc::now();
        // 5 requests each from two IPs in different subnets — no ban.
        for i in 0..5i64 {
            assert!(d.process(&http_event("203.0.113.7", "/a", 200, base + chrono::Duration::seconds(i))).is_none());
            assert!(d.process(&http_event("198.51.100.9", "/a", 200, base + chrono::Duration::seconds(i))).is_none());
        }
    }
}
