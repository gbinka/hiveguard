use std::collections::{HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use ipnet::IpNet;

use crate::detector::Detector;
use crate::detectors::netkey::subnet_of;
use crate::models::{Action, DetectionSignal, EventType, NormalizedEvent};

/// Sweep idle per-IP / per-subnet state every this many counted POSTs.
const SWEEP_EVERY: u64 = 4096;

/// HTTP login brute-force detector.
///
/// Tracks POST requests to login endpoints (e.g. `/wp-login.php`,
/// `/xmlrpc.php`) per IP in a sliding window. Detects bots that
/// spray login attempts across multiple WordPress sites.
///
/// Unlike `PathProbeDetector` (which fires on a single hit and is
/// too aggressive for legitimate admin login pages), this detector
/// uses threshold-based rate limiting — real users log in once or
/// twice, bots hammer the endpoint dozens of times.
pub struct HttpLoginBruteforceDetector {
    /// Login paths to monitor (POST requests only).
    paths: Vec<String>,
    /// Number of POST requests in `window` to trigger detection.
    threshold: u32,
    /// Sliding window duration.
    window: Duration,
    /// Ban duration once threshold is exceeded.
    ban_duration: Duration,
    /// Sliding window of POST timestamps per IP.
    hits: DashMap<IpAddr, VecDeque<DateTime<Utc>>>,
    /// Optional subnet aggregation (UA-rotating botnets spreading the
    /// attempts over many addresses of one /24): prefix 0 = off per family.
    subnet_v4_prefix: u8,
    subnet_v6_prefix: u8,
    /// POSTs from the whole subnet within `window` to fire (0 = off).
    subnet_threshold: u32,
    /// Distinct source IPs required in the subnet before it fires, so one
    /// noisy host (handled per IP anyway) never bans its neighbours.
    subnet_min_distinct_ips: usize,
    /// Sliding window of (timestamp, source IP) per subnet.
    subnet_hits: DashMap<IpNet, VecDeque<(DateTime<Utc>, IpAddr)>>,
    events: AtomicU64,
}

/// Defaults applied when subnet aggregation is enabled without explicit
/// thresholds (plugin keys `subnet_threshold` / `subnet_min_distinct_ips`).
pub const DEFAULT_SUBNET_THRESHOLD: u32 = 20;
pub const DEFAULT_SUBNET_MIN_DISTINCT_IPS: usize = 5;

impl HttpLoginBruteforceDetector {
    pub fn new() -> Self {
        Self {
            paths: default_login_paths(),
            threshold: 5,
            window: Duration::from_secs(600), // 10 min
            ban_duration: Duration::from_secs(86400), // 24h
            hits: DashMap::new(),
            subnet_v4_prefix: 0,
            subnet_v6_prefix: 0,
            subnet_threshold: DEFAULT_SUBNET_THRESHOLD,
            subnet_min_distinct_ips: DEFAULT_SUBNET_MIN_DISTINCT_IPS,
            subnet_hits: DashMap::new(),
            events: AtomicU64::new(0),
        }
    }

    pub fn with_config(
        paths: Vec<String>,
        threshold: u32,
        window: Duration,
        ban_duration: Duration,
    ) -> Self {
        Self {
            paths,
            threshold,
            window,
            ban_duration,
            hits: DashMap::new(),
            subnet_v4_prefix: 0,
            subnet_v6_prefix: 0,
            subnet_threshold: DEFAULT_SUBNET_THRESHOLD,
            subnet_min_distinct_ips: DEFAULT_SUBNET_MIN_DISTINCT_IPS,
            subnet_hits: DashMap::new(),
            events: AtomicU64::new(0),
        }
    }

    /// Enable subnet aggregation: POSTs from all addresses of one IPv4
    /// `/v4_prefix` (IPv6 `/v6_prefix`) are counted together; when the subnet
    /// reaches `threshold` POSTs in the window from at least
    /// `min_distinct_ips` different addresses, the signal targets the whole
    /// (truncated) subnet. A prefix of 0 disables that family; `threshold`
    /// 0 disables both.
    pub fn with_subnet_aggregation(
        mut self,
        v4_prefix: u8,
        v6_prefix: u8,
        threshold: u32,
        min_distinct_ips: usize,
    ) -> Self {
        self.subnet_v4_prefix = v4_prefix.min(32);
        self.subnet_v6_prefix = v6_prefix.min(128);
        self.subnet_threshold = threshold;
        self.subnet_min_distinct_ips = min_distinct_ips.max(1);
        self
    }

    fn maybe_sweep(&self, now: DateTime<Utc>) {
        if self.events.fetch_add(1, Ordering::Relaxed) % SWEEP_EVERY != SWEEP_EVERY - 1 {
            return;
        }
        let cutoff = now - chrono::Duration::from_std(self.window).unwrap_or(chrono::Duration::zero());
        self.hits.retain(|_, d| d.back().is_some_and(|t| *t >= cutoff));
        self.subnet_hits
            .retain(|_, d| d.back().is_some_and(|(t, _)| *t >= cutoff));
    }

    /// Record a POST in the subnet window; returns the subnet signal when
    /// the subnet threshold and the distinct-IP minimum are both reached.
    fn subnet_check(&self, ip: IpAddr, now: DateTime<Utc>, path: &str) -> Option<DetectionSignal> {
        if self.subnet_threshold == 0 {
            return None;
        }
        let subnet = subnet_of(ip, self.subnet_v4_prefix, self.subnet_v6_prefix)?;
        let cutoff = now - chrono::Duration::from_std(self.window).unwrap_or(chrono::Duration::zero());
        let cap = self.subnet_threshold as usize * 4 + 64;
        let mut deque = self.subnet_hits.entry(subnet).or_default();
        deque.push_back((now, ip));
        while deque.front().is_some_and(|(t, _)| *t < cutoff) || deque.len() > cap {
            deque.pop_front();
        }
        let count = deque.len();
        if count < self.subnet_threshold as usize {
            return None;
        }
        let distinct = deque.iter().map(|(_, a)| *a).collect::<HashSet<_>>().len();
        if distinct < self.subnet_min_distinct_ips {
            return None;
        }
        deque.clear();
        drop(deque);
        let reason = format!(
            "HTTP login brute-force (subnet): {count} POST requests to '{path}' from {distinct} addresses in {subnet} in {:?}",
            self.window,
        );
        let evidence = format!("{subnet}:http_login_bruteforce:subnet:{count}:{}", now.timestamp() / 60);
        Some(DetectionSignal {
            source_ip: subnet,
            severity: 180,
            confidence: 0.90,
            reason,
            evidence_hash: *blake3::hash(evidence.as_bytes()).as_bytes(),
            suggested_action: Action::Ban(self.ban_duration),
            detector_name: self.name().to_string(),
            timestamp: now,
        })
    }

    fn ip_to_net(ip: IpAddr) -> IpNet {
        match ip {
            IpAddr::V4(v4) => IpNet::V4(ipnet::Ipv4Net::new(v4, 32).unwrap()),
            IpAddr::V6(v6) => IpNet::V6(ipnet::Ipv6Net::new(v6, 128).unwrap()),
        }
    }

    fn compute_evidence_hash(ip: &IpAddr, count: u32) -> [u8; 32] {
        let input = format!("{ip}:http_login_bruteforce:{count}");
        *blake3::hash(input.as_bytes()).as_bytes()
    }

    fn prune_window(deque: &mut VecDeque<DateTime<Utc>>, window: Duration, now: DateTime<Utc>) {
        let cutoff = now - chrono::Duration::from_std(window).unwrap_or(chrono::Duration::zero());
        while let Some(front) = deque.front() {
            if *front < cutoff {
                deque.pop_front();
            } else {
                break;
            }
        }
    }

    /// Check if the request path matches any monitored login endpoint.
    fn matches_login_path(&self, request_path: &str) -> bool {
        for login_path in &self.paths {
            if request_path.starts_with(login_path.as_str()) {
                return true;
            }
        }
        false
    }
}

impl Default for HttpLoginBruteforceDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for HttpLoginBruteforceDetector {
    fn name(&self) -> &str {
        "http_login_bruteforce"
    }

    fn process(&self, event: &NormalizedEvent) -> Option<DetectionSignal> {
        // Match all HTTP event types — the response status doesn't matter,
        // the attempt itself is what we're counting.
        match event.event_type {
            EventType::HttpRequest | EventType::Http4xx | EventType::Http5xx => {}
            _ => return None,
        }

        // Only count POST requests (GET to view the login page is normal).
        let method = event.metadata.get("method")?;
        if !method.eq_ignore_ascii_case("POST") {
            return None;
        }

        let request_path = event.metadata.get("path")?;
        if !self.matches_login_path(request_path) {
            return None;
        }

        let ip = event.source_ip;
        let now = event.timestamp;
        self.maybe_sweep(now);

        // Subnet first: a subnet ban covers the member IP as well.
        if let Some(signal) = self.subnet_check(ip, now, request_path) {
            return Some(signal);
        }

        let mut deque = self.hits.entry(ip).or_default();
        deque.push_back(now);
        Self::prune_window(&mut deque, self.window, now);

        let count = deque.len() as u32;
        if count < self.threshold {
            return None;
        }
        drop(deque);

        let reason = format!(
            "HTTP login brute-force: {} POST requests to '{}' from {} in {:?}",
            count, request_path, ip, self.window,
        );
        let evidence_hash = Self::compute_evidence_hash(&ip, count);

        Some(DetectionSignal {
            source_ip: Self::ip_to_net(ip),
            severity: 180,
            confidence: 0.90,
            reason,
            evidence_hash,
            suggested_action: Action::Ban(self.ban_duration),
            detector_name: self.name().to_string(),
            timestamp: event.timestamp,
        })
    }
}

fn default_login_paths() -> Vec<String> {
    vec![
        "/wp-login.php".into(),
        "/xmlrpc.php".into(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn make_post_event(ip: &str, path: &str, ts: DateTime<Utc>) -> NormalizedEvent {
        let mut metadata = HashMap::new();
        metadata.insert("path".to_string(), path.to_string());
        metadata.insert("method".to_string(), "POST".to_string());
        metadata.insert("status_code".to_string(), "200".to_string());
        NormalizedEvent {
            timestamp: ts,
            source_ip: ip.parse().unwrap(),
            event_type: EventType::HttpRequest,
            source_name: "nginx".to_string(),
            raw_line: String::new(),
            metadata,
        }
    }

    fn make_get_event(ip: &str, path: &str, ts: DateTime<Utc>) -> NormalizedEvent {
        let mut metadata = HashMap::new();
        metadata.insert("path".to_string(), path.to_string());
        metadata.insert("method".to_string(), "GET".to_string());
        metadata.insert("status_code".to_string(), "200".to_string());
        NormalizedEvent {
            timestamp: ts,
            source_ip: ip.parse().unwrap(),
            event_type: EventType::HttpRequest,
            source_name: "nginx".to_string(),
            raw_line: String::new(),
            metadata,
        }
    }

    #[test]
    fn test_single_post_no_signal() {
        let mut det = HttpLoginBruteforceDetector::new();
        let ev = make_post_event("1.2.3.4", "/wp-login.php", Utc::now());
        assert!(det.process(&ev).is_none());
    }

    #[test]
    fn test_get_requests_ignored() {
        let mut det = HttpLoginBruteforceDetector::new();
        let now = Utc::now();
        for i in 0..10 {
            let ts = now + chrono::Duration::seconds(i);
            let ev = make_get_event("1.2.3.4", "/wp-login.php", ts);
            assert!(det.process(&ev).is_none(), "GET #{} should not trigger", i);
        }
    }

    #[test]
    fn test_threshold_triggers() {
        let mut det = HttpLoginBruteforceDetector::with_config(
            vec!["/wp-login.php".into()],
            5,
            Duration::from_secs(600),
            Duration::from_secs(86400),
        );
        let now = Utc::now();
        for i in 0..4 {
            let ts = now + chrono::Duration::seconds(i * 10);
            let ev = make_post_event("10.0.0.1", "/wp-login.php", ts);
            assert!(det.process(&ev).is_none(), "POST #{} before threshold", i);
        }
        // 5th POST should trigger
        let ev = make_post_event("10.0.0.1", "/wp-login.php", now + chrono::Duration::seconds(50));
        let signal = det.process(&ev);
        assert!(signal.is_some(), "5th POST should trigger detection");
        let s = signal.unwrap();
        assert_eq!(s.severity, 180);
        assert!(s.reason.contains("HTTP login brute-force"));
    }

    #[test]
    fn test_different_ips_independent() {
        let mut det = HttpLoginBruteforceDetector::with_config(
            vec!["/wp-login.php".into()],
            3,
            Duration::from_secs(600),
            Duration::from_secs(86400),
        );
        let now = Utc::now();

        // 2 POSTs from each IP — neither should trigger
        for i in 0..2 {
            let ts = now + chrono::Duration::seconds(i * 10);
            let ev1 = make_post_event("1.1.1.1", "/wp-login.php", ts);
            let ev2 = make_post_event("2.2.2.2", "/wp-login.php", ts);
            assert!(det.process(&ev1).is_none());
            assert!(det.process(&ev2).is_none());
        }
    }

    #[test]
    fn test_window_expiry() {
        let mut det = HttpLoginBruteforceDetector::with_config(
            vec!["/wp-login.php".into()],
            3,
            Duration::from_secs(60),
            Duration::from_secs(86400),
        );
        let now = Utc::now();

        // 2 POSTs now
        for i in 0..2 {
            let ts = now + chrono::Duration::seconds(i);
            let ev = make_post_event("10.0.0.1", "/wp-login.php", ts);
            assert!(det.process(&ev).is_none());
        }

        // 3rd POST 2 minutes later — first 2 should have expired
        let ev = make_post_event("10.0.0.1", "/wp-login.php", now + chrono::Duration::seconds(121));
        assert!(det.process(&ev).is_none(), "Old hits should have expired");
    }

    #[test]
    fn test_xmlrpc_detected() {
        let mut det = HttpLoginBruteforceDetector::with_config(
            vec!["/xmlrpc.php".into()],
            2,
            Duration::from_secs(600),
            Duration::from_secs(86400),
        );
        let now = Utc::now();
        let ev1 = make_post_event("5.5.5.5", "/xmlrpc.php", now);
        assert!(det.process(&ev1).is_none());
        let ev2 = make_post_event("5.5.5.5", "/xmlrpc.php", now + chrono::Duration::seconds(5));
        assert!(det.process(&ev2).is_some(), "2nd POST to xmlrpc should trigger");
    }

    #[test]
    fn test_non_login_path_ignored() {
        let mut det = HttpLoginBruteforceDetector::new();
        let now = Utc::now();
        for i in 0..10 {
            let ts = now + chrono::Duration::seconds(i);
            let ev = make_post_event("1.2.3.4", "/contact-form", ts);
            assert!(det.process(&ev).is_none());
        }
    }

    #[test]
    fn test_http5xx_counted() {
        let mut det = HttpLoginBruteforceDetector::with_config(
            vec!["/wp-login.php".into()],
            2,
            Duration::from_secs(600),
            Duration::from_secs(86400),
        );
        let now = Utc::now();

        // POST returning 503 (Http5xx) should still be counted
        let mut metadata = HashMap::new();
        metadata.insert("path".to_string(), "/wp-login.php".to_string());
        metadata.insert("method".to_string(), "POST".to_string());
        metadata.insert("status_code".to_string(), "503".to_string());
        let ev1 = NormalizedEvent {
            timestamp: now,
            source_ip: "9.9.9.9".parse().unwrap(),
            event_type: EventType::Http5xx,
            source_name: "nginx".to_string(),
            raw_line: String::new(),
            metadata: metadata.clone(),
        };
        assert!(det.process(&ev1).is_none());

        let ev2 = NormalizedEvent {
            timestamp: now + chrono::Duration::seconds(5),
            source_ip: "9.9.9.9".parse().unwrap(),
            event_type: EventType::Http5xx,
            source_name: "nginx".to_string(),
            raw_line: String::new(),
            metadata,
        };
        assert!(det.process(&ev2).is_some());
    }

    fn rotating_subnet_detector() -> HttpLoginBruteforceDetector {
        HttpLoginBruteforceDetector::with_config(
            vec!["/wp-login.php".into()],
            5,
            Duration::from_secs(600),
            Duration::from_secs(86400),
        )
        .with_subnet_aggregation(24, 64, 20, 5)
    }

    #[test]
    fn subnet_aggregation_off_by_default() {
        let det = HttpLoginBruteforceDetector::new();
        let now = Utc::now();
        // 50 IPs × 1 POST each: never reaches the per-IP threshold.
        for i in 1..=50 {
            let ev = make_post_event(&format!("100.64.53.{i}"), "/wp-login.php", now);
            assert!(det.process(&ev).is_none());
        }
    }

    #[test]
    fn ua_rotating_botnet_in_one_slash24_bans_the_subnet() {
        let det = rotating_subnet_detector();
        let now = Utc::now();
        let mut fired = None;
        for i in 1..=50u32 {
            let ev = make_post_event(
                &format!("100.64.53.{i}"),
                "/wp-login.php",
                now + chrono::Duration::seconds(i as i64),
            );
            if let Some(s) = det.process(&ev) {
                fired = Some((i, s));
                break;
            }
        }
        let (at, signal) = fired.expect("subnet signal");
        assert_eq!(at, 20);
        // Truncated network, so the scoring bucket key is stable and the
        // ban covers the whole /24 (no /24 → /32 collapse).
        assert_eq!(signal.source_ip.to_string(), "100.64.53.0/24");
        assert_eq!(signal.source_ip.addr().to_string(), "100.64.53.0");
        assert!(signal.severity as f32 * signal.confidence >= 100.0);
        assert!(signal.reason.contains("20 addresses"));
    }

    #[test]
    fn single_noisy_host_does_not_ban_its_subnet() {
        let det = HttpLoginBruteforceDetector::with_config(
            vec!["/wp-login.php".into()],
            1000, // per-IP rule effectively off for this test
            Duration::from_secs(600),
            Duration::from_secs(86400),
        )
        .with_subnet_aggregation(24, 64, 20, 5);
        let now = Utc::now();
        for i in 0..40 {
            let ip = format!("100.64.53.{}", 1 + (i % 4)); // only 4 distinct IPs
            let ev = make_post_event(&ip, "/wp-login.php", now + chrono::Duration::seconds(i));
            assert!(det.process(&ev).is_none(), "below min_distinct_ips");
        }
    }

    #[test]
    fn subnet_window_expires() {
        let det = rotating_subnet_detector();
        let now = Utc::now();
        for i in 1..=19u32 {
            let ev = make_post_event(&format!("100.64.53.{i}"), "/wp-login.php", now);
            assert!(det.process(&ev).is_none());
        }
        // 11 minutes later the first 19 are out of the 10-minute window.
        let later = now + chrono::Duration::seconds(660);
        let ev = make_post_event("100.64.53.100", "/wp-login.php", later);
        assert!(det.process(&ev).is_none());
    }

    #[test]
    fn ipv6_subnet_aggregation() {
        let det = rotating_subnet_detector();
        let now = Utc::now();
        let mut last = None;
        for i in 1..=20u32 {
            let ev = make_post_event(&format!("2001:db8:7:7::{i:x}"), "/wp-login.php", now);
            last = det.process(&ev);
        }
        assert_eq!(last.expect("v6 subnet").source_ip.to_string(), "2001:db8:7:7::/64");
    }
}
