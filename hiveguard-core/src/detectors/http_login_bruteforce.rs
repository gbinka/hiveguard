use std::collections::VecDeque;
use std::net::IpAddr;
use std::time::Duration;

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use ipnet::IpNet;

use crate::detector::Detector;
use crate::models::{Action, DetectionSignal, EventType, NormalizedEvent};

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
}

impl HttpLoginBruteforceDetector {
    pub fn new() -> Self {
        Self {
            paths: default_login_paths(),
            threshold: 5,
            window: Duration::from_secs(600), // 10 min
            ban_duration: Duration::from_secs(86400), // 24h
            hits: DashMap::new(),
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
        }
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

        let mut deque = self.hits.entry(ip).or_default();
        deque.push_back(now);
        Self::prune_window(&mut deque, self.window, now);

        let count = deque.len() as u32;
        if count < self.threshold {
            return None;
        }

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
}
