use std::collections::VecDeque;
use std::net::IpAddr;
use std::time::Duration;

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use ipnet::IpNet;

use crate::detector::Detector;
use crate::models::{Action, DetectionSignal, EventType, NormalizedEvent};

/// SMTP brute-force detector.
///
/// Tracks SMTP authentication failure counts per IP in a sliding window.
/// Analogous to SSH brute-force detector but operates on `SmtpAuthFailure` events.
pub struct SmtpBruteforceDetector {
    threshold: u32,
    window: Duration,
    ban_duration: Duration,
    /// Sliding window of failure timestamps per IP
    failures: DashMap<IpAddr, VecDeque<DateTime<Utc>>>,
}

impl SmtpBruteforceDetector {
    pub fn new() -> Self {
        Self {
            threshold: 5,
            window: Duration::from_secs(300),       // 5 min
            ban_duration: Duration::from_secs(86400), // 24h
            failures: DashMap::new(),
        }
    }

    pub fn with_config(threshold: u32, window: Duration, ban_duration: Duration) -> Self {
        Self {
            threshold,
            window,
            ban_duration,
            failures: DashMap::new(),
        }
    }

    fn ip_to_net(ip: IpAddr) -> IpNet {
        match ip {
            IpAddr::V4(v4) => IpNet::V4(ipnet::Ipv4Net::new(v4, 32).unwrap()),
            IpAddr::V6(v6) => IpNet::V6(ipnet::Ipv6Net::new(v6, 128).unwrap()),
        }
    }

    fn compute_evidence_hash(ip: &IpAddr, reason: &str) -> [u8; 32] {
        let input = format!("{ip}:{reason}");
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
}

impl Default for SmtpBruteforceDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for SmtpBruteforceDetector {
    fn name(&self) -> &str {
        "smtp_bruteforce"
    }

    fn process(&self, event: &NormalizedEvent) -> Option<DetectionSignal> {
        if event.event_type != EventType::SmtpAuthFailure {
            return None;
        }

        let ip = event.source_ip;
        let now = event.timestamp;

        let mut deque = self.failures.entry(ip).or_default();
        deque.push_back(now);
        Self::prune_window(&mut deque, self.window, now);

        if deque.len() >= self.threshold as usize {
            let reason = format!(
                "SMTP brute-force: {} failed SASL authentications from {} in window",
                deque.len(),
                ip
            );
            let evidence_hash = Self::compute_evidence_hash(&ip, &reason);
            deque.clear();
            return Some(DetectionSignal {
                source_ip: Self::ip_to_net(ip),
                severity: 150,
                confidence: 0.9,
                reason,
                evidence_hash,
                suggested_action: Action::Ban(self.ban_duration),
                detector_name: self.name().to_string(),
                timestamp: now,
            });
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn make_smtp_failure(ip: &str, ts: DateTime<Utc>) -> NormalizedEvent {
        let mut metadata = HashMap::new();
        metadata.insert("mechanism".to_string(), "LOGIN".to_string());
        NormalizedEvent {
            timestamp: ts,
            source_ip: ip.parse().unwrap(),
            event_type: EventType::SmtpAuthFailure,
            source_name: "postfix".to_string(),
            raw_line: "SASL LOGIN authentication failed".to_string(),
            metadata,
        }
    }

    #[test]
    fn four_failures_no_ban() {
        let mut det = SmtpBruteforceDetector::new();
        let ip = "192.168.1.100";
        let base = Utc::now();

        for i in 0..4 {
            let ts = base + chrono::Duration::seconds(i * 30);
            assert!(det.process(&make_smtp_failure(ip, ts)).is_none());
        }
    }

    #[test]
    fn five_failures_triggers_ban() {
        let mut det = SmtpBruteforceDetector::new();
        let ip = "192.168.1.100";
        let base = Utc::now();

        let mut signal = None;
        for i in 0..5 {
            let ts = base + chrono::Duration::seconds(i * 30);
            if let Some(s) = det.process(&make_smtp_failure(ip, ts)) {
                signal = Some(s);
            }
        }

        let s = signal.expect("should have triggered");
        assert_eq!(s.severity, 150);
        assert_eq!(s.confidence, 0.9);
        assert_eq!(s.suggested_action, Action::Ban(Duration::from_secs(86400)));
        assert_eq!(s.detector_name, "smtp_bruteforce");
        assert!(s.reason.contains("SMTP brute-force"));
    }

    #[test]
    fn six_failures_triggers_ban() {
        let mut det = SmtpBruteforceDetector::new();
        let ip = "192.168.1.100";
        let base = Utc::now();

        let mut signal = None;
        for i in 0..6 {
            let ts = base + chrono::Duration::seconds(i * 10);
            if let Some(s) = det.process(&make_smtp_failure(ip, ts)) {
                signal = Some(s);
            }
        }
        assert!(signal.is_some());
    }

    #[test]
    fn failures_outside_window_no_ban() {
        let mut det = SmtpBruteforceDetector::new(); // window=5min
        let ip = "192.168.1.100";
        let base = Utc::now();

        // 5 failures spread over 10 minutes
        for i in 0..5 {
            let ts = base + chrono::Duration::seconds(i * 150);
            assert!(
                det.process(&make_smtp_failure(ip, ts)).is_none(),
                "should not trigger when spread over 10min"
            );
        }
    }

    #[test]
    fn different_ips_independent() {
        let mut det = SmtpBruteforceDetector::new();
        let base = Utc::now();

        for i in 0..3 {
            let ts = base + chrono::Duration::seconds(i * 10);
            assert!(det.process(&make_smtp_failure("10.0.0.1", ts)).is_none());
            assert!(det.process(&make_smtp_failure("10.0.0.2", ts)).is_none());
        }
    }

    #[test]
    fn auth_failure_event_ignored() {
        let mut det = SmtpBruteforceDetector::new();
        let event = NormalizedEvent {
            timestamp: Utc::now(),
            source_ip: "1.2.3.4".parse().unwrap(),
            event_type: EventType::AuthFailure,
            source_name: "ssh".to_string(),
            raw_line: "test".to_string(),
            metadata: HashMap::new(),
        };
        assert!(det.process(&event).is_none());
    }

    #[test]
    fn http_event_ignored() {
        let mut det = SmtpBruteforceDetector::new();
        let event = NormalizedEvent {
            timestamp: Utc::now(),
            source_ip: "1.2.3.4".parse().unwrap(),
            event_type: EventType::HttpRequest,
            source_name: "nginx".to_string(),
            raw_line: "GET /".to_string(),
            metadata: HashMap::new(),
        };
        assert!(det.process(&event).is_none());
    }

    #[test]
    fn custom_config() {
        let mut det = SmtpBruteforceDetector::with_config(
            3,
            Duration::from_secs(120),
            Duration::from_secs(7200),
        );
        let ip = "10.0.0.1";
        let base = Utc::now();

        let mut signal = None;
        for i in 0..3 {
            let ts = base + chrono::Duration::seconds(i * 10);
            if let Some(s) = det.process(&make_smtp_failure(ip, ts)) {
                signal = Some(s);
            }
        }

        let s = signal.expect("should trigger at custom threshold 3");
        assert_eq!(s.suggested_action, Action::Ban(Duration::from_secs(7200)));
    }

    #[test]
    fn window_resets_after_trigger() {
        let mut det = SmtpBruteforceDetector::new(); // threshold=5
        let ip = "10.0.0.1";
        let base = Utc::now();

        // Trigger with 5 events
        for i in 0..5 {
            let ts = base + chrono::Duration::seconds(i * 10);
            det.process(&make_smtp_failure(ip, ts));
        }

        // After trigger, 4 more should NOT trigger
        let base2 = base + chrono::Duration::seconds(100);
        for i in 0..4 {
            let ts = base2 + chrono::Duration::seconds(i * 10);
            assert!(det.process(&make_smtp_failure(ip, ts)).is_none());
        }

        // 5th should trigger again
        let ts = base2 + chrono::Duration::seconds(4 * 10);
        let result = det.process(&make_smtp_failure(ip, ts));
        assert!(result.is_some(), "should trigger again after reset");
    }

    #[test]
    fn ipv6_failures_trigger() {
        let mut det = SmtpBruteforceDetector::new();
        let ip = "2001:db8::1";
        let base = Utc::now();

        let mut signal = None;
        for i in 0..5 {
            let ts = base + chrono::Duration::seconds(i * 10);
            if let Some(s) = det.process(&make_smtp_failure(ip, ts)) {
                signal = Some(s);
            }
        }

        let s = signal.expect("IPv6 should trigger");
        assert!(s.source_ip.addr().to_string().contains("2001:db8"));
        assert_eq!(s.severity, 150);
    }

    #[test]
    fn default_constructor() {
        let det = SmtpBruteforceDetector::default();
        assert_eq!(det.threshold, 5);
        assert_eq!(det.window, Duration::from_secs(300));
        assert_eq!(det.ban_duration, Duration::from_secs(86400));
        assert_eq!(det.name(), "smtp_bruteforce");
    }

    #[test]
    fn sliding_window_boundary() {
        let mut det = SmtpBruteforceDetector::with_config(
            3,
            Duration::from_secs(60),
            Duration::from_secs(3600),
        );
        let ip = "10.0.0.1";
        let base = Utc::now();

        // Event at t=0
        det.process(&make_smtp_failure(ip, base));
        // Event at t=30s
        det.process(&make_smtp_failure(ip, base + chrono::Duration::seconds(30)));
        // Event at t=61s — first event pruned, only 2 in window
        let result = det.process(&make_smtp_failure(ip, base + chrono::Duration::seconds(61)));
        assert!(result.is_none(), "first event should be pruned");
    }

    #[test]
    fn reason_contains_ip() {
        let mut det = SmtpBruteforceDetector::with_config(
            3,
            Duration::from_secs(300),
            Duration::from_secs(86400),
        );
        let ip = "10.0.0.42";
        let base = Utc::now();

        let mut signal = None;
        for i in 0..3 {
            let ts = base + chrono::Duration::seconds(i * 10);
            if let Some(s) = det.process(&make_smtp_failure(ip, ts)) {
                signal = Some(s);
            }
        }

        let s = signal.unwrap();
        assert!(s.reason.contains("10.0.0.42"));
        assert!(s.reason.contains("SMTP brute-force"));
        assert!(s.reason.contains("SASL"));
    }

    #[test]
    fn auth_success_ignored() {
        let mut det = SmtpBruteforceDetector::new();
        let event = NormalizedEvent {
            timestamp: Utc::now(),
            source_ip: "1.2.3.4".parse().unwrap(),
            event_type: EventType::AuthSuccess,
            source_name: "postfix".to_string(),
            raw_line: "test".to_string(),
            metadata: HashMap::new(),
        };
        assert!(det.process(&event).is_none());
    }
}
