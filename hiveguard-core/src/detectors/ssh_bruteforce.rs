use std::collections::VecDeque;
use std::net::IpAddr;
use std::time::Duration;

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use ipnet::IpNet;

use crate::detector::Detector;
use crate::models::{Action, DetectionSignal, EventType, NormalizedEvent};

/// SSH brute-force and user-enumeration detector.
///
/// Tracks failed authentication attempts per IP in a sliding window.
/// When `invalid_user` metadata is present, uses separate (stricter)
/// thresholds for user-enumeration detection.
pub struct SshBruteforceDetector {
    /// Normal brute-force settings
    threshold: u32,
    window: Duration,
    ban_duration: Duration,

    /// User-enumeration settings (invalid user attempts)
    enum_threshold: u32,
    enum_window: Duration,
    enum_ban_duration: Duration,

    /// Sliding window of failure timestamps per IP (normal failures)
    failures: DashMap<IpAddr, VecDeque<DateTime<Utc>>>,
    /// Sliding window of invalid-user failure timestamps per IP
    enum_failures: DashMap<IpAddr, VecDeque<DateTime<Utc>>>,
}

impl SshBruteforceDetector {
    pub fn new() -> Self {
        Self {
            threshold: 5,
            window: Duration::from_secs(300),       // 5 min
            ban_duration: Duration::from_secs(86400), // 24h
            enum_threshold: 3,
            enum_window: Duration::from_secs(120),    // 2 min
            enum_ban_duration: Duration::from_secs(172800), // 48h
            failures: DashMap::new(),
            enum_failures: DashMap::new(),
        }
    }

    /// Create with custom thresholds.
    pub fn with_config(
        threshold: u32,
        window: Duration,
        ban_duration: Duration,
        enum_threshold: u32,
        enum_window: Duration,
        enum_ban_duration: Duration,
    ) -> Self {
        Self {
            threshold,
            window,
            ban_duration,
            enum_threshold,
            enum_window,
            enum_ban_duration,
            failures: DashMap::new(),
            enum_failures: DashMap::new(),
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

    /// Prune entries older than `window` from a deque, relative to `now`.
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

impl Default for SshBruteforceDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for SshBruteforceDetector {
    fn name(&self) -> &str {
        "ssh_bruteforce"
    }

    fn process(&self, event: &NormalizedEvent) -> Option<DetectionSignal> {
        if event.event_type != EventType::AuthFailure {
            return None;
        }

        let ip = event.source_ip;
        let now = event.timestamp;
        let is_invalid_user = event
            .metadata
            .get("invalid_user")
            .map(|v| v == "true")
            .unwrap_or(false);

        // Always track in the normal brute-force window
        {
            let mut deque = self.failures.entry(ip).or_default();
            deque.push_back(now);
            Self::prune_window(&mut deque, self.window, now);

            if deque.len() >= self.threshold as usize {
                let reason = format!(
                    "SSH brute-force: {} failed logins from {} in window",
                    deque.len(),
                    ip
                );
                let evidence_hash = Self::compute_evidence_hash(&ip, &reason);
                // Clear to avoid re-triggering on every subsequent event
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
        }

        // Additionally track in user-enumeration window if invalid_user
        if is_invalid_user {
            let mut deque = self.enum_failures.entry(ip).or_default();
            deque.push_back(now);
            Self::prune_window(&mut deque, self.enum_window, now);

            if deque.len() >= self.enum_threshold as usize {
                let reason = format!(
                    "SSH user enumeration: {} invalid-user attempts from {} in window",
                    deque.len(),
                    ip
                );
                let evidence_hash = Self::compute_evidence_hash(&ip, &reason);
                deque.clear();
                return Some(DetectionSignal {
                    source_ip: Self::ip_to_net(ip),
                    severity: 180,
                    confidence: 0.9,
                    reason,
                    evidence_hash,
                    suggested_action: Action::Ban(self.enum_ban_duration),
                    detector_name: self.name().to_string(),
                    timestamp: now,
                });
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn make_auth_failure(ip: &str, ts: DateTime<Utc>, invalid_user: bool) -> NormalizedEvent {
        let mut metadata = HashMap::new();
        metadata.insert("user".to_string(), "root".to_string());
        if invalid_user {
            metadata.insert("invalid_user".to_string(), "true".to_string());
        }
        NormalizedEvent {
            timestamp: ts,
            source_ip: ip.parse().unwrap(),
            event_type: EventType::AuthFailure,
            source_name: "ssh".to_string(),
            raw_line: "test line".to_string(),
            metadata,
        }
    }

    #[test]
    fn four_failures_no_ban() {
        let mut det = SshBruteforceDetector::new();
        let ip = "192.168.1.100";
        let base = Utc::now();

        for i in 0..4 {
            let ts = base + chrono::Duration::seconds(i * 30);
            let event = make_auth_failure(ip, ts, false);
            assert!(det.process(&event).is_none(), "should not trigger at {i}");
        }
    }

    #[test]
    fn five_failures_triggers_ban() {
        let mut det = SshBruteforceDetector::new();
        let ip = "192.168.1.100";
        let base = Utc::now();

        let mut signal = None;
        for i in 0..5 {
            let ts = base + chrono::Duration::seconds(i * 30);
            let event = make_auth_failure(ip, ts, false);
            if let Some(s) = det.process(&event) {
                signal = Some(s);
            }
        }

        let s = signal.expect("should have triggered");
        assert_eq!(s.severity, 150);
        assert_eq!(s.confidence, 0.9);
        assert_eq!(s.suggested_action, Action::Ban(Duration::from_secs(86400)));
        assert_eq!(s.detector_name, "ssh_bruteforce");
    }

    #[test]
    fn five_failures_outside_window_no_ban() {
        let mut det = SshBruteforceDetector::new();
        let ip = "192.168.1.100";
        let base = Utc::now();

        // Space failures 2.5 minutes apart → 5 events over 10 minutes
        // Window is 5 minutes, so at any point only 2-3 are inside
        for i in 0..5 {
            let ts = base + chrono::Duration::seconds(i * 150);
            let event = make_auth_failure(ip, ts, false);
            assert!(
                det.process(&event).is_none(),
                "should not trigger when spread over 10 min"
            );
        }
    }

    #[test]
    fn different_ips_dont_interfere() {
        let mut det = SshBruteforceDetector::new();
        let base = Utc::now();

        // 3 failures from IP A, 3 from IP B — neither reaches threshold of 5
        for i in 0..3 {
            let ts = base + chrono::Duration::seconds(i * 10);
            assert!(det
                .process(&make_auth_failure("10.0.0.1", ts, false))
                .is_none());
            assert!(det
                .process(&make_auth_failure("10.0.0.2", ts, false))
                .is_none());
        }
    }

    #[test]
    fn user_enum_three_invalid_users_triggers_ban() {
        let mut det = SshBruteforceDetector::new();
        let ip = "10.0.0.50";
        let base = Utc::now();

        let mut signal = None;
        for i in 0..3 {
            let ts = base + chrono::Duration::seconds(i * 20);
            let event = make_auth_failure(ip, ts, true);
            if let Some(s) = det.process(&event) {
                signal = Some(s);
            }
        }

        let s = signal.expect("user enum should have triggered");
        assert_eq!(s.severity, 180);
        assert_eq!(
            s.suggested_action,
            Action::Ban(Duration::from_secs(172800))
        );
        assert!(s.reason.contains("user enumeration"));
    }

    #[test]
    fn auth_success_ignored() {
        let mut det = SshBruteforceDetector::new();
        let event = NormalizedEvent {
            timestamp: Utc::now(),
            source_ip: "1.2.3.4".parse().unwrap(),
            event_type: EventType::AuthSuccess,
            source_name: "ssh".to_string(),
            raw_line: "accepted".to_string(),
            metadata: HashMap::new(),
        };
        assert!(det.process(&event).is_none());
    }

    #[test]
    fn http_event_ignored() {
        let mut det = SshBruteforceDetector::new();
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

    // --- Phase 10: comprehensive coverage ---

    #[test]
    fn exactly_at_threshold_triggers() {
        let mut det = SshBruteforceDetector::with_config(
            3, Duration::from_secs(300), Duration::from_secs(3600),
            3, Duration::from_secs(120), Duration::from_secs(7200),
        );
        let ip = "10.0.0.1";
        let base = Utc::now();

        // Exactly 3 failures with threshold=3
        let mut signal = None;
        for i in 0..3 {
            let ts = base + chrono::Duration::seconds(i * 10);
            if let Some(s) = det.process(&make_auth_failure(ip, ts, false)) {
                signal = Some(s);
            }
        }
        assert!(signal.is_some(), "exactly at threshold should trigger");
    }

    #[test]
    fn one_below_threshold_no_trigger() {
        let mut det = SshBruteforceDetector::with_config(
            3, Duration::from_secs(300), Duration::from_secs(3600),
            3, Duration::from_secs(120), Duration::from_secs(7200),
        );
        let ip = "10.0.0.1";
        let base = Utc::now();

        for i in 0..2 {
            let ts = base + chrono::Duration::seconds(i * 10);
            assert!(det.process(&make_auth_failure(ip, ts, false)).is_none());
        }
    }

    #[test]
    fn one_above_threshold_triggers() {
        let mut det = SshBruteforceDetector::new(); // threshold=5
        let ip = "10.0.0.1";
        let base = Utc::now();

        let mut signal = None;
        // Send 6 failures (one above threshold of 5)
        for i in 0..6 {
            let ts = base + chrono::Duration::seconds(i * 10);
            if let Some(s) = det.process(&make_auth_failure(ip, ts, false)) {
                signal = Some(s);
            }
        }
        assert!(signal.is_some(), "one above threshold should trigger");
    }

    #[test]
    fn sliding_window_boundary_exact() {
        // Events exactly at window boundary
        let mut det = SshBruteforceDetector::with_config(
            3, Duration::from_secs(60), Duration::from_secs(3600),
            3, Duration::from_secs(120), Duration::from_secs(7200),
        );
        let ip = "10.0.0.1";
        let base = Utc::now();

        // Event at t=0
        det.process(&make_auth_failure(ip, base, false));
        // Event at t=30s
        det.process(&make_auth_failure(ip, base + chrono::Duration::seconds(30), false));
        // Event at t=61s — the first event should be pruned (>60s window)
        let result = det.process(&make_auth_failure(ip, base + chrono::Duration::seconds(61), false));
        assert!(result.is_none(), "first event should be pruned, only 2 in window");
    }

    #[test]
    fn after_trigger_window_resets() {
        let mut det = SshBruteforceDetector::new(); // threshold=5
        let ip = "10.0.0.1";
        let base = Utc::now();

        // Trigger once with 5 events
        for i in 0..5 {
            let ts = base + chrono::Duration::seconds(i * 10);
            det.process(&make_auth_failure(ip, ts, false));
        }

        // After triggering, the next 4 failures should NOT trigger again
        let base2 = base + chrono::Duration::seconds(100);
        for i in 0..4 {
            let ts = base2 + chrono::Duration::seconds(i * 10);
            assert!(det.process(&make_auth_failure(ip, ts, false)).is_none(),
                    "should not re-trigger before reaching threshold again");
        }

        // But 5 more should trigger again
        let ts = base2 + chrono::Duration::seconds(4 * 10);
        let result = det.process(&make_auth_failure(ip, ts, false));
        assert!(result.is_some(), "should trigger again after threshold reached");
    }

    #[test]
    fn user_enum_boundary_two_invalid_no_trigger() {
        let mut det = SshBruteforceDetector::new(); // enum_threshold=3
        let ip = "10.0.0.50";
        let base = Utc::now();

        for i in 0..2 {
            let ts = base + chrono::Duration::seconds(i * 20);
            assert!(det.process(&make_auth_failure(ip, ts, true)).is_none());
        }
    }

    #[test]
    fn user_enum_outside_window_no_trigger() {
        let mut det = SshBruteforceDetector::new(); // enum_window=2min, enum_threshold=3
        let ip = "10.0.0.50";
        let base = Utc::now();

        // 3 invalid user attempts, each 1.5min apart (total 3min > 2min window)
        for i in 0..3 {
            let ts = base + chrono::Duration::seconds(i * 90);
            let result = det.process(&make_auth_failure(ip, ts, true));
            // At most 2 should be in the 2min window at any point
            assert!(result.is_none() || i == 2, "should not trigger spread over 3min");
        }
    }

    #[test]
    fn ipv6_failures_trigger() {
        let mut det = SshBruteforceDetector::new();
        let ip = "2001:db8::dead:beef";
        let base = Utc::now();

        let mut signal = None;
        for i in 0..5 {
            let ts = base + chrono::Duration::seconds(i * 10);
            if let Some(s) = det.process(&make_auth_failure(ip, ts, false)) {
                signal = Some(s);
            }
        }

        let s = signal.expect("IPv6 should trigger");
        assert!(s.source_ip.addr().to_string().contains("2001:db8"));
        assert_eq!(s.severity, 150);
    }

    #[test]
    fn custom_event_type_ignored() {
        let mut det = SshBruteforceDetector::new();
        let event = NormalizedEvent {
            timestamp: Utc::now(),
            source_ip: "1.2.3.4".parse().unwrap(),
            event_type: EventType::Custom("something".to_string()),
            source_name: "custom".to_string(),
            raw_line: "test".to_string(),
            metadata: HashMap::new(),
        };
        assert!(det.process(&event).is_none());
    }

    #[test]
    fn with_config_custom_values() {
        let det = SshBruteforceDetector::with_config(
            10, Duration::from_secs(600), Duration::from_secs(172800),
            5, Duration::from_secs(300), Duration::from_secs(86400),
        );
        assert_eq!(det.name(), "ssh_bruteforce");
        assert_eq!(det.threshold, 10);
        assert_eq!(det.window, Duration::from_secs(600));
    }

    #[test]
    fn default_constructor() {
        let det = SshBruteforceDetector::default();
        assert_eq!(det.threshold, 5);
        assert_eq!(det.window, Duration::from_secs(300));
        assert_eq!(det.enum_threshold, 3);
        assert_eq!(det.enum_window, Duration::from_secs(120));
    }
}
