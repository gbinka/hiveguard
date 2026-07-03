use std::collections::VecDeque;
use std::net::IpAddr;
use std::time::Duration;

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use ipnet::IpNet;

use crate::detector::Detector;
use crate::models::{Action, DetectionSignal, EventType, NormalizedEvent};

/// HTTP 4xx flood detector.
///
/// Tracks 4xx error counts per IP in a sliding window.
/// Triggers when an IP exceeds the threshold within the window.
pub struct Http4xxFloodDetector {
    threshold: u32,
    window: Duration,
    ban_duration: Duration,
    /// Sliding window of 4xx timestamps per IP
    hits: DashMap<IpAddr, VecDeque<DateTime<Utc>>>,
}

impl Http4xxFloodDetector {
    pub fn new() -> Self {
        Self {
            threshold: 50,
            window: Duration::from_secs(60),        // 1 min
            ban_duration: Duration::from_secs(3600), // 1h
            hits: DashMap::new(),
        }
    }

    pub fn with_config(threshold: u32, window: Duration, ban_duration: Duration) -> Self {
        Self {
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

impl Default for Http4xxFloodDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for Http4xxFloodDetector {
    fn name(&self) -> &str {
        "http_4xx_flood"
    }

    fn process(&self, event: &NormalizedEvent) -> Option<DetectionSignal> {
        if event.event_type != EventType::Http4xx {
            return None;
        }

        let ip = event.source_ip;
        let now = event.timestamp;

        let mut deque = self.hits.entry(ip).or_default();
        deque.push_back(now);
        Self::prune_window(&mut deque, self.window, now);

        if deque.len() >= self.threshold as usize {
            let reason = format!(
                "HTTP 4xx flood: {} errors from {} in window",
                deque.len(),
                ip
            );
            let evidence_hash = Self::compute_evidence_hash(&ip, &reason);
            deque.clear();
            return Some(DetectionSignal {
                source_ip: Self::ip_to_net(ip),
                severity: 120,
                confidence: 0.8,
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

    fn make_4xx_event(ip: &str, ts: DateTime<Utc>) -> NormalizedEvent {
        let mut metadata = HashMap::new();
        metadata.insert("path".to_string(), "/some/path".to_string());
        metadata.insert("status_code".to_string(), "404".to_string());
        NormalizedEvent {
            timestamp: ts,
            source_ip: ip.parse().unwrap(),
            event_type: EventType::Http4xx,
            source_name: "nginx".to_string(),
            raw_line: "GET /some/path 404".to_string(),
            metadata,
        }
    }

    #[test]
    fn forty_nine_requests_no_ban() {
        let mut det = Http4xxFloodDetector::new(); // threshold=50
        let ip = "10.0.0.1";
        let base = Utc::now();

        for i in 0..49 {
            let ts = base + chrono::Duration::seconds(i);
            assert!(det.process(&make_4xx_event(ip, ts)).is_none());
        }
    }

    #[test]
    fn fifty_requests_triggers_ban() {
        let mut det = Http4xxFloodDetector::new(); // threshold=50
        let ip = "10.0.0.1";
        let base = Utc::now();

        let mut signal = None;
        for i in 0..50 {
            let ts = base + chrono::Duration::seconds(i);
            if let Some(s) = det.process(&make_4xx_event(ip, ts)) {
                signal = Some(s);
            }
        }

        let s = signal.expect("should have triggered at 50");
        assert_eq!(s.severity, 120);
        assert_eq!(s.confidence, 0.8);
        assert_eq!(s.suggested_action, Action::Ban(Duration::from_secs(3600)));
        assert_eq!(s.detector_name, "http_4xx_flood");
    }

    #[test]
    fn fifty_one_requests_triggers_ban() {
        let mut det = Http4xxFloodDetector::new(); // threshold=50
        let ip = "10.0.0.1";
        let base = Utc::now();

        let mut signal = None;
        for i in 0..51 {
            let ts = base + chrono::Duration::seconds(i);
            if let Some(s) = det.process(&make_4xx_event(ip, ts)) {
                signal = Some(s);
            }
        }
        assert!(signal.is_some(), "51 requests should trigger");
    }

    #[test]
    fn requests_outside_window_no_ban() {
        let mut det = Http4xxFloodDetector::new(); // threshold=50, window=60s
        let ip = "10.0.0.1";
        let base = Utc::now();

        // Send 50 requests spread over 120 seconds (2x the window)
        for i in 0..50 {
            let ts = base + chrono::Duration::milliseconds(i * 2400); // ~2.4s apart = 120s total
            assert!(
                det.process(&make_4xx_event(ip, ts)).is_none(),
                "should not trigger when spread over 2 minutes"
            );
        }
    }

    #[test]
    fn different_ips_independent() {
        let mut det = Http4xxFloodDetector::new(); // threshold=50
        let base = Utc::now();

        // 30 from each IP — neither reaches 50
        for i in 0..30 {
            let ts = base + chrono::Duration::seconds(i);
            assert!(det.process(&make_4xx_event("10.0.0.1", ts)).is_none());
            assert!(det.process(&make_4xx_event("10.0.0.2", ts)).is_none());
        }
    }

    #[test]
    fn http_request_event_ignored() {
        let mut det = Http4xxFloodDetector::new();
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
    fn http5xx_event_ignored() {
        let mut det = Http4xxFloodDetector::new();
        let event = NormalizedEvent {
            timestamp: Utc::now(),
            source_ip: "1.2.3.4".parse().unwrap(),
            event_type: EventType::Http5xx,
            source_name: "nginx".to_string(),
            raw_line: "GET /".to_string(),
            metadata: HashMap::new(),
        };
        assert!(det.process(&event).is_none());
    }

    #[test]
    fn auth_failure_event_ignored() {
        let mut det = Http4xxFloodDetector::new();
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
    fn custom_config_lower_threshold() {
        let mut det = Http4xxFloodDetector::with_config(
            10,
            Duration::from_secs(60),
            Duration::from_secs(7200),
        );
        let ip = "10.0.0.1";
        let base = Utc::now();

        let mut signal = None;
        for i in 0..10 {
            let ts = base + chrono::Duration::seconds(i);
            if let Some(s) = det.process(&make_4xx_event(ip, ts)) {
                signal = Some(s);
            }
        }

        let s = signal.expect("should trigger at custom threshold 10");
        assert_eq!(s.suggested_action, Action::Ban(Duration::from_secs(7200)));
    }

    #[test]
    fn window_resets_after_trigger() {
        let mut det = Http4xxFloodDetector::with_config(
            5,
            Duration::from_secs(60),
            Duration::from_secs(3600),
        );
        let ip = "10.0.0.1";
        let base = Utc::now();

        // Trigger with 5 events
        for i in 0..5 {
            let ts = base + chrono::Duration::seconds(i);
            det.process(&make_4xx_event(ip, ts));
        }

        // After trigger, 4 more should NOT trigger
        let base2 = base + chrono::Duration::seconds(10);
        for i in 0..4 {
            let ts = base2 + chrono::Duration::seconds(i);
            assert!(det.process(&make_4xx_event(ip, ts)).is_none());
        }

        // But 5th should trigger again
        let ts = base2 + chrono::Duration::seconds(4);
        let result = det.process(&make_4xx_event(ip, ts));
        assert!(result.is_some(), "should trigger again after reset");
    }

    #[test]
    fn ipv6_triggers() {
        let mut det = Http4xxFloodDetector::with_config(
            3,
            Duration::from_secs(60),
            Duration::from_secs(3600),
        );
        let ip = "2001:db8::1";
        let base = Utc::now();

        let mut signal = None;
        for i in 0..3 {
            let ts = base + chrono::Duration::seconds(i);
            if let Some(s) = det.process(&make_4xx_event(ip, ts)) {
                signal = Some(s);
            }
        }

        let s = signal.expect("IPv6 should trigger");
        assert!(s.source_ip.addr().to_string().contains("2001:db8"));
    }

    #[test]
    fn default_constructor() {
        let det = Http4xxFloodDetector::default();
        assert_eq!(det.threshold, 50);
        assert_eq!(det.window, Duration::from_secs(60));
        assert_eq!(det.ban_duration, Duration::from_secs(3600));
        assert_eq!(det.name(), "http_4xx_flood");
    }

    #[test]
    fn sliding_window_boundary() {
        let mut det = Http4xxFloodDetector::with_config(
            3,
            Duration::from_secs(60),
            Duration::from_secs(3600),
        );
        let ip = "10.0.0.1";
        let base = Utc::now();

        // Event at t=0
        det.process(&make_4xx_event(ip, base));
        // Event at t=30s
        det.process(&make_4xx_event(ip, base + chrono::Duration::seconds(30)));
        // Event at t=61s — first event pruned, only 2 in window
        let result = det.process(&make_4xx_event(ip, base + chrono::Duration::seconds(61)));
        assert!(result.is_none(), "first event should be pruned");
    }

    #[test]
    fn reason_contains_count_and_ip() {
        let mut det = Http4xxFloodDetector::with_config(
            3,
            Duration::from_secs(60),
            Duration::from_secs(3600),
        );
        let ip = "10.0.0.42";
        let base = Utc::now();

        let mut signal = None;
        for i in 0..3 {
            let ts = base + chrono::Duration::seconds(i);
            if let Some(s) = det.process(&make_4xx_event(ip, ts)) {
                signal = Some(s);
            }
        }

        let s = signal.unwrap();
        assert!(s.reason.contains("10.0.0.42"));
        assert!(s.reason.contains("HTTP 4xx flood"));
    }
}
