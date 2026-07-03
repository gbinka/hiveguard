use std::net::IpAddr;
use std::time::Duration;

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use ipnet::IpNet;

use crate::detector::Detector;
use crate::models::{Action, DetectionSignal, EventType, NormalizedEvent};

/// Request timing detector — identifies bot-like request patterns
/// by analyzing inter-arrival time standard deviation.
///
/// Bots tend to have very regular (low stddev) request intervals.
/// Severity: 40, confidence: 0.5, suggested action: Observe.
/// Heuristic signal — requires accumulation with other signals.
pub struct TimingDetector {
    /// Window size for collecting timestamps.
    window: Duration,
    /// Minimum number of requests to analyze.
    min_samples: usize,
    /// Stddev below this threshold (in ms) indicates bot behavior.
    stddev_threshold_ms: f64,
    /// Per-IP request timestamps.
    timestamps: DashMap<IpAddr, Vec<DateTime<Utc>>>,
}

impl TimingDetector {
    pub fn new() -> Self {
        Self {
            window: Duration::from_secs(60),
            min_samples: 10,
            stddev_threshold_ms: 50.0,
            timestamps: DashMap::new(),
        }
    }

    pub fn with_config(window: Duration, min_samples: usize, stddev_threshold_ms: f64) -> Self {
        Self {
            window,
            min_samples,
            stddev_threshold_ms,
            timestamps: DashMap::new(),
        }
    }

    fn ip_to_net(ip: IpAddr) -> IpNet {
        match ip {
            IpAddr::V4(v4) => IpNet::V4(ipnet::Ipv4Net::new(v4, 32).unwrap()),
            IpAddr::V6(v6) => IpNet::V6(ipnet::Ipv6Net::new(v6, 128).unwrap()),
        }
    }

    fn cleanup_old_entries(&self, ip: &IpAddr, now: DateTime<Utc>) {
        if let Some(mut timestamps) = self.timestamps.get_mut(ip) {
            let cutoff = now - chrono::Duration::from_std(self.window).unwrap_or(chrono::Duration::seconds(60));
            timestamps.retain(|t| *t > cutoff);
            if timestamps.is_empty() {
                drop(timestamps);
                self.timestamps.remove(ip);
            }
        }
    }
}

impl Default for TimingDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Compute standard deviation of inter-arrival times in milliseconds.
pub fn inter_arrival_stddev(timestamps: &[DateTime<Utc>]) -> Option<f64> {
    if timestamps.len() < 2 {
        return None;
    }

    let mut sorted = timestamps.to_vec();
    sorted.sort();

    let intervals: Vec<f64> = sorted
        .windows(2)
        .map(|w| {
            w[1].signed_duration_since(w[0])
                .num_milliseconds() as f64
        })
        .collect();

    if intervals.is_empty() {
        return None;
    }

    let mean = intervals.iter().sum::<f64>() / intervals.len() as f64;
    let variance = intervals.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / intervals.len() as f64;

    Some(variance.sqrt())
}

impl Detector for TimingDetector {
    fn name(&self) -> &str {
        "timing"
    }

    fn process(&self, event: &NormalizedEvent) -> Option<DetectionSignal> {
        match event.event_type {
            EventType::HttpRequest | EventType::Http4xx => {}
            _ => return None,
        }

        let ip = event.source_ip;
        self.cleanup_old_entries(&ip, event.timestamp);

        let mut timestamps = self.timestamps.entry(ip).or_default();
        timestamps.push(event.timestamp);

        if timestamps.len() < self.min_samples {
            return None;
        }

        let stddev = inter_arrival_stddev(&timestamps)?;

        if stddev < self.stddev_threshold_ms {
            let evidence = format!("{}:timing:stddev={:.1}ms", ip, stddev);
            Some(DetectionSignal {
                source_ip: Self::ip_to_net(ip),
                severity: 40,
                confidence: 0.5,
                reason: format!("Bot-like request timing (stddev={:.1}ms)", stddev),
                evidence_hash: *blake3::hash(evidence.as_bytes()).as_bytes(),
                suggested_action: Action::Observe,
                detector_name: "timing".into(),
                timestamp: event.timestamp,
            })
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use std::collections::HashMap;

    fn make_http_event_at(ip: &str, ts: DateTime<Utc>) -> NormalizedEvent {
        let mut metadata = HashMap::new();
        metadata.insert("path".to_string(), "/api/data".to_string());
        NormalizedEvent {
            timestamp: ts,
            source_ip: ip.parse().unwrap(),
            event_type: EventType::HttpRequest,
            source_name: "test".into(),
            raw_line: "GET /api/data".into(),
            metadata,
        }
    }

    #[test]
    fn inter_arrival_stddev_empty() {
        assert!(inter_arrival_stddev(&[]).is_none());
    }

    #[test]
    fn inter_arrival_stddev_single() {
        assert!(inter_arrival_stddev(&[Utc::now()]).is_none());
    }

    #[test]
    fn inter_arrival_stddev_uniform() {
        let base = Utc::now();
        let timestamps: Vec<_> = (0..10)
            .map(|i| base + chrono::Duration::milliseconds(i * 100))
            .collect();
        let stddev = inter_arrival_stddev(&timestamps).unwrap();
        assert!(stddev < 1.0, "Uniform intervals should have ~0 stddev, got {stddev}");
    }

    #[test]
    fn inter_arrival_stddev_varied() {
        let base = Utc::now();
        let timestamps = vec![
            base,
            base + chrono::Duration::milliseconds(100),
            base + chrono::Duration::milliseconds(500),
            base + chrono::Duration::milliseconds(510),
            base + chrono::Duration::milliseconds(1500),
        ];
        let stddev = inter_arrival_stddev(&timestamps).unwrap();
        assert!(stddev > 50.0, "Varied intervals should have higher stddev, got {stddev}");
    }

    #[test]
    fn detector_bot_like_timing() {
        let mut d = TimingDetector::with_config(Duration::from_secs(60), 5, 50.0);
        let base = Utc::now();

        // Simulate bot: exactly 100ms intervals
        for i in 0..5 {
            let event = make_http_event_at("10.0.0.1", base + chrono::Duration::milliseconds(i * 100));
            let result = d.process(&event);
            if i == 4 {
                // Should detect on the 5th event
                assert!(result.is_some(), "Should detect bot-like timing");
                let s = result.unwrap();
                assert_eq!(s.severity, 40);
                assert_eq!(s.suggested_action, Action::Observe);
            }
        }
    }

    #[test]
    fn detector_human_like_timing_no_signal() {
        let mut d = TimingDetector::with_config(Duration::from_secs(60), 5, 50.0);
        let base = Utc::now();

        // Simulate human: widely varied intervals (stddev >> 50ms)
        let offsets = [0, 200, 1200, 1350, 3000, 3500, 7000, 7100, 12000, 18500];
        let mut last_result = None;
        for &offset in &offsets {
            let event = make_http_event_at("10.0.0.1", base + chrono::Duration::milliseconds(offset));
            last_result = d.process(&event);
        }

        // With such varied intervals, stddev should be well above 50ms
        assert!(last_result.is_none(), "Human-like timing should NOT trigger signal");
    }

    #[test]
    fn insufficient_samples_no_detection() {
        let mut d = TimingDetector::with_config(Duration::from_secs(60), 10, 50.0);
        let base = Utc::now();

        for i in 0..5 {
            let event = make_http_event_at("10.0.0.1", base + chrono::Duration::milliseconds(i * 100));
            assert!(d.process(&event).is_none());
        }
    }

    #[test]
    fn ignores_non_http_events() {
        let mut d = TimingDetector::new();
        let event = NormalizedEvent {
            timestamp: Utc::now(),
            source_ip: "10.0.0.1".parse().unwrap(),
            event_type: EventType::AuthFailure,
            source_name: "test".into(),
            raw_line: "failure".into(),
            metadata: HashMap::new(),
        };
        assert!(d.process(&event).is_none());
    }

    // --- Phase 20: comprehensive coverage ---

    #[test]
    fn bot_exact_intervals_stddev_near_zero() {
        let base = Utc::now();
        // 20 requests at exactly 50ms intervals
        let timestamps: Vec<_> = (0..20)
            .map(|i| base + chrono::Duration::milliseconds(i * 50))
            .collect();
        let stddev = inter_arrival_stddev(&timestamps).unwrap();
        assert!(stddev < 1.0, "Exact intervals should have stddev ~0, got {stddev}");
    }

    #[test]
    fn human_varied_intervals_stddev_high() {
        let base = Utc::now();
        // Random-ish human intervals
        let offsets = [0, 523, 1247, 2891, 3004, 5672, 6100, 9833, 10200, 15000];
        let timestamps: Vec<_> = offsets.iter()
            .map(|&ms| base + chrono::Duration::milliseconds(ms))
            .collect();
        let stddev = inter_arrival_stddev(&timestamps).unwrap();
        assert!(stddev > 100.0, "Human-like varied intervals should have high stddev, got {stddev}");
    }

    #[test]
    fn detector_ipv6_bot_timing() {
        let mut d = TimingDetector::with_config(Duration::from_secs(60), 5, 50.0);
        let base = Utc::now();

        let mut last = None;
        for i in 0..5 {
            let event = make_http_event_at("2001:db8::1", base + chrono::Duration::milliseconds(i * 100));
            last = d.process(&event);
        }
        assert!(last.is_some(), "IPv6 bot should trigger");
        let s = last.unwrap();
        assert!(s.source_ip.addr().to_string().contains("2001:db8"));
    }

    #[test]
    fn detector_different_ips_independent() {
        let mut d = TimingDetector::with_config(Duration::from_secs(60), 5, 50.0);
        let base = Utc::now();

        // IP1: 3 requests (below threshold)
        for i in 0..3 {
            let event = make_http_event_at("10.0.0.1", base + chrono::Duration::milliseconds(i * 100));
            assert!(d.process(&event).is_none());
        }

        // IP2: 5 regular requests → triggers
        let mut last = None;
        for i in 0..5 {
            let event = make_http_event_at("10.0.0.2", base + chrono::Duration::milliseconds(i * 100));
            last = d.process(&event);
        }
        assert!(last.is_some());
    }

    #[test]
    fn detector_confidence_is_05() {
        let mut d = TimingDetector::with_config(Duration::from_secs(60), 5, 50.0);
        let base = Utc::now();

        let mut last = None;
        for i in 0..5 {
            let event = make_http_event_at("10.0.0.1", base + chrono::Duration::milliseconds(i * 100));
            last = d.process(&event);
        }
        let s = last.unwrap();
        assert!((s.confidence - 0.5).abs() < f32::EPSILON);
    }

    #[test]
    fn detector_reason_contains_stddev() {
        let mut d = TimingDetector::with_config(Duration::from_secs(60), 5, 50.0);
        let base = Utc::now();

        let mut last = None;
        for i in 0..5 {
            let event = make_http_event_at("10.0.0.1", base + chrono::Duration::milliseconds(i * 100));
            last = d.process(&event);
        }
        let s = last.unwrap();
        assert!(s.reason.contains("stddev="), "Reason should contain stddev value");
    }

    #[test]
    fn detector_default_constructor() {
        let d = TimingDetector::default();
        assert_eq!(d.name(), "timing");
        assert_eq!(d.window, Duration::from_secs(60));
        assert_eq!(d.min_samples, 10);
        assert!((d.stddev_threshold_ms - 50.0).abs() < f64::EPSILON);
    }

    #[test]
    fn detector_http4xx_events_also_tracked() {
        let mut d = TimingDetector::with_config(Duration::from_secs(60), 5, 50.0);
        let base = Utc::now();

        let mut last = None;
        for i in 0..5 {
            let mut metadata = HashMap::new();
            metadata.insert("path".to_string(), "/api/data".to_string());
            let event = NormalizedEvent {
                timestamp: base + chrono::Duration::milliseconds(i * 100),
                source_ip: "10.0.0.1".parse().unwrap(),
                event_type: EventType::Http4xx,
                source_name: "test".into(),
                raw_line: "GET /api/data".into(),
                metadata,
            };
            last = d.process(&event);
        }
        assert!(last.is_some());
    }

    #[test]
    fn detector_smtp_event_ignored() {
        let mut d = TimingDetector::new();
        let event = NormalizedEvent {
            timestamp: Utc::now(),
            source_ip: "10.0.0.1".parse().unwrap(),
            event_type: EventType::SmtpAuthFailure,
            source_name: "test".into(),
            raw_line: "failure".into(),
            metadata: HashMap::new(),
        };
        assert!(d.process(&event).is_none());
    }

    #[test]
    fn custom_config_lower_threshold() {
        let mut d = TimingDetector::with_config(Duration::from_secs(30), 3, 100.0);
        let base = Utc::now();

        // 3 uniform requests → stddev = 0 < 100ms → triggers
        let mut last = None;
        for i in 0..3 {
            let event = make_http_event_at("10.0.0.1", base + chrono::Duration::milliseconds(i * 200));
            last = d.process(&event);
        }
        assert!(last.is_some());
    }
}
