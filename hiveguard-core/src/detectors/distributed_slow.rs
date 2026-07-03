use std::net::IpAddr;
use std::time::Duration;

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use ipnet::IpNet;

use crate::detector::Detector;
use crate::models::{Action, DetectionSignal, EventType, NormalizedEvent};

/// Distributed slow attack detector — detects multiple IPs from the same /24
/// subnet sending similar requests, suggesting a coordinated attack.
pub struct DistributedSlowDetector {
    /// Window for tracking.
    window: Duration,
    /// Number of unique IPs from same /24 to trigger.
    ip_threshold: usize,
    /// Ban duration for the /24 subnet.
    ban_duration: Duration,
    /// Per-subnet: set of IPs and their last-seen timestamps.
    subnet_activity: DashMap<IpNet, Vec<(IpAddr, DateTime<Utc>)>>,
}

impl DistributedSlowDetector {
    pub fn new() -> Self {
        Self {
            window: Duration::from_secs(600), // 10 minutes
            ip_threshold: 5,
            ban_duration: Duration::from_secs(12 * 3600), // 12h
            subnet_activity: DashMap::new(),
        }
    }

    pub fn with_config(window: Duration, ip_threshold: usize, ban_duration: Duration) -> Self {
        Self {
            window,
            ip_threshold,
            ban_duration,
            subnet_activity: DashMap::new(),
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
                // Zero out segments after /48
                for seg in segments[3..].iter_mut() {
                    *seg = 0;
                }
                let subnet_ip = std::net::Ipv6Addr::from(segments);
                Some(IpNet::V6(ipnet::Ipv6Net::new(subnet_ip, 48).ok()?))
            }
        }
    }

    fn cleanup_old_entries(&self, subnet: &IpNet, now: DateTime<Utc>) {
        if let Some(mut entries) = self.subnet_activity.get_mut(subnet) {
            let cutoff = now - chrono::Duration::from_std(self.window).unwrap_or(chrono::Duration::seconds(600));
            entries.retain(|(_, t)| *t > cutoff);
            if entries.is_empty() {
                drop(entries);
                self.subnet_activity.remove(subnet);
            }
        }
    }
}

impl Default for DistributedSlowDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for DistributedSlowDetector {
    fn name(&self) -> &str {
        "distributed_slow"
    }

    fn process(&self, event: &NormalizedEvent) -> Option<DetectionSignal> {
        match event.event_type {
            EventType::HttpRequest | EventType::Http4xx => {}
            _ => return None,
        }

        let subnet = Self::ip_to_subnet(event.source_ip)?;
        self.cleanup_old_entries(&subnet, event.timestamp);

        let mut entries = self.subnet_activity.entry(subnet).or_default();
        entries.push((event.source_ip, event.timestamp));

        // Count unique IPs in subnet
        let mut unique_ips: Vec<IpAddr> = entries.iter().map(|(ip, _)| *ip).collect();
        unique_ips.sort();
        unique_ips.dedup();

        if unique_ips.len() >= self.ip_threshold {
            let evidence = format!("{}:distributed_slow:{}_ips", subnet, unique_ips.len());
            entries.clear();

            Some(DetectionSignal {
                source_ip: subnet, // Ban the /24 subnet
                severity: 180,
                confidence: 0.7,
                reason: format!(
                    "Distributed slow attack: {} unique IPs from {} in {}s",
                    unique_ips.len(),
                    subnet,
                    self.window.as_secs()
                ),
                evidence_hash: *blake3::hash(evidence.as_bytes()).as_bytes(),
                suggested_action: Action::Ban(self.ban_duration),
                detector_name: "distributed_slow".into(),
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

    fn make_http_event(ip: &str, ts: DateTime<Utc>) -> NormalizedEvent {
        let mut metadata = HashMap::new();
        metadata.insert("path".to_string(), "/api/login".to_string());
        NormalizedEvent {
            timestamp: ts,
            source_ip: ip.parse().unwrap(),
            event_type: EventType::HttpRequest,
            source_name: "test".into(),
            raw_line: "GET /api/login".into(),
            metadata,
        }
    }

    fn make_4xx_event(ip: &str, ts: DateTime<Utc>) -> NormalizedEvent {
        let mut metadata = HashMap::new();
        metadata.insert("path".to_string(), "/login".to_string());
        metadata.insert("status_code".to_string(), "403".to_string());
        NormalizedEvent {
            timestamp: ts,
            source_ip: ip.parse().unwrap(),
            event_type: EventType::Http4xx,
            source_name: "test".into(),
            raw_line: "GET /login 403".into(),
            metadata,
        }
    }

    #[test]
    fn detect_distributed_attack() {
        let mut d = DistributedSlowDetector::with_config(Duration::from_secs(600), 3, Duration::from_secs(3600));
        let base = Utc::now();

        // 3 IPs from same /24
        assert!(d.process(&make_http_event("10.0.1.1", base)).is_none());
        assert!(d.process(&make_http_event("10.0.1.2", base)).is_none());
        let result = d.process(&make_http_event("10.0.1.3", base));
        assert!(result.is_some());

        let s = result.unwrap();
        assert_eq!(s.severity, 180);
        // Should ban the /24 subnet
        assert_eq!(s.source_ip.to_string(), "10.0.1.0/24");
    }

    #[test]
    fn same_ip_repeated_no_detection() {
        let mut d = DistributedSlowDetector::with_config(Duration::from_secs(600), 3, Duration::from_secs(3600));
        let base = Utc::now();

        // Same IP many times — still only 1 unique
        for _ in 0..10 {
            assert!(d.process(&make_http_event("10.0.1.1", base)).is_none());
        }
    }

    #[test]
    fn different_subnets_tracked_separately() {
        let mut d = DistributedSlowDetector::with_config(Duration::from_secs(600), 3, Duration::from_secs(3600));
        let base = Utc::now();

        // IPs from different /24s
        d.process(&make_http_event("10.0.1.1", base));
        d.process(&make_http_event("10.0.2.1", base)); // Different subnet
        let result = d.process(&make_http_event("10.0.1.2", base));
        assert!(result.is_none()); // Only 2 unique IPs in 10.0.1.0/24
    }

    #[test]
    fn ip_to_subnet_v4() {
        let subnet = DistributedSlowDetector::ip_to_subnet("10.0.1.55".parse().unwrap()).unwrap();
        assert_eq!(subnet.to_string(), "10.0.1.0/24");
    }

    #[test]
    fn ignores_non_http() {
        let mut d = DistributedSlowDetector::new();
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
    fn default_threshold_5_ips() {
        let mut d = DistributedSlowDetector::new();
        let base = Utc::now();

        // 4 IPs → no ban
        for i in 1..=4u8 {
            let ip = format!("192.168.1.{i}");
            assert!(d.process(&make_http_event(&ip, base)).is_none());
        }

        // 5th IP → ban the /24
        let result = d.process(&make_http_event("192.168.1.5", base));
        assert!(result.is_some());
        let s = result.unwrap();
        assert_eq!(s.source_ip.to_string(), "192.168.1.0/24");
        assert_eq!(s.suggested_action, Action::Ban(Duration::from_secs(12 * 3600)));
    }

    #[test]
    fn ipv6_subnet_grouping_48() {
        let mut d = DistributedSlowDetector::with_config(Duration::from_secs(600), 3, Duration::from_secs(3600));
        let base = Utc::now();

        // 3 IPs in same /48
        d.process(&make_http_event("2001:db8:1::1", base));
        d.process(&make_http_event("2001:db8:1::2", base));
        let result = d.process(&make_http_event("2001:db8:1::3", base));
        assert!(result.is_some());
        let s = result.unwrap();
        assert_eq!(s.source_ip.to_string(), "2001:db8:1::/48");
    }

    #[test]
    fn ipv6_different_48_subnets_independent() {
        let mut d = DistributedSlowDetector::with_config(Duration::from_secs(600), 3, Duration::from_secs(3600));
        let base = Utc::now();

        // IPs from two different /48 subnets → neither reaches 3
        d.process(&make_http_event("2001:db8:1::1", base));
        d.process(&make_http_event("2001:db8:2::1", base)); // different /48
        let result = d.process(&make_http_event("2001:db8:1::2", base));
        assert!(result.is_none()); // only 2 unique in 2001:db8:1::/48
    }

    #[test]
    fn window_expiry_clears_old_entries() {
        let mut d = DistributedSlowDetector::with_config(Duration::from_secs(60), 3, Duration::from_secs(3600));
        let base = Utc::now();

        // 2 IPs at time 0
        d.process(&make_http_event("10.0.1.1", base));
        d.process(&make_http_event("10.0.1.2", base));

        // 2 IPs at time +120s (outside 60s window — old entries pruned)
        let late = base + chrono::Duration::seconds(120);
        d.process(&make_http_event("10.0.1.3", late));
        let result = d.process(&make_http_event("10.0.1.4", late));
        assert!(result.is_none()); // only 2 unique in current window
    }

    #[test]
    fn http4xx_also_counted() {
        let mut d = DistributedSlowDetector::with_config(Duration::from_secs(600), 3, Duration::from_secs(3600));
        let base = Utc::now();

        d.process(&make_http_event("10.0.1.1", base));
        d.process(&make_4xx_event("10.0.1.2", base));
        let result = d.process(&make_4xx_event("10.0.1.3", base));
        assert!(result.is_some());
    }

    #[test]
    fn clears_after_trigger() {
        let mut d = DistributedSlowDetector::with_config(Duration::from_secs(600), 3, Duration::from_secs(3600));
        let base = Utc::now();

        // Trigger
        d.process(&make_http_event("10.0.1.1", base));
        d.process(&make_http_event("10.0.1.2", base));
        d.process(&make_http_event("10.0.1.3", base));

        // After trigger, window is cleared — new events start fresh
        let result = d.process(&make_http_event("10.0.1.4", base));
        assert!(result.is_none());
    }

    #[test]
    fn default_constructor_values() {
        let d = DistributedSlowDetector::default();
        assert_eq!(d.name(), "distributed_slow");
        assert_eq!(d.ip_threshold, 5);
        assert_eq!(d.window, Duration::from_secs(600));
        assert_eq!(d.ban_duration, Duration::from_secs(12 * 3600));
    }

    #[test]
    fn reason_contains_ip_count_and_subnet() {
        let mut d = DistributedSlowDetector::with_config(Duration::from_secs(600), 3, Duration::from_secs(3600));
        let base = Utc::now();

        d.process(&make_http_event("10.0.1.1", base));
        d.process(&make_http_event("10.0.1.2", base));
        let result = d.process(&make_http_event("10.0.1.3", base));
        let s = result.unwrap();
        assert!(s.reason.contains("3 unique IPs"));
        assert!(s.reason.contains("10.0.1.0/24"));
    }

    #[test]
    fn confidence_is_0_7() {
        let mut d = DistributedSlowDetector::with_config(Duration::from_secs(600), 3, Duration::from_secs(3600));
        let base = Utc::now();

        d.process(&make_http_event("10.0.1.1", base));
        d.process(&make_http_event("10.0.1.2", base));
        let result = d.process(&make_http_event("10.0.1.3", base));
        let s = result.unwrap();
        assert!((s.confidence - 0.7).abs() < f32::EPSILON);
    }

    #[test]
    fn ignores_auth_success() {
        let mut d = DistributedSlowDetector::new();
        let event = NormalizedEvent {
            timestamp: Utc::now(),
            source_ip: "10.0.0.1".parse().unwrap(),
            event_type: EventType::AuthSuccess,
            source_name: "test".into(),
            raw_line: "success".into(),
            metadata: HashMap::new(),
        };
        assert!(d.process(&event).is_none());
    }

    #[test]
    fn ignores_smtp_auth_failure() {
        let mut d = DistributedSlowDetector::new();
        let event = NormalizedEvent {
            timestamp: Utc::now(),
            source_ip: "10.0.0.1".parse().unwrap(),
            event_type: EventType::SmtpAuthFailure,
            source_name: "test".into(),
            raw_line: "smtp fail".into(),
            metadata: HashMap::new(),
        };
        assert!(d.process(&event).is_none());
    }
}
