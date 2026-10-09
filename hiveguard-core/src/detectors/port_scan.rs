use std::net::IpAddr;
use std::time::Duration;

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use ipnet::IpNet;

use crate::detector::Detector;
use crate::models::{Action, DetectionSignal, EventType, NormalizedEvent};

/// Port scan detector — detects hosts accessing many different ports.
///
/// Note: Full implementation requires netlink/conntrack integration.
/// This version works with `EventType::PortAccess` events from custom parsers.
/// Default: >=6 unique ports in 10 min → ban 48h. The window is long because
/// firewall logs are rate-limited samples (UFW logs ~3 blocks/min host-wide),
/// so slow scanners only ever show a few ports per minute.
pub struct PortScanDetector {
    /// Window for tracking port access.
    window: Duration,
    /// Number of distinct ports to trigger detection.
    threshold: usize,
    /// Ban duration.
    ban_duration: Duration,
    /// Per-IP: (port, last seen) entries, at most one per distinct port.
    port_access: DashMap<IpAddr, Vec<(u16, DateTime<Utc>)>>,
}

impl PortScanDetector {
    pub fn new() -> Self {
        Self {
            window: Duration::from_secs(600),
            threshold: 6,
            ban_duration: Duration::from_secs(48 * 3600), // 48h
            port_access: DashMap::new(),
        }
    }

    pub fn with_config(window: Duration, threshold: usize, ban_duration: Duration) -> Self {
        Self {
            window,
            threshold,
            ban_duration,
            port_access: DashMap::new(),
        }
    }

    fn ip_to_net(ip: IpAddr) -> IpNet {
        match ip {
            IpAddr::V4(v4) => IpNet::V4(ipnet::Ipv4Net::new(v4, 32).unwrap()),
            IpAddr::V6(v6) => IpNet::V6(ipnet::Ipv6Net::new(v6, 128).unwrap()),
        }
    }

    fn cleanup_old_entries(&self, ip: &IpAddr, now: DateTime<Utc>) {
        if let Some(mut entries) = self.port_access.get_mut(ip) {
            let cutoff = now - chrono::Duration::from_std(self.window).unwrap_or(chrono::Duration::seconds(30));
            entries.retain(|(_, t)| *t > cutoff);
            if entries.is_empty() {
                drop(entries);
                self.port_access.remove(ip);
            }
        }
    }
}

impl Default for PortScanDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for PortScanDetector {
    fn name(&self) -> &str {
        "port_scan"
    }

    fn process(&self, event: &NormalizedEvent) -> Option<DetectionSignal> {
        if event.event_type != EventType::PortAccess {
            return None;
        }

        let port: u16 = event.metadata.get("port")?.parse().ok()?;
        let ip = event.source_ip;

        self.cleanup_old_entries(&ip, event.timestamp);

        let mut entries = self.port_access.entry(ip).or_default();
        // Keep one entry per port so repeated hits on the same port cannot
        // grow the list over the (long) window.
        entries.retain(|(p, _)| *p != port);
        entries.push((port, event.timestamp));
        let unique_ports = entries.len();

        if unique_ports >= self.threshold {
            let evidence = format!("{}:port_scan:{}_ports", ip, unique_ports);
            // Clear the entries to avoid repeated firing
            entries.clear();

            Some(DetectionSignal {
                source_ip: Self::ip_to_net(ip),
                severity: 200,
                confidence: 0.9,
                reason: format!("Port scan detected: {} unique ports in {}s", unique_ports, self.window.as_secs()),
                evidence_hash: *blake3::hash(evidence.as_bytes()).as_bytes(),
                suggested_action: Action::Ban(self.ban_duration),
                detector_name: "port_scan".into(),
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

    fn make_port_event(ip: &str, port: u16, ts: DateTime<Utc>) -> NormalizedEvent {
        let mut metadata = HashMap::new();
        metadata.insert("port".to_string(), port.to_string());
        NormalizedEvent {
            timestamp: ts,
            source_ip: ip.parse().unwrap(),
            event_type: EventType::PortAccess,
            source_name: "test".into(),
            raw_line: format!("port {port}"),
            metadata,
        }
    }

    #[test]
    fn detect_port_scan() {
        let mut d = PortScanDetector::with_config(Duration::from_secs(30), 5, Duration::from_secs(3600));
        let base = Utc::now();

        for port in 0..4 {
            let event = make_port_event("10.0.0.1", 1000 + port, base);
            assert!(d.process(&event).is_none());
        }

        // 5th unique port triggers detection
        let event = make_port_event("10.0.0.1", 1004, base);
        let result = d.process(&event);
        assert!(result.is_some());
        let s = result.unwrap();
        assert_eq!(s.severity, 200);
        assert!((s.confidence - 0.9).abs() < f32::EPSILON);
    }

    #[test]
    fn same_port_no_scan() {
        let mut d = PortScanDetector::with_config(Duration::from_secs(30), 5, Duration::from_secs(3600));
        let base = Utc::now();

        // Same port repeated — only 1 unique port
        for _ in 0..10 {
            let event = make_port_event("10.0.0.1", 80, base);
            assert!(d.process(&event).is_none());
        }
    }

    #[test]
    fn ignores_non_port_events() {
        let mut d = PortScanDetector::new();
        let event = NormalizedEvent {
            timestamp: Utc::now(),
            source_ip: "10.0.0.1".parse().unwrap(),
            event_type: EventType::HttpRequest,
            source_name: "test".into(),
            raw_line: "GET /".into(),
            metadata: HashMap::new(),
        };
        assert!(d.process(&event).is_none());
    }

    #[test]
    fn separate_ips_tracked_independently() {
        let mut d = PortScanDetector::with_config(Duration::from_secs(30), 3, Duration::from_secs(3600));
        let base = Utc::now();

        // IP1: 2 ports
        d.process(&make_port_event("10.0.0.1", 80, base));
        d.process(&make_port_event("10.0.0.1", 443, base));

        // IP2: 3 ports → triggers
        d.process(&make_port_event("10.0.0.2", 80, base));
        d.process(&make_port_event("10.0.0.2", 443, base));
        let result = d.process(&make_port_event("10.0.0.2", 8080, base));
        assert!(result.is_some());

        // IP1: still only 2 ports, no trigger
        assert!(d.process(&make_port_event("10.0.0.1", 80, base)).is_none());
    }

    // --- Phase 20: comprehensive coverage ---

    #[test]
    fn default_threshold_6_ports_in_10m() {
        let d = PortScanDetector::new();
        let base = Utc::now();

        // 5 unique ports spread over 9 minutes → no ban
        for port in 0..5 {
            let event = make_port_event("10.0.0.1", 1000 + port, base + chrono::Duration::seconds(port as i64 * 108));
            assert!(d.process(&event).is_none());
        }

        // 6th unique port within the 10 min window → ban
        let event = make_port_event("10.0.0.1", 1005, base + chrono::Duration::seconds(590));
        let result = d.process(&event);
        assert!(result.is_some());
        let s = result.unwrap();
        assert_eq!(s.suggested_action, Action::Ban(Duration::from_secs(48 * 3600)));
    }

    #[test]
    fn ports_outside_window_no_trigger() {
        let mut d = PortScanDetector::with_config(Duration::from_secs(30), 5, Duration::from_secs(3600));
        let base = Utc::now();

        // 3 ports at time 0
        for port in 0..3 {
            let event = make_port_event("10.0.0.1", 1000 + port, base);
            d.process(&event);
        }

        // 3 ports at time +60s (outside 30s window)
        let late = base + chrono::Duration::seconds(60);
        for port in 3..6 {
            let event = make_port_event("10.0.0.1", 1000 + port, late);
            // Only 3 unique ports in the window now
            assert!(d.process(&event).is_none());
        }
    }

    #[test]
    fn port_scan_ipv6() {
        let mut d = PortScanDetector::with_config(Duration::from_secs(30), 3, Duration::from_secs(3600));
        let base = Utc::now();

        for port in 0..3 {
            let event = make_port_event("2001:db8::1", 1000 + port, base);
            if port == 2 {
                let result = d.process(&event);
                assert!(result.is_some());
                let s = result.unwrap();
                assert!(s.source_ip.addr().to_string().contains("2001:db8"));
            } else {
                d.process(&event);
            }
        }
    }

    #[test]
    fn port_scan_clears_after_trigger() {
        let mut d = PortScanDetector::with_config(Duration::from_secs(30), 3, Duration::from_secs(3600));
        let base = Utc::now();

        // Trigger first scan
        for port in 0..3 {
            d.process(&make_port_event("10.0.0.1", 1000 + port, base));
        }

        // After trigger, window is cleared — need 3 more
        let event = make_port_event("10.0.0.1", 2000, base);
        assert!(d.process(&event).is_none());
    }

    #[test]
    fn port_scan_missing_port_metadata() {
        let mut d = PortScanDetector::new();
        let event = NormalizedEvent {
            timestamp: Utc::now(),
            source_ip: "10.0.0.1".parse().unwrap(),
            event_type: EventType::PortAccess,
            source_name: "test".into(),
            raw_line: "port access".into(),
            metadata: HashMap::new(), // no "port" key
        };
        assert!(d.process(&event).is_none());
    }

    #[test]
    fn port_scan_invalid_port_value() {
        let mut d = PortScanDetector::new();
        let mut metadata = HashMap::new();
        metadata.insert("port".to_string(), "not_a_number".to_string());
        let event = NormalizedEvent {
            timestamp: Utc::now(),
            source_ip: "10.0.0.1".parse().unwrap(),
            event_type: EventType::PortAccess,
            source_name: "test".into(),
            raw_line: "port access".into(),
            metadata,
        };
        assert!(d.process(&event).is_none());
    }

    #[test]
    fn port_scan_default_constructor() {
        let d = PortScanDetector::default();
        assert_eq!(d.name(), "port_scan");
        assert_eq!(d.threshold, 6);
        assert_eq!(d.window, Duration::from_secs(600));
        assert_eq!(d.ban_duration, Duration::from_secs(48 * 3600));
    }

    #[test]
    fn repeated_hits_on_one_port_do_not_accumulate() {
        let d = PortScanDetector::with_config(Duration::from_secs(600), 3, Duration::from_secs(3600));
        let base = Utc::now();
        for i in 0..1000 {
            assert!(d.process(&make_port_event("10.0.0.1", 23, base + chrono::Duration::milliseconds(i))).is_none());
        }
        assert_eq!(d.port_access.get(&"10.0.0.1".parse::<IpAddr>().unwrap()).unwrap().len(), 1);
    }

    #[test]
    fn port_scan_reason_contains_count() {
        let mut d = PortScanDetector::with_config(Duration::from_secs(30), 3, Duration::from_secs(3600));
        let base = Utc::now();

        let mut last = None;
        for port in 0..3 {
            last = d.process(&make_port_event("10.0.0.1", 1000 + port, base));
        }
        let s = last.unwrap();
        assert!(s.reason.contains("3 unique ports"));
    }
}
