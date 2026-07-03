use std::net::IpAddr;
use std::time::Duration;

use ipnet::IpNet;

use crate::detector::Detector;
use crate::models::{Action, DetectionSignal, EventType, NormalizedEvent};

/// Honeypot path detector — fake endpoints that trigger immediate high-severity bans.
///
/// Any access to a configured honeypot path is by definition malicious,
/// providing zero false positives. Uses `Action::Escalate` for cluster
/// propagation with high priority.
pub struct HoneypotDetector {
    /// Honeypot paths that will trigger detection.
    paths: Vec<String>,
    /// Ban duration (None = permanent). Stored for config roundtrip; actual
    /// ban duration is determined by the scoring engine.
    #[allow(dead_code)]
    ban_duration: Option<Duration>,
    /// Severity score (≥ 250 by default).
    severity: u8,
}

impl HoneypotDetector {
    pub fn new() -> Self {
        Self {
            paths: vec![
                "/.git/config".into(),
                "/.aws/credentials".into(),
                "/backup.sql".into(),
                "/debug/vars".into(),
                "/server-status".into(),
                "/actuator/env".into(),
            ],
            ban_duration: None, // permanent
            severity: 250,
        }
    }

    /// Create with custom honeypot paths (legacy, permanent ban).
    pub fn with_paths(paths: Vec<String>) -> Self {
        Self {
            paths,
            ban_duration: None,
            severity: 250,
        }
    }

    /// Create with full configuration from YAML.
    pub fn with_config(paths: Vec<String>, ban_duration: Option<Duration>, severity: u8) -> Self {
        Self {
            paths,
            ban_duration,
            severity: severity.max(250), // enforce minimum 250
        }
    }

    fn ip_to_net(ip: IpAddr) -> IpNet {
        match ip {
            IpAddr::V4(v4) => IpNet::V4(ipnet::Ipv4Net::new(v4, 32).unwrap()),
            IpAddr::V6(v6) => IpNet::V6(ipnet::Ipv6Net::new(v6, 128).unwrap()),
        }
    }
}

impl Default for HoneypotDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for HoneypotDetector {
    fn name(&self) -> &str {
        "honeypot"
    }

    fn process(&self, event: &NormalizedEvent) -> Option<DetectionSignal> {
        match event.event_type {
            EventType::HttpRequest | EventType::Http4xx => {}
            _ => return None,
        }

        let path = event.metadata.get("path")?;

        for honeypot in &self.paths {
            if path.starts_with(honeypot.as_str()) {
                let evidence = format!("{}:honeypot:{}", event.source_ip, path);
                return Some(DetectionSignal {
                    source_ip: Self::ip_to_net(event.source_ip),
                    severity: self.severity,
                    confidence: 1.0,
                    reason: format!("Honeypot path accessed: {}", honeypot),
                    evidence_hash: *blake3::hash(evidence.as_bytes()).as_bytes(),
                    suggested_action: Action::Escalate,
                    detector_name: "honeypot".into(),
                    timestamp: event.timestamp,
                });
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

    fn make_http_event(ip: &str, path: &str) -> NormalizedEvent {
        let mut metadata = HashMap::new();
        metadata.insert("path".to_string(), path.to_string());
        NormalizedEvent {
            timestamp: Utc::now(),
            source_ip: ip.parse().unwrap(),
            event_type: EventType::HttpRequest,
            source_name: "test".into(),
            raw_line: format!("GET {path}"),
            metadata,
        }
    }

    fn make_http_event_4xx(ip: &str, path: &str) -> NormalizedEvent {
        let mut metadata = HashMap::new();
        metadata.insert("path".to_string(), path.to_string());
        NormalizedEvent {
            timestamp: Utc::now(),
            source_ip: ip.parse().unwrap(),
            event_type: EventType::Http4xx,
            source_name: "test".into(),
            raw_line: format!("GET {path}"),
            metadata,
        }
    }

    #[test]
    fn honeypot_detects_git_config() {
        let mut d = HoneypotDetector::new();
        let event = make_http_event("10.0.0.1", "/.git/config");
        let signal = d.process(&event);
        assert!(signal.is_some());
        let s = signal.unwrap();
        assert!(s.severity >= 250);
        assert!((s.confidence - 1.0).abs() < f32::EPSILON);
        assert_eq!(s.suggested_action, Action::Escalate);
    }

    #[test]
    fn honeypot_detects_aws_creds() {
        let mut d = HoneypotDetector::new();
        let event = make_http_event("10.0.0.1", "/.aws/credentials");
        assert!(d.process(&event).is_some());
    }

    #[test]
    fn honeypot_ignores_normal_path() {
        let mut d = HoneypotDetector::new();
        let event = make_http_event("10.0.0.1", "/index.html");
        assert!(d.process(&event).is_none());
    }

    #[test]
    fn honeypot_ignores_non_http_events() {
        let mut d = HoneypotDetector::new();
        let event = NormalizedEvent {
            timestamp: Utc::now(),
            source_ip: "10.0.0.1".parse().unwrap(),
            event_type: EventType::AuthFailure,
            source_name: "test".into(),
            raw_line: "ssh failure".into(),
            metadata: HashMap::new(),
        };
        assert!(d.process(&event).is_none());
    }

    #[test]
    fn custom_honeypot_paths() {
        let mut d = HoneypotDetector::with_paths(vec!["/secret-trap".into()]);
        let event = make_http_event("10.0.0.1", "/secret-trap");
        assert!(d.process(&event).is_some());

        let normal = make_http_event("10.0.0.1", "/.git/config");
        assert!(d.process(&normal).is_none()); // Not in custom paths
    }

    // --- Phase 20: comprehensive coverage ---

    #[test]
    fn honeypot_severity_at_least_250() {
        let mut d = HoneypotDetector::new();
        let event = make_http_event("203.0.113.1", "/.git/config");
        let s = d.process(&event).unwrap();
        assert!(s.severity >= 250, "Honeypot severity should be >= 250, got {}", s.severity);
    }

    #[test]
    fn honeypot_confidence_is_1() {
        let mut d = HoneypotDetector::new();
        let event = make_http_event("203.0.113.1", "/backup.sql");
        let s = d.process(&event).unwrap();
        assert!((s.confidence - 1.0).abs() < f32::EPSILON);
    }

    #[test]
    fn honeypot_uses_escalate_action() {
        let mut d = HoneypotDetector::new();
        let event = make_http_event("203.0.113.1", "/debug/vars");
        let s = d.process(&event).unwrap();
        assert_eq!(s.suggested_action, Action::Escalate);
    }

    #[test]
    fn honeypot_with_config_permanent() {
        let mut d = HoneypotDetector::with_config(
            vec!["/trap".into()],
            None, // permanent
            255,
        );
        let event = make_http_event("10.0.0.1", "/trap");
        let s = d.process(&event).unwrap();
        assert_eq!(s.severity, 255);
        assert_eq!(s.suggested_action, Action::Escalate);
    }

    #[test]
    fn honeypot_with_config_timed_ban() {
        let mut d = HoneypotDetector::with_config(
            vec!["/canary".into()],
            Some(Duration::from_secs(3600)),
            250,
        );
        let event = make_http_event("10.0.0.1", "/canary");
        let s = d.process(&event).unwrap();
        assert!(s.severity >= 250);
    }

    #[test]
    fn honeypot_severity_enforces_minimum_250() {
        // Even if config says severity=100, enforce minimum 250
        let d = HoneypotDetector::with_config(vec!["/x".into()], None, 100);
        assert_eq!(d.severity, 250);
    }

    #[test]
    fn honeypot_detects_backup_sql() {
        let mut d = HoneypotDetector::new();
        let event = make_http_event("10.0.0.1", "/backup.sql");
        assert!(d.process(&event).is_some());
    }

    #[test]
    fn honeypot_detects_server_status() {
        let mut d = HoneypotDetector::new();
        let event = make_http_event("10.0.0.1", "/server-status");
        assert!(d.process(&event).is_some());
    }

    #[test]
    fn honeypot_detects_actuator_env() {
        let mut d = HoneypotDetector::new();
        let event = make_http_event("10.0.0.1", "/actuator/env");
        assert!(d.process(&event).is_some());
    }

    #[test]
    fn honeypot_subpath_matches() {
        let mut d = HoneypotDetector::new();
        let event = make_http_event("10.0.0.1", "/.git/config/something");
        assert!(d.process(&event).is_some());
    }

    #[test]
    fn honeypot_detects_http_4xx_events() {
        let mut d = HoneypotDetector::new();
        let event = make_http_event_4xx("10.0.0.1", "/.git/config");
        assert!(d.process(&event).is_some());
    }

    #[test]
    fn honeypot_ipv6() {
        let mut d = HoneypotDetector::new();
        let event = make_http_event("2001:db8::1", "/backup.sql");
        let s = d.process(&event).unwrap();
        assert!(s.source_ip.addr().to_string().contains("2001:db8"));
    }

    #[test]
    fn honeypot_evidence_hash_differs() {
        let mut d = HoneypotDetector::new();
        let e1 = make_http_event("10.0.0.1", "/.git/config");
        let e2 = make_http_event("10.0.0.2", "/.git/config");
        let s1 = d.process(&e1).unwrap();
        let s2 = d.process(&e2).unwrap();
        assert_ne!(s1.evidence_hash, s2.evidence_hash);
    }

    #[test]
    fn honeypot_missing_path_no_signal() {
        let mut d = HoneypotDetector::new();
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
    fn honeypot_default_constructor() {
        let d = HoneypotDetector::default();
        assert_eq!(d.name(), "honeypot");
        assert_eq!(d.paths.len(), 6);
        assert!(d.severity >= 250);
        assert!(d.ban_duration.is_none()); // permanent
    }

    #[test]
    fn honeypot_http5xx_ignored() {
        let mut d = HoneypotDetector::new();
        let event = NormalizedEvent {
            timestamp: Utc::now(),
            source_ip: "10.0.0.1".parse().unwrap(),
            event_type: EventType::Http5xx,
            source_name: "test".into(),
            raw_line: "GET /backup.sql".into(),
            metadata: {
                let mut m = HashMap::new();
                m.insert("path".to_string(), "/backup.sql".to_string());
                m
            },
        };
        assert!(d.process(&event).is_none());
    }

    #[test]
    fn honeypot_reason_contains_path() {
        let mut d = HoneypotDetector::new();
        let event = make_http_event("10.0.0.1", "/.aws/credentials");
        let s = d.process(&event).unwrap();
        assert!(s.reason.contains("/.aws/credentials"));
    }

    #[test]
    fn honeypot_multiple_hits_each_signal() {
        let mut d = HoneypotDetector::new();
        let e1 = make_http_event("10.0.0.1", "/.git/config");
        let e2 = make_http_event("10.0.0.1", "/backup.sql");
        assert!(d.process(&e1).is_some());
        assert!(d.process(&e2).is_some());
    }
}
