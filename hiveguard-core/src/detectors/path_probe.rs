use std::net::IpAddr;
use std::time::Duration;

use ipnet::IpNet;

use crate::detector::Detector;
use crate::models::{Action, DetectionSignal, EventType, NormalizedEvent};

/// Detects HTTP requests to suspicious/probed paths.
///
/// A single hit on any configured path produces an immediate detection signal.
pub struct PathProbeDetector {
    paths: Vec<String>,
    ban_duration: Duration,
}

impl PathProbeDetector {
    pub fn new() -> Self {
        Self {
            paths: vec![
                "/wp-login.php".into(),
                "/xmlrpc.php".into(),
                "/.env".into(),
                "/phpmyadmin".into(),
                "/wp-admin".into(),
            ],
            ban_duration: Duration::from_secs(259200), // 72h
        }
    }

    /// Create with custom paths and ban duration.
    pub fn with_config(paths: Vec<String>, ban_duration: Duration) -> Self {
        Self {
            paths,
            ban_duration,
        }
    }

    fn ip_to_net(ip: IpAddr) -> IpNet {
        match ip {
            IpAddr::V4(v4) => IpNet::V4(ipnet::Ipv4Net::new(v4, 32).unwrap()),
            IpAddr::V6(v6) => IpNet::V6(ipnet::Ipv6Net::new(v6, 128).unwrap()),
        }
    }

    fn compute_evidence_hash(ip: &IpAddr, path: &str) -> [u8; 32] {
        let input = format!("{ip}:path_probe:{path}");
        *blake3::hash(input.as_bytes()).as_bytes()
    }

    /// Check if the given request path matches any suspicious path.
    /// Uses starts_with to catch sub-paths like `/wp-admin/install.php`.
    fn matches_probe_path(&self, request_path: &str) -> Option<&str> {
        for probe in &self.paths {
            if request_path.starts_with(probe.as_str()) {
                return Some(probe.as_str());
            }
        }
        None
    }
}

impl Default for PathProbeDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for PathProbeDetector {
    fn name(&self) -> &str {
        "path_probe"
    }

    fn process(&self, event: &NormalizedEvent) -> Option<DetectionSignal> {
        // Inspect all HTTP events — a probe to a suspicious path is malicious
        // regardless of whether the server returned 200, 404, or 503.
        match event.event_type {
            EventType::HttpRequest | EventType::Http4xx | EventType::Http5xx => {}
            _ => return None,
        }

        let request_path = event.metadata.get("path")?;
        let matched = self.matches_probe_path(request_path)?;

        let ip = event.source_ip;
        let reason = format!(
            "Path probe: request to suspicious path '{}' from {}",
            matched, ip
        );
        let evidence_hash = Self::compute_evidence_hash(&ip, matched);

        Some(DetectionSignal {
            source_ip: Self::ip_to_net(ip),
            severity: 200,
            confidence: 0.95,
            reason,
            evidence_hash,
            suggested_action: Action::Ban(self.ban_duration),
            detector_name: self.name().to_string(),
            timestamp: event.timestamp,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use std::collections::HashMap;

    fn make_http_event(
        ip: &str,
        path: &str,
        event_type: EventType,
    ) -> NormalizedEvent {
        let mut metadata = HashMap::new();
        metadata.insert("path".to_string(), path.to_string());
        metadata.insert("method".to_string(), "GET".to_string());
        metadata.insert("user_agent".to_string(), "Mozilla/5.0".to_string());
        metadata.insert("status_code".to_string(), "404".to_string());
        NormalizedEvent {
            timestamp: Utc::now(),
            source_ip: ip.parse().unwrap(),
            event_type,
            source_name: "nginx".to_string(),
            raw_line: format!("GET {path} HTTP/1.1"),
            metadata,
        }
    }

    #[test]
    fn wp_login_triggers_signal() {
        let mut det = PathProbeDetector::new();
        let event = make_http_event("1.2.3.4", "/wp-login.php", EventType::Http4xx);
        let signal = det.process(&event).expect("should detect wp-login");
        assert_eq!(signal.severity, 200);
        assert_eq!(signal.confidence, 0.95);
        assert_eq!(
            signal.suggested_action,
            Action::Ban(Duration::from_secs(259200))
        );
        assert!(signal.reason.contains("/wp-login.php"));
    }

    #[test]
    fn env_triggers_signal() {
        let mut det = PathProbeDetector::new();
        let event = make_http_event("5.6.7.8", "/.env", EventType::Http4xx);
        assert!(det.process(&event).is_some());
    }

    #[test]
    fn xmlrpc_triggers_signal() {
        let mut det = PathProbeDetector::new();
        let event = make_http_event("5.6.7.8", "/xmlrpc.php", EventType::HttpRequest);
        assert!(det.process(&event).is_some());
    }

    #[test]
    fn phpmyadmin_triggers_signal() {
        let mut det = PathProbeDetector::new();
        let event = make_http_event("5.6.7.8", "/phpmyadmin", EventType::Http4xx);
        assert!(det.process(&event).is_some());
    }

    #[test]
    fn wp_admin_subpath_triggers_signal() {
        let mut det = PathProbeDetector::new();
        let event = make_http_event("5.6.7.8", "/wp-admin/install.php", EventType::Http4xx);
        assert!(det.process(&event).is_some());
    }

    #[test]
    fn index_html_no_signal() {
        let mut det = PathProbeDetector::new();
        let event = make_http_event("1.2.3.4", "/index.html", EventType::HttpRequest);
        assert!(det.process(&event).is_none());
    }

    #[test]
    fn normal_path_no_signal() {
        let mut det = PathProbeDetector::new();
        let event = make_http_event("1.2.3.4", "/api/v1/users", EventType::HttpRequest);
        assert!(det.process(&event).is_none());
    }

    #[test]
    fn auth_failure_event_ignored() {
        let mut det = PathProbeDetector::new();
        let mut metadata = HashMap::new();
        metadata.insert("path".to_string(), "/wp-login.php".to_string());
        let event = NormalizedEvent {
            timestamp: Utc::now(),
            source_ip: "1.2.3.4".parse().unwrap(),
            event_type: EventType::AuthFailure,
            source_name: "ssh".to_string(),
            raw_line: "test".to_string(),
            metadata,
        };
        assert!(det.process(&event).is_none());
    }

    #[test]
    fn http5xx_also_detected() {
        let mut det = PathProbeDetector::new();
        let event = make_http_event("1.2.3.4", "/wp-login.php", EventType::Http5xx);
        let signal = det.process(&event);
        assert!(signal.is_some(), "Http5xx probe should be detected");
    }

    #[test]
    fn missing_path_metadata_no_signal() {
        let mut det = PathProbeDetector::new();
        let event = NormalizedEvent {
            timestamp: Utc::now(),
            source_ip: "1.2.3.4".parse().unwrap(),
            event_type: EventType::Http4xx,
            source_name: "nginx".to_string(),
            raw_line: "test".to_string(),
            metadata: HashMap::new(),
        };
        assert!(det.process(&event).is_none());
    }

    #[test]
    fn custom_paths_config() {
        let mut det = PathProbeDetector::with_config(
            vec!["/secret".into(), "/admin".into()],
            Duration::from_secs(3600),
        );
        let event = make_http_event("1.2.3.4", "/secret", EventType::Http4xx);
        let signal = det.process(&event).expect("custom path should trigger");
        assert_eq!(
            signal.suggested_action,
            Action::Ban(Duration::from_secs(3600))
        );
    }

    // --- Phase 10: comprehensive coverage ---

    #[test]
    fn path_is_case_sensitive() {
        let mut det = PathProbeDetector::new();
        // /wp-login.php should match, /WP-LOGIN.PHP should NOT
        let event_lower = make_http_event("1.2.3.4", "/wp-login.php", EventType::Http4xx);
        assert!(det.process(&event_lower).is_some());

        let event_upper = make_http_event("1.2.3.4", "/WP-LOGIN.PHP", EventType::Http4xx);
        assert!(det.process(&event_upper).is_none());
    }

    #[test]
    fn path_with_query_string() {
        let mut det = PathProbeDetector::new();
        // /wp-login.php?action=login starts with /wp-login.php
        let event = make_http_event("1.2.3.4", "/wp-login.php?action=login", EventType::Http4xx);
        assert!(det.process(&event).is_some());
    }

    #[test]
    fn path_with_fragment() {
        let mut det = PathProbeDetector::new();
        let event = make_http_event("1.2.3.4", "/.env.bak", EventType::Http4xx);
        assert!(det.process(&event).is_some()); // starts with /.env
    }

    #[test]
    fn phpmyadmin_subpath() {
        let mut det = PathProbeDetector::new();
        let event = make_http_event("1.2.3.4", "/phpmyadmin/index.php", EventType::Http4xx);
        assert!(det.process(&event).is_some());
    }

    #[test]
    fn similar_but_not_matching_path() {
        let mut det = PathProbeDetector::new();
        // /wp-content is NOT /wp-login.php or /wp-admin
        let event = make_http_event("1.2.3.4", "/wp-content/themes/style.css", EventType::HttpRequest);
        assert!(det.process(&event).is_none());
    }

    #[test]
    fn ipv6_path_probe() {
        let mut det = PathProbeDetector::new();
        let event = make_http_event("2001:db8::1", "/wp-login.php", EventType::Http4xx);
        let signal = det.process(&event).expect("should detect");
        assert!(signal.source_ip.addr().to_string().contains("2001:db8"));
    }

    #[test]
    fn multiple_probes_same_ip() {
        let mut det = PathProbeDetector::new();
        // Each probe generates a signal independently (threshold=1)
        let event1 = make_http_event("1.2.3.4", "/wp-login.php", EventType::Http4xx);
        assert!(det.process(&event1).is_some());

        let event2 = make_http_event("1.2.3.4", "/.env", EventType::Http4xx);
        assert!(det.process(&event2).is_some());

        let event3 = make_http_event("1.2.3.4", "/xmlrpc.php", EventType::HttpRequest);
        assert!(det.process(&event3).is_some());
    }

    #[test]
    fn evidence_hash_differs_for_different_paths() {
        let mut det = PathProbeDetector::new();
        let event1 = make_http_event("1.2.3.4", "/wp-login.php", EventType::Http4xx);
        let signal1 = det.process(&event1).unwrap();

        let event2 = make_http_event("1.2.3.4", "/.env", EventType::Http4xx);
        let signal2 = det.process(&event2).unwrap();

        assert_ne!(signal1.evidence_hash, signal2.evidence_hash);
    }

    #[test]
    fn evidence_hash_differs_for_different_ips() {
        let mut det = PathProbeDetector::new();
        let event1 = make_http_event("1.2.3.4", "/wp-login.php", EventType::Http4xx);
        let signal1 = det.process(&event1).unwrap();

        let event2 = make_http_event("5.6.7.8", "/wp-login.php", EventType::Http4xx);
        let signal2 = det.process(&event2).unwrap();

        assert_ne!(signal1.evidence_hash, signal2.evidence_hash);
    }

    #[test]
    fn default_constructor() {
        let det = PathProbeDetector::default();
        assert_eq!(det.name(), "path_probe");
        assert_eq!(det.paths.len(), 5);
        assert_eq!(det.ban_duration, Duration::from_secs(259200));
    }

    #[test]
    fn empty_path_in_metadata() {
        let mut det = PathProbeDetector::new();
        let mut metadata = HashMap::new();
        metadata.insert("path".to_string(), "".to_string());
        let event = NormalizedEvent {
            timestamp: Utc::now(),
            source_ip: "1.2.3.4".parse().unwrap(),
            event_type: EventType::Http4xx,
            source_name: "nginx".to_string(),
            raw_line: "test".to_string(),
            metadata,
        };
        assert!(det.process(&event).is_none());
    }

    #[test]
    fn connection_event_ignored() {
        let mut det = PathProbeDetector::new();
        let event = NormalizedEvent {
            timestamp: Utc::now(),
            source_ip: "1.2.3.4".parse().unwrap(),
            event_type: EventType::ConnectionEvent,
            source_name: "test".to_string(),
            raw_line: "test".to_string(),
            metadata: {
                let mut m = HashMap::new();
                m.insert("path".to_string(), "/wp-login.php".to_string());
                m
            },
        };
        assert!(det.process(&event).is_none());
    }
}
