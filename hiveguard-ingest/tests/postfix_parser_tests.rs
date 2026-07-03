use std::io::Write;
use std::net::IpAddr;

use hiveguard_core::models::EventType;
use hiveguard_ingest::file_watcher::FileWatcher;
use hiveguard_ingest::postfix_parser::{
    parse_postfix_line, postfix_event_to_normalized, PostfixPatterns,
};

fn patterns() -> PostfixPatterns {
    PostfixPatterns::new()
}

fn fixture_path() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("mail.log.sample")
}

fn parse_fixture() -> Vec<hiveguard_core::models::NormalizedEvent> {
    let content = std::fs::read_to_string(fixture_path()).unwrap();
    let patterns = patterns();
    content
        .lines()
        .filter_map(|line| parse_postfix_line(line, &patterns))
        .map(postfix_event_to_normalized)
        .collect()
}

#[test]
fn fixture_parses_expected_event_count() {
    // 8 SASL auth failure lines in fixture:
    // Lines 1-5: warning/SASL patterns
    // Line 10: warning LOGIN
    // Line 12: warning PLAIN
    // Line 14: SASL LOGIN client= format
    let events = parse_fixture();
    assert_eq!(events.len(), 8, "Expected 8 SASL auth failure events");
}

#[test]
fn fixture_all_smtp_auth_failure() {
    let events = parse_fixture();
    for event in &events {
        assert_eq!(
            event.event_type,
            EventType::SmtpAuthFailure,
            "All events should be SmtpAuthFailure, got {:?} for: {}",
            event.event_type,
            event.raw_line
        );
    }
}

#[test]
fn fixture_source_name_is_postfix() {
    let events = parse_fixture();
    for event in &events {
        assert_eq!(event.source_name, "postfix");
    }
}

#[test]
fn fixture_metadata_contains_mechanism() {
    let events = parse_fixture();
    for event in &events {
        assert!(
            event.metadata.contains_key("mechanism"),
            "Event missing mechanism metadata: {}",
            event.raw_line
        );
    }
}

#[test]
fn fixture_ipv6_addresses() {
    let events = parse_fixture();
    let ipv6_events: Vec<_> = events
        .iter()
        .filter(|e| e.source_ip.is_ipv6())
        .collect();
    assert_eq!(ipv6_events.len(), 2, "Expected 2 IPv6 events");
}

#[test]
fn fixture_mechanisms_found() {
    let events = parse_fixture();
    let mechanisms: Vec<&str> = events
        .iter()
        .map(|e| e.metadata.get("mechanism").unwrap().as_str())
        .collect();
    assert!(mechanisms.contains(&"PLAIN"), "Missing PLAIN mechanism");
    assert!(mechanisms.contains(&"LOGIN"), "Missing LOGIN mechanism");
    assert!(mechanisms.contains(&"CRAM-MD5"), "Missing CRAM-MD5 mechanism");
}

#[test]
fn fixture_ips_extracted() {
    let events = parse_fixture();
    let ips: Vec<IpAddr> = events.iter().map(|e| e.source_ip).collect();
    assert!(ips.contains(&"203.0.113.50".parse().unwrap()));
    assert!(ips.contains(&"198.51.100.20".parse().unwrap()));
    assert!(ips.contains(&"10.20.30.40".parse().unwrap()));
    assert!(ips.contains(&"172.16.0.100".parse().unwrap()));
    assert!(ips.contains(&"2001:db8::1".parse().unwrap()));
    assert!(ips.contains(&"45.33.32.156".parse().unwrap()));
}

#[test]
fn fixture_non_matching_lines_skipped() {
    // Total lines in fixture: 14
    // Matching lines: 8
    // Non-matching: 6 (connect, qmgr, dovecot, disconnect, smtp, cleanup)
    let content = std::fs::read_to_string(fixture_path()).unwrap();
    let total_lines = content.lines().count();
    let events = parse_fixture();
    assert_eq!(
        total_lines - events.len(),
        6,
        "Expected 6 non-matching lines"
    );
}

#[test]
fn file_watcher_with_postfix_parser() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("mail.log");

    {
        let mut f = std::fs::File::create(&log_path).unwrap();
        writeln!(f, "Apr  8 14:30:22 mailhost postfix/smtpd[12345]: warning: unknown[203.0.113.50]: SASL LOGIN authentication failed").unwrap();
        writeln!(f, "Apr  8 14:31:00 mailhost postfix/smtpd[12346]: connect from unknown[10.0.0.1]").unwrap();
        writeln!(f, "Apr  8 14:32:00 mailhost postfix/smtpd[12347]: warning: unknown[198.51.100.20]: SASL PLAIN authentication failed").unwrap();
    }

    let mut fw = FileWatcher::new(&log_path, false).unwrap();
    let lines = fw.read_new_lines().unwrap();
    let patterns = patterns();
    let events: Vec<_> = lines
        .iter()
        .filter_map(|line| parse_postfix_line(line, &patterns))
        .map(postfix_event_to_normalized)
        .collect();

    assert_eq!(events.len(), 2);
    assert_eq!(events[0].source_ip, "203.0.113.50".parse::<IpAddr>().unwrap());
    assert_eq!(events[1].source_ip, "198.51.100.20".parse::<IpAddr>().unwrap());
}
