use std::io::Write;
use std::net::IpAddr;

use hiveguard_core::models::EventType;
use hiveguard_ingest::custom_parser::{parse_custom_line, CustomLogSource};
use hiveguard_ingest::file_watcher::FileWatcher;
use hiveguard_ingest::LogSource;

use regex::Regex;

#[test]
fn custom_regex_with_named_groups_parses_correctly() {
    let pattern = Regex::new(r"FAILED_LOGIN ip=(?P<ip>\S+) user=(?P<user>\S+)").unwrap();
    let line = "2026-04-08 14:00:00 FAILED_LOGIN ip=203.0.113.50 user=admin";
    let event = parse_custom_line(line, &pattern, "brute_force").unwrap();
    assert_eq!(event.source_ip, "203.0.113.50".parse::<IpAddr>().unwrap());
    assert_eq!(event.event_type, EventType::Custom("brute_force".to_string()));
    assert_eq!(event.source_name, "custom_brute_force");
    assert_eq!(event.metadata.get("user").unwrap(), "admin");
}

#[test]
fn missing_ip_group_errors_on_init() {
    let result = CustomLogSource::new(
        "/tmp/test.log",
        r"user=(\S+)",
        "test_detector",
    );
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("named group 'ip'"),
        "Error should mention missing ip group: {}",
        err
    );
}

#[test]
fn invalid_regex_errors_on_init() {
    let result = CustomLogSource::new(
        "/tmp/test.log",
        r"[invalid(regex",
        "test_detector",
    );
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("Invalid custom regex"),
        "Error should mention invalid regex: {}",
        err
    );
}

#[test]
fn malformed_line_skipped() {
    let pattern = Regex::new(r"FAILED_LOGIN ip=(?P<ip>\S+)").unwrap();
    let line = "INFO: System started normally";
    assert!(parse_custom_line(line, &pattern, "brute_force").is_none());
}

#[test]
fn invalid_ip_in_match_skipped() {
    let pattern = Regex::new(r"ip=(?P<ip>\S+)").unwrap();
    let line = "FAILED_LOGIN ip=not.valid.ip.addr";
    assert!(parse_custom_line(line, &pattern, "test").is_none());
}

#[test]
fn custom_source_valid_pattern_has_correct_name() {
    let source = CustomLogSource::new(
        "/tmp/test.log",
        r"(?P<ip>[0-9.]+)",
        "my_detector",
    )
    .unwrap();
    assert_eq!(source.name(), "custom_my_detector");
}

#[test]
fn file_watcher_with_custom_parser() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("app.log");

    {
        let mut f = std::fs::File::create(&log_path).unwrap();
        writeln!(f, "2026-04-08 FAILED_LOGIN ip=10.0.0.1 user=admin").unwrap();
        writeln!(f, "2026-04-08 INFO: all is well").unwrap();
        writeln!(f, "2026-04-08 FAILED_LOGIN ip=10.0.0.2 user=root").unwrap();
        writeln!(f, "2026-04-08 FAILED_LOGIN ip=not-valid user=x").unwrap();
    }

    let mut fw = FileWatcher::new(&log_path, false).unwrap();
    let lines = fw.read_new_lines().unwrap();
    let pattern = Regex::new(r"FAILED_LOGIN ip=(?P<ip>\S+) user=(?P<user>\S+)").unwrap();
    let events: Vec<_> = lines
        .iter()
        .filter_map(|line| parse_custom_line(line, &pattern, "brute_force"))
        .collect();

    assert_eq!(events.len(), 2);
    assert_eq!(events[0].source_ip, "10.0.0.1".parse::<IpAddr>().unwrap());
    assert_eq!(events[0].metadata.get("user").unwrap(), "admin");
    assert_eq!(events[1].source_ip, "10.0.0.2".parse::<IpAddr>().unwrap());
    assert_eq!(events[1].metadata.get("user").unwrap(), "root");
}

#[test]
fn custom_parse_preserves_raw_line() {
    let pattern = Regex::new(r"ip=(?P<ip>[0-9.]+)").unwrap();
    let line = "2026-04-08 ERROR: blocked ip=1.2.3.4 on port 80";
    let event = parse_custom_line(line, &pattern, "test").unwrap();
    assert_eq!(event.raw_line, line);
}

#[test]
fn custom_parse_optional_groups_absent() {
    let pattern = Regex::new(r"ip=(?P<ip>[0-9.]+)").unwrap();
    let line = "blocked ip=1.2.3.4";
    let event = parse_custom_line(line, &pattern, "test").unwrap();
    assert!(event.metadata.get("user").is_none());
    assert!(event.metadata.get("path").is_none());
    assert!(event.metadata.get("status").is_none());
}
