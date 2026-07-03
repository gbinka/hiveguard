use std::io::Write;

use hiveguard_core::models::EventType;
use hiveguard_ingest::ssh_parser::{parse_ssh_line, ssh_event_to_normalized, SshPatterns};

fn load_fixture() -> String {
    std::fs::read_to_string("tests/fixtures/auth.log.sample")
        .expect("Failed to read auth.log.sample fixture")
}

fn patterns() -> SshPatterns {
    SshPatterns::new()
}

#[test]
fn test_fixture_parses_expected_event_count() {
    let content = load_fixture();
    let patterns = patterns();
    let events: Vec<_> = content
        .lines()
        .filter_map(|line| parse_ssh_line(line, &patterns))
        .collect();

    // Expected matches:
    // 3 Failed password for admin (lines 1-3)
    // 2 Failed password for invalid user (lines 4-5)
    // 2 Invalid user (lines 6-7)
    // 1 Accepted password (line 8)
    // 1 Accepted publickey for deploy (line 9)
    // 3 Failed password for root (lines 14-16)
    // 1 Accepted publickey for admin (line 17)
    // 1 Failed password for invalid user postgres IPv6 (line 18)
    // 1 Invalid user nagios IPv6 (line 20)
    // Total: 15
    assert_eq!(events.len(), 15, "Expected 15 parsed events from fixture");
}

#[test]
fn test_fixture_auth_failure_count() {
    let content = load_fixture();
    let patterns = patterns();
    let failures: Vec<_> = content
        .lines()
        .filter_map(|line| parse_ssh_line(line, &patterns))
        .filter(|e| e.event_type == EventType::AuthFailure)
        .collect();

    // 3 admin + 2 invalid user failed + 2 Invalid user + 3 root + 1 postgres + 1 nagios = 12
    assert_eq!(failures.len(), 12, "Expected 12 auth failure events");
}

#[test]
fn test_fixture_auth_success_count() {
    let content = load_fixture();
    let patterns = patterns();
    let successes: Vec<_> = content
        .lines()
        .filter_map(|line| parse_ssh_line(line, &patterns))
        .filter(|e| e.event_type == EventType::AuthSuccess)
        .collect();

    // 1 Accepted password + 2 Accepted publickey = 3
    assert_eq!(successes.len(), 3, "Expected 3 auth success events");
}

#[test]
fn test_fixture_invalid_user_metadata() {
    let content = load_fixture();
    let patterns = patterns();
    let invalid_users: Vec<_> = content
        .lines()
        .filter_map(|line| parse_ssh_line(line, &patterns))
        .filter(|e| e.invalid_user)
        .collect();

    // 2 "Failed password for invalid user" + 2 "Invalid user" + 1 IPv6 failed invalid + 1 IPv6 invalid user = 6
    assert_eq!(
        invalid_users.len(),
        6,
        "Expected 6 events with invalid_user=true"
    );

    for event in &invalid_users {
        assert_eq!(event.event_type, EventType::AuthFailure);
    }
}

#[test]
fn test_fixture_ipv6_addresses() {
    let content = load_fixture();
    let patterns = patterns();
    let ipv6_events: Vec<_> = content
        .lines()
        .filter_map(|line| parse_ssh_line(line, &patterns))
        .filter(|e| e.source_ip.is_ipv6())
        .collect();

    assert_eq!(ipv6_events.len(), 2, "Expected 2 IPv6 events");
    let ips: Vec<String> = ipv6_events.iter().map(|e| e.source_ip.to_string()).collect();
    assert!(ips.contains(&"2001:db8::1".to_string()));
    assert!(ips.contains(&"2001:db8::dead:beef".to_string()));
}

#[test]
fn test_fixture_normalization() {
    let content = load_fixture();
    let patterns = patterns();
    let normalized: Vec<_> = content
        .lines()
        .filter_map(|line| parse_ssh_line(line, &patterns))
        .map(ssh_event_to_normalized)
        .collect();

    for event in &normalized {
        assert_eq!(event.source_name, "ssh");
        assert!(event.metadata.contains_key("user"));
        assert!(!event.raw_line.is_empty());
    }
}

#[test]
fn test_fixture_users_extracted() {
    let content = load_fixture();
    let patterns = patterns();
    let users: Vec<String> = content
        .lines()
        .filter_map(|line| parse_ssh_line(line, &patterns))
        .map(|e| e.user.clone())
        .collect();

    assert!(users.contains(&"admin".to_string()));
    assert!(users.contains(&"root".to_string()));
    assert!(users.contains(&"hacker".to_string()));
    assert!(users.contains(&"deploy".to_string()));
    assert!(users.contains(&"test".to_string()));
    assert!(users.contains(&"postgres".to_string()));
    assert!(users.contains(&"nagios".to_string()));
}

#[test]
fn test_file_watcher_with_ssh_parser() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("auth.log");

    // Write initial content
    {
        let mut f = std::fs::File::create(&log_path).unwrap();
        writeln!(f, "Apr  8 14:30:22 server sshd[1234]: Failed password for admin from 192.168.1.100 port 22 ssh2").unwrap();
        writeln!(f, "Apr  8 14:34:00 server CRON[5678]: (root) CMD (/usr/bin/something)").unwrap();
    }

    let mut fw = hiveguard_ingest::FileWatcher::new(&log_path, false).unwrap();
    let patterns = patterns();

    let lines = fw.read_new_lines().unwrap();
    let events: Vec<_> = lines
        .iter()
        .filter_map(|l| parse_ssh_line(l, &patterns))
        .collect();

    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event_type, EventType::AuthFailure);
    assert_eq!(events[0].user, "admin");

    // Append more lines
    {
        let mut f = std::fs::OpenOptions::new().append(true).open(&log_path).unwrap();
        writeln!(f, "Apr  8 14:33:00 server sshd[1237]: Accepted password for root from 192.168.1.1 port 22 ssh2").unwrap();
    }

    let lines = fw.read_new_lines().unwrap();
    let events: Vec<_> = lines
        .iter()
        .filter_map(|l| parse_ssh_line(l, &patterns))
        .collect();

    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event_type, EventType::AuthSuccess);
    assert_eq!(events[0].user, "root");
}
