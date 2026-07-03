use std::io::Write;

use hiveguard_core::models::EventType;
use hiveguard_ingest::nginx_parser::{nginx_event_to_normalized, parse_nginx_line, NginxPattern};

fn load_fixture() -> String {
    std::fs::read_to_string("tests/fixtures/nginx_access.log.sample")
        .expect("Failed to read nginx_access.log.sample fixture")
}

fn pattern() -> NginxPattern {
    NginxPattern::new()
}

#[test]
fn test_fixture_parses_expected_event_count() {
    let content = load_fixture();
    let pattern = pattern();
    let events: Vec<_> = content
        .lines()
        .filter_map(|line| parse_nginx_line(line, &pattern))
        .collect();

    // 23 lines total, 2 malformed lines (line 22 and 23) = 21 valid events
    assert_eq!(events.len(), 21, "Expected 21 parsed events from fixture");
}

#[test]
fn test_fixture_http_request_count() {
    let content = load_fixture();
    let pattern = pattern();
    let requests: Vec<_> = content
        .lines()
        .filter_map(|line| parse_nginx_line(line, &pattern))
        .map(nginx_event_to_normalized)
        .filter(|e| e.event_type == EventType::HttpRequest)
        .collect();

    // 200s: lines 1,2,3,13,16,20 = 6; 301: line 4 = 1; total = 7
    assert_eq!(requests.len(), 7, "Expected 7 HttpRequest events (2xx + 3xx)");
}

#[test]
fn test_fixture_http4xx_count() {
    let content = load_fixture();
    let pattern = pattern();
    let events_4xx: Vec<_> = content
        .lines()
        .filter_map(|line| parse_nginx_line(line, &pattern))
        .map(nginx_event_to_normalized)
        .filter(|e| e.event_type == EventType::Http4xx)
        .collect();

    // 404: lines 5,6,9,10,12,15 = 6; 403: lines 7,8,11,14,21 = 5; 400: line 17 = 1; total = 12
    assert_eq!(events_4xx.len(), 12, "Expected 12 Http4xx events");
}

#[test]
fn test_fixture_http5xx_count() {
    let content = load_fixture();
    let pattern = pattern();
    let events_5xx: Vec<_> = content
        .lines()
        .filter_map(|line| parse_nginx_line(line, &pattern))
        .map(nginx_event_to_normalized)
        .filter(|e| e.event_type == EventType::Http5xx)
        .collect();

    // 500: line 18, 502: line 19 = 2
    assert_eq!(events_5xx.len(), 2, "Expected 2 Http5xx events");
}

#[test]
fn test_fixture_metadata_contains_required_fields() {
    let content = load_fixture();
    let pattern = pattern();
    let normalized: Vec<_> = content
        .lines()
        .filter_map(|line| parse_nginx_line(line, &pattern))
        .map(nginx_event_to_normalized)
        .collect();

    for event in &normalized {
        assert_eq!(event.source_name, "nginx");
        assert!(event.metadata.contains_key("path"), "Missing 'path' in metadata");
        assert!(event.metadata.contains_key("method"), "Missing 'method' in metadata");
        assert!(
            event.metadata.contains_key("user_agent"),
            "Missing 'user_agent' in metadata"
        );
        assert!(
            event.metadata.contains_key("status_code"),
            "Missing 'status_code' in metadata"
        );
        assert!(!event.raw_line.is_empty());
    }
}

#[test]
fn test_fixture_scanner_user_agents() {
    let content = load_fixture();
    let pattern = pattern();
    let events: Vec<_> = content
        .lines()
        .filter_map(|line| parse_nginx_line(line, &pattern))
        .filter(|e| e.user_agent.contains("Nikto") || e.user_agent.contains("sqlmap"))
        .collect();

    assert_eq!(events.len(), 5, "Expected 5 scanner UA events (3 Nikto + 2 sqlmap)");

    let nikto_count = events.iter().filter(|e| e.user_agent.contains("Nikto")).count();
    let sqlmap_count = events.iter().filter(|e| e.user_agent.contains("sqlmap")).count();
    assert_eq!(nikto_count, 3);
    assert_eq!(sqlmap_count, 2);
}

#[test]
fn test_fixture_probe_paths() {
    let content = load_fixture();
    let pattern = pattern();
    let probe_paths = ["/wp-login.php", "/.env", "/.git/config", "/phpmyadmin"];
    let events: Vec<_> = content
        .lines()
        .filter_map(|line| parse_nginx_line(line, &pattern))
        .filter(|e| probe_paths.contains(&e.path.as_str()))
        .collect();

    // /wp-login.php x2, /.env x1, /.git/config x1, /phpmyadmin x1 = 5
    assert_eq!(events.len(), 5, "Expected 5 probe path events");
}

#[test]
fn test_fixture_ipv6_addresses() {
    let content = load_fixture();
    let pattern = pattern();
    let ipv6_events: Vec<_> = content
        .lines()
        .filter_map(|line| parse_nginx_line(line, &pattern))
        .filter(|e| e.source_ip.is_ipv6())
        .collect();

    assert_eq!(ipv6_events.len(), 2, "Expected 2 IPv6 events");
    let ips: Vec<String> = ipv6_events.iter().map(|e| e.source_ip.to_string()).collect();
    assert!(ips.contains(&"2001:db8::1".to_string()));
    assert!(ips.contains(&"2001:db8::dead:beef".to_string()));
}

#[test]
fn test_fixture_malformed_lines_skipped() {
    let content = load_fixture();
    let pattern = pattern();
    let total_lines = content.lines().count();
    let parsed_count = content
        .lines()
        .filter_map(|line| parse_nginx_line(line, &pattern))
        .count();

    // 2 malformed lines should be skipped
    assert_eq!(total_lines - parsed_count, 2, "Expected 2 malformed lines to be skipped");
}

#[test]
fn test_file_watcher_with_nginx_parser() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("access.log");

    {
        let mut f = std::fs::File::create(&log_path).unwrap();
        writeln!(f, r#"192.168.1.10 - - [08/Apr/2026:14:20:01 +0000] "GET / HTTP/1.1" 200 5123 "-" "Mozilla/5.0""#).unwrap();
        writeln!(f, "this is not a valid line").unwrap();
    }

    let mut fw = hiveguard_ingest::FileWatcher::new(&log_path, false).unwrap();
    let pattern = pattern();

    let lines = fw.read_new_lines().unwrap();
    let events: Vec<_> = lines
        .iter()
        .filter_map(|l| parse_nginx_line(l, &pattern))
        .collect();

    assert_eq!(events.len(), 1);
    assert_eq!(events[0].status_code, 200);
    assert_eq!(events[0].path, "/");

    // Append more lines
    {
        let mut f = std::fs::OpenOptions::new().append(true).open(&log_path).unwrap();
        writeln!(f, r#"10.0.0.5 - - [08/Apr/2026:14:20:10 +0000] "GET /admin HTTP/1.1" 403 289 "-" "curl/8.0""#).unwrap();
    }

    let lines = fw.read_new_lines().unwrap();
    let events: Vec<_> = lines
        .iter()
        .filter_map(|l| parse_nginx_line(l, &pattern))
        .collect();

    assert_eq!(events.len(), 1);
    assert_eq!(events[0].status_code, 403);
    assert_eq!(events[0].path, "/admin");
}
