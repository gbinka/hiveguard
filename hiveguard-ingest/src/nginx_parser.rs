use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use chrono::{DateTime, FixedOffset, Utc};
use notify::{EventKind, RecursiveMode, Watcher};
use regex::Regex;
use tokio::sync::mpsc;
use tracing::{info, trace, warn};

use hiveguard_core::errors::HiveGuardError;
use hiveguard_core::models::{EventType, NormalizedEvent};

use crate::file_watcher::{self, FileWatcher};
use crate::source::LogSource;

/// Parsed Nginx access log event before normalization.
#[derive(Debug, Clone)]
pub struct NginxEvent {
    pub source_ip: IpAddr,
    pub timestamp: DateTime<Utc>,
    pub method: String,
    pub path: String,
    pub protocol: String,
    pub status_code: u16,
    pub body_bytes_sent: u64,
    pub user_agent: String,
    pub raw_line: String,
}

/// Compiled regex pattern for Nginx combined log format.
pub struct NginxPattern {
    combined: Regex,
}

impl Default for NginxPattern {
    fn default() -> Self {
        Self::new()
    }
}

impl NginxPattern {
    pub fn new() -> Self {
        // Nginx combined log format:
        // $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"
        Self {
            combined: Regex::new(
                r#"^([0-9a-fA-F.:]+) - [^\s]+ \[([^\]]+)\] "([^"]*)" (\d{3}) (\d+) "[^"]*" "([^"]*)""#
            ).unwrap(),
        }
    }
}

/// Parse Nginx timestamp format: `dd/Mon/yyyy:HH:mm:ss +zone`
pub fn parse_nginx_timestamp(ts: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_str(ts, "%d/%b/%Y:%H:%M:%S %z")
        .ok()
        .map(|dt: DateTime<FixedOffset>| dt.with_timezone(&Utc))
}

/// Parse the request line into (method, path, protocol).
/// Returns None if the request line is malformed.
fn parse_request_line(request: &str) -> Option<(String, String, String)> {
    let parts: Vec<&str> = request.splitn(3, ' ').collect();
    if parts.len() >= 2 {
        let method = parts[0].to_string();
        let path = parts[1].to_string();
        let protocol = if parts.len() == 3 {
            parts[2].to_string()
        } else {
            String::new()
        };
        Some((method, path, protocol))
    } else {
        None
    }
}

/// Map HTTP status code to an EventType.
fn status_to_event_type(status: u16) -> EventType {
    match status {
        400..=499 => EventType::Http4xx,
        500..=599 => EventType::Http5xx,
        _ => EventType::HttpRequest,
    }
}

/// Try to parse a single Nginx access log line into an NginxEvent.
/// Returns None if the line doesn't match the combined format.
pub fn parse_nginx_line(line: &str, pattern: &NginxPattern) -> Option<NginxEvent> {
    let caps = pattern.combined.captures(line)?;

    let ip_str = &caps[1];
    let source_ip: IpAddr = match ip_str.parse() {
        Ok(ip) => ip,
        Err(_) => {
            warn!(line = line, "Failed to parse IP from Nginx log line");
            return None;
        }
    };

    let timestamp = parse_nginx_timestamp(&caps[2]).unwrap_or_else(Utc::now);

    let request_str = &caps[3];
    let (method, path, protocol) = match parse_request_line(request_str) {
        Some(parsed) => parsed,
        None => {
            trace!(line = line, "Malformed request line, skipping");
            return None;
        }
    };

    let status_code: u16 = match caps[4].parse() {
        Ok(s) => s,
        Err(_) => {
            warn!(line = line, "Failed to parse status code");
            return None;
        }
    };

    let body_bytes_sent: u64 = caps[5].parse().unwrap_or(0);
    let user_agent = caps[6].to_string();

    Some(NginxEvent {
        source_ip,
        timestamp,
        method,
        path,
        protocol,
        status_code,
        body_bytes_sent,
        user_agent,
        raw_line: line.to_string(),
    })
}

/// Convert an NginxEvent into a NormalizedEvent.
pub fn nginx_event_to_normalized(event: NginxEvent) -> NormalizedEvent {
    let event_type = status_to_event_type(event.status_code);

    let mut metadata = HashMap::new();
    metadata.insert("path".to_string(), event.path);
    metadata.insert("method".to_string(), event.method);
    metadata.insert("user_agent".to_string(), event.user_agent);
    metadata.insert("status_code".to_string(), event.status_code.to_string());

    NormalizedEvent {
        timestamp: event.timestamp,
        source_ip: event.source_ip,
        event_type,
        source_name: "nginx".to_string(),
        raw_line: event.raw_line,
        metadata,
    }
}

/// Nginx access.log source implementing the LogSource trait.
pub struct NginxLogSource {
    access_log_path: PathBuf,
    data_dir: Option<PathBuf>,
    stop_tx: Option<tokio::sync::watch::Sender<bool>>,
}

impl NginxLogSource {
    pub fn new(access_log_path: impl Into<PathBuf>) -> Self {
        Self {
            access_log_path: access_log_path.into(),
            data_dir: None,
            stop_tx: None,
        }
    }

    /// Set the data directory for offset persistence.
    pub fn with_data_dir(mut self, data_dir: impl Into<PathBuf>) -> Self {
        self.data_dir = Some(data_dir.into());
        self
    }
}

#[async_trait::async_trait]
impl LogSource for NginxLogSource {
    fn name(&self) -> &str {
        "nginx"
    }

    async fn start(
        &mut self,
        sender: mpsc::Sender<NormalizedEvent>,
    ) -> Result<(), HiveGuardError> {
        let path = self.access_log_path.clone();
        if !path.exists() {
            return Err(HiveGuardError::Config(format!(
                "Nginx access log not found: {}",
                path.display()
            )));
        }

        // Load persisted offset or start from end
        let initial_offset = self
            .data_dir
            .as_ref()
            .map(|d| file_watcher::load_offset(d, "nginx"))
            .filter(|&o| o > 0);

        let mut fw = if let Some(offset) = initial_offset {
            info!(offset = offset, "Resuming Nginx log from saved offset");
            FileWatcher::with_offset(path.clone(), offset)
        } else {
            FileWatcher::new(path.clone(), true)?
        };

        let (stop_tx, mut stop_rx) = tokio::sync::watch::channel(false);
        self.stop_tx = Some(stop_tx);

        let data_dir = self.data_dir.clone();
        let pattern = NginxPattern::new();

        let (notify_tx, mut notify_rx) = mpsc::channel::<()>(16);

        let notify_tx_clone = notify_tx.clone();
        let mut watcher =
            notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
                if let Ok(event) = res {
                    if matches!(event.kind, EventKind::Modify(_)) {
                        let _ = notify_tx_clone.blocking_send(());
                    }
                }
            })
            .map_err(|e| HiveGuardError::Io(std::io::Error::other(e)))?;

        let watch_path = path.parent().unwrap_or(Path::new("."));
        watcher
            .watch(watch_path, RecursiveMode::NonRecursive)
            .map_err(|e| HiveGuardError::Io(std::io::Error::other(e)))?;

        tokio::spawn(async move {
            let _watcher = watcher;

            loop {
                tokio::select! {
                    _ = stop_rx.changed() => {
                        if *stop_rx.borrow() {
                            info!("Nginx log source stopping");
                            if let Some(ref dd) = data_dir {
                                let _ = file_watcher::save_offset(dd, "nginx", fw.offset());
                            }
                            break;
                        }
                    }
                    Some(()) = notify_rx.recv() => {
                        while notify_rx.try_recv().is_ok() {}

                        match fw.read_new_lines() {
                            Ok(lines) => {
                                for line in lines {
                                    if let Some(event) = parse_nginx_line(&line, &pattern) {
                                        let normalized = nginx_event_to_normalized(event);
                                        if sender.send(normalized).await.is_err() {
                                            info!("Channel closed, Nginx source stopping");
                                            return;
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                warn!(error = %e, "Error reading new lines from Nginx log");
                            }
                        }
                    }
                }
            }
        });

        info!(path = %self.access_log_path.display(), "Nginx log source started");
        Ok(())
    }

    async fn stop(&mut self) -> Result<(), HiveGuardError> {
        if let Some(tx) = self.stop_tx.take() {
            let _ = tx.send(true);
        }
        info!("Nginx log source stopped");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Timelike;

    fn pattern() -> NginxPattern {
        NginxPattern::new()
    }

    #[test]
    fn test_parse_normal_200_request() {
        let line = r#"192.168.1.10 - - [08/Apr/2026:14:20:01 +0000] "GET / HTTP/1.1" 200 5123 "-" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36""#;
        let event = parse_nginx_line(line, &pattern()).unwrap();
        assert_eq!(event.source_ip, "192.168.1.10".parse::<IpAddr>().unwrap());
        assert_eq!(event.method, "GET");
        assert_eq!(event.path, "/");
        assert_eq!(event.protocol, "HTTP/1.1");
        assert_eq!(event.status_code, 200);
        assert_eq!(event.body_bytes_sent, 5123);
        assert!(event.user_agent.contains("Mozilla"));
    }

    #[test]
    fn test_parse_404_request() {
        let line = r#"203.0.113.50 - - [08/Apr/2026:14:20:10 +0000] "GET /nonexistent-page HTTP/1.1" 404 1234 "-" "Mozilla/5.0 (compatible; Googlebot/2.1)""#;
        let event = parse_nginx_line(line, &pattern()).unwrap();
        assert_eq!(event.status_code, 404);
        assert_eq!(event.path, "/nonexistent-page");
    }

    #[test]
    fn test_parse_403_request() {
        let line = r#"198.51.100.20 - - [08/Apr/2026:14:20:15 +0000] "GET /admin/config HTTP/1.1" 403 289 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)""#;
        let event = parse_nginx_line(line, &pattern()).unwrap();
        assert_eq!(event.status_code, 403);
        assert_eq!(event.path, "/admin/config");
    }

    #[test]
    fn test_parse_500_request() {
        let line = r#"192.168.1.10 - - [08/Apr/2026:14:20:40 +0000] "GET /api/internal HTTP/1.1" 500 0 "-" "Mozilla/5.0 (X11; Linux x86_64)""#;
        let event = parse_nginx_line(line, &pattern()).unwrap();
        assert_eq!(event.status_code, 500);
        assert_eq!(event.body_bytes_sent, 0);
    }

    #[test]
    fn test_parse_502_request() {
        let line = r#"192.168.1.10 - - [08/Apr/2026:14:20:41 +0000] "POST /api/webhook HTTP/1.1" 502 0 "https://example.com/" "webhookd/1.0""#;
        let event = parse_nginx_line(line, &pattern()).unwrap();
        assert_eq!(event.status_code, 502);
        assert_eq!(event.method, "POST");
    }

    #[test]
    fn test_parse_wp_login() {
        let line = r#"172.16.0.100 - - [08/Apr/2026:14:20:20 +0000] "GET /wp-login.php HTTP/1.1" 404 4567 "-" "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1""#;
        let event = parse_nginx_line(line, &pattern()).unwrap();
        assert_eq!(event.path, "/wp-login.php");
        assert_eq!(event.status_code, 404);
    }

    #[test]
    fn test_parse_env_probe() {
        let line = r#"172.16.0.100 - - [08/Apr/2026:14:20:22 +0000] "GET /.env HTTP/1.1" 403 162 "-" "Mozilla/5.0 (compatible)""#;
        let event = parse_nginx_line(line, &pattern()).unwrap();
        assert_eq!(event.path, "/.env");
        assert_eq!(event.status_code, 403);
    }

    #[test]
    fn test_parse_nikto_ua() {
        let line = r#"45.33.32.156 - - [08/Apr/2026:14:20:30 +0000] "GET / HTTP/1.1" 200 5123 "-" "Nikto/2.1.6""#;
        let event = parse_nginx_line(line, &pattern()).unwrap();
        assert_eq!(event.user_agent, "Nikto/2.1.6");
    }

    #[test]
    fn test_parse_sqlmap_ua() {
        let line = r#"10.20.30.40 - - [08/Apr/2026:14:20:35 +0000] "GET / HTTP/1.1" 200 5123 "-" "sqlmap/1.7.2#stable (https://sqlmap.org)""#;
        let event = parse_nginx_line(line, &pattern()).unwrap();
        assert!(event.user_agent.contains("sqlmap"));
    }

    #[test]
    fn test_parse_ipv6() {
        let line = r#"2001:db8::1 - - [08/Apr/2026:14:20:50 +0000] "GET /index.html HTTP/1.1" 200 8192 "-" "Mozilla/5.0 (X11; Linux x86_64)""#;
        let event = parse_nginx_line(line, &pattern()).unwrap();
        assert_eq!(event.source_ip, "2001:db8::1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_parse_authenticated_user() {
        let line = r#"192.168.1.10 - admin [08/Apr/2026:14:20:02 +0000] "GET /dashboard HTTP/1.1" 200 8432 "https://example.com/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)""#;
        let event = parse_nginx_line(line, &pattern()).unwrap();
        assert_eq!(event.source_ip, "192.168.1.10".parse::<IpAddr>().unwrap());
        assert_eq!(event.path, "/dashboard");
    }

    #[test]
    fn test_malformed_line_returns_none() {
        let lines = vec![
            "",
            "not a log line at all",
            "this is not a valid log line at all",
            r#"- - [08/Apr/2026:14:20:55 +0000] "GET / HTTP/1.1" 200 100 "-" "test""#,
        ];
        for line in lines {
            assert!(
                parse_nginx_line(line, &pattern()).is_none(),
                "Expected None for: {}",
                line
            );
        }
    }

    #[test]
    fn test_nginx_timestamp_parsing() {
        let ts = parse_nginx_timestamp("08/Apr/2026:14:20:01 +0000");
        assert!(ts.is_some());
        let dt = ts.unwrap();
        assert_eq!(dt.format("%Y-%m-%d %H:%M:%S").to_string(), "2026-04-08 14:20:01");
    }

    #[test]
    fn test_nginx_timestamp_with_offset() {
        let ts = parse_nginx_timestamp("08/Apr/2026:16:20:01 +0200");
        assert!(ts.is_some());
        let dt = ts.unwrap();
        // +0200 means UTC is 2 hours earlier
        assert_eq!(dt.format("%Y-%m-%d %H:%M:%S").to_string(), "2026-04-08 14:20:01");
    }

    #[test]
    fn test_nginx_timestamp_invalid() {
        assert!(parse_nginx_timestamp("not a timestamp").is_none());
        assert!(parse_nginx_timestamp("").is_none());
    }

    #[test]
    fn test_status_to_event_type_mapping() {
        assert_eq!(status_to_event_type(200), EventType::HttpRequest);
        assert_eq!(status_to_event_type(301), EventType::HttpRequest);
        assert_eq!(status_to_event_type(304), EventType::HttpRequest);
        assert_eq!(status_to_event_type(400), EventType::Http4xx);
        assert_eq!(status_to_event_type(403), EventType::Http4xx);
        assert_eq!(status_to_event_type(404), EventType::Http4xx);
        assert_eq!(status_to_event_type(499), EventType::Http4xx);
        assert_eq!(status_to_event_type(500), EventType::Http5xx);
        assert_eq!(status_to_event_type(502), EventType::Http5xx);
        assert_eq!(status_to_event_type(599), EventType::Http5xx);
    }

    #[test]
    fn test_nginx_event_to_normalized() {
        let event = NginxEvent {
            source_ip: "192.168.1.10".parse().unwrap(),
            timestamp: Utc::now(),
            method: "GET".to_string(),
            path: "/admin".to_string(),
            protocol: "HTTP/1.1".to_string(),
            status_code: 403,
            body_bytes_sent: 289,
            user_agent: "Nikto/2.1.6".to_string(),
            raw_line: "test line".to_string(),
        };
        let normalized = nginx_event_to_normalized(event);
        assert_eq!(normalized.source_name, "nginx");
        assert_eq!(normalized.event_type, EventType::Http4xx);
        assert_eq!(normalized.source_ip, "192.168.1.10".parse::<IpAddr>().unwrap());
        assert_eq!(normalized.metadata.get("path").unwrap(), "/admin");
        assert_eq!(normalized.metadata.get("method").unwrap(), "GET");
        assert_eq!(normalized.metadata.get("user_agent").unwrap(), "Nikto/2.1.6");
        assert_eq!(normalized.metadata.get("status_code").unwrap(), "403");
    }

    #[test]
    fn test_nginx_event_to_normalized_5xx() {
        let event = NginxEvent {
            source_ip: "10.0.0.1".parse().unwrap(),
            timestamp: Utc::now(),
            method: "POST".to_string(),
            path: "/api/webhook".to_string(),
            protocol: "HTTP/1.1".to_string(),
            status_code: 502,
            body_bytes_sent: 0,
            user_agent: "webhookd/1.0".to_string(),
            raw_line: "test line".to_string(),
        };
        let normalized = nginx_event_to_normalized(event);
        assert_eq!(normalized.event_type, EventType::Http5xx);
        assert_eq!(normalized.metadata.get("status_code").unwrap(), "502");
    }

    #[test]
    fn test_nginx_event_to_normalized_200() {
        let event = NginxEvent {
            source_ip: "10.0.0.1".parse().unwrap(),
            timestamp: Utc::now(),
            method: "GET".to_string(),
            path: "/".to_string(),
            protocol: "HTTP/1.1".to_string(),
            status_code: 200,
            body_bytes_sent: 5123,
            user_agent: "Mozilla/5.0".to_string(),
            raw_line: "test line".to_string(),
        };
        let normalized = nginx_event_to_normalized(event);
        assert_eq!(normalized.event_type, EventType::HttpRequest);
    }

    // --- Phase 10: comprehensive coverage ---

    #[test]
    fn test_parse_ipv6_nginx_line() {
        let pattern = NginxPattern::new();
        let line = r#"2001:db8::1 - - [10/Apr/2024:14:30:00 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0""#;
        let event = parse_nginx_line(line, &pattern).unwrap();
        assert_eq!(event.source_ip, "2001:db8::1".parse::<IpAddr>().unwrap());
        assert_eq!(event.status_code, 200);
        assert_eq!(event.path, "/index.html");
    }

    #[test]
    fn test_empty_line_returns_none_nginx() {
        let pattern = NginxPattern::new();
        assert!(parse_nginx_line("", &pattern).is_none());
    }

    #[test]
    fn test_garbage_line_returns_none_nginx() {
        let pattern = NginxPattern::new();
        assert!(parse_nginx_line("this is not a log line at all", &pattern).is_none());
    }

    #[test]
    fn test_long_user_agent() {
        let pattern = NginxPattern::new();
        let long_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
        let line = format!(
            r#"10.0.0.1 - - [10/Apr/2024:14:30:00 +0000] "GET / HTTP/1.1" 200 5000 "-" "{}""#,
            long_ua
        );
        let event = parse_nginx_line(&line, &pattern).unwrap();
        assert_eq!(event.user_agent, long_ua);
    }

    #[test]
    fn test_path_with_query_string() {
        let pattern = NginxPattern::new();
        let line = r#"10.0.0.1 - - [10/Apr/2024:14:30:00 +0000] "GET /search?q=test&page=2 HTTP/1.1" 200 1000 "-" "curl/7.81""#;
        let event = parse_nginx_line(line, &pattern).unwrap();
        assert_eq!(event.path, "/search?q=test&page=2");
    }

    #[test]
    fn test_delete_method() {
        let pattern = NginxPattern::new();
        let line = r#"10.0.0.1 - - [10/Apr/2024:14:30:00 +0000] "DELETE /api/resource/123 HTTP/1.1" 204 0 "-" "curl/7.81""#;
        let event = parse_nginx_line(line, &pattern).unwrap();
        assert_eq!(event.method, "DELETE");
        assert_eq!(event.status_code, 204);
    }

    #[test]
    fn test_status_301_redirect() {
        let pattern = NginxPattern::new();
        let line = r#"10.0.0.1 - - [10/Apr/2024:14:30:00 +0000] "GET /old-page HTTP/1.1" 301 0 "-" "Mozilla/5.0""#;
        let event = parse_nginx_line(line, &pattern).unwrap();
        let normalized = nginx_event_to_normalized(event);
        assert_eq!(normalized.event_type, EventType::HttpRequest); // 3xx = HttpRequest
    }

    #[test]
    fn test_status_304_not_modified() {
        let pattern = NginxPattern::new();
        let line = r#"10.0.0.1 - - [10/Apr/2024:14:30:00 +0000] "GET /style.css HTTP/1.1" 304 0 "-" "Mozilla/5.0""#;
        let event = parse_nginx_line(line, &pattern).unwrap();
        let normalized = nginx_event_to_normalized(event);
        assert_eq!(normalized.event_type, EventType::HttpRequest); // 3xx = HttpRequest
    }

    #[test]
    fn test_status_499_client_closed() {
        let pattern = NginxPattern::new();
        let line = r#"10.0.0.1 - - [10/Apr/2024:14:30:00 +0000] "GET /slow-api HTTP/1.1" 499 0 "-" "Mozilla/5.0""#;
        let event = parse_nginx_line(line, &pattern).unwrap();
        let normalized = nginx_event_to_normalized(event);
        assert_eq!(normalized.event_type, EventType::Http4xx);
    }

    #[test]
    fn test_large_body_bytes() {
        let pattern = NginxPattern::new();
        let line = r#"10.0.0.1 - - [10/Apr/2024:14:30:00 +0000] "GET /large-file HTTP/1.1" 200 104857600 "-" "wget/1.21""#;
        let event = parse_nginx_line(line, &pattern).unwrap();
        assert_eq!(event.body_bytes_sent, 104857600); // 100MB
    }

    #[test]
    fn test_nginx_timestamp_negative_offset() {
        let ts = parse_nginx_timestamp("10/Apr/2024:14:30:00 -0500");
        assert!(ts.is_some());
        // 14:30 -0500 = 19:30 UTC
        assert_eq!(ts.unwrap().hour(), 19);
    }

    #[test]
    fn test_normalized_metadata_fields() {
        let event = NginxEvent {
            source_ip: "10.0.0.1".parse().unwrap(),
            timestamp: Utc::now(),
            method: "PUT".to_string(),
            path: "/api/update".to_string(),
            protocol: "HTTP/2.0".to_string(),
            status_code: 403,
            body_bytes_sent: 250,
            user_agent: "test-agent".to_string(),
            raw_line: "test".to_string(),
        };
        let normalized = nginx_event_to_normalized(event);
        assert_eq!(normalized.metadata.get("method").unwrap(), "PUT");
        assert_eq!(normalized.metadata.get("path").unwrap(), "/api/update");
        assert_eq!(normalized.metadata.get("user_agent").unwrap(), "test-agent");
        assert_eq!(normalized.metadata.get("status_code").unwrap(), "403");
        assert_eq!(normalized.source_name, "nginx");
    }
}
