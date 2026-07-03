use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use chrono::Utc;
use notify::{EventKind, RecursiveMode, Watcher};
use regex::Regex;
use tokio::sync::mpsc;
use tracing::{info, warn};

use hiveguard_core::errors::HiveGuardError;
use hiveguard_core::models::{EventType, NormalizedEvent};

use crate::file_watcher::{self, FileWatcher};
use crate::source::LogSource;

/// Custom regex-based log parser configured from YAML.
/// Requires a named group `ip` in the regex pattern.
/// Optional named groups: `user`, `path`, `status`.
#[derive(Debug)]
pub struct CustomLogSource {
    log_path: PathBuf,
    pattern: Regex,
    detector_name: String,
    source_label: String,
    data_dir: Option<PathBuf>,
    stop_tx: Option<tokio::sync::watch::Sender<bool>>,
}

impl CustomLogSource {
    /// Create a new CustomLogSource.
    ///
    /// # Arguments
    /// * `log_path` — path to the log file to watch
    /// * `pattern` — regex pattern string (must contain named group `ip`)
    /// * `detector_name` — name used for `EventType::Custom(detector_name)`
    ///
    /// # Errors
    /// Returns `HiveGuardError::Config` if:
    /// - the regex pattern is invalid
    /// - the regex pattern does not contain a named group `ip`
    pub fn new(
        log_path: impl Into<PathBuf>,
        pattern: &str,
        detector_name: impl Into<String>,
    ) -> Result<Self, HiveGuardError> {
        // Guard against excessively complex regex patterns (F-8)
        if pattern.len() > 1024 {
            return Err(HiveGuardError::Config(
                "Custom regex pattern exceeds maximum length of 1024 characters".to_string(),
            ));
        }

        let compiled = Regex::new(pattern).map_err(|e| {
            HiveGuardError::Config(format!("Invalid custom regex pattern: {}", e))
        })?;

        // Validate that the pattern contains named group `ip`
        let has_ip_group = compiled
            .capture_names()
            .any(|name| name == Some("ip"));

        if !has_ip_group {
            return Err(HiveGuardError::Config(
                "Custom regex pattern must contain named group 'ip' (e.g., (?P<ip>...))".to_string(),
            ));
        }

        let detector_name = detector_name.into();
        let path: PathBuf = log_path.into();
        let source_label = format!("custom_{}", detector_name);

        Ok(Self {
            log_path: path,
            pattern: compiled,
            detector_name,
            source_label,
            data_dir: None,
            stop_tx: None,
        })
    }

    /// Set the data directory for offset persistence.
    pub fn with_data_dir(mut self, data_dir: impl Into<PathBuf>) -> Self {
        self.data_dir = Some(data_dir.into());
        self
    }
}

/// Try to parse a single log line using the custom regex pattern.
/// Returns None if the line doesn't match or the IP is invalid.
pub fn parse_custom_line(
    line: &str,
    pattern: &Regex,
    detector_name: &str,
) -> Option<NormalizedEvent> {
    let caps = pattern.captures(line)?;

    let ip_str = caps.name("ip")?.as_str();
    let ip: IpAddr = match ip_str.parse() {
        Ok(ip) => ip,
        Err(_) => {
            warn!(line = line, ip = ip_str, "Failed to parse IP from custom log line");
            return None;
        }
    };

    let mut metadata = HashMap::new();

    if let Some(user) = caps.name("user") {
        metadata.insert("user".to_string(), user.as_str().to_string());
    }
    if let Some(path) = caps.name("path") {
        metadata.insert("path".to_string(), path.as_str().to_string());
    }
    if let Some(status) = caps.name("status") {
        metadata.insert("status".to_string(), status.as_str().to_string());
    }

    Some(NormalizedEvent {
        timestamp: Utc::now(),
        source_ip: ip,
        event_type: EventType::Custom(detector_name.to_string()),
        source_name: format!("custom_{}", detector_name),
        raw_line: line.to_string(),
        metadata,
    })
}

#[async_trait::async_trait]
impl LogSource for CustomLogSource {
    fn name(&self) -> &str {
        &self.source_label
    }

    async fn start(
        &mut self,
        sender: mpsc::Sender<NormalizedEvent>,
    ) -> Result<(), HiveGuardError> {
        let path = self.log_path.clone();
        if !path.exists() {
            return Err(HiveGuardError::Config(format!(
                "Custom log file not found: {}",
                path.display()
            )));
        }

        let initial_offset = self
            .data_dir
            .as_ref()
            .map(|d| file_watcher::load_offset(d, &self.source_label))
            .filter(|&o| o > 0);

        let mut fw = if let Some(offset) = initial_offset {
            info!(offset = offset, source = %self.source_label, "Resuming custom log from saved offset");
            FileWatcher::with_offset(path.clone(), offset)
        } else {
            FileWatcher::new(path.clone(), true)?
        };

        let (stop_tx, mut stop_rx) = tokio::sync::watch::channel(false);
        self.stop_tx = Some(stop_tx);

        let data_dir = self.data_dir.clone();
        let pattern = self.pattern.clone();
        let detector_name = self.detector_name.clone();
        let source_label = self.source_label.clone();

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

        let source_label_clone = source_label.clone();
        tokio::spawn(async move {
            let _watcher = watcher;

            loop {
                tokio::select! {
                    _ = stop_rx.changed() => {
                        if *stop_rx.borrow() {
                            info!(source = %source_label_clone, "Custom log source stopping");
                            if let Some(ref dd) = data_dir {
                                let _ = file_watcher::save_offset(dd, &source_label_clone, fw.offset());
                            }
                            break;
                        }
                    }
                    Some(()) = notify_rx.recv() => {
                        while notify_rx.try_recv().is_ok() {}

                        match fw.read_new_lines() {
                            Ok(lines) => {
                                for line in lines {
                                    if let Some(normalized) = parse_custom_line(&line, &pattern, &detector_name) {
                                        if sender.send(normalized).await.is_err() {
                                            info!(source = %source_label_clone, "Channel closed, custom source stopping");
                                            return;
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                warn!(source = %source_label_clone, error = %e, "Error reading new lines from custom log");
                            }
                        }
                    }
                }
            }
        });

        info!(path = %self.log_path.display(), source = %source_label, "Custom log source started");
        Ok(())
    }

    async fn stop(&mut self) -> Result<(), HiveGuardError> {
        if let Some(tx) = self.stop_tx.take() {
            let _ = tx.send(true);
        }
        info!(source = %self.source_label, "Custom log source stopped");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_custom_parse_basic_ip_user() {
        let pattern = Regex::new(r"FAILED_LOGIN ip=(?P<ip>\S+) user=(?P<user>\S+)").unwrap();
        let line = "2026-04-08 FAILED_LOGIN ip=203.0.113.50 user=admin";
        let event = parse_custom_line(line, &pattern, "brute_force").unwrap();
        assert_eq!(event.source_ip, "203.0.113.50".parse::<IpAddr>().unwrap());
        assert_eq!(event.event_type, EventType::Custom("brute_force".to_string()));
        assert_eq!(event.source_name, "custom_brute_force");
        assert_eq!(event.metadata.get("user").unwrap(), "admin");
        assert_eq!(event.raw_line, line);
    }

    #[test]
    fn test_custom_parse_ip_only() {
        let pattern = Regex::new(r"blocked (?P<ip>[0-9.]+)").unwrap();
        let line = "firewall: blocked 10.20.30.40 on port 443";
        let event = parse_custom_line(line, &pattern, "firewall").unwrap();
        assert_eq!(event.source_ip, "10.20.30.40".parse::<IpAddr>().unwrap());
        assert!(event.metadata.get("user").is_none());
    }

    #[test]
    fn test_custom_parse_with_path_and_status() {
        let pattern = Regex::new(
            r"(?P<ip>[0-9.]+)\s+(?P<path>/\S+)\s+(?P<status>\d+)"
        ).unwrap();
        let line = "192.168.1.1 /admin/login 403";
        let event = parse_custom_line(line, &pattern, "web_probe").unwrap();
        assert_eq!(event.source_ip, "192.168.1.1".parse::<IpAddr>().unwrap());
        assert_eq!(event.metadata.get("path").unwrap(), "/admin/login");
        assert_eq!(event.metadata.get("status").unwrap(), "403");
    }

    #[test]
    fn test_custom_parse_ipv6() {
        let pattern = Regex::new(r"from=(?P<ip>[0-9a-fA-F:]+)").unwrap();
        let line = "connection from=2001:db8::1 rejected";
        let event = parse_custom_line(line, &pattern, "conn_reject").unwrap();
        assert_eq!(event.source_ip, "2001:db8::1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_custom_parse_no_match_returns_none() {
        let pattern = Regex::new(r"FAILED_LOGIN ip=(?P<ip>\S+)").unwrap();
        let line = "INFO: User logged in successfully";
        assert!(parse_custom_line(line, &pattern, "brute_force").is_none());
    }

    #[test]
    fn test_custom_parse_invalid_ip_returns_none() {
        let pattern = Regex::new(r"ip=(?P<ip>\S+)").unwrap();
        let line = "FAILED_LOGIN ip=not-an-ip user=admin";
        assert!(parse_custom_line(line, &pattern, "brute_force").is_none());
    }

    #[test]
    fn test_custom_parse_empty_line_returns_none() {
        let pattern = Regex::new(r"ip=(?P<ip>\S+)").unwrap();
        assert!(parse_custom_line("", &pattern, "test").is_none());
    }

    #[test]
    fn test_custom_source_new_valid() {
        let result = CustomLogSource::new(
            "/tmp/test.log",
            r"ip=(?P<ip>\S+)",
            "test_detector",
        );
        assert!(result.is_ok());
        let source = result.unwrap();
        assert_eq!(source.name(), "custom_test_detector");
    }

    #[test]
    fn test_custom_source_new_missing_ip_group() {
        let result = CustomLogSource::new(
            "/tmp/test.log",
            r"user=(\S+)",
            "bad_detector",
        );
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("named group 'ip'"), "Error was: {}", err);
    }

    #[test]
    fn test_custom_source_new_invalid_regex() {
        let result = CustomLogSource::new(
            "/tmp/test.log",
            r"[invalid(regex",
            "bad_detector",
        );
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("Invalid custom regex"), "Error was: {}", err);
    }

    #[test]
    fn test_custom_source_name_derived_from_detector() {
        let source = CustomLogSource::new(
            "/tmp/test.log",
            r"(?P<ip>[0-9.]+)",
            "my_app_auth",
        ).unwrap();
        assert_eq!(source.name(), "custom_my_app_auth");
    }

    #[test]
    fn test_custom_parse_multiple_named_groups() {
        let pattern = Regex::new(
            r"ip=(?P<ip>\S+)\s+user=(?P<user>\S+)\s+path=(?P<path>\S+)\s+status=(?P<status>\d+)"
        ).unwrap();
        let line = "ip=192.168.1.100 user=hacker path=/secret status=401";
        let event = parse_custom_line(line, &pattern, "full_match").unwrap();
        assert_eq!(event.source_ip, "192.168.1.100".parse::<IpAddr>().unwrap());
        assert_eq!(event.metadata.get("user").unwrap(), "hacker");
        assert_eq!(event.metadata.get("path").unwrap(), "/secret");
        assert_eq!(event.metadata.get("status").unwrap(), "401");
        assert_eq!(event.event_type, EventType::Custom("full_match".to_string()));
    }
}
