use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use chrono::{DateTime, NaiveDateTime, Utc};
use notify::{EventKind, RecursiveMode, Watcher};
use regex::Regex;
use tokio::sync::mpsc;
use tracing::{info, trace, warn};

use hiveguard_core::errors::HiveGuardError;
use hiveguard_core::models::{EventType, NormalizedEvent};

use crate::file_watcher::{self, FileWatcher};
use crate::source::LogSource;

/// Parsed SSH log event before normalization.
#[derive(Debug, Clone)]
pub struct SshEvent {
    pub timestamp_str: String,
    pub event_type: EventType,
    pub source_ip: IpAddr,
    pub user: String,
    pub invalid_user: bool,
    pub raw_line: String,
}

/// Compiled regex patterns for SSH auth log parsing.
pub struct SshPatterns {
    /// `Failed password for <user> from <ip> port <port>`
    failed_password: Regex,
    /// `Failed password for invalid user <user> from <ip>`
    failed_password_invalid: Regex,
    /// `Invalid user <user> from <ip>`
    invalid_user: Regex,
    /// `Accepted password for <user> from <ip>`
    accepted_password: Regex,
    /// `Accepted publickey for <user> from <ip>`
    accepted_publickey: Regex,
    /// Syslog timestamp prefix
    syslog_timestamp: Regex,
}

impl Default for SshPatterns {
    fn default() -> Self {
        Self::new()
    }
}

impl SshPatterns {
    pub fn new() -> Self {
        Self {
            failed_password: Regex::new(
                r"Failed password for ([^\s]+) from ([0-9a-fA-F.:]+) port \d+"
            ).unwrap(),
            failed_password_invalid: Regex::new(
                r"Failed password for invalid user ([^\s]+) from ([0-9a-fA-F.:]+)"
            ).unwrap(),
            invalid_user: Regex::new(
                r"Invalid user ([^\s]+) from ([0-9a-fA-F.:]+)"
            ).unwrap(),
            accepted_password: Regex::new(
                r"Accepted password for ([^\s]+) from ([0-9a-fA-F.:]+)"
            ).unwrap(),
            accepted_publickey: Regex::new(
                r"Accepted publickey for ([^\s]+) from ([0-9a-fA-F.:]+)"
            ).unwrap(),
            syslog_timestamp: Regex::new(
                r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
            ).unwrap(),
        }
    }
}

/// Parse a syslog-format timestamp string (e.g., "Apr  8 14:30:22") into a `DateTime<Utc>`.
/// Uses the current year since syslog timestamps don't include it.
pub fn parse_syslog_timestamp(ts: &str) -> Option<DateTime<Utc>> {
    let current_year = Utc::now().format("%Y").to_string();
    let with_year = format!("{} {}", current_year, ts);
    NaiveDateTime::parse_from_str(&with_year, "%Y %b %e %H:%M:%S")
        .ok()
        .map(|naive| naive.and_utc())
}

/// Try to parse a single auth.log line into an SshEvent.
/// Returns None if the line doesn't match any known SSH pattern.
pub fn parse_ssh_line(line: &str, patterns: &SshPatterns) -> Option<SshEvent> {
    // Extract syslog timestamp
    let timestamp_str = patterns
        .syslog_timestamp
        .captures(line)
        .map(|c| c[1].to_string())
        .unwrap_or_default();

    // Try patterns in order of specificity
    // 1. Failed password for invalid user
    if let Some(caps) = patterns.failed_password_invalid.captures(line) {
        let user = caps[1].to_string();
        let ip: IpAddr = match caps[2].parse() {
            Ok(ip) => ip,
            Err(_) => {
                warn!(line = line, "Failed to parse IP from auth.log line");
                return None;
            }
        };
        return Some(SshEvent {
            timestamp_str,
            event_type: EventType::AuthFailure,
            source_ip: ip,
            user,
            invalid_user: true,
            raw_line: line.to_string(),
        });
    }

    // 2. Failed password for valid user
    if let Some(caps) = patterns.failed_password.captures(line) {
        let user = caps[1].to_string();
        let ip: IpAddr = match caps[2].parse() {
            Ok(ip) => ip,
            Err(_) => {
                warn!(line = line, "Failed to parse IP from auth.log line");
                return None;
            }
        };
        return Some(SshEvent {
            timestamp_str,
            event_type: EventType::AuthFailure,
            source_ip: ip,
            user,
            invalid_user: false,
            raw_line: line.to_string(),
        });
    }

    // 3. Invalid user (without "Failed password" prefix)
    if let Some(caps) = patterns.invalid_user.captures(line) {
        let user = caps[1].to_string();
        let ip: IpAddr = match caps[2].parse() {
            Ok(ip) => ip,
            Err(_) => {
                warn!(line = line, "Failed to parse IP from auth.log line");
                return None;
            }
        };
        return Some(SshEvent {
            timestamp_str,
            event_type: EventType::AuthFailure,
            source_ip: ip,
            user,
            invalid_user: true,
            raw_line: line.to_string(),
        });
    }

    // 4. Accepted password
    if let Some(caps) = patterns.accepted_password.captures(line) {
        let user = caps[1].to_string();
        let ip: IpAddr = match caps[2].parse() {
            Ok(ip) => ip,
            Err(_) => {
                warn!(line = line, "Failed to parse IP from auth.log line");
                return None;
            }
        };
        return Some(SshEvent {
            timestamp_str,
            event_type: EventType::AuthSuccess,
            source_ip: ip,
            user,
            invalid_user: false,
            raw_line: line.to_string(),
        });
    }

    // 5. Accepted publickey
    if let Some(caps) = patterns.accepted_publickey.captures(line) {
        let user = caps[1].to_string();
        let ip: IpAddr = match caps[2].parse() {
            Ok(ip) => ip,
            Err(_) => {
                warn!(line = line, "Failed to parse IP from auth.log line");
                return None;
            }
        };
        return Some(SshEvent {
            timestamp_str,
            event_type: EventType::AuthSuccess,
            source_ip: ip,
            user,
            invalid_user: false,
            raw_line: line.to_string(),
        });
    }

    // No match — not an SSH auth event we care about
    trace!(line = line, "Line did not match any SSH pattern, skipping");
    None
}

/// Convert an SshEvent into a NormalizedEvent.
pub fn ssh_event_to_normalized(event: SshEvent) -> NormalizedEvent {
    let timestamp = parse_syslog_timestamp(&event.timestamp_str)
        .unwrap_or_else(Utc::now);

    let mut metadata = HashMap::new();
    metadata.insert("user".to_string(), event.user);
    if event.invalid_user {
        metadata.insert("invalid_user".to_string(), "true".to_string());
    }

    NormalizedEvent {
        timestamp,
        source_ip: event.source_ip,
        event_type: event.event_type,
        source_name: "ssh".to_string(),
        raw_line: event.raw_line,
        metadata,
    }
}

/// SSH auth.log source implementing the LogSource trait.
pub struct SshLogSource {
    auth_log_path: PathBuf,
    data_dir: Option<PathBuf>,
    stop_tx: Option<tokio::sync::watch::Sender<bool>>,
}

impl SshLogSource {
    pub fn new(auth_log_path: impl Into<PathBuf>) -> Self {
        Self {
            auth_log_path: auth_log_path.into(),
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
impl LogSource for SshLogSource {
    fn name(&self) -> &str {
        "ssh"
    }

    async fn start(
        &mut self,
        sender: mpsc::Sender<NormalizedEvent>,
    ) -> Result<(), HiveGuardError> {
        let path = self.auth_log_path.clone();
        if !path.exists() {
            return Err(HiveGuardError::Config(format!(
                "SSH auth log not found: {}",
                path.display()
            )));
        }

        // Load persisted offset or start from end
        let initial_offset = self
            .data_dir
            .as_ref()
            .map(|d| file_watcher::load_offset(d, "ssh"))
            .filter(|&o| o > 0);

        let mut fw = if let Some(offset) = initial_offset {
            info!(offset = offset, "Resuming SSH log from saved offset");
            FileWatcher::with_offset(path.clone(), offset)
        } else {
            FileWatcher::new(path.clone(), true)?
        };

        let (stop_tx, mut stop_rx) = tokio::sync::watch::channel(false);
        self.stop_tx = Some(stop_tx);

        let data_dir = self.data_dir.clone();
        let patterns = SshPatterns::new();

        // Set up file system watcher
        let (notify_tx, mut notify_rx) = mpsc::channel::<()>(16);

        let notify_tx_clone = notify_tx.clone();
        let mut watcher = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
            if let Ok(event) = res {
                if matches!(event.kind, EventKind::Modify(_)) {
                    let _ = notify_tx_clone.blocking_send(());
                }
            }
        })
        .map_err(|e| HiveGuardError::Io(std::io::Error::other(e)))?;

        // Watch the parent directory (handles rotation better)
        let watch_path = path.parent().unwrap_or(Path::new("."));
        watcher
            .watch(watch_path, RecursiveMode::NonRecursive)
            .map_err(|e| HiveGuardError::Io(std::io::Error::other(e)))?;

        tokio::spawn(async move {
            // Keep watcher alive
            let _watcher = watcher;

            loop {
                tokio::select! {
                    _ = stop_rx.changed() => {
                        if *stop_rx.borrow() {
                            info!("SSH log source stopping");
                            // Save offset on shutdown
                            if let Some(ref dd) = data_dir {
                                let _ = file_watcher::save_offset(dd, "ssh", fw.offset());
                            }
                            break;
                        }
                    }
                    Some(()) = notify_rx.recv() => {
                        // Drain any queued notifications to batch reads
                        while notify_rx.try_recv().is_ok() {}

                        match fw.read_new_lines() {
                            Ok(lines) => {
                                for line in lines {
                                    if let Some(event) = parse_ssh_line(&line, &patterns) {
                                        let normalized = ssh_event_to_normalized(event);
                                        if sender.send(normalized).await.is_err() {
                                            info!("Channel closed, SSH source stopping");
                                            return;
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                warn!(error = %e, "Error reading new lines from SSH log");
                            }
                        }
                    }
                }
            }
        });

        info!(path = %self.auth_log_path.display(), "SSH log source started");
        Ok(())
    }

    async fn stop(&mut self) -> Result<(), HiveGuardError> {
        if let Some(tx) = self.stop_tx.take() {
            let _ = tx.send(true);
        }
        info!("SSH log source stopped");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Datelike;

    fn patterns() -> SshPatterns {
        SshPatterns::new()
    }

    #[test]
    fn test_parse_failed_password() {
        let line = "Apr  8 14:30:22 server sshd[1234]: Failed password for admin from 192.168.1.100 port 22 ssh2";
        let event = parse_ssh_line(line, &patterns()).unwrap();
        assert_eq!(event.event_type, EventType::AuthFailure);
        assert_eq!(event.source_ip, "192.168.1.100".parse::<IpAddr>().unwrap());
        assert_eq!(event.user, "admin");
        assert!(!event.invalid_user);
        assert_eq!(event.timestamp_str, "Apr  8 14:30:22");
    }

    #[test]
    fn test_parse_failed_password_invalid_user() {
        let line = "Apr  8 14:31:00 server sshd[1235]: Failed password for invalid user hacker from 10.0.0.50 port 54321 ssh2";
        let event = parse_ssh_line(line, &patterns()).unwrap();
        assert_eq!(event.event_type, EventType::AuthFailure);
        assert_eq!(event.source_ip, "10.0.0.50".parse::<IpAddr>().unwrap());
        assert_eq!(event.user, "hacker");
        assert!(event.invalid_user);
    }

    #[test]
    fn test_parse_invalid_user() {
        let line = "Apr  8 14:32:00 server sshd[1236]: Invalid user test from 172.16.0.1";
        let event = parse_ssh_line(line, &patterns()).unwrap();
        assert_eq!(event.event_type, EventType::AuthFailure);
        assert_eq!(event.source_ip, "172.16.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(event.user, "test");
        assert!(event.invalid_user);
    }

    #[test]
    fn test_parse_accepted_password() {
        let line = "Apr  8 14:33:00 server sshd[1237]: Accepted password for root from 192.168.1.1 port 22 ssh2";
        let event = parse_ssh_line(line, &patterns()).unwrap();
        assert_eq!(event.event_type, EventType::AuthSuccess);
        assert_eq!(event.source_ip, "192.168.1.1".parse::<IpAddr>().unwrap());
        assert_eq!(event.user, "root");
        assert!(!event.invalid_user);
    }

    #[test]
    fn test_parse_accepted_publickey() {
        let line = "Apr  8 14:34:00 server sshd[1238]: Accepted publickey for deploy from 10.10.10.10 port 55555 ssh2";
        let event = parse_ssh_line(line, &patterns()).unwrap();
        assert_eq!(event.event_type, EventType::AuthSuccess);
        assert_eq!(event.source_ip, "10.10.10.10".parse::<IpAddr>().unwrap());
        assert_eq!(event.user, "deploy");
        assert!(!event.invalid_user);
    }

    #[test]
    fn test_parse_ipv6() {
        let line = "Apr  8 14:35:00 server sshd[1239]: Failed password for admin from 2001:db8::1 port 22 ssh2";
        let event = parse_ssh_line(line, &patterns()).unwrap();
        assert_eq!(event.source_ip, "2001:db8::1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_unrelated_line_returns_none() {
        let line = "Apr  8 14:36:00 server CRON[5678]: (root) CMD (/usr/bin/something)";
        assert!(parse_ssh_line(line, &patterns()).is_none());
    }

    #[test]
    fn test_malformed_line_no_panic() {
        let lines = vec![
            "",
            "not a log line at all",
            "Apr  8 14:30:00 server sshd[1234]:",
            "Failed password for",
            "Apr  8 14:30:00 server sshd[1234]: Failed password for admin from not_an_ip port 22",
        ];
        for line in lines {
            // Should not panic, just return None
            let _ = parse_ssh_line(line, &patterns());
        }
    }

    #[test]
    fn test_syslog_timestamp_parsing() {
        let ts = parse_syslog_timestamp("Apr  8 14:30:22");
        assert!(ts.is_some());
        let dt = ts.unwrap();
        assert_eq!(dt.format("%m-%d %H:%M:%S").to_string(), "04-08 14:30:22");
    }

    #[test]
    fn test_syslog_timestamp_single_digit_day() {
        let ts = parse_syslog_timestamp("Jan  3 09:15:00");
        assert!(ts.is_some());
        let dt = ts.unwrap();
        assert_eq!(dt.format("%m-%d %H:%M:%S").to_string(), "01-03 09:15:00");
    }

    #[test]
    fn test_syslog_timestamp_invalid() {
        assert!(parse_syslog_timestamp("not a timestamp").is_none());
        assert!(parse_syslog_timestamp("").is_none());
    }

    #[test]
    fn test_ssh_event_to_normalized() {
        let event = SshEvent {
            timestamp_str: "Apr  8 14:30:22".to_string(),
            event_type: EventType::AuthFailure,
            source_ip: "192.168.1.100".parse().unwrap(),
            user: "admin".to_string(),
            invalid_user: true,
            raw_line: "test line".to_string(),
        };
        let normalized = ssh_event_to_normalized(event);
        assert_eq!(normalized.source_name, "ssh");
        assert_eq!(normalized.event_type, EventType::AuthFailure);
        assert_eq!(normalized.source_ip, "192.168.1.100".parse::<IpAddr>().unwrap());
        assert_eq!(normalized.metadata.get("user").unwrap(), "admin");
        assert_eq!(normalized.metadata.get("invalid_user").unwrap(), "true");
    }

    #[test]
    fn test_ssh_event_to_normalized_no_invalid_user() {
        let event = SshEvent {
            timestamp_str: "Apr  8 14:30:22".to_string(),
            event_type: EventType::AuthSuccess,
            source_ip: "10.0.0.1".parse().unwrap(),
            user: "root".to_string(),
            invalid_user: false,
            raw_line: "test line".to_string(),
        };
        let normalized = ssh_event_to_normalized(event);
        assert!(normalized.metadata.get("invalid_user").is_none());
        assert_eq!(normalized.metadata.get("user").unwrap(), "root");
    }

    // --- Phase 10: comprehensive coverage ---

    #[test]
    fn test_ipv6_failed_password() {
        let patterns = SshPatterns::new();
        let line = "Apr  9 10:00:00 host sshd[1234]: Failed password for admin from 2001:db8::1 port 22 ssh2";
        let event = parse_ssh_line(line, &patterns).unwrap();
        assert_eq!(event.event_type, EventType::AuthFailure);
        assert_eq!(event.source_ip, "2001:db8::1".parse::<IpAddr>().unwrap());
        assert_eq!(event.user, "admin");
        assert!(!event.invalid_user);
    }

    #[test]
    fn test_ipv6_accepted_publickey() {
        let patterns = SshPatterns::new();
        let line = "Apr  9 10:00:00 host sshd[1234]: Accepted publickey for deploy from ::1 port 22 ssh2";
        let event = parse_ssh_line(line, &patterns).unwrap();
        assert_eq!(event.event_type, EventType::AuthSuccess);
        assert_eq!(event.source_ip, "::1".parse::<IpAddr>().unwrap());
        assert_eq!(event.user, "deploy");
    }

    #[test]
    fn test_empty_line_returns_none() {
        let patterns = SshPatterns::new();
        assert!(parse_ssh_line("", &patterns).is_none());
    }

    #[test]
    fn test_whitespace_only_line_returns_none() {
        let patterns = SshPatterns::new();
        assert!(parse_ssh_line("   \t  ", &patterns).is_none());
    }

    #[test]
    fn test_sshd_with_high_pid() {
        let patterns = SshPatterns::new();
        let line = "Dec 31 23:59:59 server sshd[999999]: Failed password for root from 1.2.3.4 port 54321 ssh2";
        let event = parse_ssh_line(line, &patterns).unwrap();
        assert_eq!(event.user, "root");
        assert_eq!(event.source_ip, "1.2.3.4".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_syslog_timestamp_february() {
        let ts = parse_syslog_timestamp("Feb 28 00:00:01");
        assert!(ts.is_some());
        let dt = ts.unwrap();
        assert_eq!(dt.month(), 2);
        assert_eq!(dt.day(), 28);
    }

    #[test]
    fn test_syslog_timestamp_january_first() {
        let ts = parse_syslog_timestamp("Jan  1 00:00:00");
        assert!(ts.is_some());
        assert_eq!(ts.unwrap().day(), 1);
    }

    #[test]
    fn test_invalid_ip_in_ssh_line() {
        let patterns = SshPatterns::new();
        // Invalid IP address - regex may match but IpAddr parse should fail
        let line = "Apr  9 10:00:00 host sshd[1234]: Failed password for root from 999.999.999.999 port 22 ssh2";
        // parse_ssh_line should return None because IP is invalid
        assert!(parse_ssh_line(line, &patterns).is_none());
    }

    #[test]
    fn test_username_with_dots() {
        let patterns = SshPatterns::new();
        let line = "Apr  9 10:00:00 host sshd[1234]: Failed password for user.name from 10.0.0.1 port 22 ssh2";
        let event = parse_ssh_line(line, &patterns).unwrap();
        assert_eq!(event.user, "user.name");
    }

    #[test]
    fn test_normalized_event_raw_line_preserved() {
        let raw = "Apr  9 10:00:00 host sshd[1234]: Accepted password for admin from 10.0.0.1 port 22 ssh2";
        let patterns = SshPatterns::new();
        let event = parse_ssh_line(raw, &patterns).unwrap();
        let norm = ssh_event_to_normalized(event);
        assert_eq!(norm.raw_line, raw);
    }
}
