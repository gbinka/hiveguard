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

/// Parsed Postfix SASL auth failure event before normalization.
#[derive(Debug, Clone)]
pub struct PostfixEvent {
    pub timestamp_str: String,
    pub source_ip: IpAddr,
    pub mechanism: String,
    pub raw_line: String,
}

/// Compiled regex patterns for Postfix mail log parsing.
pub struct PostfixPatterns {
    /// `warning: <hostname>[<ip>]: SASL <mechanism> authentication failed`
    sasl_warning: Regex,
    /// `SASL LOGIN authentication failed` with `client=<hostname>[<ip>]`
    sasl_login_failed: Regex,
    /// Syslog timestamp prefix
    syslog_timestamp: Regex,
}

impl Default for PostfixPatterns {
    fn default() -> Self {
        Self::new()
    }
}

impl PostfixPatterns {
    pub fn new() -> Self {
        Self {
            sasl_warning: Regex::new(
                r"warning:\s+\S+\[(?P<ip>[^\]]+)\]:\s+SASL\s+(?P<mech>\S+)\s+authentication\s+failed"
            ).unwrap(),
            sasl_login_failed: Regex::new(
                r"SASL\s+LOGIN\s+authentication\s+failed.*client=\S+\[(?P<ip>[^\]]+)\]"
            ).unwrap(),
            syslog_timestamp: Regex::new(
                r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
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

/// Try to parse a single mail.log line into a PostfixEvent.
/// Returns None if the line doesn't match any known Postfix SASL failure pattern.
pub fn parse_postfix_line(line: &str, patterns: &PostfixPatterns) -> Option<PostfixEvent> {
    let timestamp_str = patterns
        .syslog_timestamp
        .captures(line)
        .and_then(|c| c.name("ts"))
        .map(|m| m.as_str().to_string())
        .unwrap_or_default();

    // Try warning pattern first (more specific)
    if let Some(caps) = patterns.sasl_warning.captures(line) {
        let ip_str = caps.name("ip")?.as_str();
        let ip: IpAddr = match ip_str.parse() {
            Ok(ip) => ip,
            Err(_) => {
                warn!(line = line, ip = ip_str, "Failed to parse IP from Postfix log line");
                return None;
            }
        };
        let mechanism = caps.name("mech").map(|m| m.as_str().to_string()).unwrap_or_default();
        return Some(PostfixEvent {
            timestamp_str,
            source_ip: ip,
            mechanism,
            raw_line: line.to_string(),
        });
    }

    // Try SASL LOGIN pattern with client= format
    if let Some(caps) = patterns.sasl_login_failed.captures(line) {
        let ip_str = caps.name("ip")?.as_str();
        let ip: IpAddr = match ip_str.parse() {
            Ok(ip) => ip,
            Err(_) => {
                warn!(line = line, ip = ip_str, "Failed to parse IP from Postfix log line");
                return None;
            }
        };
        return Some(PostfixEvent {
            timestamp_str,
            source_ip: ip,
            mechanism: "LOGIN".to_string(),
            raw_line: line.to_string(),
        });
    }

    trace!(line = line, "Line did not match any Postfix pattern, skipping");
    None
}

/// Convert a PostfixEvent into a NormalizedEvent.
pub fn postfix_event_to_normalized(event: PostfixEvent) -> NormalizedEvent {
    let timestamp = parse_syslog_timestamp(&event.timestamp_str)
        .unwrap_or_else(Utc::now);

    let mut metadata = HashMap::new();
    metadata.insert("mechanism".to_string(), event.mechanism);

    NormalizedEvent {
        timestamp,
        source_ip: event.source_ip,
        event_type: EventType::SmtpAuthFailure,
        source_name: "postfix".to_string(),
        raw_line: event.raw_line,
        metadata,
    }
}

/// Postfix mail.log source implementing the LogSource trait.
pub struct PostfixLogSource {
    log_path: PathBuf,
    data_dir: Option<PathBuf>,
    stop_tx: Option<tokio::sync::watch::Sender<bool>>,
}

impl PostfixLogSource {
    pub fn new(log_path: impl Into<PathBuf>) -> Self {
        Self {
            log_path: log_path.into(),
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
impl LogSource for PostfixLogSource {
    fn name(&self) -> &str {
        "postfix"
    }

    async fn start(
        &mut self,
        sender: mpsc::Sender<NormalizedEvent>,
    ) -> Result<(), HiveGuardError> {
        let path = self.log_path.clone();
        if !path.exists() {
            return Err(HiveGuardError::Config(format!(
                "Postfix log not found: {}",
                path.display()
            )));
        }

        let initial_offset = self
            .data_dir
            .as_ref()
            .map(|d| file_watcher::load_offset(d, "postfix"))
            .filter(|&o| o > 0);

        let mut fw = if let Some(offset) = initial_offset {
            info!(offset = offset, "Resuming Postfix log from saved offset");
            FileWatcher::with_offset(path.clone(), offset)
        } else {
            FileWatcher::new(path.clone(), true)?
        };

        let (stop_tx, mut stop_rx) = tokio::sync::watch::channel(false);
        self.stop_tx = Some(stop_tx);

        let data_dir = self.data_dir.clone();
        let patterns = PostfixPatterns::new();

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
                            info!("Postfix log source stopping");
                            if let Some(ref dd) = data_dir {
                                let _ = file_watcher::save_offset(dd, "postfix", fw.offset());
                            }
                            break;
                        }
                    }
                    Some(()) = notify_rx.recv() => {
                        while notify_rx.try_recv().is_ok() {}

                        match fw.read_new_lines() {
                            Ok(lines) => {
                                for line in lines {
                                    if let Some(event) = parse_postfix_line(&line, &patterns) {
                                        let normalized = postfix_event_to_normalized(event);
                                        if sender.send(normalized).await.is_err() {
                                            info!("Channel closed, Postfix source stopping");
                                            return;
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                warn!(error = %e, "Error reading new lines from Postfix log");
                            }
                        }
                    }
                }
            }
        });

        info!(path = %self.log_path.display(), "Postfix log source started");
        Ok(())
    }

    async fn stop(&mut self) -> Result<(), HiveGuardError> {
        if let Some(tx) = self.stop_tx.take() {
            let _ = tx.send(true);
        }
        info!("Postfix log source stopped");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn patterns() -> PostfixPatterns {
        PostfixPatterns::new()
    }

    #[test]
    fn test_sasl_warning_plain() {
        let line = "Apr  8 14:30:22 mailhost postfix/smtpd[12345]: warning: unknown[203.0.113.50]: SASL PLAIN authentication failed: UGFzc3dvcmQ=";
        let event = parse_postfix_line(line, &patterns()).unwrap();
        assert_eq!(event.source_ip, "203.0.113.50".parse::<IpAddr>().unwrap());
        assert_eq!(event.mechanism, "PLAIN");
        assert_eq!(event.raw_line, line);
    }

    #[test]
    fn test_sasl_warning_login() {
        let line = "Apr  8 14:31:00 mailhost postfix/smtpd[12345]: warning: mail.example.com[198.51.100.20]: SASL LOGIN authentication failed: authentication failure";
        let event = parse_postfix_line(line, &patterns()).unwrap();
        assert_eq!(event.source_ip, "198.51.100.20".parse::<IpAddr>().unwrap());
        assert_eq!(event.mechanism, "LOGIN");
    }

    #[test]
    fn test_sasl_login_failed_client_format() {
        let line = "Apr  8 14:32:00 mailhost postfix/smtpd[12346]: SASL LOGIN authentication failed, client=unknown[10.20.30.40]";
        let event = parse_postfix_line(line, &patterns()).unwrap();
        assert_eq!(event.source_ip, "10.20.30.40".parse::<IpAddr>().unwrap());
        assert_eq!(event.mechanism, "LOGIN");
    }

    #[test]
    fn test_sasl_warning_cram_md5() {
        let line = "Apr  8 14:33:00 mailhost postfix/smtpd[12347]: warning: spammer.example.net[172.16.0.100]: SASL CRAM-MD5 authentication failed";
        let event = parse_postfix_line(line, &patterns()).unwrap();
        assert_eq!(event.source_ip, "172.16.0.100".parse::<IpAddr>().unwrap());
        assert_eq!(event.mechanism, "CRAM-MD5");
    }

    #[test]
    fn test_ipv6_sasl_warning() {
        let line = "Apr  8 14:34:00 mailhost postfix/smtpd[12348]: warning: unknown[2001:db8::1]: SASL LOGIN authentication failed: authentication failure";
        let event = parse_postfix_line(line, &patterns()).unwrap();
        assert_eq!(event.source_ip, "2001:db8::1".parse::<IpAddr>().unwrap());
        assert_eq!(event.mechanism, "LOGIN");
    }

    #[test]
    fn test_unrelated_line_returns_none() {
        let line = "Apr  8 14:35:00 mailhost postfix/smtpd[12349]: connect from unknown[192.168.1.1]";
        assert!(parse_postfix_line(line, &patterns()).is_none());
    }

    #[test]
    fn test_postfix_queue_line_returns_none() {
        let line = "Apr  8 14:36:00 mailhost postfix/qmgr[1234]: ABC123: from=<user@example.com>, size=1234, nrcpt=1 (queue active)";
        assert!(parse_postfix_line(line, &patterns()).is_none());
    }

    #[test]
    fn test_dovecot_line_returns_none() {
        let line = "Apr  8 14:37:00 mailhost dovecot: imap-login: Disconnected (no auth attempts): rip=192.168.1.1";
        assert!(parse_postfix_line(line, &patterns()).is_none());
    }

    #[test]
    fn test_empty_line_returns_none() {
        assert!(parse_postfix_line("", &patterns()).is_none());
    }

    #[test]
    fn test_malformed_ip_returns_none() {
        let line = "Apr  8 14:38:00 mailhost postfix/smtpd[12350]: warning: unknown[999.999.999.999]: SASL LOGIN authentication failed";
        assert!(parse_postfix_line(line, &patterns()).is_none());
    }

    #[test]
    fn test_postfix_event_to_normalized() {
        let event = PostfixEvent {
            timestamp_str: "Apr  8 14:30:22".to_string(),
            source_ip: "203.0.113.50".parse().unwrap(),
            mechanism: "LOGIN".to_string(),
            raw_line: "test line".to_string(),
        };
        let norm = postfix_event_to_normalized(event);
        assert_eq!(norm.source_name, "postfix");
        assert_eq!(norm.event_type, EventType::SmtpAuthFailure);
        assert_eq!(norm.source_ip, "203.0.113.50".parse::<IpAddr>().unwrap());
        assert_eq!(norm.metadata.get("mechanism").unwrap(), "LOGIN");
        assert_eq!(norm.raw_line, "test line");
    }

    #[test]
    fn test_postfix_event_to_normalized_preserves_mechanism() {
        let event = PostfixEvent {
            timestamp_str: "".to_string(),
            source_ip: "10.0.0.1".parse().unwrap(),
            mechanism: "CRAM-MD5".to_string(),
            raw_line: "raw".to_string(),
        };
        let norm = postfix_event_to_normalized(event);
        assert_eq!(norm.metadata.get("mechanism").unwrap(), "CRAM-MD5");
    }

    #[test]
    fn test_syslog_timestamp_parsing() {
        let ts = parse_syslog_timestamp("Apr  8 14:30:22");
        assert!(ts.is_some());
        let dt = ts.unwrap();
        assert_eq!(dt.month(), 4);
        assert_eq!(dt.day(), 8);
        assert_eq!(dt.hour(), 14);
        assert_eq!(dt.minute(), 30);
        assert_eq!(dt.second(), 22);
    }

    #[test]
    fn test_syslog_timestamp_invalid() {
        assert!(parse_syslog_timestamp("not a timestamp").is_none());
    }

    use chrono::{Datelike, Timelike};

    #[test]
    fn test_timestamp_extracted_from_line() {
        let line = "Jan  1 00:00:01 mailhost postfix/smtpd[1]: warning: unknown[10.0.0.1]: SASL LOGIN authentication failed";
        let event = parse_postfix_line(line, &patterns()).unwrap();
        assert_eq!(event.timestamp_str, "Jan  1 00:00:01");
    }
}
