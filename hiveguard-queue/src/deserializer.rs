//! Shared message deserialisation logic for all queue sources (Phase 6).
//!
//! [`MessageRouter`] pre-compiles all log-line parsers once and reuses them
//! across every incoming message, regardless of the queue backend.

use std::borrow::Cow;

use hiveguard_core::config::{KafkaTopicFormat, KafkaTopicParser};
use hiveguard_core::models::NormalizedEvent;
use hiveguard_ingest::nginx_parser::{nginx_event_to_normalized, parse_nginx_line, NginxPattern};
use hiveguard_ingest::postfix_parser::{
    parse_postfix_line, postfix_event_to_normalized, PostfixPatterns,
};
use hiveguard_ingest::ssh_parser::{parse_ssh_line, ssh_event_to_normalized, SshPatterns};
use hiveguard_ingest::syslog_parser::parse_syslog;
use hiveguard_ingest::SyslogRouter;

// ---------------------------------------------------------------------------
// MessageRouter
// ---------------------------------------------------------------------------

/// Stateful router that holds pre-compiled parsers.
///
/// Create once per source task; reuse for every message.
pub struct MessageRouter {
    syslog_router: SyslogRouter,
    ssh_patterns: SshPatterns,
    nginx_pattern: NginxPattern,
    postfix_patterns: PostfixPatterns,
}

impl MessageRouter {
    /// Create a router with built-in default routes (sshd, nginx, postfix).
    pub fn new() -> Self {
        Self {
            syslog_router: SyslogRouter::from_config(&[])
                .expect("SyslogRouter::from_config cannot fail with empty routes"),
            ssh_patterns: SshPatterns::new(),
            nginx_pattern: NginxPattern::new(),
            postfix_patterns: PostfixPatterns::new(),
        }
    }

    /// Route a raw UTF-8 string based on `format` and `parser`.
    ///
    /// Returns `None` if no parser matched or the payload is unrecognisable.
    pub fn route(
        &self,
        raw: &str,
        format: &KafkaTopicFormat,
        parser: &KafkaTopicParser,
        source_name: &str,
    ) -> Option<NormalizedEvent> {
        match format {
            KafkaTopicFormat::Json => {
                let line: Cow<str> = match extract_json_log_line(raw) {
                    Some(owned) => Cow::Owned(owned),
                    None => Cow::Borrowed(raw),
                };
                self.apply_parser(&line, parser, source_name)
            }
            KafkaTopicFormat::Syslog => {
                let msg = parse_syslog(raw)?;
                self.syslog_router.route(msg, source_name, None)
            }
        }
    }

    /// Route a raw line without JSON unwrapping (Kinesis / CloudWatch payloads
    /// have already been extracted to plain strings by the AWS SDK / our caller).
    pub fn route_line(
        &self,
        line: &str,
        parser: &KafkaTopicParser,
        source_name: &str,
    ) -> Option<NormalizedEvent> {
        self.apply_parser(line, parser, source_name)
    }

    fn apply_parser(
        &self,
        line: &str,
        parser: &KafkaTopicParser,
        source_name: &str,
    ) -> Option<NormalizedEvent> {
        match parser {
            KafkaTopicParser::Ssh => {
                parse_ssh_line(line, &self.ssh_patterns).map(ssh_event_to_normalized)
            }
            KafkaTopicParser::Nginx => {
                parse_nginx_line(line, &self.nginx_pattern).map(nginx_event_to_normalized)
            }
            KafkaTopicParser::Postfix => {
                parse_postfix_line(line, &self.postfix_patterns).map(postfix_event_to_normalized)
            }
            KafkaTopicParser::Auto => {
                if let Some(ev) = parse_ssh_line(line, &self.ssh_patterns) {
                    return Some(ssh_event_to_normalized(ev));
                }
                if let Some(ev) = parse_nginx_line(line, &self.nginx_pattern) {
                    return Some(nginx_event_to_normalized(ev));
                }
                if let Some(ev) = parse_postfix_line(line, &self.postfix_patterns) {
                    return Some(postfix_event_to_normalized(ev));
                }
                // Last resort: try syslog wrapping.
                let msg = parse_syslog(line)?;
                self.syslog_router.route(msg, source_name, None)
            }
        }
    }
}

impl Default for MessageRouter {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// JSON unwrapping
// ---------------------------------------------------------------------------

/// Extract a raw log line from a JSON-wrapped payload.
///
/// Supports Filebeat (`"message"`), Fluentd/Docker (`"log"`),
/// Logstash (`"msg"`), and AWS (`"@message"`).
///
/// Returns `None` if the input is not a JSON object or has none of the known
/// keys, so the caller can fall back to treating `raw` as the log line.
pub fn extract_json_log_line(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if !trimmed.starts_with('{') {
        return None;
    }
    let v: serde_json::Value = serde_json::from_str(trimmed).ok()?;
    let obj = v.as_object()?;
    for key in &["message", "log", "msg", "@message"] {
        if let Some(serde_json::Value::String(s)) = obj.get(*key) {
            return Some(s.clone());
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_message_key() {
        let json = r#"{"message": "Failed password for root from 1.2.3.4 port 22"}"#;
        assert_eq!(
            extract_json_log_line(json).as_deref(),
            Some("Failed password for root from 1.2.3.4 port 22")
        );
    }

    #[test]
    fn extracts_log_key() {
        let json = r#"{"log": "some log line", "host": "server1"}"#;
        assert_eq!(
            extract_json_log_line(json).as_deref(),
            Some("some log line")
        );
    }

    #[test]
    fn plain_text_returns_none() {
        assert!(extract_json_log_line("plain text line").is_none());
    }

    #[test]
    fn json_without_known_key_returns_none() {
        let json = r#"{"timestamp": "2026-01-01", "level": "warn"}"#;
        assert!(extract_json_log_line(json).is_none());
    }
}
