use std::collections::HashMap;
use std::net::IpAddr;

use chrono::{DateTime, FixedOffset, NaiveDateTime, Utc};
use regex::Regex;
use tracing::trace;

use hiveguard_core::models::{EventType, NormalizedEvent};

#[derive(Debug, Clone)]
pub struct SshEvent {
    pub timestamp_str: String,
    pub event_type: EventType,
    pub source_ip: IpAddr,
    pub user: String,
    pub invalid_user: bool,
    pub raw_line: String,
}

pub struct SshPatterns {
    failed_password: Regex,
    failed_password_invalid: Regex,
    invalid_user: Regex,
    accepted_password: Regex,
    accepted_publickey: Regex,
    syslog_timestamp: Regex,
}

impl SshPatterns {
    pub fn new() -> Self {
        Self {
            failed_password: Regex::new(r"Failed password for ([^\s]+) from ([0-9a-fA-F.:]+) port \d+").unwrap(),
            failed_password_invalid: Regex::new(r"Failed password for invalid user ([^\s]+) from ([0-9a-fA-F.:]+)").unwrap(),
            invalid_user: Regex::new(r"Invalid user ([^\s]+) from ([0-9a-fA-F.:]+)").unwrap(),
            accepted_password: Regex::new(r"Accepted password for ([^\s]+) from ([0-9a-fA-F.:]+)").unwrap(),
            accepted_publickey: Regex::new(r"Accepted publickey for ([^\s]+) from ([0-9a-fA-F.:]+)").unwrap(),
            syslog_timestamp: Regex::new(r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+").unwrap(),
        }
    }
}

pub fn parse_syslog_timestamp(ts: &str) -> Option<DateTime<Utc>> {
    let current_year = Utc::now().format("%Y").to_string();
    let with_year = format!("{} {}", current_year, ts);
    NaiveDateTime::parse_from_str(&with_year, "%Y %b %e %H:%M:%S").ok().map(|naive| naive.and_utc())
}

pub fn parse_ssh_line(line: &str, patterns: &SshPatterns) -> Option<SshEvent> {
    let timestamp_str = patterns.syslog_timestamp.captures(line).map(|caps| caps[1].to_string()).unwrap_or_default();
    if let Some(caps) = patterns.failed_password_invalid.captures(line) {
        return Some(SshEvent { timestamp_str, event_type: EventType::AuthFailure, source_ip: caps[2].parse().ok()?, user: caps[1].to_string(), invalid_user: true, raw_line: line.to_string() });
    }
    if let Some(caps) = patterns.failed_password.captures(line) {
        return Some(SshEvent { timestamp_str, event_type: EventType::AuthFailure, source_ip: caps[2].parse().ok()?, user: caps[1].to_string(), invalid_user: false, raw_line: line.to_string() });
    }
    if let Some(caps) = patterns.invalid_user.captures(line) {
        return Some(SshEvent { timestamp_str, event_type: EventType::AuthFailure, source_ip: caps[2].parse().ok()?, user: caps[1].to_string(), invalid_user: true, raw_line: line.to_string() });
    }
    if let Some(caps) = patterns.accepted_password.captures(line) {
        return Some(SshEvent { timestamp_str, event_type: EventType::AuthSuccess, source_ip: caps[2].parse().ok()?, user: caps[1].to_string(), invalid_user: false, raw_line: line.to_string() });
    }
    if let Some(caps) = patterns.accepted_publickey.captures(line) {
        return Some(SshEvent { timestamp_str, event_type: EventType::AuthSuccess, source_ip: caps[2].parse().ok()?, user: caps[1].to_string(), invalid_user: false, raw_line: line.to_string() });
    }
    trace!(line = line, "ssh line did not match any known pattern");
    None
}

pub fn ssh_event_to_normalized(event: SshEvent) -> NormalizedEvent {
    let mut metadata = HashMap::new();
    metadata.insert("user".to_string(), event.user);
    if event.invalid_user {
        metadata.insert("invalid_user".to_string(), "true".to_string());
    }
    NormalizedEvent {
        timestamp: parse_syslog_timestamp(&event.timestamp_str).unwrap_or_else(Utc::now),
        source_ip: event.source_ip,
        event_type: event.event_type,
        source_name: "ssh".to_string(),
        raw_line: event.raw_line,
        metadata,
    }
}

#[derive(Debug, Clone)]
pub struct NginxEvent {
    pub source_ip: IpAddr,
    pub timestamp: DateTime<Utc>,
    pub method: String,
    pub path: String,
    pub status_code: u16,
    pub user_agent: String,
    pub raw_line: String,
}

pub struct NginxPattern {
    combined: Regex,
}

impl NginxPattern {
    pub fn new() -> Self {
        Self {
            combined: Regex::new(r#"^([0-9a-fA-F.:]+) - [^\s]+ \[([^\]]+)\] "([^"]*)" (\d{3}) (\d+) "[^"]*" "([^"]*)""#).unwrap(),
        }
    }
}

fn parse_nginx_timestamp(ts: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_str(ts, "%d/%b/%Y:%H:%M:%S %z").ok().map(|dt: DateTime<FixedOffset>| dt.with_timezone(&Utc))
}

fn parse_request_line(request: &str) -> Option<(String, String)> {
    let parts: Vec<&str> = request.splitn(3, ' ').collect();
    if parts.len() < 2 {
        return None;
    }
    Some((parts[0].to_string(), parts[1].to_string()))
}

pub fn parse_nginx_line(line: &str, pattern: &NginxPattern) -> Option<NginxEvent> {
    let caps = pattern.combined.captures(line)?;
    let (method, path) = parse_request_line(&caps[3])?;
    Some(NginxEvent {
        source_ip: caps[1].parse().ok()?,
        timestamp: parse_nginx_timestamp(&caps[2]).unwrap_or_else(Utc::now),
        method,
        path,
        status_code: caps[4].parse().ok()?,
        user_agent: caps[6].to_string(),
        raw_line: line.to_string(),
    })
}

pub fn nginx_event_to_normalized(event: NginxEvent) -> NormalizedEvent {
    let event_type = match event.status_code {
        400..=499 => EventType::Http4xx,
        500..=599 => EventType::Http5xx,
        _ => EventType::HttpRequest,
    };
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

#[derive(Debug, Clone)]
pub struct PostfixEvent {
    pub timestamp_str: String,
    pub source_ip: IpAddr,
    pub mechanism: String,
    pub raw_line: String,
}

pub struct PostfixPatterns {
    sasl_warning: Regex,
    sasl_login_failed: Regex,
    syslog_timestamp: Regex,
}

impl PostfixPatterns {
    pub fn new() -> Self {
        Self {
            sasl_warning: Regex::new(r"warning:\s+\S+\[(?P<ip>[^\]]+)\]:\s+SASL\s+(?P<mech>\S+)\s+authentication\s+failed").unwrap(),
            sasl_login_failed: Regex::new(r"SASL\s+LOGIN\s+authentication\s+failed.*client=\S+\[(?P<ip>[^\]]+)\]").unwrap(),
            syslog_timestamp: Regex::new(r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+").unwrap(),
        }
    }
}

pub fn parse_postfix_line(line: &str, patterns: &PostfixPatterns) -> Option<PostfixEvent> {
    let timestamp_str = patterns.syslog_timestamp.captures(line).and_then(|caps| caps.name("ts")).map(|m| m.as_str().to_string()).unwrap_or_default();
    if let Some(caps) = patterns.sasl_warning.captures(line) {
        return Some(PostfixEvent { timestamp_str, source_ip: caps.name("ip")?.as_str().parse().ok()?, mechanism: caps.name("mech").map(|m| m.as_str().to_string()).unwrap_or_default(), raw_line: line.to_string() });
    }
    if let Some(caps) = patterns.sasl_login_failed.captures(line) {
        return Some(PostfixEvent { timestamp_str, source_ip: caps.name("ip")?.as_str().parse().ok()?, mechanism: "LOGIN".to_string(), raw_line: line.to_string() });
    }
    trace!(line = line, "postfix line did not match any known pattern");
    None
}

pub fn postfix_event_to_normalized(event: PostfixEvent) -> NormalizedEvent {
    let mut metadata = HashMap::new();
    metadata.insert("mechanism".to_string(), event.mechanism);
    NormalizedEvent {
        timestamp: parse_syslog_timestamp(&event.timestamp_str).unwrap_or_else(Utc::now),
        source_ip: event.source_ip,
        event_type: EventType::SmtpAuthFailure,
        source_name: "postfix".to_string(),
        raw_line: event.raw_line,
        metadata,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssh_parser_emits_auth_failure() {
        let event = parse_ssh_line("May  7 11:42:12 host sshd[123]: Failed password for invalid user root from 192.0.2.1 port 22 ssh2", &SshPatterns::new()).unwrap();
        assert_eq!(event.source_ip, "192.0.2.1".parse::<IpAddr>().unwrap());
        assert!(event.invalid_user);
    }

    #[test]
    fn nginx_parser_emits_http4xx() {
        let event = parse_nginx_line(r#"203.0.113.9 - - [08/Apr/2026:14:31:11 +0000] "GET /wp-login.php HTTP/1.1" 404 153 "-" "scanner""#, &NginxPattern::new()).unwrap();
        assert_eq!(nginx_event_to_normalized(event).event_type, EventType::Http4xx);
    }

    #[test]
    fn postfix_parser_emits_smtp_auth_failure() {
        let event = parse_postfix_line("May  7 11:42:12 mail postfix/smtpd[1234]: warning: client.example[192.0.2.5]: SASL PLAIN authentication failed", &PostfixPatterns::new()).unwrap();
        assert_eq!(postfix_event_to_normalized(event).event_type, EventType::SmtpAuthFailure);
    }
}