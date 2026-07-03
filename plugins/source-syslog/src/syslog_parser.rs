use std::net::IpAddr;

use chrono::{DateTime, NaiveDateTime, Utc};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SyslogFacility {
    Kernel = 0,
    User = 1,
    Mail = 2,
    Daemon = 3,
    Auth = 4,
    Syslog = 5,
    Lpr = 6,
    News = 7,
    Uucp = 8,
    Clock = 9,
    AuthPriv = 10,
    Ftp = 11,
    Ntp = 12,
    LogAudit = 13,
    LogAlert = 14,
    Cron = 15,
    Local0 = 16,
    Local1 = 17,
    Local2 = 18,
    Local3 = 19,
    Local4 = 20,
    Local5 = 21,
    Local6 = 22,
    Local7 = 23,
}

impl SyslogFacility {
    fn from_prival(prival: u8) -> Self {
        match prival >> 3 {
            0 => Self::Kernel,
            1 => Self::User,
            2 => Self::Mail,
            3 => Self::Daemon,
            4 => Self::Auth,
            5 => Self::Syslog,
            6 => Self::Lpr,
            7 => Self::News,
            8 => Self::Uucp,
            9 => Self::Clock,
            10 => Self::AuthPriv,
            11 => Self::Ftp,
            12 => Self::Ntp,
            13 => Self::LogAudit,
            14 => Self::LogAlert,
            15 => Self::Cron,
            16 => Self::Local0,
            17 => Self::Local1,
            18 => Self::Local2,
            19 => Self::Local3,
            20 => Self::Local4,
            21 => Self::Local5,
            22 => Self::Local6,
            23 => Self::Local7,
            _ => Self::User,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SyslogSeverity {
    Emergency = 0,
    Alert = 1,
    Critical = 2,
    Error = 3,
    Warning = 4,
    Notice = 5,
    Informational = 6,
    Debug = 7,
}

impl SyslogSeverity {
    fn from_prival(prival: u8) -> Self {
        match prival & 0x07 {
            0 => Self::Emergency,
            1 => Self::Alert,
            2 => Self::Critical,
            3 => Self::Error,
            4 => Self::Warning,
            5 => Self::Notice,
            6 => Self::Informational,
            _ => Self::Debug,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructuredDataElement {
    pub id: String,
    pub params: Vec<(String, String)>,
}

#[derive(Debug, Clone)]
pub struct SyslogMessage {
    pub facility: SyslogFacility,
    pub severity: SyslogSeverity,
    pub timestamp: Option<DateTime<Utc>>,
    pub hostname: Option<String>,
    pub app_name: Option<String>,
    pub procid: Option<String>,
    pub msgid: Option<String>,
    pub structured_data: Vec<StructuredDataElement>,
    pub message: String,
}

fn parse_pri(input: &str) -> Option<(u8, &str)> {
    let rest = input.strip_prefix('<')?;
    let end = rest.find('>')?;
    let prival: u8 = rest[..end].parse().ok()?;
    if prival > 191 {
        return None;
    }
    Some((prival, &rest[end + 1..]))
}

fn split_sp(input: &str) -> Option<(&str, &str)> {
    let pos = input.find(' ')?;
    Some((&input[..pos], &input[pos + 1..]))
}

fn nil_or_some(tok: &str) -> Option<String> {
    if tok == "-" { None } else { Some(tok.to_string()) }
}

fn parse_rfc5424_timestamp(ts: &str) -> Option<DateTime<Utc>> {
    if ts == "-" {
        return None;
    }
    DateTime::parse_from_rfc3339(ts).ok().map(|dt| dt.with_timezone(&Utc))
}

fn parse_rfc3164_timestamp(ts: &str) -> Option<DateTime<Utc>> {
    let year = Utc::now().format("%Y").to_string();
    let with_year = format!("{} {}", year, ts.trim());
    NaiveDateTime::parse_from_str(&with_year, "%Y %b %e %H:%M:%S").ok().map(|dt| dt.and_utc())
}

fn parse_structured_data(input: &str) -> (Vec<StructuredDataElement>, &str) {
    if let Some(rest) = input.strip_prefix('-') {
        if rest.is_empty() || rest.starts_with(' ') {
            return (Vec::new(), rest);
        }
    }
    if !input.starts_with('[') {
        return (Vec::new(), input);
    }

    let mut elements = Vec::new();
    let mut rest = input;
    while rest.starts_with('[') {
        rest = &rest[1..];
        let id_end = rest.find(|c: char| c == ' ' || c == ']').unwrap_or(rest.len());
        let id = rest[..id_end].to_string();
        rest = &rest[id_end..];
        let mut params = Vec::new();

        while rest.starts_with(' ') {
            rest = &rest[1..];
            if rest.starts_with(']') {
                break;
            }
            let eq_pos = match rest.find('=') {
                Some(pos) => pos,
                None => break,
            };
            let param_name = rest[..eq_pos].to_string();
            rest = &rest[eq_pos + 1..];
            if !rest.starts_with('"') {
                break;
            }
            rest = &rest[1..];

            let bytes = rest.as_bytes();
            let mut value = String::new();
            let mut idx = 0usize;
            let consumed = loop {
                if idx >= bytes.len() {
                    break idx;
                }
                match bytes[idx] {
                    b'\\' if idx + 1 < bytes.len() => {
                        value.push(bytes[idx + 1] as char);
                        idx += 2;
                    }
                    b'"' => break idx + 1,
                    byte => {
                        value.push(byte as char);
                        idx += 1;
                    }
                }
            };
            rest = &rest[consumed..];
            params.push((param_name, value));
        }

        if rest.starts_with(']') {
            rest = &rest[1..];
        }
        elements.push(StructuredDataElement { id, params });
    }

    (elements, rest)
}

pub fn parse_rfc5424(input: &str) -> Option<SyslogMessage> {
    let (prival, rest) = parse_pri(input)?;
    let facility = SyslogFacility::from_prival(prival);
    let severity = SyslogSeverity::from_prival(prival);
    let (_version, rest) = split_sp(rest)?;
    let (ts_tok, rest) = split_sp(rest)?;
    let (hostname_tok, rest) = split_sp(rest)?;
    let (app_name_tok, rest) = split_sp(rest)?;
    let (procid_tok, rest) = split_sp(rest)?;
    let (msgid_tok, rest) = split_sp(rest)?;
    let (structured_data, rest) = parse_structured_data(rest);
    let message = if let Some(msg) = rest.strip_prefix(' ') { msg.to_string() } else { rest.to_string() };
    Some(SyslogMessage {
        facility,
        severity,
        timestamp: parse_rfc5424_timestamp(ts_tok),
        hostname: nil_or_some(hostname_tok),
        app_name: nil_or_some(app_name_tok),
        procid: nil_or_some(procid_tok),
        msgid: nil_or_some(msgid_tok),
        structured_data,
        message,
    })
}

pub fn parse_rfc3164(input: &str) -> Option<SyslogMessage> {
    let (prival, rest) = parse_pri(input)?;
    let facility = SyslogFacility::from_prival(prival);
    let severity = SyslogSeverity::from_prival(prival);
    if rest.len() < 16 {
        return None;
    }
    let ts_str = &rest[..15];
    let timestamp = parse_rfc3164_timestamp(ts_str);
    let rest = rest[15..].trim_start_matches(' ');
    let (hostname_str, rest) = split_sp(rest)?;
    let hostname = Some(hostname_str.to_string());
    let colon_pos = rest.find(':')?;
    let tag_part = &rest[..colon_pos];
    let (app_name, procid) = if let Some(bracket) = tag_part.find('[') {
        let app = &tag_part[..bracket];
        let pid_end = tag_part.find(']').unwrap_or(tag_part.len());
        let pid = &tag_part[bracket + 1..pid_end];
        (
            if app.is_empty() { None } else { Some(app.to_string()) },
            if pid.is_empty() { None } else { Some(pid.to_string()) },
        )
    } else {
        (
            if tag_part.is_empty() { None } else { Some(tag_part.to_string()) },
            None,
        )
    };
    Some(SyslogMessage {
        facility,
        severity,
        timestamp,
        hostname,
        app_name,
        procid,
        msgid: None,
        structured_data: Vec::new(),
        message: rest[colon_pos + 1..].trim_start_matches(' ').to_string(),
    })
}

pub fn parse_syslog(input: &str) -> Option<SyslogMessage> {
    let input = input.trim_end_matches(['\n', '\r']);
    if let Some((_, rest)) = parse_pri(input) {
        if rest.starts_with(|c: char| c.is_ascii_digit()) {
            if let Some(msg) = parse_rfc5424(input) {
                return Some(msg);
            }
        }
    }
    parse_rfc3164(input)
}

pub fn extract_ip_from_message(message: &str) -> Option<IpAddr> {
    let words: Vec<&str> = message.split_whitespace().collect();
    for (idx, word) in words.iter().enumerate() {
        let lower = word.to_ascii_lowercase();
        if matches!(lower.as_str(), "from" | "client:") {
            if let Some(next) = words.get(idx + 1) {
                let clean = next.trim_matches(['[', ']', ',', ';', '\'', '"', '(', ')']);
                if let Ok(ip) = clean.parse::<IpAddr>() {
                    return Some(ip);
                }
            }
        }

        let after_eq = lower.strip_prefix("src=").or_else(|| lower.strip_prefix("client=")).or_else(|| lower.strip_prefix("rhost="));
        if let Some(candidate) = after_eq {
            let clean = candidate.trim_matches(['[', ']', ',', ';']);
            if let Ok(ip) = clean.parse::<IpAddr>() {
                return Some(ip);
            }
            if let Some(eq_pos) = word.find('=') {
                let original = word[eq_pos + 1..].trim_matches(['[', ']', ',', ';']);
                if let Ok(ip) = original.parse::<IpAddr>() {
                    return Some(ip);
                }
            }
        }

        let clean = word.trim_matches(['[', ']', ',', ';', '(', ')']);
        if let Ok(ip) = clean.parse::<IpAddr>() {
            if (ip.is_ipv4() && clean.contains('.')) || (ip.is_ipv6() && (clean.contains(':') || clean == "::")) {
                return Some(ip);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_rfc5424_line() {
        let msg = parse_syslog("<14>1 2024-01-01T00:00:00Z host app 1 - - test message").unwrap();
        assert_eq!(msg.app_name.as_deref(), Some("app"));
        assert_eq!(msg.message, "test message");
    }

    #[test]
    fn parse_rfc3164_line() {
        let msg = parse_syslog("<34>Oct 11 22:14:15 mymachine su[100]: test message").unwrap();
        assert_eq!(msg.app_name.as_deref(), Some("su"));
        assert!(msg.message.contains("test message"));
    }

    #[test]
    fn extract_ip_from_message_works() {
        assert_eq!(extract_ip_from_message("Failed password for root from 1.2.3.4 port 22"), Some("1.2.3.4".parse().unwrap()));
    }
}
