//! RFC 5424 and RFC 3164 syslog message parser.
//!
//! RFC 5424: `<PRI>VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME SP PROCID SP MSGID SP STRUCTURED-DATA [SP MSG]`
//! RFC 3164: `<PRI>TIMESTAMP HOSTNAME TAG[PID]: MSG`

use std::net::IpAddr;

use chrono::{DateTime, NaiveDateTime, Utc};

// ---------------------------------------------------------------------------
// Facility
// ---------------------------------------------------------------------------

/// Syslog facility values (RFC 5424, Table 1).
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

// ---------------------------------------------------------------------------
// Severity
// ---------------------------------------------------------------------------

/// Syslog severity values (RFC 5424, Table 2).
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

// ---------------------------------------------------------------------------
// Structured data
// ---------------------------------------------------------------------------

/// A single structured data element from RFC 5424 §6.3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructuredDataElement {
    pub id: String,
    pub params: Vec<(String, String)>,
}

// ---------------------------------------------------------------------------
// Parsed message
// ---------------------------------------------------------------------------

/// Fully parsed syslog message (RFC 5424 or RFC 3164).
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

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Parse `<NNN>` PRI field, returning `(prival, rest)`.
fn parse_pri(input: &str) -> Option<(u8, &str)> {
    let rest = input.strip_prefix('<')?;
    let end = rest.find('>')?;
    let prival: u8 = rest[..end].parse().ok()?;
    if prival > 191 {
        return None;
    }
    Some((prival, &rest[end + 1..]))
}

/// Split at first space, returning `(token, rest_after_space)`.
fn split_sp(input: &str) -> Option<(&str, &str)> {
    let pos = input.find(' ')?;
    Some((&input[..pos], &input[pos + 1..]))
}

/// Return `None` for RFC 5424 NILVALUE (`-`), else `Some(s.to_string())`.
fn nil_or_some(tok: &str) -> Option<String> {
    if tok == "-" {
        None
    } else {
        Some(tok.to_string())
    }
}

// ---------------------------------------------------------------------------
// Timestamp parsers
// ---------------------------------------------------------------------------

fn parse_rfc5424_timestamp(ts: &str) -> Option<DateTime<Utc>> {
    if ts == "-" {
        return None;
    }
    DateTime::parse_from_rfc3339(ts)
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
}

fn parse_rfc3164_timestamp(ts: &str) -> Option<DateTime<Utc>> {
    let year = Utc::now().format("%Y").to_string();
    let with_year = format!("{} {}", year, ts.trim());
    NaiveDateTime::parse_from_str(&with_year, "%Y %b %e %H:%M:%S")
        .ok()
        .map(|ndt| ndt.and_utc())
}

// ---------------------------------------------------------------------------
// Structured data parser
// ---------------------------------------------------------------------------

fn parse_structured_data(input: &str) -> (Vec<StructuredDataElement>, &str) {
    // NILVALUE: a lone `-`
    if let Some(rest) = input.strip_prefix('-') {
        // Only treat as NILVALUE if next char is space or end-of-string
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
        rest = &rest[1..]; // consume '['

        // SD-ID (up to space or ']')
        let id_end = match rest.find(|c: char| c == ' ' || c == ']') {
            Some(p) => p,
            None => break,
        };
        let id = rest[..id_end].to_string();
        rest = &rest[id_end..];

        let mut params = Vec::new();

        while rest.starts_with(' ') {
            rest = &rest[1..]; // consume space
            if rest.starts_with(']') {
                break;
            }
            // PARAM-NAME "=" %d34 PARAM-VALUE %d34
            let eq_pos = match rest.find('=') {
                Some(p) => p,
                None => break,
            };
            let param_name = rest[..eq_pos].to_string();
            rest = &rest[eq_pos + 1..];

            if !rest.starts_with('"') {
                break;
            }
            rest = &rest[1..]; // consume opening '"'

            // Parse param value with escape handling (RFC 5424 §6.3.3)
            let mut value = String::new();
            let bytes = rest.as_bytes();
            let mut i = 0usize;
            let consumed;
            loop {
                if i >= bytes.len() {
                    consumed = i;
                    break;
                }
                match bytes[i] {
                    b'\\' if i + 1 < bytes.len() => {
                        // Escaped char: \", \\, \]
                        value.push(bytes[i + 1] as char);
                        i += 2;
                    }
                    b'"' => {
                        i += 1; // consume closing '"'
                        consumed = i;
                        break;
                    }
                    b => {
                        value.push(b as char);
                        i += 1;
                    }
                }
            }
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

// ---------------------------------------------------------------------------
// RFC 5424 parser
// ---------------------------------------------------------------------------

/// Parse an RFC 5424 syslog message.
pub fn parse_rfc5424(input: &str) -> Option<SyslogMessage> {
    let (prival, rest) = parse_pri(input)?;
    let facility = SyslogFacility::from_prival(prival);
    let severity = SyslogSeverity::from_prival(prival);

    let (version_tok, rest) = split_sp(rest)?;
    // RFC 5424 VERSION must be a digit; currently only "1" is defined
    let _version: u8 = version_tok.parse().ok()?;

    let (ts_tok, rest) = split_sp(rest)?;
    let timestamp = parse_rfc5424_timestamp(ts_tok);

    let (hostname_tok, rest) = split_sp(rest)?;
    let hostname = nil_or_some(hostname_tok);

    let (app_name_tok, rest) = split_sp(rest)?;
    let app_name = nil_or_some(app_name_tok);

    let (procid_tok, rest) = split_sp(rest)?;
    let procid = nil_or_some(procid_tok);

    let (msgid_tok, rest) = split_sp(rest)?;
    let msgid = nil_or_some(msgid_tok);

    let (structured_data, rest) = parse_structured_data(rest);

    // MSG: optional, preceded by a space
    let message = if let Some(msg) = rest.strip_prefix(' ') {
        msg.to_string()
    } else {
        rest.to_string()
    };

    Some(SyslogMessage {
        facility,
        severity,
        timestamp,
        hostname,
        app_name,
        procid,
        msgid,
        structured_data,
        message,
    })
}

// ---------------------------------------------------------------------------
// RFC 3164 parser
// ---------------------------------------------------------------------------

/// Parse an RFC 3164 (legacy BSD syslog) message.
///
/// Format: `<PRI>TIMESTAMP HOSTNAME TAG[PID]: MSG`
pub fn parse_rfc3164(input: &str) -> Option<SyslogMessage> {
    let (prival, rest) = parse_pri(input)?;
    let facility = SyslogFacility::from_prival(prival);
    let severity = SyslogSeverity::from_prival(prival);

    // Timestamp is exactly 15 chars: "Mmm DD HH:MM:SS" or "Mmm  D HH:MM:SS"
    if rest.len() < 16 {
        return None;
    }
    let ts_str = &rest[..15];
    let timestamp = parse_rfc3164_timestamp(ts_str);
    let rest = rest[15..].trim_start_matches(' ');

    // HOSTNAME (up to next space)
    let (hostname_str, rest) = split_sp(rest)?;
    let hostname = Some(hostname_str.to_string());

    // TAG[PID]: or TAG:
    let colon_pos = rest.find(':')?;
    let tag_part = &rest[..colon_pos];

    let (app_name, procid) = if let Some(bracket) = tag_part.find('[') {
        let app = &tag_part[..bracket];
        let pid_end = tag_part.find(']').unwrap_or(tag_part.len());
        let pid = &tag_part[bracket + 1..pid_end];
        (
            if app.is_empty() {
                None
            } else {
                Some(app.to_string())
            },
            if pid.is_empty() {
                None
            } else {
                Some(pid.to_string())
            },
        )
    } else {
        (
            if tag_part.is_empty() {
                None
            } else {
                Some(tag_part.to_string())
            },
            None,
        )
    };

    let message = rest[colon_pos + 1..].trim_start_matches(' ').to_string();

    Some(SyslogMessage {
        facility,
        severity,
        timestamp,
        hostname,
        app_name,
        procid,
        msgid: None,
        structured_data: Vec::new(),
        message,
    })
}

// ---------------------------------------------------------------------------
// Unified entry point
// ---------------------------------------------------------------------------

/// Parse a syslog line, trying RFC 5424 first and falling back to RFC 3164.
///
/// Leading/trailing CRLF is stripped before parsing.
pub fn parse_syslog(input: &str) -> Option<SyslogMessage> {
    let input = input.trim_end_matches(['\n', '\r']);

    // RFC 5424: after `<NNN>`, the first token is a VERSION digit
    if let Some((_, rest)) = parse_pri(input) {
        if rest.starts_with(|c: char| c.is_ascii_digit()) {
            if let Some(msg) = parse_rfc5424(input) {
                return Some(msg);
            }
        }
    }

    // Fall back to RFC 3164
    parse_rfc3164(input)
}

// ---------------------------------------------------------------------------
// IP extraction helper
// ---------------------------------------------------------------------------

/// Try to find an IP address in a free-form log message.
///
/// Recognises common patterns used in SSH, iptables, nginx, and postfix logs:
/// - `from <ip>`, `client: <ip>`, `client= <ip>`
/// - Key-value pairs: `SRC=<ip>`, `src=<ip>`, `rhost=<ip>`, `client=<ip>`
/// - Bare IP in brackets: `[1.2.3.4]`
pub fn extract_ip_from_message(message: &str) -> Option<IpAddr> {
    let words: Vec<&str> = message.split_whitespace().collect();
    for (i, &word) in words.iter().enumerate() {
        let lower = word.to_ascii_lowercase();

        // "from <ip>" or "client:" patterns (value is next token)
        if matches!(lower.as_str(), "from" | "client:") {
            if let Some(&next) = words.get(i + 1) {
                let clean = next.trim_matches(['[', ']', ',', ';', '\'', '"', '(', ')']);
                if let Ok(ip) = clean.parse::<IpAddr>() {
                    return Some(ip);
                }
            }
        }

        // Key=value patterns where value is part of this token
        let after_eq = lower
            .strip_prefix("src=")
            .or_else(|| lower.strip_prefix("client="))
            .or_else(|| lower.strip_prefix("rhost="));
        if let Some(candidate_lower) = after_eq {
            // Try the lower-case slice first (works for pure ASCII IPs)
            let clean = candidate_lower.trim_matches(['[', ']', ',', ';']);
            if let Ok(ip) = clean.parse::<IpAddr>() {
                return Some(ip);
            }
            // Also try with original casing (IPv6 may have upper hex)
            if let Some(eq_pos) = word.find('=') {
                let candidate = word[eq_pos + 1..].trim_matches(['[', ']', ',', ';']);
                if let Ok(ip) = candidate.parse::<IpAddr>() {
                    return Some(ip);
                }
            }
        }

        // Standalone IP possibly wrapped in brackets
        let clean = word.trim_matches(['[', ']', ',', ';', '(', ')']);
        if let Ok(ip) = clean.parse::<IpAddr>() {
            // Accept IPv4 (has dots) or IPv6 (has colons / is just "::")
            if (ip.is_ipv4() && clean.contains('.'))
                || (ip.is_ipv6() && (clean.contains(':') || clean == "::"))
            {
                return Some(ip);
            }
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

    // ── RFC 5424 ──────────────────────────────────────────────────────────

    #[test]
    fn test_rfc5424_basic() {
        let line = r#"<34>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 [exampleSDID@32473 iut="3" eventSource="Application" eventID="1011"] 'su root' failed"#;
        let msg = parse_syslog(line).unwrap();
        assert_eq!(msg.hostname.as_deref(), Some("mymachine.example.com"));
        assert_eq!(msg.app_name.as_deref(), Some("su"));
        assert_eq!(msg.msgid.as_deref(), Some("ID47"));
        assert_eq!(msg.structured_data.len(), 1);
        assert_eq!(msg.structured_data[0].id, "exampleSDID@32473");
        assert_eq!(
            msg.structured_data[0].params[0],
            ("iut".to_string(), "3".to_string())
        );
        assert!(msg.message.contains("su root"));
    }

    #[test]
    fn test_rfc5424_nil_fields() {
        let line = "<165>1 2003-08-24T05:14:15.000003-07:00 192.0.2.1 myproc 8710 - - It's time";
        let msg = parse_rfc5424(line).unwrap();
        assert_eq!(msg.msgid, None);
        assert!(msg.structured_data.is_empty());
        assert!(msg.message.contains("It's time"));
    }

    #[test]
    fn test_rfc5424_nil_timestamp() {
        let line = "<13>1 - mymachine myapp 1234 - - message here";
        let msg = parse_rfc5424(line).unwrap();
        assert!(msg.timestamp.is_none());
        assert_eq!(msg.message, "message here");
    }

    #[test]
    fn test_rfc5424_no_msg() {
        let line = "<14>1 2003-10-11T22:14:15Z host app 123 - -";
        let msg = parse_rfc5424(line).unwrap();
        assert_eq!(msg.message, "");
    }

    #[test]
    fn test_rfc5424_multiple_sd_elements() {
        let line = r#"<14>1 2003-10-11T22:14:15Z host app - - [foo@1 a="1"][bar@2 b="2"] msg"#;
        let msg = parse_rfc5424(line).unwrap();
        assert_eq!(msg.structured_data.len(), 2);
        assert_eq!(msg.structured_data[0].id, "foo@1");
        assert_eq!(msg.structured_data[1].id, "bar@2");
    }

    #[test]
    fn test_rfc5424_ssh_message() {
        let line = "<86>1 2024-01-15T10:23:45Z server1 sshd 12345 - - Failed password for root from 192.168.1.100 port 22 ssh2";
        let msg = parse_rfc5424(line).unwrap();
        assert_eq!(msg.app_name.as_deref(), Some("sshd"));
        assert!(msg.message.contains("Failed password"));
    }

    #[test]
    fn test_rfc5424_structured_data_escaped_quote() {
        let line = r#"<14>1 2024-01-01T00:00:00Z h app - - [x k="a\"b"] msg"#;
        let msg = parse_rfc5424(line).unwrap();
        assert_eq!(msg.structured_data[0].params[0].1, r#"a"b"#);
    }

    #[test]
    fn test_rfc5424_crlf_stripped() {
        let line = "<14>1 2024-01-01T00:00:00Z host app 1 - - test\r\n";
        let msg = parse_syslog(line).unwrap();
        assert!(msg.message.contains("test"));
    }

    // ── RFC 3164 ──────────────────────────────────────────────────────────

    #[test]
    fn test_rfc3164_basic() {
        let line = "<34>Oct 11 22:14:15 mymachine su[100]: 'su root' failed for lonvick";
        let msg = parse_syslog(line).unwrap();
        assert_eq!(msg.hostname.as_deref(), Some("mymachine"));
        assert_eq!(msg.app_name.as_deref(), Some("su"));
        assert_eq!(msg.procid.as_deref(), Some("100"));
        assert!(msg.message.contains("su root"));
    }

    #[test]
    fn test_rfc3164_sshd() {
        let line = "<86>May  7 11:42:12 server1 sshd[12345]: Failed password for root from 192.168.1.100 port 22 ssh2";
        let msg = parse_syslog(line).unwrap();
        assert_eq!(msg.app_name.as_deref(), Some("sshd"));
        assert!(msg.message.contains("Failed password"));
        let ip = extract_ip_from_message(&msg.message);
        assert_eq!(ip, Some("192.168.1.100".parse().unwrap()));
    }

    #[test]
    fn test_rfc3164_no_pid() {
        let line = "<86>May  7 11:42:12 server1 sshd: Some log message here";
        let msg = parse_rfc3164(line).unwrap();
        assert_eq!(msg.app_name.as_deref(), Some("sshd"));
        assert_eq!(msg.procid, None);
    }

    #[test]
    fn test_rfc3164_nginx() {
        let line = r#"<86>May  7 11:42:12 server1 nginx[1234]: 192.168.1.50 - - [07/May/2024:11:42:12 +0000] "GET /admin HTTP/1.1" 404 0 "-" "-""#;
        let msg = parse_rfc3164(line).unwrap();
        assert_eq!(msg.app_name.as_deref(), Some("nginx"));
        assert!(msg.message.contains("192.168.1.50"));
    }

    #[test]
    fn test_rfc3164_iptables_format() {
        let line = "<4>May  7 11:42:12 firewall kernel: [12345.678] IN=eth0 OUT= SRC=1.2.3.4 DST=10.0.0.1 PROTO=TCP DPT=22";
        let msg = parse_rfc3164(line).unwrap();
        assert_eq!(msg.app_name.as_deref(), Some("kernel"));
        let ip = extract_ip_from_message(&msg.message);
        assert_eq!(ip, Some("1.2.3.4".parse().unwrap()));
    }

    #[test]
    fn test_rfc3164_postfix() {
        let line = "<14>May  7 11:42:12 mail postfix/smtpd[1234]: warning: 192.168.1.1[192.168.1.1]: SASL PLAIN authentication failed";
        let msg = parse_rfc3164(line).unwrap();
        assert!(msg.app_name.as_deref().unwrap().contains("postfix"));
    }

    // ── Facility / Severity ───────────────────────────────────────────────

    #[test]
    fn test_facility_auth_and_severity_warning() {
        // 36 = AUTH(4)*8 + WARNING(4)
        let line = "<36>1 2024-01-01T00:00:00Z h a - - - msg";
        let msg = parse_rfc5424(line).unwrap();
        assert!(matches!(msg.facility, SyslogFacility::Auth));
        assert!(matches!(msg.severity, SyslogSeverity::Warning));
    }

    #[test]
    fn test_facility_local0_emergency() {
        // 128 = LOCAL0(16)*8 + EMERGENCY(0)
        let line = "<128>1 2024-01-01T00:00:00Z h a - - - msg";
        let msg = parse_rfc5424(line).unwrap();
        assert!(matches!(msg.facility, SyslogFacility::Local0));
        assert!(matches!(msg.severity, SyslogSeverity::Emergency));
    }

    // ── IP extraction ─────────────────────────────────────────────────────

    #[test]
    fn test_extract_ip_from_pattern() {
        assert_eq!(
            extract_ip_from_message("Failed password for root from 1.2.3.4 port 22"),
            Some("1.2.3.4".parse().unwrap())
        );
    }

    #[test]
    fn test_extract_ip_src_equals() {
        assert_eq!(
            extract_ip_from_message("IN=eth0 OUT= SRC=10.0.0.1 DST=192.168.1.1 PROTO=TCP"),
            Some("10.0.0.1".parse().unwrap())
        );
    }

    #[test]
    fn test_extract_ip_no_ip() {
        assert_eq!(extract_ip_from_message("no ip address here"), None);
    }

    #[test]
    fn test_extract_ip_ipv6() {
        assert_eq!(
            extract_ip_from_message("Failed password for user from ::1 port 22"),
            Some("::1".parse().unwrap())
        );
    }

    #[test]
    fn test_extract_ip_bracketed() {
        assert_eq!(
            extract_ip_from_message("connection from [192.0.2.5] accepted"),
            Some("192.0.2.5".parse().unwrap())
        );
    }

    // ── Unified parse_syslog ──────────────────────────────────────────────

    #[test]
    fn test_parse_syslog_prefers_5424() {
        let line = "<14>1 2024-01-01T00:00:00Z host app 1 - - test message";
        let msg = parse_syslog(line).unwrap();
        assert_eq!(msg.app_name.as_deref(), Some("app"));
        assert_eq!(msg.procid.as_deref(), Some("1"));
        assert_eq!(msg.message, "test message");
    }

    #[test]
    fn test_parse_syslog_falls_back_to_3164() {
        let line = "<34>Oct 11 22:14:15 mymachine su[100]: test message";
        let msg = parse_syslog(line).unwrap();
        assert_eq!(msg.app_name.as_deref(), Some("su"));
        assert!(msg.message.contains("test message"));
    }

    #[test]
    fn test_parse_invalid_no_pri() {
        assert!(parse_rfc5424("no pri here").is_none());
        assert!(parse_rfc3164("no pri here").is_none());
    }

    #[test]
    fn test_parse_pri_too_large() {
        assert!(parse_pri("<200>rest").is_none());
    }

    // Corpus sample: minimal valid RFC 5424
    #[test]
    fn test_rfc5424_minimal_with_utf8_bom_msg() {
        // BOM (U+FEFF) prefix on MSG is valid per RFC 5424 §6.4
        let line = "<14>1 2024-06-01T00:00:00Z h a - - - \u{FEFF}hello";
        let msg = parse_rfc5424(line).unwrap();
        assert!(msg.message.contains("hello"));
    }

    // Corpus sample: structured data with no params
    #[test]
    fn test_rfc5424_sd_no_params() {
        let line = "<14>1 2024-01-01T00:00:00Z h a - - [origin] msg";
        let msg = parse_rfc5424(line).unwrap();
        assert_eq!(msg.structured_data.len(), 1);
        assert_eq!(msg.structured_data[0].id, "origin");
        assert!(msg.structured_data[0].params.is_empty());
    }
}
