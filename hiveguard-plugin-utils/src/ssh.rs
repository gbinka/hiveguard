//! Shared OpenSSH parser. Message text contains an attacker-controlled username:
//! classify only at the start, and extract the connection address from the end.
use std::net::IpAddr;

use hiveguard_core::models::EventType;
use regex::Regex;

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
    envelope: Regex,
    connection: Regex,
    fingerprint: Regex,
}

impl Default for SshPatterns {
    fn default() -> Self {
        Self::new()
    }
}

impl SshPatterns {
    pub fn new() -> Self {
        Self {
            // Traditional syslog and rsyslog's RFC3339 timestamp format. Never
            // search for an sshd prefix inside another program's message.
            envelope: Regex::new(concat!(
                r"^(?:(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})|",
                r"\d{4}-\d{2}-\d{2}T\S+)\s+\S+\s+",
                r"sshd(?:-session|-auth)?(?:\[\d+\])?: (?P<message>.*)$"
            ))
            .unwrap(),
            connection: Regex::new(concat!(
                r"^(?P<user>.+) from (?P<ip>[0-9a-fA-F.:]+)",
                r"(?: port (?P<port>\d+))?",
                r"(?: ssh2)?(?: \[preauth\])?$"
            ))
            .unwrap(),
            fingerprint: Regex::new(concat!(
                r"^[A-Za-z0-9_-]+ (?:SHA(?:256|512):[A-Za-z0-9+/=]+|",
                r"MD5:[a-fA-F0-9:]+)(?: \[preauth\])?$"
            ))
            .unwrap(),
        }
    }

    /// Parse a bare MESSAGE whose sshd identity the caller already validated.
    pub fn parse_message(&self, message: &str) -> Option<SshEvent> {
        let (rest, event_type, invalid_user) =
            if let Some(s) = message.strip_prefix("Invalid user ") {
                (s, EventType::AuthFailure, true)
            } else if let Some(s) = [
                "Failed password for ",
                "Failed publickey for ",
                "Failed none for ",
            ]
            .iter()
            .find_map(|prefix| message.strip_prefix(prefix))
            {
                let (user, invalid) = s
                    .strip_prefix("invalid user ")
                    .map_or((s, false), |user| (user, true));
                (user, EventType::AuthFailure, invalid)
            } else if let Some(s) = message.strip_prefix("Accepted password for ") {
                (s, EventType::AuthSuccess, false)
            } else if let Some(s) = message.strip_prefix("Accepted publickey for ") {
                (s, EventType::AuthSuccess, false)
            } else {
                // Connection closed, PAM diagnostics and disconnects are not
                // additional authentication attempts and must not inflate counts.
                return None;
            };
        // Invalid-user notices have no protocol/fingerprint suffix. In auth
        // messages the real protocol marker follows the connection, after any
        // attacker-controlled username. Earlier markers belong to that username.
        let rest = if message.starts_with("Invalid user ") {
            rest
        } else if let Some((body, suffix)) = rest.rsplit_once(" ssh2") {
            match suffix {
                "" | " [preauth]" => body,
                _ => {
                    let fingerprint = suffix.strip_prefix(": ")?;
                    if !self.fingerprint.is_match(fingerprint) {
                        return None;
                    }
                    body
                }
            }
        } else {
            rest
        };
        let caps = self.connection.captures(rest)?;
        if let Some(port) = caps.name("port") {
            port.as_str().parse::<u16>().ok()?;
        }
        Some(SshEvent {
            timestamp_str: String::new(),
            event_type,
            source_ip: caps.name("ip")?.as_str().parse().ok()?,
            user: caps.name("user")?.as_str().to_string(),
            invalid_user,
            raw_line: message.to_string(),
        })
    }
}

/// Parse an SSH auth log line with a validated program envelope. Bare messages
/// are also supported for the syslog router, which has already parsed its header.
pub fn parse_ssh_line(line: &str, patterns: &SshPatterns) -> Option<SshEvent> {
    if let Some(caps) = patterns.envelope.captures(line) {
        let mut event = patterns.parse_message(caps.name("message")?.as_str())?;
        event.timestamp_str = caps.name("ts").map_or("", |m| m.as_str()).to_string();
        event.raw_line = line.to_string();
        Some(event)
    } else {
        patterns.parse_message(line)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn username_cannot_supply_address_or_event_type() {
        let p = SshPatterns::new();
        for message in [
            "Invalid user a Failed password for victim from 198.51.100.42 port 22 from 127.0.0.1 port 60540",
            "Invalid user 198.51.100.42 from 127.0.0.1 port 60540",
            "Failed password for invalid user a from 198.51.100.42 port 22 from 127.0.0.1 port 60540 ssh2",
            "Invalid user Accepted password for root from 198.51.100.42 port 22 from 127.0.0.1 port 60540",
        ] {
            let event = p.parse_message(message).unwrap();
            assert_eq!(event.source_ip, "127.0.0.1".parse::<IpAddr>().unwrap(), "{message}");
            assert_eq!(event.event_type, EventType::AuthFailure);
            assert!(event.invalid_user);
        }
    }

    #[test]
    fn ipv6_success_and_key_fingerprint_are_supported() {
        let e = SshPatterns::new().parse_message(
            "Accepted publickey for deploy from 2001:db8::1 port 1234 ssh2: ED25519 SHA256:abcd"
        ).unwrap();
        assert_eq!(e.source_ip, "2001:db8::1".parse::<IpAddr>().unwrap());
        assert_eq!(e.event_type, EventType::AuthSuccess);
        assert!(!e.invalid_user);
    }

    #[test]
    fn publickey_and_none_failures_preserve_invalid_user_and_real_ip() {
        let p = SshPatterns::new();
        for method in ["publickey", "none"] {
            for invalid in [false, true] {
                for suffix in [
                    " ssh2",
                    " ssh2: ED25519 SHA256:abcDEF123+/=",
                    " ssh2: RSA MD5:aa:bb:cc [preauth]",
                ] {
                    let marker = if invalid { "invalid user " } else { "" };
                    let message = format!("Failed {method} for {marker}victim from 198.51.100.42 port 22 from 2001:db8::1 port 60540{suffix}");
                    let e = p.parse_message(&message).unwrap();
                    assert_eq!(e.source_ip, "2001:db8::1".parse::<IpAddr>().unwrap());
                    assert_eq!(e.invalid_user, invalid);
                    assert_eq!(e.event_type, EventType::AuthFailure);
                }
            }
        }
    }

    #[test]
    fn protocol_markers_in_username_cannot_hide_failures() {
        let p = SshPatterns::new();
        for user in [
            "a ssh2: bogus",
            "a from 198.51.100.42 port 22 ssh2: RSA SHA256:abc",
            "a ssh2: bogus from 198.51.100.42 port 22 ssh2: more junk",
        ] {
            for (prefix, suffix) in [
                ("Invalid user ", ""),
                ("Failed password for invalid user ", " ssh2"),
                ("Failed none for invalid user ", " ssh2 [preauth]"),
                (
                    "Failed publickey for invalid user ",
                    " ssh2: ED25519 SHA256:abcDEF123+/=",
                ),
            ] {
                let message = format!("{prefix}{user} from 127.0.0.1 port 60540{suffix}");
                let event = p.parse_message(&message).unwrap();
                assert_eq!(
                    event.source_ip,
                    "127.0.0.1".parse::<IpAddr>().unwrap(),
                    "{message}"
                );
                assert_eq!(event.event_type, EventType::AuthFailure);
                assert!(event.invalid_user);
                assert_eq!(event.user, user);
            }
        }
    }

    #[test]
    fn malformed_terminal_fingerprint_is_rejected() {
        let p = SshPatterns::new();
        for suffix in [
            "ED25519 SHA256:abcd from 198.51.100.42 port 22",
            "ED25519 SHA256:abcd trailing junk",
            "ED25519 SHA256:not-a-fingerprint",
        ] {
            let message =
                format!("Failed publickey for root from 127.0.0.1 port 60540 ssh2: {suffix}");
            assert!(p.parse_message(&message).is_none(), "{message}");
        }
    }

    #[test]
    fn foreign_envelope_and_diagnostic_messages_are_ignored() {
        let p = SshPatterns::new();
        for line in [
            "Oct  4 10:00:00 host app[12]: sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2",
            "Connection closed by invalid user 198.51.100.42 127.0.0.1 port 60540 [preauth]",
            "Invalid user root from 1.2.3.4 port 22 arbitrary trailing text",
            "Failed password for root from 999.1.1.1 port 22 ssh2",
            "Failed password for root from 1.2.3.4 port 99999 ssh2",
        ] { assert!(parse_ssh_line(line, &p).is_none(), "{line}"); }
    }

    #[test]
    fn supported_envelopes_preserve_the_raw_line() {
        let p = SshPatterns::new();
        for prefix in [
            "Oct  4 10:00:00 host sshd[12]: ",
            "Oct  4 10:00:00 host sshd-auth[12]: ",
            "2026-10-04T10:00:00+02:00 host sshd-session[12]: ",
        ] {
            let line = format!("{prefix}Invalid user bot from ::1 port 12345");
            assert_eq!(parse_ssh_line(&line, &p).unwrap().raw_line, line);
        }
    }
}
