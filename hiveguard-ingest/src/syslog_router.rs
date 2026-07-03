//! Syslog message router — Phase 5.2.1
//!
//! [`SyslogRouter`] dispatches a parsed [`SyslogMessage`] to the appropriate
//! parser based on a list of user-configured [`SyslogRouteConfig`] rules.
//!
//! Rule evaluation:
//! 1. User-supplied routes are evaluated in order; **first match wins**.
//! 2. If no user route matches, built-in defaults apply:
//!    - `app_name` == "sshd"                        → SSH parser
//!    - `app_name` ∈ {"nginx","apache2","httpd"}     → Nginx parser
//!    - `app_name` ∈ {"postfix","sendmail"}          → Postfix parser
//!    - `app_name` ∈ {"kernel","iptables","nftables"}→ iptables/nftables parser
//!    - anything else                                → generic IP fallback
//! 3. If the generic fallback cannot find an IP, the message is silently dropped.

use std::net::IpAddr;

use regex::Regex;

use hiveguard_core::config::{SyslogRouteConfig, SyslogRouteParser};
use hiveguard_core::errors::HiveGuardError;
use hiveguard_core::models::NormalizedEvent;

use crate::netdev_parser::{parse_cisco_asa_line, parse_iptables_line, parse_pf_line};
use crate::nginx_parser::{nginx_event_to_normalized, parse_nginx_line, NginxPattern};
use crate::postfix_parser::{parse_postfix_line, postfix_event_to_normalized, PostfixPatterns};
use crate::ssh_parser::{parse_ssh_line, ssh_event_to_normalized, SshPatterns};
use crate::syslog_parser::{extract_ip_from_message, SyslogFacility, SyslogMessage};

// ---------------------------------------------------------------------------
// Compiled route
// ---------------------------------------------------------------------------

struct CompiledRoute {
    /// Normalised lowercase app_name to match, or `None` to match any.
    app_name: Option<String>,
    /// Compiled glob-as-regex for hostname, or `None` to match any.
    hostname_re: Option<Regex>,
    /// Normalised lowercase facility name to match, or `None` to match any.
    facility: Option<String>,
    /// The parser to invoke.
    parser: SyslogRouteParser,
    /// Pre-compiled custom pattern (requires named capture group `ip`).
    custom_re: Option<Regex>,
}

impl CompiledRoute {
    fn from_config(cfg: &SyslogRouteConfig) -> Result<Self, HiveGuardError> {
        let app_name = cfg
            .r#match
            .app_name
            .as_deref()
            .map(|s| s.to_ascii_lowercase());

        let hostname_re = cfg
            .r#match
            .hostname_pattern
            .as_deref()
            .map(glob_to_regex)
            .transpose()
            .map_err(|e| HiveGuardError::Config(format!("invalid hostname_pattern: {e}")))?;

        let facility = cfg
            .r#match
            .facility
            .as_deref()
            .map(|s| s.to_ascii_lowercase());

        let custom_re = if cfg.parser == SyslogRouteParser::Custom {
            let pat = cfg.pattern.as_deref().ok_or_else(|| {
                HiveGuardError::Config("syslog route with parser: custom requires a `pattern` field".to_string())
            })?;
            Some(Regex::new(pat).map_err(|e| {
                HiveGuardError::Config(format!("invalid custom route pattern `{pat}`: {e}"))
            })?)
        } else {
            None
        };

        Ok(CompiledRoute {
            app_name,
            hostname_re,
            facility,
            parser: cfg.parser.clone(),
            custom_re,
        })
    }

    /// Returns `true` if this route matches the given message.
    fn matches(&self, msg: &SyslogMessage, app_lower: &str) -> bool {
        // app_name condition
        if let Some(ref want) = self.app_name {
            if want != app_lower {
                return false;
            }
        }
        // hostname_pattern condition
        if let Some(ref re) = self.hostname_re {
            let host = msg.hostname.as_deref().unwrap_or("");
            if !re.is_match(host) {
                return false;
            }
        }
        // facility condition (SyslogFacility is not Option — compare via Debug repr)
        if let Some(ref want) = self.facility {
            let got = format!("{:?}", msg.facility).to_ascii_lowercase();
            if &got != want {
                return false;
            }
        }
        true
    }
}

// ---------------------------------------------------------------------------
// SyslogRouter
// ---------------------------------------------------------------------------

/// Routes parsed syslog messages to the correct parser/normaliser.
pub struct SyslogRouter {
    routes: Vec<CompiledRoute>,
    ssh_patterns: SshPatterns,
    nginx_pattern: NginxPattern,
    postfix_patterns: PostfixPatterns,
}

impl SyslogRouter {
    /// Build a router from user-supplied route configs.
    ///
    /// Returns an error if any route's regex or pattern is invalid.
    pub fn from_config(routes: &[SyslogRouteConfig]) -> Result<Self, HiveGuardError> {
        let compiled = routes
            .iter()
            .map(CompiledRoute::from_config)
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            routes: compiled,
            ssh_patterns: SshPatterns::new(),
            nginx_pattern: NginxPattern::new(),
            postfix_patterns: PostfixPatterns::new(),
        })
    }

    /// Convert a parsed [`SyslogMessage`] into a [`NormalizedEvent`].
    ///
    /// Returns `None` if the message should be dropped (no IP extractable, or
    /// matched a `Drop` route).
    pub fn route(
        &self,
        msg: SyslogMessage,
        source_name: &str,
        sender_ip: Option<IpAddr>,
    ) -> Option<NormalizedEvent> {
        use chrono::Utc;
        use std::collections::HashMap;
        use hiveguard_core::models::EventType;

        let timestamp = msg.timestamp.unwrap_or_else(Utc::now);
        let message = msg.message.clone();

        // Normalize app_name: strip subprocess suffix ("postfix/smtpd" → "postfix")
        let app_lower = msg
            .app_name
            .as_deref()
            .unwrap_or("")
            .split('/')
            .next()
            .unwrap_or("")
            .to_ascii_lowercase();

        // 1. Try user-configured routes in order
        for route in &self.routes {
            if route.matches(&msg, &app_lower) {
                return self.apply_parser(route, &msg, &message, &app_lower, source_name, sender_ip, timestamp);
            }
        }

        // 2. Built-in default routes
        match app_lower.as_str() {
            "sshd" => {
                if let Some(event) = parse_ssh_line(&message, &self.ssh_patterns) {
                    return Some(ssh_event_to_normalized(event));
                }
            }
            "nginx" | "apache2" | "httpd" => {
                if let Some(event) = parse_nginx_line(&message, &self.nginx_pattern) {
                    return Some(nginx_event_to_normalized(event));
                }
            }
            "postfix" | "sendmail" => {
                if let Some(event) = parse_postfix_line(&message, &self.postfix_patterns) {
                    return Some(postfix_event_to_normalized(event));
                }
            }
            "kernel" | "iptables" | "nftables" => {
                if let Some(ev) = parse_iptables_line(&message) {
                    return Some(ev.to_normalized(source_name));
                }
            }
            _ => {}
        }

        // 3. Generic fallback: extract IP from text or use sender IP
        let source_ip = extract_ip_from_message(&message).or(sender_ip)?;

        let mut metadata = HashMap::new();
        if let Some(ref hostname) = msg.hostname {
            metadata.insert("syslog_hostname".to_string(), hostname.clone());
        }
        if let Some(ref app) = msg.app_name {
            metadata.insert("syslog_app_name".to_string(), app.clone());
        }
        if let Some(ref pid) = msg.procid {
            metadata.insert("syslog_procid".to_string(), pid.clone());
        }
        for element in &msg.structured_data {
            for (k, v) in &element.params {
                metadata.insert(format!("sd_{}_{}", element.id, k), v.clone());
            }
        }

        Some(NormalizedEvent {
            timestamp,
            source_ip,
            event_type: EventType::Custom(app_lower),
            source_name: source_name.to_string(),
            raw_line: message,
            metadata,
        })
    }

    // -----------------------------------------------------------------------
    // Internal: apply a specific parser variant
    // -----------------------------------------------------------------------

    fn apply_parser(
        &self,
        route: &CompiledRoute,
        msg: &SyslogMessage,
        message: &str,
        app_lower: &str,
        source_name: &str,
        sender_ip: Option<IpAddr>,
        timestamp: chrono::DateTime<chrono::Utc>,
    ) -> Option<NormalizedEvent> {
        use std::collections::HashMap;
        use hiveguard_core::models::EventType;

        match route.parser {
            SyslogRouteParser::Drop => None,

            SyslogRouteParser::Ssh => {
                let event = parse_ssh_line(message, &self.ssh_patterns)?;
                Some(ssh_event_to_normalized(event))
            }

            SyslogRouteParser::Nginx => {
                let event = parse_nginx_line(message, &self.nginx_pattern)?;
                Some(nginx_event_to_normalized(event))
            }

            SyslogRouteParser::Postfix => {
                let event = parse_postfix_line(message, &self.postfix_patterns)?;
                Some(postfix_event_to_normalized(event))
            }

            SyslogRouteParser::Iptables => {
                let ev = parse_iptables_line(message)?;
                Some(ev.to_normalized(source_name))
            }

            SyslogRouteParser::CiscoAsa => {
                let ev = parse_cisco_asa_line(message)?;
                Some(ev.to_normalized(source_name))
            }

            SyslogRouteParser::Pfsense => {
                let ev = parse_pf_line(message)?;
                Some(ev.to_normalized(source_name))
            }

            SyslogRouteParser::Custom => {
                let re = route.custom_re.as_ref()?;
                let caps = re.captures(message)?;
                let src_str = caps.name("ip").map(|m| m.as_str())?;
                let source_ip: std::net::IpAddr = src_str.parse().ok().or(sender_ip)?;

                let mut metadata = HashMap::new();
                metadata.insert("syslog_app_name".to_string(), app_lower.to_string());
                if let Some(ref hostname) = msg.hostname {
                    metadata.insert("syslog_hostname".to_string(), hostname.clone());
                }

                Some(NormalizedEvent {
                    timestamp,
                    source_ip,
                    event_type: EventType::Custom(app_lower.to_string()),
                    source_name: source_name.to_string(),
                    raw_line: message.to_string(),
                    metadata,
                })
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Glob → Regex helper
// ---------------------------------------------------------------------------

/// Convert a simple glob pattern (`*`, `?`) to a full-match regex.
fn glob_to_regex(glob: &str) -> Result<Regex, regex::Error> {
    let mut pattern = String::with_capacity(glob.len() + 4);
    pattern.push('^');
    for ch in glob.chars() {
        match ch {
            '*' => pattern.push_str(".*"),
            '?' => pattern.push('.'),
            c => {
                for escaped in c.to_string().chars() {
                    if r"\.+^${}[]|()?*".contains(escaped) {
                        pattern.push('\\');
                    }
                    pattern.push(escaped);
                }
            }
        }
    }
    pattern.push('$');
    Regex::new(&pattern)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use hiveguard_core::config::{SyslogRouteMatch, SyslogRouteParser};

    fn make_route(
        app_name: Option<&str>,
        hostname_pattern: Option<&str>,
        parser: SyslogRouteParser,
        pattern: Option<&str>,
    ) -> SyslogRouteConfig {
        SyslogRouteConfig {
            r#match: SyslogRouteMatch {
                app_name: app_name.map(String::from),
                hostname_pattern: hostname_pattern.map(String::from),
                facility: None,
            },
            parser,
            pattern: pattern.map(String::from),
        }
    }

    fn minimal_msg(app_name: &str, message: &str) -> SyslogMessage {
        SyslogMessage {
            facility: SyslogFacility::User,
            severity: crate::syslog_parser::SyslogSeverity::Informational,
            timestamp: None,
            hostname: Some("testhost".to_string()),
            app_name: Some(app_name.to_string()),
            procid: None,
            msgid: None,
            structured_data: vec![],
            message: message.to_string(),
        }
    }

    #[test]
    fn drop_route_returns_none() {
        let routes = vec![make_route(Some("noisyd"), None, SyslogRouteParser::Drop, None)];
        let router = SyslogRouter::from_config(&routes).unwrap();
        let msg = minimal_msg("noisyd", "lots of noise");
        assert!(router.route(msg, "test", None).is_none());
    }

    #[test]
    fn iptables_route_matches_app_name() {
        let routes = vec![make_route(Some("kernel"), None, SyslogRouteParser::Iptables, None)];
        let router = SyslogRouter::from_config(&routes).unwrap();
        let line = "IN=eth0 OUT= SRC=1.2.3.4 DST=10.0.0.1 PROTO=TCP DPT=22";
        let msg = minimal_msg("kernel", line);
        let ev = router.route(msg, "test", None).expect("should produce event");
        assert_eq!(ev.source_ip, "1.2.3.4".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn cisco_asa_route() {
        let routes = vec![make_route(Some("%asa"), None, SyslogRouteParser::CiscoAsa, None)];
        let router = SyslogRouter::from_config(&routes).unwrap();
        let line = r#"%ASA-4-106023: Deny tcp src outside:203.0.113.5/54321 dst inside:10.0.0.1/443 by access-group "out""#;
        let msg = minimal_msg("%asa", line);
        let ev = router.route(msg, "test", None).expect("should produce event");
        assert_eq!(ev.source_ip, "203.0.113.5".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn custom_route_extracts_ip() {
        let routes = vec![make_route(
            Some("myapp"),
            None,
            SyslogRouteParser::Custom,
            Some(r"blocked from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"),
        )];
        let router = SyslogRouter::from_config(&routes).unwrap();
        let msg = minimal_msg("myapp", "blocked from 5.5.5.5 port 1234");
        let ev = router.route(msg, "test", None).expect("should produce event");
        assert_eq!(ev.source_ip, "5.5.5.5".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn hostname_glob_matches() {
        let routes = vec![make_route(None, Some("*.router.local"), SyslogRouteParser::Iptables, None)];
        let router = SyslogRouter::from_config(&routes).unwrap();

        let line = "IN=eth0 OUT= SRC=8.8.8.8 DST=10.0.0.1 PROTO=UDP DPT=53";
        let mut msg = minimal_msg("kernel", line);
        msg.hostname = Some("edge1.router.local".to_string());
        let ev = router.route(msg, "test", None).expect("should match via hostname glob");
        assert_eq!(ev.source_ip, "8.8.8.8".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn hostname_glob_no_match_falls_through() {
        let routes = vec![make_route(None, Some("*.router.local"), SyslogRouteParser::Drop, None)];
        let router = SyslogRouter::from_config(&routes).unwrap();

        // Hostname doesn't match the glob — should NOT be dropped
        let line = "IN=eth0 OUT= SRC=7.7.7.7 DST=10.0.0.1 PROTO=UDP DPT=53";
        let mut msg = minimal_msg("kernel", line);
        msg.hostname = Some("other.host".to_string());
        // Built-in default for "kernel" should still fire
        let ev = router.route(msg, "test", None);
        assert!(ev.is_some());
    }

    #[test]
    fn builtin_default_ssh() {
        let router = SyslogRouter::from_config(&[]).unwrap();
        let line = "Failed password for root from 1.2.3.4 port 22 ssh2";
        let msg = minimal_msg("sshd", line);
        let ev = router.route(msg, "test", None).expect("SSH default should match");
        assert_eq!(ev.source_ip, "1.2.3.4".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn glob_to_regex_wildcard() {
        let re = glob_to_regex("*.example.com").unwrap();
        assert!(re.is_match("foo.example.com"));
        assert!(re.is_match("bar.baz.example.com"));
        assert!(!re.is_match("notexample.com"));
    }

    #[test]
    fn invalid_custom_route_config_error() {
        let routes = vec![make_route(Some("app"), None, SyslogRouteParser::Custom, Some("[invalid(regex"))];
        assert!(SyslogRouter::from_config(&routes).is_err());
    }

    #[test]
    fn custom_route_missing_pattern_error() {
        let routes = vec![make_route(Some("app"), None, SyslogRouteParser::Custom, None)];
        assert!(SyslogRouter::from_config(&routes).is_err());
    }
}
