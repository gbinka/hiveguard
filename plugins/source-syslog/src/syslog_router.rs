use std::net::IpAddr;

use regex::Regex;

use hiveguard_core::config::{SyslogRouteConfig, SyslogRouteParser};
use hiveguard_core::errors::HiveGuardError;
use hiveguard_core::models::NormalizedEvent;

use crate::netdev_parser::{parse_cisco_asa_line, parse_iptables_line, parse_pf_line};
use crate::parsers::{nginx_event_to_normalized, parse_nginx_line, parse_postfix_line, parse_ssh_line, postfix_event_to_normalized, ssh_event_to_normalized, NginxPattern, PostfixPatterns, SshPatterns};
use crate::syslog_parser::{extract_ip_from_message, SyslogMessage};

struct CompiledRoute {
    app_name: Option<String>,
    hostname_re: Option<Regex>,
    facility: Option<String>,
    parser: SyslogRouteParser,
    custom_re: Option<Regex>,
}

impl CompiledRoute {
    fn from_config(cfg: &SyslogRouteConfig) -> Result<Self, HiveGuardError> {
        let app_name = cfg.r#match.app_name.as_deref().map(|s| s.to_ascii_lowercase());
        let hostname_re = cfg.r#match.hostname_pattern.as_deref().map(glob_to_regex).transpose().map_err(|e| HiveGuardError::Config(format!("invalid hostname_pattern: {e}")))?;
        let facility = cfg.r#match.facility.as_deref().map(|s| s.to_ascii_lowercase());
        let custom_re = if cfg.parser == SyslogRouteParser::Custom {
            let pattern = cfg.pattern.as_deref().ok_or_else(|| HiveGuardError::Config("syslog route with parser: custom requires a `pattern` field".to_string()))?;
            Some(Regex::new(pattern).map_err(|e| HiveGuardError::Config(format!("invalid custom route pattern `{pattern}`: {e}")))?)
        } else {
            None
        };
        Ok(Self { app_name, hostname_re, facility, parser: cfg.parser.clone(), custom_re })
    }

    fn matches(&self, msg: &SyslogMessage, app_lower: &str) -> bool {
        if let Some(ref want) = self.app_name {
            if want != app_lower {
                return false;
            }
        }
        if let Some(ref re) = self.hostname_re {
            if !re.is_match(msg.hostname.as_deref().unwrap_or("")) {
                return false;
            }
        }
        if let Some(ref want) = self.facility {
            if &format!("{:?}", msg.facility).to_ascii_lowercase() != want {
                return false;
            }
        }
        true
    }
}

pub struct SyslogRouter {
    routes: Vec<CompiledRoute>,
    ssh_patterns: SshPatterns,
    nginx_pattern: NginxPattern,
    postfix_patterns: PostfixPatterns,
}

impl SyslogRouter {
    pub fn from_config(routes: &[SyslogRouteConfig]) -> Result<Self, HiveGuardError> {
        let compiled = routes.iter().map(CompiledRoute::from_config).collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            routes: compiled,
            ssh_patterns: SshPatterns::new(),
            nginx_pattern: NginxPattern::new(),
            postfix_patterns: PostfixPatterns::new(),
        })
    }

    pub fn route(&self, msg: SyslogMessage, source_name: &str, sender_ip: Option<IpAddr>) -> Option<NormalizedEvent> {
        use chrono::Utc;
        use std::collections::HashMap;
        use hiveguard_core::models::EventType;

        let timestamp = msg.timestamp.unwrap_or_else(Utc::now);
        let message = msg.message.clone();
        let app_lower = msg.app_name.as_deref().unwrap_or("").split('/').next().unwrap_or("").to_ascii_lowercase();

        for route in &self.routes {
            if route.matches(&msg, &app_lower) {
                return self.apply_parser(route, &msg, &message, &app_lower, source_name, sender_ip, timestamp);
            }
        }

        match app_lower.as_str() {
            "sshd" => parse_ssh_line(&message, &self.ssh_patterns).map(ssh_event_to_normalized),
            "nginx" | "apache2" | "httpd" => parse_nginx_line(&message, &self.nginx_pattern).map(nginx_event_to_normalized),
            "postfix" | "sendmail" => parse_postfix_line(&message, &self.postfix_patterns).map(postfix_event_to_normalized),
            "kernel" | "iptables" | "nftables" => parse_iptables_line(&message).map(|ev| ev.to_normalized(source_name)),
            _ => {
                let source_ip = extract_ip_from_message(&message).or(sender_ip)?;
                let mut metadata = HashMap::new();
                if let Some(ref hostname) = msg.hostname {
                    metadata.insert("syslog_hostname".to_string(), hostname.clone());
                }
                if let Some(ref app_name) = msg.app_name {
                    metadata.insert("syslog_app_name".to_string(), app_name.clone());
                }
                if let Some(ref procid) = msg.procid {
                    metadata.insert("syslog_procid".to_string(), procid.clone());
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
        }
    }

    fn apply_parser(&self, route: &CompiledRoute, msg: &SyslogMessage, message: &str, app_lower: &str, source_name: &str, sender_ip: Option<IpAddr>, timestamp: chrono::DateTime<chrono::Utc>) -> Option<NormalizedEvent> {
        use std::collections::HashMap;
        use hiveguard_core::models::EventType;

        match route.parser {
            SyslogRouteParser::Drop => None,
            SyslogRouteParser::Ssh => parse_ssh_line(message, &self.ssh_patterns).map(ssh_event_to_normalized),
            SyslogRouteParser::Nginx => parse_nginx_line(message, &self.nginx_pattern).map(nginx_event_to_normalized),
            SyslogRouteParser::Postfix => parse_postfix_line(message, &self.postfix_patterns).map(postfix_event_to_normalized),
            SyslogRouteParser::Iptables => parse_iptables_line(message).map(|ev| ev.to_normalized(source_name)),
            SyslogRouteParser::CiscoAsa => parse_cisco_asa_line(message).map(|ev| ev.to_normalized(source_name)),
            SyslogRouteParser::Pfsense => parse_pf_line(message).map(|ev| ev.to_normalized(source_name)),
            SyslogRouteParser::Custom => {
                let re = route.custom_re.as_ref()?;
                let caps = re.captures(message)?;
                let source_ip: IpAddr = caps.name("ip")?.as_str().parse().ok().or(sender_ip)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use hiveguard_core::config::{SyslogRouteMatch, SyslogRouteParser};
    use crate::syslog_parser::{SyslogFacility, SyslogSeverity};

    fn make_route(app_name: Option<&str>, parser: SyslogRouteParser, pattern: Option<&str>) -> SyslogRouteConfig {
        SyslogRouteConfig {
            r#match: SyslogRouteMatch { app_name: app_name.map(String::from), hostname_pattern: None, facility: None },
            parser,
            pattern: pattern.map(String::from),
        }
    }

    fn minimal_msg(app_name: &str, message: &str) -> SyslogMessage {
        SyslogMessage {
            facility: SyslogFacility::User,
            severity: SyslogSeverity::Informational,
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
    fn builtin_default_ssh_route() {
        let router = SyslogRouter::from_config(&[]).unwrap();
        let ev = router.route(minimal_msg("sshd", "Failed password for root from 1.2.3.4 port 22 ssh2"), "source.syslog.udp", None).unwrap();
        assert_eq!(ev.source_ip, "1.2.3.4".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn custom_route_extracts_ip() {
        let routes = vec![make_route(Some("myapp"), SyslogRouteParser::Custom, Some(r"blocked from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"))];
        let router = SyslogRouter::from_config(&routes).unwrap();
        let ev = router.route(minimal_msg("myapp", "blocked from 5.5.5.5 port 1234"), "source.syslog.udp", None).unwrap();
        assert_eq!(ev.source_ip, "5.5.5.5".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn iptables_route_matches() {
        let routes = vec![make_route(Some("kernel"), SyslogRouteParser::Iptables, None)];
        let router = SyslogRouter::from_config(&routes).unwrap();
        let ev = router.route(minimal_msg("kernel", "IN=eth0 OUT= SRC=1.2.3.4 DST=10.0.0.1 PROTO=TCP DPT=22"), "source.syslog.udp", None).unwrap();
        assert_eq!(ev.source_ip, "1.2.3.4".parse::<IpAddr>().unwrap());
    }
}
