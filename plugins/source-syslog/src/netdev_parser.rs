use std::collections::HashMap;
use std::net::IpAddr;

use chrono::Utc;
use regex::Regex;

use hiveguard_core::models::{EventType, NormalizedEvent};

#[derive(Debug, Clone, PartialEq)]
pub struct NetdevEvent {
    pub src_ip: IpAddr,
    pub dst_ip: Option<IpAddr>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub proto: Option<String>,
    pub action: String,
    pub device_type: &'static str,
    pub in_iface: Option<String>,
    pub raw: String,
}

impl NetdevEvent {
    pub fn to_normalized(&self, source_name: &str) -> NormalizedEvent {
        let mut metadata = HashMap::new();
        metadata.insert("action".to_string(), self.action.clone());
        metadata.insert("device_type".to_string(), self.device_type.to_string());
        if let Some(ref dst) = self.dst_ip {
            metadata.insert("dst_ip".to_string(), dst.to_string());
        }
        if let Some(ref iface) = self.in_iface {
            metadata.insert("in_iface".to_string(), iface.clone());
        }
        if let Some(ref proto) = self.proto {
            metadata.insert("proto".to_string(), proto.clone());
        }
        if let Some(dst_port) = self.dst_port {
            metadata.insert("dst_port".to_string(), dst_port.to_string());
        }
        if let Some(src_port) = self.src_port {
            metadata.insert("src_port".to_string(), src_port.to_string());
        }
        NormalizedEvent {
            timestamp: Utc::now(),
            source_ip: self.src_ip,
            event_type: EventType::Custom(format!("netdev_{}", self.device_type)),
            source_name: source_name.to_string(),
            raw_line: self.raw.clone(),
            metadata,
        }
    }
}

fn kv<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let needle = format!("{key}=");
    let start = line.find(needle.as_str())? + needle.len();
    let rest = &line[start..];
    let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
    let value = &rest[..end];
    if value.is_empty() { None } else { Some(value) }
}

pub fn parse_iptables_line(line: &str) -> Option<NetdevEvent> {
    let src_ip: IpAddr = kv(line, "SRC")?.parse().ok()?;
    let dst_ip = kv(line, "DST").and_then(|s| s.parse().ok());
    let src_port = kv(line, "SPT").and_then(|s| s.parse().ok());
    let dst_port = kv(line, "DPT").and_then(|s| s.parse().ok());
    let proto = kv(line, "PROTO").map(str::to_ascii_uppercase);
    let in_iface = kv(line, "IN").map(String::from);
    let action = if line.contains("ACCEPT") || line.contains("accept") {
        "ACCEPT"
    } else if line.contains("REJECT") || line.contains("reject") {
        "REJECT"
    } else {
        "DROP"
    };
    let device_type = if line.contains("nftables") || line.contains("nft:") {
        "nftables"
    } else {
        "iptables"
    };
    Some(NetdevEvent {
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        proto,
        action: action.to_string(),
        device_type,
        in_iface,
        raw: line.to_string(),
    })
}

fn asa_patterns() -> (Regex, Regex, Regex) {
    let pat_a = Regex::new(r"(?i)%ASA-\d-\d+:\s+(?P<action>\w+)\s+(?P<proto>\w+)\s+src\s+\S+:(?P<src_ip>[\d.a-fA-F:]+)(?:/(?P<src_port>\d+))?\s+dst\s+\S+:(?P<dst_ip>[\d.a-fA-F:]+)(?:/(?P<dst_port>\d+))?").unwrap();
    let pat_b = Regex::new(r"(?i)%ASA-\d-\d+:.*?(?:denied|permitted).*?from\s+(?P<src_ip>[\d.a-fA-F:]+)(?:/(?P<src_port>\d+))?\s+to\s+(?P<dst_ip>[\d.a-fA-F:]+)(?:/(?P<dst_port>\d+))?").unwrap();
    let pat_c = Regex::new(r"(?i)%ASA-\d-\d+:.*?(?P<src_ip>(?:\d{1,3}\.){3}\d{1,3})").unwrap();
    (pat_a, pat_b, pat_c)
}

pub fn parse_cisco_asa_line(line: &str) -> Option<NetdevEvent> {
    if !line.contains("%ASA-") {
        return None;
    }
    let (pat_a, pat_b, pat_c) = asa_patterns();
    let (src_ip, dst_ip, src_port, dst_port, proto, action) = if let Some(caps) = pat_a.captures(line) {
        (
            caps.name("src_ip")?.as_str().parse().ok()?,
            caps.name("dst_ip").and_then(|m| m.as_str().parse().ok()),
            caps.name("src_port").and_then(|m| m.as_str().parse().ok()),
            caps.name("dst_port").and_then(|m| m.as_str().parse().ok()),
            caps.name("proto").map(|m| m.as_str().to_ascii_uppercase()),
            caps.name("action").map(|m| m.as_str().to_string()).unwrap_or_else(|| "Deny".to_string()),
        )
    } else if let Some(caps) = pat_b.captures(line) {
        (
            caps.name("src_ip")?.as_str().parse().ok()?,
            caps.name("dst_ip").and_then(|m| m.as_str().parse().ok()),
            caps.name("src_port").and_then(|m| m.as_str().parse().ok()),
            caps.name("dst_port").and_then(|m| m.as_str().parse().ok()),
            None,
            if line.to_ascii_lowercase().contains("permit") { "Permit".to_string() } else { "Deny".to_string() },
        )
    } else if let Some(caps) = pat_c.captures(line) {
        (
            caps.name("src_ip")?.as_str().parse().ok()?,
            None,
            None,
            None,
            None,
            if line.to_ascii_lowercase().contains("permit") { "Permit".to_string() } else { "Deny".to_string() },
        )
    } else {
        return None;
    };

    Some(NetdevEvent {
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        proto,
        action,
        device_type: "cisco_asa",
        in_iface: None,
        raw: line.to_string(),
    })
}

pub fn parse_pf_line(line: &str) -> Option<NetdevEvent> {
    parse_pf_filterlog(line).or_else(|| parse_pf_classic(line))
}

fn parse_pf_filterlog(line: &str) -> Option<NetdevEvent> {
    let csv = if let Some(rest) = line.strip_prefix("filterlog: ") {
        rest
    } else if line.contains(",match,") || line.contains(",block,") || line.contains(",pass,") {
        line
    } else {
        return None;
    };
    let fields: Vec<&str> = csv.split(',').collect();
    if fields.len() < 20 {
        return None;
    }
    Some(NetdevEvent {
        src_ip: fields.get(18)?.trim().parse().ok()?,
        dst_ip: fields.get(19).and_then(|s| s.trim().parse().ok()),
        src_port: fields.get(20).and_then(|s| s.trim().parse().ok()),
        dst_port: fields.get(21).and_then(|s| s.trim().parse().ok()),
        proto: fields.get(16).map(|s| s.to_ascii_uppercase()),
        action: fields.get(6)?.trim().to_string(),
        device_type: "pfsense",
        in_iface: fields.get(4).map(|s| s.to_string()),
        raw: line.to_string(),
    })
}

fn parse_pf_classic(line: &str) -> Option<NetdevEvent> {
    static PAT_PF_CLASSIC: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    let pat = PAT_PF_CLASSIC.get_or_init(|| {
        Regex::new(r"(?i)rule\s+\d+[^:]*:\s+(?P<action>block|pass)\s+(?:in|out)\s+on\s+(?P<iface>\S+):\s+(?P<src>[0-9a-fA-F.:]+?)(?:\.(?P<sp>\d+))?\s*>\s*(?P<dst>[0-9a-fA-F.:]+?)(?:\.(?P<dp>\d+))?(?:\s|:|\z)").unwrap()
    });
    let caps = pat.captures(line)?;
    Some(NetdevEvent {
        src_ip: caps.name("src")?.as_str().parse().ok()?,
        dst_ip: caps.name("dst").and_then(|m| m.as_str().parse().ok()),
        src_port: caps.name("sp").and_then(|m| m.as_str().parse().ok()),
        dst_port: caps.name("dp").and_then(|m| m.as_str().parse().ok()),
        proto: None,
        action: caps.name("action").map(|m| m.as_str().to_string()).unwrap_or_else(|| "block".to_string()),
        device_type: "pfsense",
        in_iface: caps.name("iface").map(|m| m.as_str().to_string()),
        raw: line.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iptables_parser_extracts_ip() {
        let ev = parse_iptables_line("IN=eth0 OUT= SRC=1.2.3.4 DST=10.0.0.1 PROTO=TCP DPT=22").unwrap();
        assert_eq!(ev.src_ip, "1.2.3.4".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn cisco_parser_extracts_ip() {
        let ev = parse_cisco_asa_line("%ASA-2-106001: Inbound TCP connection denied from 203.0.113.5/12345 to 198.51.100.1/443 flags SYN on interface outside").unwrap();
        assert_eq!(ev.src_ip, "203.0.113.5".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn pfsense_parser_extracts_ip() {
        let ev = parse_pf_line("filterlog: 5,16,,1234567890,em0,match,block,in,4,0x0,,64,0,0,DF,6,tcp,52,1.2.3.4,10.0.0.1,45678,22,0,AS,0,0,52,0").unwrap();
        assert_eq!(ev.src_ip, "1.2.3.4".parse::<IpAddr>().unwrap());
    }
}
