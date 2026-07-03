//! Parsers for network-device syslog messages — Phase 5.2.2
//!
//! Implements:
//! - **iptables / nftables** kernel log lines (`IN=… SRC=… DST=… PROTO=… DPT=…`)
//! - **Cisco ASA** deny/permit messages (`%ASA-N-NNNNNN: Deny tcp …`)
//! - **pfSense / OpenBSD pf** filterlog (CSV) and classic `rule N/M(match): …`

use std::collections::HashMap;
use std::net::IpAddr;
use std::str::FromStr;

use chrono::Utc;
use regex::Regex;

use hiveguard_core::models::{EventType, NormalizedEvent};

// ---------------------------------------------------------------------------
// Shared result type
// ---------------------------------------------------------------------------

/// Normalised representation of a network-device block/permit event.
#[derive(Debug, Clone, PartialEq)]
pub struct NetdevEvent {
    pub src_ip: IpAddr,
    pub dst_ip: Option<IpAddr>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub proto: Option<String>,
    /// "DROP", "REJECT", "block", "Deny", "pass", etc.
    pub action: String,
    /// "iptables", "nftables", "cisco_asa", "pfsense"
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
        if let Some(ref p) = self.proto {
            metadata.insert("proto".to_string(), p.clone());
        }
        if let Some(dpt) = self.dst_port {
            metadata.insert("dst_port".to_string(), dpt.to_string());
        }
        if let Some(spt) = self.src_port {
            metadata.insert("src_port".to_string(), spt.to_string());
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

// ---------------------------------------------------------------------------
// iptables / nftables
// ---------------------------------------------------------------------------
//
// Example lines:
//   kernel: [1234.56] IN=eth0 OUT= MAC=... SRC=1.2.3.4 DST=10.0.0.1 ... PROTO=TCP SPT=45678 DPT=22 ...
//   kernel: iptables-dropped: IN=eth0 SRC=1.2.3.4 DST=10.0.0.1 PROTO=UDP DPT=53
//   nftables: DROP IN=eth0 OUT= SRC=1.2.3.4 DST=10.0.0.1 PROTO=ICMP

/// Extract a key=value pair from an iptables/nftables log token stream.
fn kv<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    // Find "KEY=<value>" where value ends at whitespace or end of string.
    let needle = format!("{key}=");
    let start = line.find(needle.as_str())? + needle.len();
    let rest = &line[start..];
    let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
    let val = &rest[..end];
    if val.is_empty() { None } else { Some(val) }
}

/// Parse an iptables or nftables kernel log line.
///
/// Returns `None` if no `SRC=` field is found (not an iptables log line).
pub fn parse_iptables_line(line: &str) -> Option<NetdevEvent> {
    let src_ip: IpAddr = kv(line, "SRC")?.parse().ok()?;
    let dst_ip: Option<IpAddr> = kv(line, "DST").and_then(|s| s.parse().ok());
    let src_port: Option<u16> = kv(line, "SPT").and_then(|s| s.parse().ok());
    let dst_port: Option<u16> = kv(line, "DPT").and_then(|s| s.parse().ok());
    let proto: Option<String> = kv(line, "PROTO").map(str::to_ascii_uppercase);
    let in_iface: Option<String> = kv(line, "IN").map(String::from);

    // Infer action from common log-prefix keywords; default to DROP
    let action = if line.contains("ACCEPT") || line.contains("accept") {
        "ACCEPT"
    } else if line.contains("REJECT") || line.contains("reject") {
        "REJECT"
    } else {
        "DROP"
    };

    // Detect whether this is an nftables line
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

// ---------------------------------------------------------------------------
// Cisco ASA
// ---------------------------------------------------------------------------
//
// Example lines:
//   %ASA-4-106023: Deny tcp src outside:1.2.3.4/1234 dst inside:10.0.0.1/80 by access-group "outside" [0x0, 0x0]
//   %ASA-3-106014: Deny inbound icmp src outside:1.2.3.4 dst inside:10.0.0.1 (type 8, code 0)
//   %ASA-2-106001: Inbound TCP connection denied from 1.2.3.4/1234 to 10.0.0.1/80 flags SYN on interface outside

/// Compile ASA regex patterns once (cheap — called at most once per message).
fn asa_patterns() -> (Regex, Regex, Regex) {
    // Pattern A: "%ASA-N-NNNNNN: <Action> <proto> src <iface>:<ip>/<port> dst <iface>:<ip>/<port>"
    let pat_a = Regex::new(
        r"(?i)%ASA-\d-\d+:\s+(?P<action>\w+)\s+(?P<proto>\w+)\s+src\s+\S+:(?P<src_ip>[\d.a-fA-F:]+)(?:/(?P<src_port>\d+))?\s+dst\s+\S+:(?P<dst_ip>[\d.a-fA-F:]+)(?:/(?P<dst_port>\d+))?"
    ).unwrap();
    // Pattern B: "%ASA-N-106001: … denied from <ip>/<port> to <ip>/<port>"
    let pat_b = Regex::new(
        r"(?i)%ASA-\d-\d+:.*?(?:denied|permitted).*?from\s+(?P<src_ip>[\d.a-fA-F:]+)(?:/(?P<src_port>\d+))?\s+to\s+(?P<dst_ip>[\d.a-fA-F:]+)(?:/(?P<dst_port>\d+))?"
    ).unwrap();
    // Pattern C: generic – grab the first IPv4/IPv6 address after the colon
    let pat_c = Regex::new(
        r"(?i)%ASA-\d-\d+:.*?(?P<src_ip>(?:\d{1,3}\.){3}\d{1,3})"
    ).unwrap();
    (pat_a, pat_b, pat_c)
}

/// Parse a Cisco ASA syslog line.
///
/// Returns `None` if the line doesn't start with `%ASA-`.
pub fn parse_cisco_asa_line(line: &str) -> Option<NetdevEvent> {
    if !line.contains("%ASA-") {
        return None;
    }

    let (pat_a, pat_b, pat_c) = asa_patterns();

    // Try pattern A first (most specific)
    let (src_ip, dst_ip, src_port, dst_port, proto, action) = if let Some(caps) = pat_a.captures(line) {
        let src_ip: IpAddr = caps.name("src_ip")?.as_str().parse().ok()?;
        let dst_ip: Option<IpAddr> = caps.name("dst_ip").and_then(|m| m.as_str().parse().ok());
        let src_port: Option<u16> = caps.name("src_port").and_then(|m| m.as_str().parse().ok());
        let dst_port: Option<u16> = caps.name("dst_port").and_then(|m| m.as_str().parse().ok());
        let proto = caps.name("proto").map(|m| m.as_str().to_ascii_uppercase());
        let action = caps.name("action").map(|m| m.as_str().to_string()).unwrap_or_else(|| "Deny".to_string());
        (src_ip, dst_ip, src_port, dst_port, proto, action)
    } else if let Some(caps) = pat_b.captures(line) {
        let src_ip: IpAddr = caps.name("src_ip")?.as_str().parse().ok()?;
        let dst_ip: Option<IpAddr> = caps.name("dst_ip").and_then(|m| m.as_str().parse().ok());
        let src_port: Option<u16> = caps.name("src_port").and_then(|m| m.as_str().parse().ok());
        let dst_port: Option<u16> = caps.name("dst_port").and_then(|m| m.as_str().parse().ok());
        let action = if line.to_ascii_lowercase().contains("permit") { "Permit".to_string() } else { "Deny".to_string() };
        (src_ip, dst_ip, src_port, dst_port, None, action)
    } else if let Some(caps) = pat_c.captures(line) {
        let src_ip: IpAddr = caps.name("src_ip")?.as_str().parse().ok()?;
        let action = if line.to_ascii_lowercase().contains("permit") { "Permit".to_string() } else { "Deny".to_string() };
        (src_ip, None, None, None, None, action)
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

// ---------------------------------------------------------------------------
// pfSense / OpenBSD pf
// ---------------------------------------------------------------------------
//
// Modern pfSense filterlog CSV format (IPv4 TCP example, 19 fields before port):
//   filterlog: 5,16,,1234567890,em0,match,block,in,4,0x0,,64,0,0,DF,6,tcp,52,1.2.3.4,10.0.0.1,45678,22,0,...
//
// Field indices (0-based) for IPv4:
//   0=rule, 1=sub_rule, 2=anchor, 3=tracker, 4=iface, 5=reason, 6=action,
//   7=direction, 8=ip_ver, 9=tos, 10=ecn, 11=ttl, 12=id, 13=offset, 14=flags,
//   15=proto_id, 16=proto_name, 17=length, 18=src_ip, 19=dst_ip,
//   20=src_port, 21=dst_port, ...
//
// Classic BSD pf log (via syslog):
//   rule 100/0(match): block in on em0: 1.2.3.4.12345 > 10.0.0.1.22: Flags [S], seq 0, length 0

/// Parse a pfSense/OpenBSD pf log line (filterlog CSV or classic format).
///
/// Returns `None` if the line cannot be identified as a pf log entry.
pub fn parse_pf_line(line: &str) -> Option<NetdevEvent> {
    // Try CSV filterlog format first
    if let Some(ev) = parse_pf_filterlog(line) {
        return Some(ev);
    }
    // Fall back to classic BSD pf log format
    parse_pf_classic(line)
}

fn parse_pf_filterlog(line: &str) -> Option<NetdevEvent> {
    // Strip optional "filterlog: " prefix
    let csv = if let Some(rest) = line.strip_prefix("filterlog: ") {
        rest
    } else if line.contains(",match,") || line.contains(",block,") || line.contains(",pass,") {
        line
    } else {
        return None;
    };

    let fields: Vec<&str> = csv.split(',').collect();
    // Minimum 20 fields required for IPv4
    if fields.len() < 20 {
        return None;
    }

    let action = fields.get(6)?.trim().to_string();
    let in_iface = fields.get(4).map(|s| s.to_string());
    let proto = fields.get(16).map(|s| s.to_ascii_uppercase());

    // IPv4: src=18, dst=19; TCP/UDP ports: 20=src, 21=dst
    let src_ip: IpAddr = fields.get(18)?.trim().parse().ok()?;
    let dst_ip: Option<IpAddr> = fields.get(19).and_then(|s| s.trim().parse().ok());
    let src_port: Option<u16> = fields.get(20).and_then(|s| s.trim().parse().ok());
    let dst_port: Option<u16> = fields.get(21).and_then(|s| s.trim().parse().ok());

    Some(NetdevEvent {
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        proto,
        action,
        device_type: "pfsense",
        in_iface,
        raw: line.to_string(),
    })
}

fn parse_pf_classic(line: &str) -> Option<NetdevEvent> {
    // Pattern: "rule N/M(match): block|pass in|out on <iface>: <src_ip>.<src_port> > <dst_ip>.<dst_port>"
    // or:      "rule N/M(match): block in on em0: 1.2.3.4 > 10.0.0.1"
    static PAT_PF_CLASSIC: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    let pat = PAT_PF_CLASSIC.get_or_init(|| {
        Regex::new(
            r"(?i)rule\s+\d+[^:]*:\s+(?P<action>block|pass)\s+(?:in|out)\s+on\s+(?P<iface>\S+):\s+(?P<src>[0-9a-fA-F.:]+?)(?:\.(?P<sp>\d+))?\s*>\s*(?P<dst>[0-9a-fA-F.:]+?)(?:\.(?P<dp>\d+))?(?:\s|:|\z)"
        ).unwrap()
    });

    let caps = pat.captures(line)?;
    let src_ip: IpAddr = caps.name("src")?.as_str().parse().ok()?;
    let dst_ip: Option<IpAddr> = caps.name("dst").and_then(|m| m.as_str().parse().ok());
    let src_port: Option<u16> = caps.name("sp").and_then(|m| m.as_str().parse().ok());
    let dst_port: Option<u16> = caps.name("dp").and_then(|m| m.as_str().parse().ok());
    let action = caps.name("action").map(|m| m.as_str().to_string()).unwrap_or_else(|| "block".to_string());
    let in_iface = caps.name("iface").map(|m| m.as_str().to_string());

    Some(NetdevEvent {
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        proto: None,
        action,
        device_type: "pfsense",
        in_iface,
        raw: line.to_string(),
    })
}

// (OnceLock-based regex helpers are inlined per function; no macro needed)

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- iptables ---

    #[test]
    fn iptables_tcp_drop() {
        let line = "IN=eth0 OUT= MAC=aa:bb:cc:dd:ee:ff:11:22:33:44:55:66:08:00 SRC=1.2.3.4 DST=10.0.0.1 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=0 DF PROTO=TCP SPT=55000 DPT=22 WINDOW=29200 RES=0x00 SYN URGP=0";
        let ev = parse_iptables_line(line).expect("should parse");
        assert_eq!(ev.src_ip, "1.2.3.4".parse::<IpAddr>().unwrap());
        assert_eq!(ev.dst_ip, Some("10.0.0.1".parse().unwrap()));
        assert_eq!(ev.src_port, Some(55000));
        assert_eq!(ev.dst_port, Some(22));
        assert_eq!(ev.proto, Some("TCP".to_string()));
        assert_eq!(ev.action, "DROP");
        assert_eq!(ev.device_type, "iptables");
    }

    #[test]
    fn iptables_udp_no_ports() {
        // Minimal line without SPT/DPT
        let line = "IN=eth0 OUT= SRC=5.6.7.8 DST=192.168.1.1 PROTO=UDP";
        let ev = parse_iptables_line(line).expect("should parse");
        assert_eq!(ev.src_ip, "5.6.7.8".parse::<IpAddr>().unwrap());
        assert_eq!(ev.dst_port, None);
        assert_eq!(ev.proto, Some("UDP".to_string()));
    }

    #[test]
    fn nftables_line_detected() {
        let line = "nftables: DROP IN=eth0 OUT= SRC=9.9.9.9 DST=10.10.10.10 PROTO=ICMP";
        let ev = parse_iptables_line(line).expect("should parse");
        assert_eq!(ev.device_type, "nftables");
        assert_eq!(ev.action, "DROP");
    }

    #[test]
    fn iptables_no_src_returns_none() {
        let line = "IN=eth0 OUT= PROTO=TCP DPT=22";
        assert!(parse_iptables_line(line).is_none());
    }

    // --- Cisco ASA ---

    #[test]
    fn cisco_asa_106023_deny() {
        let line = r#"%ASA-4-106023: Deny tcp src outside:1.2.3.4/54321 dst inside:10.0.0.1/80 by access-group "outside" [0x0, 0x0]"#;
        let ev = parse_cisco_asa_line(line).expect("should parse");
        assert_eq!(ev.src_ip, "1.2.3.4".parse::<IpAddr>().unwrap());
        assert_eq!(ev.dst_ip, Some("10.0.0.1".parse().unwrap()));
        assert_eq!(ev.src_port, Some(54321));
        assert_eq!(ev.dst_port, Some(80));
        assert_eq!(ev.action, "Deny");
        assert_eq!(ev.proto, Some("TCP".to_string()));
        assert_eq!(ev.device_type, "cisco_asa");
    }

    #[test]
    fn cisco_asa_106001_denied_from() {
        let line = "%ASA-2-106001: Inbound TCP connection denied from 203.0.113.5/12345 to 198.51.100.1/443 flags SYN on interface outside";
        let ev = parse_cisco_asa_line(line).expect("should parse");
        assert_eq!(ev.src_ip, "203.0.113.5".parse::<IpAddr>().unwrap());
        assert_eq!(ev.dst_port, Some(443));
        assert_eq!(ev.action, "Deny");
    }

    #[test]
    fn cisco_asa_no_prefix_returns_none() {
        let line = "Deny tcp src outside:1.2.3.4/54321";
        assert!(parse_cisco_asa_line(line).is_none());
    }

    // --- pfSense filterlog ---

    #[test]
    fn pfsense_filterlog_csv() {
        // Simplified 22-field filterlog line (IPv4 TCP)
        let line = "filterlog: 5,16,,1234567890,em0,match,block,in,4,0x0,,64,0,0,DF,6,tcp,52,1.2.3.4,10.0.0.1,45678,22,0,AS,0,0,52,0";
        let ev = parse_pf_line(line).expect("should parse");
        assert_eq!(ev.src_ip, "1.2.3.4".parse::<IpAddr>().unwrap());
        assert_eq!(ev.dst_ip, Some("10.0.0.1".parse().unwrap()));
        assert_eq!(ev.src_port, Some(45678));
        assert_eq!(ev.dst_port, Some(22));
        assert_eq!(ev.action, "block");
        assert_eq!(ev.device_type, "pfsense");
        assert_eq!(ev.proto, Some("TCP".to_string()));
    }

    #[test]
    fn pfsense_classic_format() {
        let line = "rule 100/0(match): block in on em0: 1.2.3.4.12345 > 10.0.0.1.22: Flags [S], seq 0, length 0";
        let ev = parse_pf_line(line).expect("should parse");
        assert_eq!(ev.src_ip, "1.2.3.4".parse::<IpAddr>().unwrap());
        assert_eq!(ev.src_port, Some(12345));
        assert_eq!(ev.dst_port, Some(22));
        assert_eq!(ev.action, "block");
        assert_eq!(ev.in_iface, Some("em0".to_string()));
    }

    #[test]
    fn pfsense_unknown_format_returns_none() {
        assert!(parse_pf_line("random syslog line with no pf markers").is_none());
    }

    // --- to_normalized ---

    #[test]
    fn to_normalized_sets_metadata() {
        let line = "IN=eth0 OUT= SRC=1.1.1.1 DST=2.2.2.2 PROTO=TCP DPT=80";
        let ev = parse_iptables_line(line).unwrap();
        let normalized = ev.to_normalized("test_source");
        assert_eq!(normalized.source_ip, "1.1.1.1".parse::<IpAddr>().unwrap());
        assert_eq!(normalized.metadata.get("action").map(String::as_str), Some("DROP"));
        assert_eq!(normalized.metadata.get("device_type").map(String::as_str), Some("iptables"));
        assert_eq!(normalized.metadata.get("dst_port").map(String::as_str), Some("80"));
    }
}
