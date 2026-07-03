//! SIEM Export — Phase 3.1
//!
//! Provides serialization of HiveGuard ban and detection events into
//! industry-standard SIEM formats and delivers them over syslog.
//!
//! # Supported formats
//!
//! - **CEF** (ArcSight Common Event Format v0.1) — task 3.1.1
//! - **LEEF** (IBM QRadar Log Event Extended Format 2.0) — task 3.1.2
//!
//! # Delivery
//!
//! `SiemSyslogExporter` (task 3.1.3) wraps formatted strings in RFC 5424
//! syslog frames and delivers them over:
//!
//! - **TCP** — with octet-counting framing (RFC 6587)
//! - **UDP** — fire-and-forget
//!
//! # Prometheus metrics
//!
//! - `hiveguard_siem_exported_total{exporter}`
//! - `hiveguard_siem_export_errors_total{exporter}`
//! - `hiveguard_siem_buffer_size_bytes`

use std::fmt::Write as _;
use std::io::Write;
use std::net::{TcpStream, UdpSocket};
use std::time::Duration;

use chrono::Utc;
use tracing::{debug, error, warn};

use hiveguard_core::config::{SiemFormat, SiemProtocol, SiemSyslogConfig};
use hiveguard_core::models::{BanRecord, BanSource, DetectionSignal};

use crate::metrics::{SharedMetrics, SiemLabels};

// ---------------------------------------------------------------------------
// Shared SIEM event type
// ---------------------------------------------------------------------------

/// Normalised SIEM event — holds the fields needed by CEF and LEEF formatters.
/// Created from either a `BanRecord` or a `DetectionSignal`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SiemEvent {
    /// Source IP (subject of the ban / signal).
    pub src_ip: String,
    /// Human-readable reason / description.
    pub reason: String,
    /// Raw severity (0–255 HiveGuard scale).
    pub severity: u8,
    /// Name of the detector or `"ManualAdmin"` / `"ClusterPeer"`.
    pub detector: String,
    /// Ban duration as a human-readable string, e.g. `"24h"` or `"permanent"`.
    pub ban_duration: String,
    /// Optional ISO 3166-1 alpha-2 country code.
    pub country: Option<String>,
    /// Optional ASN number.
    pub asn: Option<u32>,
    /// Event variant name used as CEF `eventClassId` / LEEF event id.
    pub event_class: String,
    /// RFC 3339 timestamp of the event.
    pub timestamp: String,
}

impl SiemEvent {
    /// Build a `SiemEvent` from a `BanRecord`.
    pub fn from_ban(record: &BanRecord) -> Self {
        let detector = match &record.source {
            BanSource::LocalDetector(name) => name.clone(),
            BanSource::ClusterPeer(node) => format!("ClusterPeer:{node}"),
            BanSource::ManualAdmin => "ManualAdmin".to_string(),
        };

        let ban_duration = match record.expires_at {
            None => "permanent".to_string(),
            Some(expires) => {
                let secs = (expires - record.created_at).num_seconds().max(0) as u64;
                if secs % 86_400 == 0 && secs > 0 {
                    format!("{}d", secs / 86_400)
                } else if secs % 3_600 == 0 && secs > 0 {
                    format!("{}h", secs / 3_600)
                } else if secs % 60 == 0 && secs > 0 {
                    format!("{}m", secs / 60)
                } else {
                    format!("{secs}s")
                }
            }
        };

        let (country, asn) = match &record.geo_info {
            Some(g) => (g.country_iso.clone(), g.asn),
            None => (None, None),
        };

        Self {
            src_ip: record.subject.addr().to_string(),
            reason: record.reason.clone(),
            severity: record.severity,
            detector,
            ban_duration,
            country,
            asn,
            event_class: "BanTriggered".to_string(),
            timestamp: record.created_at.to_rfc3339(),
        }
    }

    /// Build a `SiemEvent` from a `DetectionSignal`.
    pub fn from_signal(signal: &DetectionSignal) -> Self {
        Self {
            src_ip: signal.source_ip.addr().to_string(),
            reason: signal.reason.clone(),
            severity: signal.severity,
            detector: signal.detector_name.clone(),
            ban_duration: String::new(),
            country: None,
            asn: None,
            event_class: "DetectionSignal".to_string(),
            timestamp: signal.timestamp.to_rfc3339(),
        }
    }
}

// ---------------------------------------------------------------------------
// 3.1.1 — CEF serializer
// ---------------------------------------------------------------------------

/// Escape special CEF characters in header fields (`|` and `\`).
fn cef_escape_header(s: &str) -> String {
    s.replace('\\', "\\\\").replace('|', "\\|")
}

/// Escape special CEF characters in extension values (`=`, `\`, and newlines).
fn cef_escape_ext(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('=', "\\=")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

/// Map a HiveGuard severity (0–255) to a CEF severity (0–10).
fn severity_to_cef(s: u8) -> u8 {
    (s as u16 * 10 / 255).min(10) as u8
}

/// Serialise a `SiemEvent` as an ArcSight CEF v0.1 string.
///
/// Output format:
/// ```text
/// CEF:0|HiveGuard|hiveguard-daemon|{version}|{event_class}|{reason}|{cef_severity}|src={ip} cs1={ban_dur} cs1Label=BanDuration cn1={severity} cn1Label=Severity msg={reason} [cs2={country} cs2Label=Country cn2={asn} cn2Label=ASN]
/// ```
pub fn format_cef(event: &SiemEvent) -> String {
    let version = env!("CARGO_PKG_VERSION");
    let cef_sev = severity_to_cef(event.severity);

    let mut ext = String::new();
    let _ = write!(ext, "src={}", cef_escape_ext(&event.src_ip));
    let _ = write!(ext, " rt={}", cef_escape_ext(&event.timestamp));

    if !event.ban_duration.is_empty() {
        let _ = write!(ext, " cs1={}", cef_escape_ext(&event.ban_duration));
        ext.push_str(" cs1Label=BanDuration");
    }

    let _ = write!(ext, " cn1={}", event.severity);
    ext.push_str(" cn1Label=Severity");
    let _ = write!(ext, " msg={}", cef_escape_ext(&event.reason));
    let _ = write!(ext, " deviceExternalId={}", cef_escape_ext(&event.detector));

    if let Some(ref country) = event.country {
        let _ = write!(ext, " cs2={}", cef_escape_ext(country));
        ext.push_str(" cs2Label=Country");
    }
    if let Some(asn) = event.asn {
        let _ = write!(ext, " cn2={asn}");
        ext.push_str(" cn2Label=ASN");
    }

    format!(
        "CEF:0|HiveGuard|hiveguard-daemon|{version}|{event_class}|{name}|{cef_sev}|{ext}",
        version = cef_escape_header(version),
        event_class = cef_escape_header(&event.event_class),
        name = cef_escape_header(&event.reason),
        cef_sev = cef_sev,
        ext = ext,
    )
}

// ---------------------------------------------------------------------------
// 3.1.2 — LEEF serializer
// ---------------------------------------------------------------------------

/// Escape LEEF extension value (backslash and the separator character).
fn leef_escape_value(s: &str, sep: &str) -> String {
    // Escape backslash first, then the separator
    let s = s.replace('\\', "\\\\");
    if sep.len() == 1 {
        let c = sep.chars().next().unwrap();
        s.replace(c, &format!("\\{c}"))
    } else {
        s.replace(sep, &format!("\\{sep}"))
    }
}

/// Serialise a `SiemEvent` as an IBM QRadar LEEF 2.0 string.
///
/// Output format:
/// ```text
/// LEEF:2.0|HiveGuard|hiveguard-daemon|{version}|{event_class}|{sep}src={ip}{sep}severity={sev}{sep}cat={detector}{sep}devTime={ts}{sep}msg={reason}[{sep}cs1={ban_dur}{sep}cs2={country}{sep}cn1={asn}]
/// ```
pub fn format_leef(event: &SiemEvent, separator: &str) -> String {
    let version = env!("CARGO_PKG_VERSION");
    let sep = separator;

    let mut fields = String::new();
    let _ = write!(fields, "{sep}src={}", leef_escape_value(&event.src_ip, sep));
    let _ = write!(
        fields,
        "{sep}severity={}",
        leef_escape_value(&event.severity.to_string(), sep)
    );
    let _ = write!(
        fields,
        "{sep}cat={}",
        leef_escape_value(&event.detector, sep)
    );
    let _ = write!(
        fields,
        "{sep}devTime={}",
        leef_escape_value(&event.timestamp, sep)
    );
    let _ = write!(
        fields,
        "{sep}msg={}",
        leef_escape_value(&event.reason, sep)
    );

    if !event.ban_duration.is_empty() {
        let _ = write!(
            fields,
            "{sep}cs1={}",
            leef_escape_value(&event.ban_duration, sep)
        );
        let _ = write!(fields, "{sep}cs1Label=BanDuration");
    }

    if let Some(ref country) = event.country {
        let _ = write!(
            fields,
            "{sep}cs2={}",
            leef_escape_value(country, sep)
        );
        let _ = write!(fields, "{sep}cs2Label=Country");
    }

    if let Some(asn) = event.asn {
        let _ = write!(fields, "{sep}cn1={asn}");
        let _ = write!(fields, "{sep}cn1Label=ASN");
    }

    format!(
        "LEEF:2.0|HiveGuard|hiveguard-daemon|{version}|{event_class}|{fields}",
        version = version,
        event_class = &event.event_class,
        fields = fields,
    )
}

// ---------------------------------------------------------------------------
// 3.1.3 — Syslog TCP/UDP exporter
// ---------------------------------------------------------------------------

/// RFC 5424 syslog facility: LOCAL0 (16).
const SYSLOG_FACILITY_LOCAL0: u8 = 16;
/// RFC 5424 syslog severity: INFO (6).
const SYSLOG_SEVERITY_INFO: u8 = 6;
/// RFC 5424 PRI value for LOCAL0 + INFO.
const SYSLOG_PRI: u8 = SYSLOG_FACILITY_LOCAL0 * 8 + SYSLOG_SEVERITY_INFO;

/// Obtain the local hostname without any external crate.
/// Falls back to reading `/proc/sys/kernel/hostname` (Linux) then to `"-"`.
fn local_hostname() -> String {
    // Try the kernel hostname file (Linux)
    if let Ok(h) = std::fs::read_to_string("/proc/sys/kernel/hostname") {
        let trimmed = h.trim().to_string();
        if !trimmed.is_empty() {
            return trimmed;
        }
    }
    // Fall back to NILVALUE
    "-".to_string()
}

/// Build an RFC 5424 syslog frame for a CEF/LEEF payload.
///
/// Format: `<PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID - MSG\n`
fn build_syslog_frame(payload: &str) -> Vec<u8> {
    let timestamp = Utc::now().to_rfc3339();
    let hostname = local_hostname();

    let syslog_msg = format!(
        "<{pri}>1 {ts} {host} hiveguard-daemon - - - {payload}\n",
        pri = SYSLOG_PRI,
        ts = timestamp,
        host = hostname,
        payload = payload,
    );
    syslog_msg.into_bytes()
}

/// Wrap a raw syslog message with octet-count framing (RFC 6587 §3.4.1).
///
/// Format: `{LEN} {MSG}` where LEN is the byte length of MSG (including the
/// trailing newline).
fn octet_count_frame(raw: &[u8]) -> Vec<u8> {
    let mut framed = format!("{} ", raw.len()).into_bytes();
    framed.extend_from_slice(raw);
    framed
}

/// SIEM exporter that delivers formatted events over TCP or UDP syslog.
pub struct SiemSyslogExporter {
    config: SiemSyslogConfig,
    /// Persisted TCP connection (reconnected on error).
    tcp_conn: Option<TcpStream>,
    metrics: Option<SharedMetrics>,
}

impl SiemSyslogExporter {
    /// Create a new exporter from the given configuration.
    pub fn new(config: SiemSyslogConfig) -> Self {
        Self {
            config,
            tcp_conn: None,
            metrics: None,
        }
    }

    /// Attach a metrics handle for observability.
    pub fn with_metrics(mut self, metrics: SharedMetrics) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Format a `SiemEvent` according to the configured format.
    fn format_event(&self, event: &SiemEvent) -> String {
        match self.config.format {
            SiemFormat::Cef => format_cef(event),
            SiemFormat::Leef => format_leef(event, &self.config.leef_separator),
        }
    }

    /// Export a single `SiemEvent`.  Errors are logged; the caller is not
    /// expected to retry — the caller-level ring buffer handles retries.
    pub fn export(&mut self, event: &SiemEvent) {
        let payload = self.format_event(event);
        let result = match self.config.protocol {
            SiemProtocol::Tcp => self.send_tcp(&payload),
            SiemProtocol::Udp => self.send_udp(&payload),
        };

        let labels = SiemLabels {
            exporter: "syslog".to_string(),
        };

        if let Some(ref m) = self.metrics {
            match result {
                Ok(()) => {
                    m.siem_exported_total.get_or_create(&labels).inc();
                }
                Err(ref e) => {
                    m.siem_export_errors_total.get_or_create(&labels).inc();
                    error!(host = %self.config.host, error = %e, "SIEM export failed");
                }
            }
        } else if let Err(ref e) = result {
            error!(host = %self.config.host, error = %e, "SIEM export failed");
        }
    }

    /// Send payload over TCP with octet-count framing (RFC 6587).
    fn send_tcp(&mut self, payload: &str) -> Result<(), String> {
        let raw = build_syslog_frame(payload);
        let framed = octet_count_frame(&raw);

        // Attempt to reuse existing connection; reconnect on failure.
        if let Some(ref mut conn) = self.tcp_conn {
            if conn.write_all(&framed).is_ok() {
                debug!(host = %self.config.host, "SIEM TCP send ok ({} bytes)", framed.len());
                return Ok(());
            }
            warn!(host = %self.config.host, "SIEM TCP write failed, reconnecting");
            self.tcp_conn = None;
        }

        // Establish new connection.
        let conn = TcpStream::connect(&self.config.host)
            .map_err(|e| format!("TCP connect to {}: {e}", self.config.host))?;
        conn.set_write_timeout(Some(Duration::from_secs(5)))
            .ok();
        let mut conn = conn;
        conn.write_all(&framed)
            .map_err(|e| format!("TCP write: {e}"))?;
        debug!(host = %self.config.host, "SIEM TCP send ok ({} bytes)", framed.len());
        self.tcp_conn = Some(conn);
        Ok(())
    }

    /// Send payload over UDP (fire-and-forget, no framing).
    fn send_udp(&self, payload: &str) -> Result<(), String> {
        let raw = build_syslog_frame(payload);
        let socket = UdpSocket::bind("0.0.0.0:0")
            .map_err(|e| format!("UDP bind: {e}"))?;
        socket.set_write_timeout(Some(Duration::from_secs(3))).ok();
        socket
            .send_to(&raw, &self.config.host)
            .map_err(|e| format!("UDP send_to {}: {e}", self.config.host))?;
        debug!(host = %self.config.host, "SIEM UDP send ok ({} bytes)", raw.len());
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn sample_event() -> SiemEvent {
        SiemEvent {
            src_ip: "1.2.3.4".to_string(),
            reason: "SSH Brute-force".to_string(),
            severity: 80,
            detector: "ssh_bruteforce".to_string(),
            ban_duration: "24h".to_string(),
            country: Some("PL".to_string()),
            asn: Some(5617),
            event_class: "BanTriggered".to_string(),
            timestamp: "2026-01-15T10:00:00+00:00".to_string(),
        }
    }

    // --- CEF ---

    #[test]
    fn cef_contains_required_fields() {
        let event = sample_event();
        let cef = format_cef(&event);

        assert!(cef.starts_with("CEF:0|HiveGuard|hiveguard-daemon|"));
        assert!(cef.contains("|BanTriggered|"));
        assert!(cef.contains("src=1.2.3.4"));
        assert!(cef.contains("cn1=80"));
        assert!(cef.contains("cn1Label=Severity"));
        assert!(cef.contains("cs1=24h"));
        assert!(cef.contains("cs1Label=BanDuration"));
        assert!(cef.contains("cs2=PL"));
        assert!(cef.contains("cs2Label=Country"));
        assert!(cef.contains("cn2=5617"));
    }

    #[test]
    fn cef_severity_mapping() {
        // severity 255 → CEF 10
        assert_eq!(severity_to_cef(255), 10);
        // severity 0 → CEF 0
        assert_eq!(severity_to_cef(0), 0);
        // severity 128 → CEF 5
        assert_eq!(severity_to_cef(128), 5);
    }

    #[test]
    fn cef_escapes_pipe_in_header() {
        let mut event = sample_event();
        event.reason = "Attack|test=foo".to_string();
        let cef = format_cef(&event);
        // Header field (name) should have pipe escaped
        assert!(cef.contains("Attack\\|test"));
    }

    #[test]
    fn cef_escapes_equals_in_extension() {
        let mut event = sample_event();
        event.reason = "payload=evil".to_string();
        let cef = format_cef(&event);
        // Extension field value should have = escaped
        assert!(cef.contains("msg=payload\\=evil"));
    }

    #[test]
    fn cef_no_ban_duration_for_signal() {
        let mut event = sample_event();
        event.ban_duration = String::new();
        let cef = format_cef(&event);
        assert!(!cef.contains("cs1Label=BanDuration"));
    }

    // --- LEEF ---

    #[test]
    fn leef_contains_required_fields() {
        let event = sample_event();
        let leef = format_leef(&event, "^");

        assert!(leef.starts_with("LEEF:2.0|HiveGuard|hiveguard-daemon|"));
        assert!(leef.contains("|BanTriggered|"));
        assert!(leef.contains("^src=1.2.3.4"));
        assert!(leef.contains("^severity=80"));
        assert!(leef.contains("^cat=ssh_bruteforce"));
        assert!(leef.contains("^msg=SSH Brute-force"));
        assert!(leef.contains("^cs1=24h"));
        assert!(leef.contains("^cs1Label=BanDuration"));
        assert!(leef.contains("^cs2=PL"));
        assert!(leef.contains("^cn1=5617"));
    }

    #[test]
    fn leef_tab_separator() {
        let event = sample_event();
        let leef = format_leef(&event, "\t");
        assert!(leef.contains("\tsrc=1.2.3.4"));
        assert!(leef.contains("\tseverity=80"));
    }

    #[test]
    fn leef_escapes_separator_in_value() {
        let mut event = sample_event();
        event.reason = "test^value".to_string();
        let leef = format_leef(&event, "^");
        assert!(leef.contains("msg=test\\^value"));
    }

    // --- Syslog framing ---

    #[test]
    fn octet_count_frame_format() {
        let msg = b"hello\n";
        let framed = octet_count_frame(msg);
        // Should start with "{len} " prefix
        let prefix = format!("{} ", msg.len());
        assert!(framed.starts_with(prefix.as_bytes()));
        assert_eq!(&framed[prefix.len()..], msg);
    }

    #[test]
    fn syslog_frame_contains_pri_and_version() {
        let frame = build_syslog_frame("test payload");
        let s = String::from_utf8(frame).unwrap();
        // PRI = 134 (LOCAL0*8 + INFO = 128+6)
        assert!(s.starts_with("<134>1 "));
        assert!(s.contains("hiveguard-daemon"));
        assert!(s.contains("test payload"));
    }

    // --- SiemEvent construction ---

    #[test]
    fn siem_event_from_ban_record() {
        use hiveguard_core::models::{BanRecord, BanSource};
        use ipnet::IpNet;

        let now = Utc.with_ymd_and_hms(2026, 1, 15, 10, 0, 0).unwrap();
        let expires = Utc.with_ymd_and_hms(2026, 1, 16, 10, 0, 0).unwrap(); // +24h

        let record = BanRecord {
            subject: "1.2.3.4/32".parse::<IpNet>().unwrap(),
            created_at: now,
            expires_at: Some(expires),
            severity: 90,
            reason: "SSH brute-force".to_string(),
            evidence_hash: [0u8; 32],
            source: BanSource::LocalDetector("ssh_bruteforce".to_string()),
            geo_info: None,
        };

        let event = SiemEvent::from_ban(&record);
        assert_eq!(event.src_ip, "1.2.3.4");
        assert_eq!(event.ban_duration, "1d");
        assert_eq!(event.severity, 90);
        assert_eq!(event.detector, "ssh_bruteforce");
        assert_eq!(event.event_class, "BanTriggered");
    }

    #[test]
    fn siem_event_permanent_ban() {
        use hiveguard_core::models::{BanRecord, BanSource};
        use ipnet::IpNet;

        let now = Utc::now();
        let record = BanRecord {
            subject: "10.0.0.1/32".parse::<IpNet>().unwrap(),
            created_at: now,
            expires_at: None,
            severity: 250,
            reason: "Honeypot hit".to_string(),
            evidence_hash: [0u8; 32],
            source: BanSource::ManualAdmin,
            geo_info: None,
        };

        let event = SiemEvent::from_ban(&record);
        assert_eq!(event.ban_duration, "permanent");
        assert_eq!(event.detector, "ManualAdmin");
    }
}
