use std::collections::HashMap;
use std::net::IpAddr;

use chrono::{DateTime, Utc};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

/// Normalized event from any log source.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NormalizedEvent {
    pub timestamp: DateTime<Utc>,
    pub source_ip: IpAddr,
    pub event_type: EventType,
    pub source_name: String,
    pub raw_line: String,
    pub metadata: HashMap<String, String>,
}

/// Categorized event type from log sources.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum EventType {
    AuthFailure,
    AuthSuccess,
    HttpRequest,
    Http4xx,
    Http5xx,
    SmtpAuthFailure,
    PortAccess,
    ConnectionEvent,
    Custom(String),
}

/// Detection signal — output of a detector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionSignal {
    pub source_ip: IpNet,
    pub severity: u8,
    pub confidence: f32,
    pub reason: String,
    pub evidence_hash: [u8; 32],
    pub suggested_action: Action,
    pub detector_name: String,
    pub timestamp: DateTime<Utc>,
}

/// Suggested action from a detector signal.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Action {
    Ban(std::time::Duration),
    Observe,
    Escalate,
}

/// Ban record in the store.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BanRecord {
    pub subject: IpNet,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub severity: u8,
    pub reason: String,
    pub evidence_hash: [u8; 32],
    pub source: BanSource,
    /// GeoIP enrichment data added at ban-creation time (optional).
    ///
    /// NOTE: no `skip_serializing_if` here — WAL/snapshot use postcard,
    /// a positional binary format where skipping a field on serialize
    /// makes the record unreadable on deserialize.
    #[serde(default)]
    pub geo_info: Option<GeoIpInfo>,
}

/// Origin of a ban record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum BanSource {
    LocalDetector(String),
    ClusterPeer(String),
    ManualAdmin,
}

/// GeoIP / ASN enrichment data for an IP address.
///
/// All fields are optional — they are `None` when the GeoIP databases are
/// unavailable or the IP address is not found in them.
///
/// NOTE: no `skip_serializing_if` on the fields — this struct is embedded
/// in [`BanRecord`], which round-trips through postcard (WAL/snapshot).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct GeoIpInfo {
    /// ISO 3166-1 alpha-2 country code (e.g. `"PL"`, `"US"`).
    #[serde(default)]
    pub country_iso: Option<String>,
    /// Autonomous System Number.
    #[serde(default)]
    pub asn: Option<u32>,
    /// Human-readable ASN organisation name.
    #[serde(default)]
    pub asn_org: Option<String>,
    /// `true` when the ASN belongs to a known cloud / datacenter provider.
    pub is_datacenter: bool,
}
