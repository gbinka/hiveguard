//! Field mapping layer for Sigma rules.
//!
//! Sigma rules use their own field vocabulary (e.g. `SourceAddress`,
//! `cs-uri-stem`, `CommandLine`, `EventID`).  This module maps those names
//! to the internal accessors used by `NormalizedEvent`:
//!
//! - Reserved accessors: `"source_ip"`, `"raw_line"`, `"source_name"`,
//!   `"event_type"`, `"timestamp"`.
//! - Everything else is looked up in `event.metadata` by exact key first, then
//!   lower-cased key as a fallback.
//!
//! An administrator can supply additional mappings via `sigma_fieldmap.yaml`:
//! ```yaml
//! SourceAddress: source_ip
//! cs-uri-stem: http_path
//! CommandLine: command
//! EventID: event_id
//! ```

use std::collections::HashMap;

use hiveguard_core::models::NormalizedEvent;

// ---------------------------------------------------------------------------
// Default field map
// ---------------------------------------------------------------------------

/// Build the default Sigma-field → internal-accessor map.
fn default_field_map() -> HashMap<String, String> {
    // (sigma_field, internal_accessor)
    let entries: &[(&str, &str)] = &[
        // ── IP address ────────────────────────────────────────────────────
        ("SourceAddress", "source_ip"),
        ("src_ip", "source_ip"),
        ("c-ip", "source_ip"),
        ("SrcIP", "source_ip"),
        ("srcip", "source_ip"),
        ("sourceip", "source_ip"),
        ("SourceIp", "source_ip"),
        ("src", "source_ip"),
        ("c_ip", "source_ip"),
        ("src-ip", "source_ip"),
        ("ClientIP", "source_ip"),
        ("ipaddr", "source_ip"),
        ("IpAddress", "source_ip"),
        ("IpAddr", "source_ip"),
        ("RemoteAddress", "source_ip"),
        ("client_ip", "source_ip"),
        // ── Raw log ───────────────────────────────────────────────────────
        ("EventLog", "raw_line"),
        ("Message", "raw_line"),
        ("LogEntry", "raw_line"),
        ("raw", "raw_line"),
        ("msg", "raw_line"),
        ("message", "raw_line"),
        // ── HTTP path ─────────────────────────────────────────────────────
        ("cs-uri-stem", "http_path"),
        ("cs-uri", "http_path"),
        ("RequestUri", "http_path"),
        ("request_uri", "http_path"),
        ("uri_path", "http_path"),
        ("http_path", "http_path"),
        ("URL", "http_path"),
        ("url", "http_path"),
        ("Url", "http_path"),
        // ── HTTP method ───────────────────────────────────────────────────
        ("cs-method", "http_method"),
        ("http_method", "http_method"),
        ("RequestMethod", "http_method"),
        ("Method", "http_method"),
        // ── HTTP status ───────────────────────────────────────────────────
        ("sc-status", "http_status"),
        ("status_code", "http_status"),
        ("http_status", "http_status"),
        ("StatusCode", "http_status"),
        ("status", "http_status"),
        // ── User-Agent ────────────────────────────────────────────────────
        ("UserAgent", "user_agent"),
        ("user_agent", "user_agent"),
        ("cs(User-Agent)", "user_agent"),
        ("HttpUserAgent", "user_agent"),
        ("ua", "user_agent"),
        // ── Username ──────────────────────────────────────────────────────
        ("Username", "user"),
        ("TargetUserName", "user"),
        ("user", "user"),
        ("User", "user"),
        ("LogonUser", "user"),
        ("AccountName", "user"),
        ("SubjectUserName", "user"),
        ("account", "user"),
        // ── Command line ──────────────────────────────────────────────────
        ("CommandLine", "command"),
        ("command", "command"),
        ("cmd", "command"),
        ("ProcessCommand", "command"),
        // ── Event ID ──────────────────────────────────────────────────────
        ("EventID", "event_id"),
        ("eventid", "event_id"),
        ("event_id", "event_id"),
        // ── Destination port ──────────────────────────────────────────────
        ("DestinationPort", "dst_port"),
        ("dst_port", "dst_port"),
        ("dpt", "dst_port"),
        ("DestPort", "dst_port"),
        ("dest_port", "dst_port"),
        // ── Source port ───────────────────────────────────────────────────
        ("SourcePort", "src_port"),
        ("src_port", "src_port"),
        ("spt", "src_port"),
        // ── Destination IP ────────────────────────────────────────────────
        ("DestAddress", "dst_ip"),
        ("dst_ip", "dst_ip"),
        ("DestinationAddress", "dst_ip"),
        ("dhost", "dst_ip"),
        // ── Protocol ──────────────────────────────────────────────────────
        ("Protocol", "protocol"),
        ("proto", "protocol"),
        // ── Process ───────────────────────────────────────────────────────
        ("ProcessName", "process"),
        ("Image", "process"),
        ("process", "process"),
        // ── Hostname ──────────────────────────────────────────────────────
        ("Hostname", "hostname"),
        ("hostname", "hostname"),
        ("dhost", "hostname"),
        ("ComputerName", "hostname"),
        // ── Logon type ────────────────────────────────────────────────────
        ("LogonType", "logon_type"),
    ];

    entries
        .iter()
        .map(|&(k, v)| (k.to_lowercase(), v.to_string()))
        .collect()
}

// ---------------------------------------------------------------------------
// FieldMapper
// ---------------------------------------------------------------------------

/// Maps Sigma field names to `NormalizedEvent` field values.
#[derive(Debug, Clone)]
pub struct FieldMapper {
    /// Sigma field name (lower-cased) → internal accessor key.
    map: HashMap<String, String>,
}

impl Default for FieldMapper {
    fn default() -> Self {
        Self::new()
    }
}

impl FieldMapper {
    /// Create a mapper with the built-in default mappings.
    pub fn new() -> Self {
        FieldMapper {
            map: default_field_map(),
        }
    }

    /// Create from an explicit mapping (e.g. loaded from `sigma_fieldmap.yaml`).
    /// Built-in defaults are still included; explicit entries take precedence.
    pub fn with_extra_mappings(mut self, extra: HashMap<String, String>) -> Self {
        for (k, v) in extra {
            self.map.insert(k.to_lowercase(), v);
        }
        self
    }

    /// Load additional mappings from YAML text.
    ///
    /// The YAML must be a flat mapping of `sigma_field: internal_key`.
    pub fn load_yaml(&mut self, yaml_text: &str) -> crate::error::Result<()> {
        let extra: HashMap<String, String> = serde_yaml::from_str(yaml_text)?;
        for (k, v) in extra {
            self.map.insert(k.to_lowercase(), v);
        }
        Ok(())
    }

    /// Retrieve the value of a Sigma field from a `NormalizedEvent`.
    ///
    /// Returns `None` if the field cannot be resolved.
    pub fn get_field(&self, event: &NormalizedEvent, sigma_field: &str) -> Option<String> {
        // Resolve the internal accessor (lowercase lookup, fallback to sigma_field itself).
        let internal_key: &str = self
            .map
            .get(&sigma_field.to_lowercase())
            .map(|s| s.as_str())
            .unwrap_or(sigma_field);

        match internal_key {
            "source_ip" => Some(event.source_ip.to_string()),
            "raw_line" => Some(event.raw_line.clone()),
            "source_name" => Some(event.source_name.clone()),
            "event_type" => Some(format!("{:?}", event.event_type)),
            "timestamp" => Some(event.timestamp.to_rfc3339()),
            key => {
                // Metadata lookup: exact key first, then lower-cased key.
                event
                    .metadata
                    .get(key)
                    .or_else(|| event.metadata.get(&key.to_lowercase()))
                    .cloned()
            }
        }
    }

    /// Return a reference to the underlying mapping for inspection or serialization.
    pub fn mappings(&self) -> &HashMap<String, String> {
        &self.map
    }
}

// ---------------------------------------------------------------------------
// Default field maps for known log categories
// ---------------------------------------------------------------------------

/// Returns a `FieldMapper` pre-loaded with SSH-specific field aliases.
pub fn ssh_field_mapper() -> FieldMapper {
    let extra: HashMap<String, String> = [
        ("srcport", "src_port"),
        ("port", "src_port"),
        ("method", "auth_method"),
        ("AuthMethod", "auth_method"),
    ]
    .iter()
    .map(|&(k, v)| (k.to_string(), v.to_string()))
    .collect();
    FieldMapper::new().with_extra_mappings(extra)
}

/// Returns a `FieldMapper` pre-loaded with web/HTTP-specific field aliases.
pub fn web_field_mapper() -> FieldMapper {
    let extra: HashMap<String, String> = [
        ("cs-referer", "http_referer"),
        ("Referer", "http_referer"),
        ("cs-bytes", "bytes_sent"),
        ("sc-bytes", "bytes_received"),
        ("time-taken", "response_time_ms"),
    ]
    .iter()
    .map(|&(k, v)| (k.to_string(), v.to_string()))
    .collect();
    FieldMapper::new().with_extra_mappings(extra)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use hiveguard_core::models::{EventType, NormalizedEvent};
    use std::collections::HashMap;

    fn make_event() -> NormalizedEvent {
        let mut metadata = HashMap::new();
        metadata.insert("event_id".to_string(), "4625".to_string());
        metadata.insert("http_path".to_string(), "/admin/login".to_string());
        metadata.insert("command".to_string(), "powershell -enc dQBuAGkAYwBvAGQAZQ==".to_string());
        metadata.insert("user".to_string(), "administrator".to_string());
        NormalizedEvent {
            timestamp: chrono::Utc::now(),
            source_ip: "10.20.30.40".parse().unwrap(),
            event_type: EventType::AuthFailure,
            source_name: "test_source".to_string(),
            raw_line: "failed password for administrator from 10.20.30.40".to_string(),
            metadata,
        }
    }

    #[test]
    fn source_ip_accessor() {
        let mapper = FieldMapper::new();
        let event = make_event();
        assert_eq!(mapper.get_field(&event, "SourceAddress"), Some("10.20.30.40".to_string()));
        assert_eq!(mapper.get_field(&event, "src_ip"), Some("10.20.30.40".to_string()));
        assert_eq!(mapper.get_field(&event, "ClientIP"), Some("10.20.30.40".to_string()));
    }

    #[test]
    fn raw_line_accessor() {
        let mapper = FieldMapper::new();
        let event = make_event();
        assert!(mapper.get_field(&event, "Message").is_some());
        assert!(mapper.get_field(&event, "message").is_some());
    }

    #[test]
    fn metadata_event_id() {
        let mapper = FieldMapper::new();
        let event = make_event();
        assert_eq!(mapper.get_field(&event, "EventID"), Some("4625".to_string()));
    }

    #[test]
    fn metadata_command_line() {
        let mapper = FieldMapper::new();
        let event = make_event();
        let val = mapper.get_field(&event, "CommandLine");
        assert!(val.is_some());
        assert!(val.unwrap().contains("powershell"));
    }

    #[test]
    fn fallback_to_raw_metadata_key() {
        // Unknown Sigma field → fall back to metadata[key]
        let mapper = FieldMapper::new();
        let mut event = make_event();
        event.metadata.insert("custom_field".to_string(), "custom_value".to_string());
        assert_eq!(mapper.get_field(&event, "custom_field"), Some("custom_value".to_string()));
    }

    #[test]
    fn extra_mappings_override() {
        let extra: HashMap<String, String> = [("MyField".to_string(), "event_id".to_string())]
            .into_iter()
            .collect();
        let mapper = FieldMapper::new().with_extra_mappings(extra);
        let event = make_event();
        assert_eq!(mapper.get_field(&event, "MyField"), Some("4625".to_string()));
    }

    #[test]
    fn load_yaml_extra_mappings() {
        let mut mapper = FieldMapper::new();
        mapper.load_yaml("MyCustomField: event_id\n").unwrap();
        let event = make_event();
        assert_eq!(mapper.get_field(&event, "MyCustomField"), Some("4625".to_string()));
    }

    #[test]
    fn unknown_field_returns_none_if_not_in_metadata() {
        let mapper = FieldMapper::new();
        let event = make_event();
        assert_eq!(mapper.get_field(&event, "NonExistentSigmaField_xyz"), None);
    }
}
