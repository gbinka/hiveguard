use serde::{Deserialize, Serialize};

/// Export format for ban data.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ExportFormat {
    Json,
    Csv,
}

/// Request sent from CLI client to daemon via Unix socket.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ApiRequest {
    Status,
    Ban {
        target: String,
        duration: Option<String>,
        reason: Option<String>,
    },
    Unban {
        target: String,
    },
    WhitelistAdd {
        target: String,
    },
    WhitelistRemove {
        target: String,
    },
    ListBans {
        limit: Option<usize>,
    },
    ListWhitelist,
    TopThreats {
        limit: usize,
    },
    ExportBans {
        format: ExportFormat,
    },
    /// Replay detection from recorded events for the last N duration.
    /// Currently a stub — architecture note: full replay requires an event journal
    /// (e.g., persisted NormalizedEvents with timestamps) that can be fed back
    /// through the detector + scoring pipeline. Future implementation would:
    /// 1. Read events from a time-windowed event log
    /// 2. Re-run detectors in simulation mode (no enforcement)
    /// 3. Return the signals/bans that would have been generated
    Replay {
        duration: String,
    },
}

/// Response sent from daemon to CLI client via Unix socket.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ApiResponse {
    StatusInfo {
        uptime_secs: u64,
        total_bans: usize,
        total_whitelisted: usize,
        version: String,
    },
    Ok {
        message: String,
    },
    Error {
        message: String,
    },
    BanList {
        bans: Vec<BanInfo>,
    },
    WhitelistEntries {
        entries: Vec<String>,
    },
    ThreatList {
        threats: Vec<ThreatInfo>,
    },
    ExportData {
        data: String,
        format: ExportFormat,
    },
}

/// Serializable ban information for API responses.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BanInfo {
    pub subject: String,
    pub created_at: String,
    pub expires_at: Option<String>,
    pub severity: u8,
    pub reason: String,
    pub source: String,
}

/// Serializable threat information for API responses.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ThreatInfo {
    pub ip: String,
    pub total_severity: u32,
    pub ban_count: u32,
    pub last_seen: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialize_deserialize_api_request_status() {
        let req = ApiRequest::Status;
        let json = serde_json::to_string(&req).unwrap();
        let parsed: ApiRequest = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, ApiRequest::Status));
    }

    #[test]
    fn serialize_deserialize_api_request_ban() {
        let req = ApiRequest::Ban {
            target: "10.0.0.1".to_string(),
            duration: Some("24h".to_string()),
            reason: Some("brute force".to_string()),
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: ApiRequest = serde_json::from_str(&json).unwrap();
        match parsed {
            ApiRequest::Ban {
                target,
                duration,
                reason,
            } => {
                assert_eq!(target, "10.0.0.1");
                assert_eq!(duration.unwrap(), "24h");
                assert_eq!(reason.unwrap(), "brute force");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn serialize_deserialize_api_request_unban() {
        let req = ApiRequest::Unban {
            target: "192.168.1.0/24".to_string(),
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: ApiRequest = serde_json::from_str(&json).unwrap();
        match parsed {
            ApiRequest::Unban { target } => assert_eq!(target, "192.168.1.0/24"),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn serialize_deserialize_api_request_whitelist_add() {
        let req = ApiRequest::WhitelistAdd {
            target: "10.0.0.0/8".to_string(),
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: ApiRequest = serde_json::from_str(&json).unwrap();
        match parsed {
            ApiRequest::WhitelistAdd { target } => assert_eq!(target, "10.0.0.0/8"),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn serialize_deserialize_api_request_list_bans() {
        let req = ApiRequest::ListBans { limit: Some(10) };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: ApiRequest = serde_json::from_str(&json).unwrap();
        match parsed {
            ApiRequest::ListBans { limit } => assert_eq!(limit, Some(10)),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn serialize_deserialize_api_request_list_whitelist() {
        let req = ApiRequest::ListWhitelist;
        let json = serde_json::to_string(&req).unwrap();
        let parsed: ApiRequest = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, ApiRequest::ListWhitelist));
    }

    #[test]
    fn serialize_deserialize_api_request_top_threats() {
        let req = ApiRequest::TopThreats { limit: 5 };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: ApiRequest = serde_json::from_str(&json).unwrap();
        match parsed {
            ApiRequest::TopThreats { limit } => assert_eq!(limit, 5),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn serialize_deserialize_api_response_status_info() {
        let resp = ApiResponse::StatusInfo {
            uptime_secs: 3600,
            total_bans: 42,
            total_whitelisted: 3,
            version: "0.1.0".to_string(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: ApiResponse = serde_json::from_str(&json).unwrap();
        match parsed {
            ApiResponse::StatusInfo {
                uptime_secs,
                total_bans,
                total_whitelisted,
                version,
            } => {
                assert_eq!(uptime_secs, 3600);
                assert_eq!(total_bans, 42);
                assert_eq!(total_whitelisted, 3);
                assert_eq!(version, "0.1.0");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn serialize_deserialize_api_response_ok() {
        let resp = ApiResponse::Ok {
            message: "done".to_string(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: ApiResponse = serde_json::from_str(&json).unwrap();
        match parsed {
            ApiResponse::Ok { message } => assert_eq!(message, "done"),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn serialize_deserialize_api_response_error() {
        let resp = ApiResponse::Error {
            message: "bad input".to_string(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: ApiResponse = serde_json::from_str(&json).unwrap();
        match parsed {
            ApiResponse::Error { message } => assert_eq!(message, "bad input"),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn serialize_deserialize_api_response_ban_list() {
        let resp = ApiResponse::BanList {
            bans: vec![BanInfo {
                subject: "10.0.0.1/32".to_string(),
                created_at: "2025-01-01T00:00:00Z".to_string(),
                expires_at: Some("2025-01-02T00:00:00Z".to_string()),
                severity: 150,
                reason: "brute force".to_string(),
                source: "ssh_bruteforce".to_string(),
            }],
        };
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: ApiResponse = serde_json::from_str(&json).unwrap();
        match parsed {
            ApiResponse::BanList { bans } => {
                assert_eq!(bans.len(), 1);
                assert_eq!(bans[0].subject, "10.0.0.1/32");
                assert_eq!(bans[0].severity, 150);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn serialize_deserialize_api_response_whitelist_entries() {
        let resp = ApiResponse::WhitelistEntries {
            entries: vec!["10.0.0.0/8".to_string(), "127.0.0.0/8".to_string()],
        };
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: ApiResponse = serde_json::from_str(&json).unwrap();
        match parsed {
            ApiResponse::WhitelistEntries { entries } => {
                assert_eq!(entries.len(), 2);
                assert_eq!(entries[0], "10.0.0.0/8");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn serialize_deserialize_api_response_threat_list() {
        let resp = ApiResponse::ThreatList {
            threats: vec![ThreatInfo {
                ip: "10.0.0.1".to_string(),
                total_severity: 300,
                ban_count: 2,
                last_seen: "2025-01-01T12:00:00Z".to_string(),
            }],
        };
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: ApiResponse = serde_json::from_str(&json).unwrap();
        match parsed {
            ApiResponse::ThreatList { threats } => {
                assert_eq!(threats.len(), 1);
                assert_eq!(threats[0].total_severity, 300);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn ban_info_fields_complete() {
        let info = BanInfo {
            subject: "1.2.3.4/32".to_string(),
            created_at: "2025-06-01T00:00:00Z".to_string(),
            expires_at: None,
            severity: 255,
            reason: "permanent ban".to_string(),
            source: "ManualAdmin".to_string(),
        };
        assert!(info.expires_at.is_none());
        assert_eq!(info.severity, 255);
    }

    // --- Phase 13: export & replay API types ---

    #[test]
    fn serialize_deserialize_api_request_export_json() {
        let req = ApiRequest::ExportBans {
            format: ExportFormat::Json,
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: ApiRequest = serde_json::from_str(&json).unwrap();
        match parsed {
            ApiRequest::ExportBans { format } => assert_eq!(format, ExportFormat::Json),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn serialize_deserialize_api_request_export_csv() {
        let req = ApiRequest::ExportBans {
            format: ExportFormat::Csv,
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: ApiRequest = serde_json::from_str(&json).unwrap();
        match parsed {
            ApiRequest::ExportBans { format } => assert_eq!(format, ExportFormat::Csv),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn serialize_deserialize_api_request_replay() {
        let req = ApiRequest::Replay {
            duration: "1h".to_string(),
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: ApiRequest = serde_json::from_str(&json).unwrap();
        match parsed {
            ApiRequest::Replay { duration } => assert_eq!(duration, "1h"),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn serialize_deserialize_api_response_export_data() {
        let resp = ApiResponse::ExportData {
            data: r#"[{"subject":"10.0.0.1/32"}]"#.to_string(),
            format: ExportFormat::Json,
        };
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: ApiResponse = serde_json::from_str(&json).unwrap();
        match parsed {
            ApiResponse::ExportData { data, format } => {
                assert!(data.contains("10.0.0.1"));
                assert_eq!(format, ExportFormat::Json);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn export_format_equality() {
        assert_eq!(ExportFormat::Json, ExportFormat::Json);
        assert_eq!(ExportFormat::Csv, ExportFormat::Csv);
        assert_ne!(ExportFormat::Json, ExportFormat::Csv);
    }
}
