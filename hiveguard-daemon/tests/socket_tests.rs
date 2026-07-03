use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::sync::Mutex;

use hiveguard_core::api::{ApiRequest, ApiResponse};
use hiveguard_core::persistence::state_manager::StateManager;
use hiveguard_core::persistence::wal::WalSyncMode;

use tempfile::TempDir;

/// Helper: start a socket server and return (socket_path, shutdown_tx)
async fn start_test_server() -> (
    std::path::PathBuf,
    tokio::sync::watch::Sender<bool>,
    TempDir,
    TempDir,
) {
    let socket_dir = TempDir::new().unwrap();
    let data_dir = TempDir::new().unwrap();
    let socket_path = socket_dir.path().join("test.sock");

    let state = StateManager::new(data_dir.path(), WalSyncMode::None).unwrap();
    let state = Arc::new(Mutex::new(state));

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    let server = hiveguard_daemon::SocketServer::new(socket_path.clone(), Arc::clone(&state));

    tokio::spawn(async move {
        server.run(shutdown_rx).await;
    });

    // Wait for socket to be ready
    for _ in 0..50 {
        if socket_path.exists() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert!(socket_path.exists(), "Socket file was not created");

    (socket_path, shutdown_tx, socket_dir, data_dir)
}

/// Helper: send a request and receive a response via raw Unix stream
async fn raw_request(socket_path: &std::path::Path, request: &ApiRequest) -> ApiResponse {
    let stream = UnixStream::connect(socket_path).await.unwrap();
    let (reader, mut writer) = stream.into_split();

    let mut json = serde_json::to_string(request).unwrap();
    json.push('\n');
    writer.write_all(json.as_bytes()).await.unwrap();
    writer.flush().await.unwrap();
    drop(writer);

    let mut buf_reader = BufReader::new(reader);
    let mut line = String::new();
    buf_reader.read_line(&mut line).await.unwrap();
    serde_json::from_str(line.trim()).unwrap()
}

#[tokio::test]
async fn status_returns_info() {
    let (socket_path, shutdown_tx, _sd, _dd) = start_test_server().await;

    let response = raw_request(&socket_path, &ApiRequest::Status).await;

    match response {
        ApiResponse::StatusInfo {
            total_bans,
            total_whitelisted,
            version,
            ..
        } => {
            assert_eq!(total_bans, 0);
            assert_eq!(total_whitelisted, 0);
            assert!(!version.is_empty());
        }
        other => panic!("Expected StatusInfo, got {:?}", other),
    }

    let _ = shutdown_tx.send(true);
}

#[tokio::test]
async fn ban_and_list_bans() {
    let (socket_path, shutdown_tx, _sd, _dd) = start_test_server().await;

    // Ban an IP
    let resp = raw_request(
        &socket_path,
        &ApiRequest::Ban {
            target: "10.0.0.1".to_string(),
            duration: Some("1h".to_string()),
            reason: Some("test ban".to_string()),
        },
    )
    .await;
    match &resp {
        ApiResponse::Ok { message } => assert!(message.contains("Banned")),
        other => panic!("Expected Ok, got {:?}", other),
    }

    // List bans — should have 1
    let resp = raw_request(&socket_path, &ApiRequest::ListBans { limit: None }).await;
    match &resp {
        ApiResponse::BanList { bans } => {
            assert_eq!(bans.len(), 1);
            assert_eq!(bans[0].subject, "10.0.0.1/32");
            assert_eq!(bans[0].reason, "test ban");
            assert_eq!(bans[0].severity, 200);
        }
        other => panic!("Expected BanList, got {:?}", other),
    }

    // Unban
    let resp = raw_request(
        &socket_path,
        &ApiRequest::Unban {
            target: "10.0.0.1".to_string(),
        },
    )
    .await;
    match &resp {
        ApiResponse::Ok { message } => assert!(message.contains("Unbanned")),
        other => panic!("Expected Ok, got {:?}", other),
    }

    // List bans — should be empty
    let resp = raw_request(&socket_path, &ApiRequest::ListBans { limit: None }).await;
    match &resp {
        ApiResponse::BanList { bans } => assert!(bans.is_empty()),
        other => panic!("Expected BanList, got {:?}", other),
    }

    let _ = shutdown_tx.send(true);
}

#[tokio::test]
async fn ban_cidr_and_list() {
    let (socket_path, shutdown_tx, _sd, _dd) = start_test_server().await;

    let resp = raw_request(
        &socket_path,
        &ApiRequest::Ban {
            target: "192.168.1.0/24".to_string(),
            duration: None,
            reason: None,
        },
    )
    .await;
    match &resp {
        ApiResponse::Ok { message } => assert!(message.contains("192.168.1.0/24")),
        other => panic!("Expected Ok, got {:?}", other),
    }

    let resp = raw_request(&socket_path, &ApiRequest::ListBans { limit: None }).await;
    match &resp {
        ApiResponse::BanList { bans } => {
            assert_eq!(bans.len(), 1);
            assert_eq!(bans[0].subject, "192.168.1.0/24");
            assert_eq!(bans[0].reason, "manual admin ban");
        }
        other => panic!("Expected BanList, got {:?}", other),
    }

    let _ = shutdown_tx.send(true);
}

#[tokio::test]
async fn whitelist_add_list_remove() {
    let (socket_path, shutdown_tx, _sd, _dd) = start_test_server().await;

    // Add whitelist
    let resp = raw_request(
        &socket_path,
        &ApiRequest::WhitelistAdd {
            target: "10.0.0.0/8".to_string(),
        },
    )
    .await;
    match &resp {
        ApiResponse::Ok { message } => assert!(message.contains("whitelist")),
        other => panic!("Expected Ok, got {:?}", other),
    }

    // List whitelist
    let resp = raw_request(&socket_path, &ApiRequest::ListWhitelist).await;
    match &resp {
        ApiResponse::WhitelistEntries { entries } => {
            assert_eq!(entries.len(), 1);
            assert_eq!(entries[0], "10.0.0.0/8");
        }
        other => panic!("Expected WhitelistEntries, got {:?}", other),
    }

    // Remove whitelist
    let resp = raw_request(
        &socket_path,
        &ApiRequest::WhitelistRemove {
            target: "10.0.0.0/8".to_string(),
        },
    )
    .await;
    match &resp {
        ApiResponse::Ok { message } => assert!(message.contains("Removed")),
        other => panic!("Expected Ok, got {:?}", other),
    }

    // List whitelist — empty
    let resp = raw_request(&socket_path, &ApiRequest::ListWhitelist).await;
    match &resp {
        ApiResponse::WhitelistEntries { entries } => assert!(entries.is_empty()),
        other => panic!("Expected WhitelistEntries, got {:?}", other),
    }

    let _ = shutdown_tx.send(true);
}

#[tokio::test]
async fn invalid_target_returns_error() {
    let (socket_path, shutdown_tx, _sd, _dd) = start_test_server().await;

    let resp = raw_request(
        &socket_path,
        &ApiRequest::Ban {
            target: "not-an-ip".to_string(),
            duration: None,
            reason: None,
        },
    )
    .await;
    match &resp {
        ApiResponse::Error { message } => assert!(message.contains("Invalid IP")),
        other => panic!("Expected Error, got {:?}", other),
    }

    let _ = shutdown_tx.send(true);
}

#[tokio::test]
async fn invalid_duration_returns_error() {
    let (socket_path, shutdown_tx, _sd, _dd) = start_test_server().await;

    let resp = raw_request(
        &socket_path,
        &ApiRequest::Ban {
            target: "10.0.0.1".to_string(),
            duration: Some("xyz".to_string()),
            reason: None,
        },
    )
    .await;
    match &resp {
        ApiResponse::Error { message } => assert!(message.contains("Invalid duration")),
        other => panic!("Expected Error, got {:?}", other),
    }

    let _ = shutdown_tx.send(true);
}

#[tokio::test]
async fn top_threats_sorted_by_severity() {
    let (socket_path, shutdown_tx, _sd, _dd) = start_test_server().await;

    // Ban multiple IPs
    raw_request(
        &socket_path,
        &ApiRequest::Ban {
            target: "10.0.0.1".to_string(),
            duration: Some("1h".to_string()),
            reason: Some("low".to_string()),
        },
    )
    .await;

    raw_request(
        &socket_path,
        &ApiRequest::Ban {
            target: "10.0.0.2".to_string(),
            duration: Some("1h".to_string()),
            reason: Some("high".to_string()),
        },
    )
    .await;

    let resp = raw_request(&socket_path, &ApiRequest::TopThreats { limit: 10 }).await;
    match &resp {
        ApiResponse::ThreatList { threats } => {
            assert_eq!(threats.len(), 2);
        }
        other => panic!("Expected ThreatList, got {:?}", other),
    }

    let _ = shutdown_tx.send(true);
}

#[tokio::test]
async fn list_bans_with_limit() {
    let (socket_path, shutdown_tx, _sd, _dd) = start_test_server().await;

    // Ban 3 IPs
    for i in 1..=3 {
        raw_request(
            &socket_path,
            &ApiRequest::Ban {
                target: format!("10.0.0.{}", i),
                duration: Some("1h".to_string()),
                reason: None,
            },
        )
        .await;
    }

    // List with limit 2
    let resp = raw_request(&socket_path, &ApiRequest::ListBans { limit: Some(2) }).await;
    match &resp {
        ApiResponse::BanList { bans } => assert_eq!(bans.len(), 2),
        other => panic!("Expected BanList, got {:?}", other),
    }

    let _ = shutdown_tx.send(true);
}

#[tokio::test]
async fn unban_nonexistent_ip_returns_ok() {
    let (socket_path, shutdown_tx, _sd, _dd) = start_test_server().await;

    let resp = raw_request(
        &socket_path,
        &ApiRequest::Unban {
            target: "10.0.0.99".to_string(),
        },
    )
    .await;
    match &resp {
        ApiResponse::Ok { message } => assert!(message.contains("was not banned")),
        other => panic!("Expected Ok, got {:?}", other),
    }

    let _ = shutdown_tx.send(true);
}

#[tokio::test]
async fn ban_permanent_duration() {
    let (socket_path, shutdown_tx, _sd, _dd) = start_test_server().await;

    let resp = raw_request(
        &socket_path,
        &ApiRequest::Ban {
            target: "10.0.0.1".to_string(),
            duration: Some("permanent".to_string()),
            reason: Some("permanent ban".to_string()),
        },
    )
    .await;
    match &resp {
        ApiResponse::Ok { message } => assert!(message.contains("Banned")),
        other => panic!("Expected Ok, got {:?}", other),
    }

    let resp = raw_request(&socket_path, &ApiRequest::ListBans { limit: None }).await;
    match &resp {
        ApiResponse::BanList { bans } => {
            assert_eq!(bans.len(), 1);
            assert!(bans[0].expires_at.is_none());
        }
        other => panic!("Expected BanList, got {:?}", other),
    }

    let _ = shutdown_tx.send(true);
}

// --- Phase 13: export integration tests ---

#[tokio::test]
async fn export_json_returns_valid_json() {
    let (socket_path, shutdown_tx, _sd, _dd) = start_test_server().await;

    raw_request(
        &socket_path,
        &ApiRequest::Ban {
            target: "10.0.0.1".to_string(),
            duration: Some("1h".to_string()),
            reason: Some("test ban 1".to_string()),
        },
    )
    .await;

    raw_request(
        &socket_path,
        &ApiRequest::Ban {
            target: "10.0.0.2".to_string(),
            duration: Some("2h".to_string()),
            reason: Some("test ban 2".to_string()),
        },
    )
    .await;

    let resp = raw_request(
        &socket_path,
        &ApiRequest::ExportBans {
            format: hiveguard_core::api::ExportFormat::Json,
        },
    )
    .await;

    match &resp {
        ApiResponse::ExportData { data, format } => {
            assert_eq!(*format, hiveguard_core::api::ExportFormat::Json);
            let parsed: Vec<hiveguard_core::api::BanInfo> =
                serde_json::from_str(data).expect("should be valid JSON array of BanInfo");
            assert_eq!(parsed.len(), 2);
            let subjects: Vec<&str> = parsed.iter().map(|b| b.subject.as_str()).collect();
            assert!(subjects.contains(&"10.0.0.1/32"));
            assert!(subjects.contains(&"10.0.0.2/32"));
        }
        other => panic!("Expected ExportData, got {:?}", other),
    }

    let _ = shutdown_tx.send(true);
}

#[tokio::test]
async fn export_csv_has_header_and_rows() {
    let (socket_path, shutdown_tx, _sd, _dd) = start_test_server().await;

    raw_request(
        &socket_path,
        &ApiRequest::Ban {
            target: "192.168.1.1".to_string(),
            duration: Some("24h".to_string()),
            reason: Some("csv test".to_string()),
        },
    )
    .await;

    let resp = raw_request(
        &socket_path,
        &ApiRequest::ExportBans {
            format: hiveguard_core::api::ExportFormat::Csv,
        },
    )
    .await;

    match &resp {
        ApiResponse::ExportData { data, format } => {
            assert_eq!(*format, hiveguard_core::api::ExportFormat::Csv);
            let lines: Vec<&str> = data.lines().collect();
            assert!(lines.len() >= 2, "should have header + at least 1 row");
            assert_eq!(lines[0], "subject,created_at,expires_at,severity,reason,source");
            assert!(lines[1].starts_with("192.168.1.1/32,"));
            assert!(lines[1].contains("csv test"));
        }
        other => panic!("Expected ExportData, got {:?}", other),
    }

    let _ = shutdown_tx.send(true);
}

#[tokio::test]
async fn export_json_empty_bans() {
    let (socket_path, shutdown_tx, _sd, _dd) = start_test_server().await;

    let resp = raw_request(
        &socket_path,
        &ApiRequest::ExportBans {
            format: hiveguard_core::api::ExportFormat::Json,
        },
    )
    .await;

    match &resp {
        ApiResponse::ExportData { data, format } => {
            assert_eq!(*format, hiveguard_core::api::ExportFormat::Json);
            let parsed: Vec<hiveguard_core::api::BanInfo> =
                serde_json::from_str(data).expect("should be valid JSON");
            assert!(parsed.is_empty());
        }
        other => panic!("Expected ExportData, got {:?}", other),
    }

    let _ = shutdown_tx.send(true);
}

#[tokio::test]
async fn replay_returns_stub_error() {
    let (socket_path, shutdown_tx, _sd, _dd) = start_test_server().await;

    let resp = raw_request(
        &socket_path,
        &ApiRequest::Replay {
            duration: "1h".to_string(),
        },
    )
    .await;

    match &resp {
        ApiResponse::Error { message } => {
            assert!(message.contains("not yet implemented"));
            assert!(message.contains("1h"));
        }
        other => panic!("Expected Error, got {:?}", other),
    }

    let _ = shutdown_tx.send(true);
}
