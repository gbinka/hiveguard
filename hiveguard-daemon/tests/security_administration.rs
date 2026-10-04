use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use hiveguard_core::ban_store::BanStore;
use hiveguard_core::errors::HiveGuardError;
use hiveguard_core::persistence::{wal::WalSyncMode, StateManager};
use hiveguard_daemon::{pipeline::ban_expiry_task, ui_api::DaemonUiApi};
use hiveguard_enforce::Enforcer;
use hiveguard_plugin_api::{BanRequest, UiApiHandle};
use ipnet::IpNet;
use tokio::sync::Mutex;

#[derive(Default)]
struct Firewall {
    fail: bool,
    bans: Vec<IpNet>,
    syncs: usize,
}

struct TestEnforcer(Arc<Mutex<Firewall>>);

#[async_trait]
impl Enforcer for TestEnforcer {
    async fn apply_ban(&mut self, subject: &IpNet) -> Result<(), HiveGuardError> {
        let mut fw = self.0.lock().await;
        if fw.fail {
            return Err(HiveGuardError::Enforcement("injected apply failure".into()));
        }
        fw.bans.push(*subject);
        Ok(())
    }
    async fn remove_ban(&mut self, subject: &IpNet) -> Result<(), HiveGuardError> {
        let mut fw = self.0.lock().await;
        if fw.fail {
            return Err(HiveGuardError::Enforcement(
                "injected remove failure".into(),
            ));
        }
        fw.bans.retain(|ban| ban != subject);
        Ok(())
    }
    async fn sync_full(&mut self, subjects: &[IpNet]) -> Result<(), HiveGuardError> {
        let mut fw = self.0.lock().await;
        fw.syncs += 1;
        if fw.fail {
            return Err(HiveGuardError::Enforcement("injected sync failure".into()));
        }
        fw.bans = subjects.to_vec();
        Ok(())
    }
    async fn get_current_bans(&self) -> Result<Vec<IpNet>, HiveGuardError> {
        Ok(self.0.lock().await.bans.clone())
    }
}

fn api(state: Arc<Mutex<StateManager>>, enf: Arc<Mutex<Box<dyn Enforcer>>>) -> DaemonUiApi {
    DaemonUiApi::new(
        "test".into(),
        "test".into(),
        state,
        enf,
        vec![],
        None,
        None,
        None,
        None,
        None,
        None,
    )
}

fn request(subject: &str) -> BanRequest {
    BanRequest {
        subject: subject.parse().unwrap(),
        duration: Duration::from_secs(3600),
        reason: "test".into(),
    }
}

#[tokio::test]
async fn manual_bans_respect_configured_and_immutable_whitelist() {
    let dir = tempfile::tempdir().unwrap();
    let state = Arc::new(Mutex::new(
        StateManager::new(dir.path(), WalSyncMode::None).unwrap(),
    ));
    state
        .lock()
        .await
        .add_whitelist("11.22.33.5/32".parse().unwrap())
        .unwrap();
    let firewall = Arc::new(Mutex::new(Firewall::default()));
    let enf: Arc<Mutex<Box<dyn Enforcer>>> =
        Arc::new(Mutex::new(Box::new(TestEnforcer(firewall.clone()))));
    let api = api(state.clone(), enf);
    for cidr in ["11.22.33.0/24", "127.0.0.1/32", "::1/128"] {
        assert!(api.add_ban(request(cidr)).await.is_err());
    }
    assert!(state.lock().await.ban_store().get_all_bans().is_empty());
    assert!(firewall.lock().await.bans.is_empty());
}

#[tokio::test]
async fn failed_admin_operations_report_error_and_reconcile_without_new_events() {
    let dir = tempfile::tempdir().unwrap();
    let state = Arc::new(Mutex::new(
        StateManager::new(dir.path(), WalSyncMode::None).unwrap(),
    ));
    let firewall = Arc::new(Mutex::new(Firewall {
        fail: true,
        ..Default::default()
    }));
    let enf: Arc<Mutex<Box<dyn Enforcer>>> =
        Arc::new(Mutex::new(Box::new(TestEnforcer(firewall.clone()))));
    let api = api(state.clone(), enf.clone());
    let subject: IpNet = "11.22.33.5/32".parse().unwrap();
    assert!(api
        .add_ban(request("11.22.33.5/32"))
        .await
        .unwrap_err()
        .to_string()
        .contains("pending retry"));
    assert_eq!(state.lock().await.ban_store().get_all_bans().len(), 1);
    let (shutdown, rx) = tokio::sync::watch::channel(false);
    let task = tokio::spawn(ban_expiry_task(
        state.clone(),
        enf,
        Duration::from_millis(10),
        rx,
        None,
    ));
    firewall.lock().await.fail = false;
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if firewall.lock().await.bans == [subject] {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    firewall.lock().await.fail = true;
    assert!(api
        .remove_ban(subject)
        .await
        .unwrap_err()
        .to_string()
        .contains("pending retry"));
    assert!(state.lock().await.ban_store().get_all_bans().is_empty());
    firewall.lock().await.fail = false;
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if firewall.lock().await.bans.is_empty() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    shutdown.send(true).unwrap();
    task.await.unwrap();
}

#[tokio::test]
async fn fail2ban_import_applies_firewall_and_rejects_whitelist() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("fail2ban.sqlite");
    // Uses the same sqlite3 dependency as the production import path.
    let output = std::process::Command::new("sqlite3")
        .arg(&db)
        .arg(
            "CREATE TABLE bans(jail TEXT, ip TEXT, timeofban INTEGER, bantime INTEGER); \
         INSERT INTO bans VALUES ('ssh','11.22.33.5',strftime('%s','now'),3600); \
         INSERT INTO bans VALUES ('ssh','127.0.0.1',strftime('%s','now'),3600);",
        )
        .output()
        .expect("sqlite3 is required to exercise fail2ban import");
    assert!(output.status.success());
    let state = Arc::new(Mutex::new(
        StateManager::new(dir.path(), WalSyncMode::None).unwrap(),
    ));
    let firewall = Arc::new(Mutex::new(Firewall::default()));
    let enf: Arc<Mutex<Box<dyn Enforcer>>> =
        Arc::new(Mutex::new(Box::new(TestEnforcer(firewall.clone()))));
    let api = api(state.clone(), enf);
    let result = api
        .fail2ban_import(Some(db.to_string_lossy().into_owned()), None)
        .await
        .unwrap();
    assert_eq!(result.imported, 1);
    assert_eq!(result.skipped, 1);
    assert_eq!(result.errors.len(), 1);
    assert_eq!(
        firewall.lock().await.bans,
        ["11.22.33.5/32".parse::<IpNet>().unwrap()]
    );

    let mut existing = state.lock().await.ban_store().get_all_bans()[0].clone();
    existing.expires_at = None;
    state.lock().await.add_ban(existing).unwrap();
    let result = api
        .fail2ban_import(Some(db.to_string_lossy().into_owned()), None)
        .await
        .unwrap();
    assert_eq!(result.imported, 1);
    assert!(
        state.lock().await.ban_store().get_all_bans()[0]
            .expires_at
            .is_none(),
        "import must not replace a permanent ban with a short one"
    );

    firewall.lock().await.fail = true;
    let result = api
        .fail2ban_import(Some(db.to_string_lossy().into_owned()), None)
        .await
        .unwrap();
    assert_eq!(
        result.imported, 0,
        "failed enforcement is not a successful import"
    );
    assert!(result.errors.iter().any(|e| e.contains("pending retry")));
}

#[tokio::test]
async fn socket_rejects_protected_ban_and_reports_firewall_failure() {
    use hiveguard_core::api::{ApiRequest, ApiResponse};
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let dir = tempfile::tempdir().unwrap();
    let state = Arc::new(Mutex::new(
        StateManager::new(dir.path(), WalSyncMode::None).unwrap(),
    ));
    let firewall = Arc::new(Mutex::new(Firewall {
        fail: true,
        ..Default::default()
    }));
    let enf: Arc<Mutex<Box<dyn Enforcer>>> = Arc::new(Mutex::new(Box::new(TestEnforcer(firewall))));
    let path = dir.path().join("control.sock");
    let server =
        hiveguard_daemon::SocketServer::new(path.clone(), state.clone()).with_enforcer(enf);
    let (shutdown, rx) = tokio::sync::watch::channel(false);
    let task = tokio::spawn(async move { server.run(rx).await });
    tokio::time::timeout(Duration::from_secs(2), async {
        while !path.exists() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    for (target, expected) in [("127.0.0.1", "protected"), ("11.22.33.5", "pending retry")] {
        let mut connection = tokio::net::UnixStream::connect(&path).await.unwrap();
        let req = ApiRequest::Ban {
            target: target.into(),
            duration: Some("1h".into()),
            reason: None,
        };
        let wire = format!("{}\n", serde_json::to_string(&req).unwrap());
        connection.write_all(wire.as_bytes()).await.unwrap();
        let mut response = String::new();
        tokio::time::timeout(
            Duration::from_secs(2),
            BufReader::new(connection).read_line(&mut response),
        )
        .await
        .unwrap()
        .unwrap();
        match serde_json::from_str::<ApiResponse>(&response).unwrap() {
            ApiResponse::Error { message } => assert!(message.contains(expected), "{message}"),
            other => panic!("expected explicit failure, got {other:?}"),
        }
    }
    assert_eq!(state.lock().await.ban_store().get_all_bans().len(), 1);
    shutdown.send(true).unwrap();
    task.await.unwrap();
}
