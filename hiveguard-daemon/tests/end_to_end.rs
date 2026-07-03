//! End-to-end smoke test exercising the full pipeline + UI API path.
//!
//! Spins up the same components `main.rs` builds (state, enforcer adapter,
//! scoring plugin, detectors, pipeline, `DaemonUiApi`), pushes a sequence of
//! `NormalizedEvent`s through it, then queries the UI API the way `ui-rest`
//! or `ui-tui` would. The intent is to catch regressions where individual
//! crates compile but the wiring breaks.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tempfile::TempDir;
use tokio::sync::{mpsc, Mutex};

use hiveguard_core::ban_store::BanStore;
use hiveguard_core::detector::Detector;
use hiveguard_core::detectors::SshBruteforceDetector;
use hiveguard_core::models::{EventType, NormalizedEvent};
use hiveguard_core::persistence::wal::WalSyncMode;
use hiveguard_core::persistence::StateManager;
use hiveguard_enforce::{Enforcer, ObserveOnlyEnforcer};
use hiveguard_plugin_api::{
    BanRequest, PluginContext, PluginInfo, PluginMetrics, ScoringEnginePlugin, UiApiHandle,
};
use hiveguard_plugin_api::context::parking_lot_compat::RegistryHandle;
use hiveguard_plugin_api::secrets::SecretResolver;
use tokio_util::sync::CancellationToken;

use hiveguard_daemon::pipeline::Pipeline;
use hiveguard_daemon::ui_api::{DaemonUiApi, UiSniffer};

async fn default_scoring() -> Box<dyn ScoringEnginePlugin> {
    let ctx = PluginContext::new(
        "scoring.default".to_string(),
        std::env::temp_dir(),
        Arc::new(SecretResolver::new()),
        PluginMetrics {
            registry: Arc::new(RegistryHandle::default()),
            plugin_id: "scoring.default".to_string(),
        },
        CancellationToken::new(),
    );
    hiveguard_plugin_scoring_default::DefaultScoringPlugin::create(ctx, serde_json::json!({}))
        .await
        .expect("default scoring plugin must construct")
}

struct Harness {
    _dir: TempDir,
    state: Arc<Mutex<StateManager>>,
    ui_api: Arc<DaemonUiApi>,
    tx: mpsc::Sender<NormalizedEvent>,
    pipeline_handle: tokio::task::JoinHandle<()>,
}

async fn build_harness() -> Harness {
    let dir = TempDir::new().unwrap();
    let state = Arc::new(Mutex::new(
        StateManager::new(dir.path(), WalSyncMode::None).unwrap(),
    ));
    let enforcer: Arc<Mutex<Box<dyn Enforcer>>> =
        Arc::new(Mutex::new(Box::new(ObserveOnlyEnforcer::new())));

    let plugin_infos = vec![PluginInfo {
        id: "scoring.default".into(),
        kind: "ScoringEngine".into(),
        health: "Healthy".into(),
        version: "0.1.0".into(),
    }];
    let ui_api = Arc::new(DaemonUiApi::new(
        "test-node".into(),
        "0.0.0-test".into(),
        state.clone(),
        enforcer.clone(),
        plugin_infos,
        None,
        None,
        None,
        None,
        None,
        None,
    ));
    let sniffer = UiSniffer::from_arc(ui_api.clone());

    let (tx, rx) = mpsc::channel(100);
    let detectors: Vec<Box<dyn Detector>> = vec![Box::new(SshBruteforceDetector::new())];
    let scoring = default_scoring().await;

    let mut pipeline = Pipeline::new(rx, detectors, scoring, state.clone(), enforcer.clone())
        .with_ui_sniffer(sniffer);

    let pipeline_handle = tokio::spawn(async move {
        pipeline.run().await;
    });

    Harness {
        _dir: dir,
        state,
        ui_api,
        tx,
        pipeline_handle,
    }
}

fn make_auth_failure(ip: IpAddr, i: usize) -> NormalizedEvent {
    NormalizedEvent {
        timestamp: chrono::Utc::now(),
        source_ip: ip,
        event_type: EventType::AuthFailure,
        source_name: "ssh".to_string(),
        raw_line: format!("Failed password for admin from {ip} port {} ssh2", 22000 + i),
        metadata: HashMap::new(),
    }
}

/// Wait until `cond` returns true or `timeout` elapses. Polls every 20ms.
async fn wait_for<F: Fn() -> bool>(cond: F, timeout: Duration) -> bool {
    let start = Instant::now();
    while !cond() {
        if start.elapsed() > timeout {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    true
}

#[tokio::test]
async fn happy_path_ssh_bruteforce_triggers_ban_visible_via_ui_api() {
    let h = build_harness().await;
    let attacker: IpAddr = "203.0.114.1".parse().unwrap();

    for i in 0..5 {
        h.tx.send(make_auth_failure(attacker, i)).await.unwrap();
    }

    let state = h.state.clone();
    let banned = wait_for(
        || {
            futures::executor::block_on(async {
                let s = state.lock().await;
                s.ban_store().is_banned(&attacker).is_some()
            })
        },
        Duration::from_secs(2),
    )
    .await;
    assert!(banned, "expected ban after 5 auth failures");

    // Verify via UI API — same surface `ui-rest`/`ui-tui` consume.
    let bans = h.ui_api.list_bans().await;
    assert!(
        bans.iter().any(|b| b.subject.contains("203.0.114.1")),
        "ban must be visible via DaemonUiApi::list_bans (got {:?})",
        bans
    );

    let info = h.ui_api.node_info().await;
    assert_eq!(info.node_name, "test-node");
    assert_eq!(info.daemon_version, "0.0.0-test");
    assert!(info.total_bans >= 1);

    let plugins = h.ui_api.list_plugins().await;
    assert!(plugins.iter().any(|p| p.id == "scoring.default"));

    drop(h.tx);
    let _ = tokio::time::timeout(Duration::from_secs(1), h.pipeline_handle).await;
}

#[tokio::test]
async fn whitelisted_ip_never_banned() {
    let h = build_harness().await;
    // RFC 1918 — covered by the immutable whitelist in `WhitelistManager`.
    let private: IpAddr = "10.20.30.40".parse().unwrap();

    for i in 0..10 {
        h.tx.send(make_auth_failure(private, i)).await.unwrap();
    }

    tokio::time::sleep(Duration::from_millis(150)).await;

    let bans = h.ui_api.list_bans().await;
    assert!(
        !bans.iter().any(|b| b.subject.contains("10.20.30.40")),
        "RFC 1918 IP must never appear in bans (got {:?})",
        bans
    );

    drop(h.tx);
    let _ = tokio::time::timeout(Duration::from_secs(1), h.pipeline_handle).await;
}

#[tokio::test]
async fn manual_ban_via_ui_api_persists_and_emits_event() {
    let h = build_harness().await;
    let mut sub = h.ui_api.subscribe();

    let subject: ipnet::IpNet = "198.51.100.5/32".parse().unwrap();
    h.ui_api
        .add_ban(BanRequest {
            subject,
            duration: Duration::from_secs(3600),
            reason: "manual operator action".to_string(),
        })
        .await
        .expect("add_ban must succeed");

    // Persistence check.
    let bans = h.ui_api.list_bans().await;
    let found = bans.iter().find(|b| b.subject.contains("198.51.100.5"));
    assert!(found.is_some(), "manual ban must be persisted");
    assert_eq!(found.unwrap().source, "admin");

    // Broadcast check — at least one BansSnapshot event arrives.
    let mut got_snapshot = false;
    for _ in 0..5 {
        match tokio::time::timeout(Duration::from_millis(200), sub.recv()).await {
            Ok(Ok(hiveguard_plugin_api::UiEvent::BansSnapshot(snap))) => {
                if snap.iter().any(|b| b.subject.contains("198.51.100.5")) {
                    got_snapshot = true;
                    break;
                }
            }
            _ => continue,
        }
    }
    assert!(got_snapshot, "expected UiEvent::BansSnapshot after add_ban");

    // Unban round-trip.
    h.ui_api
        .remove_ban(subject)
        .await
        .expect("remove_ban must succeed");
    let bans = h.ui_api.list_bans().await;
    assert!(
        !bans.iter().any(|b| b.subject.contains("198.51.100.5")),
        "ban must be removed"
    );

    drop(h.tx);
    let _ = tokio::time::timeout(Duration::from_secs(1), h.pipeline_handle).await;
}
