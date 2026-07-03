//! End-to-end test for the cluster gossip runtime: a ban announced on node A
//! must replicate to node B's ban store via QUIC gossip.
//!
//! Only built/run with the `cluster` feature (on by default via
//! `distribution-standard`).
#![cfg(feature = "cluster")]

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use ipnet::IpNet;
use tokio::sync::{watch, Mutex};

use hiveguard_core::ban_store::BanStore;
use hiveguard_core::config::HiveGuardConfig;
use hiveguard_core::models::{BanRecord, BanSource};
use hiveguard_core::persistence::state_manager::StateManager;
use hiveguard_core::persistence::wal::WalSyncMode;
use hiveguard_daemon::cluster::spawn_cluster;
use hiveguard_enforce::{Enforcer, ObserveOnlyEnforcer};
use hiveguard_net::NodeIdentity;

/// Grab a free UDP port by binding to :0 and reading back the assigned port.
fn free_udp_port() -> u16 {
    let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    sock.local_addr().unwrap().port()
}

fn make_state(dir: &std::path::Path) -> Arc<Mutex<StateManager>> {
    Arc::new(Mutex::new(
        StateManager::new(dir, WalSyncMode::None).unwrap(),
    ))
}

fn make_enforcer() -> Arc<Mutex<Box<dyn Enforcer>>> {
    Arc::new(Mutex::new(
        Box::new(ObserveOnlyEnforcer::new()) as Box<dyn Enforcer>,
    ))
}

/// Build a config that points at `peer_addr` (with pinned `peer_fp` as both a
/// strict seed and a fully-trusted founder, ban_threshold 1.0 so a single
/// founder report enforces).
fn make_config(
    name: &str,
    data_dir: &std::path::Path,
    listen_port: u16,
    peer_port: u16,
    peer_fp: &str,
) -> HiveGuardConfig {
    let yaml = format!(
        r#"
node:
  name: "{name}"
  data_dir: "{data_dir}"
  listen_gossip: "127.0.0.1:{listen_port}"
  cluster_mode: strict
  seeds:
    - address: "127.0.0.1:{peer_port}"
      fingerprint: "{peer_fp}"
  founder_nodes:
    - "{peer_fp}"
trust:
  ban_threshold: 1.0
"#,
        data_dir = data_dir.display(),
    );
    serde_yaml::from_str(&yaml).expect("config parse")
}

#[tokio::test]
async fn ban_replicates_across_two_nodes() {
    let _ = tracing_subscriber::fmt::try_init();

    let dir_a = tempfile::tempdir().unwrap();
    let dir_b = tempfile::tempdir().unwrap();

    // Pre-generate identities so we can pin each node's fingerprint in the
    // other's config. `spawn_cluster` will load (not regenerate) these.
    let fp_a = NodeIdentity::generate(dir_a.path()).unwrap().node_id().to_string();
    let fp_b = NodeIdentity::generate(dir_b.path()).unwrap().node_id().to_string();
    assert_ne!(fp_a, fp_b);

    let port_a = free_udp_port();
    let port_b = free_udp_port();

    let cfg_a = make_config("node-a", dir_a.path(), port_a, port_b, &fp_b);
    let cfg_b = make_config("node-b", dir_b.path(), port_b, port_a, &fp_a);

    let state_a = make_state(dir_a.path());
    let state_b = make_state(dir_b.path());

    let (_sd_tx_a, sd_rx_a) = watch::channel(false);
    let (_sd_tx_b, sd_rx_b) = watch::channel(false);

    let handle_a = spawn_cluster(&cfg_a, state_a.clone(), make_enforcer(), None, sd_rx_a)
        .await
        .expect("node A cluster");
    let _handle_b = spawn_cluster(&cfg_b, state_b.clone(), make_enforcer(), None, sd_rx_b)
        .await
        .expect("node B cluster");

    // Give the two nodes a moment to dial + handshake.
    tokio::time::sleep(Duration::from_millis(800)).await;

    // Issue a ban on node A.
    let banned: IpNet = "185.243.218.42/32".parse().unwrap();
    let record = BanRecord {
        subject: banned,
        created_at: Utc::now(),
        expires_at: Some(Utc::now() + chrono::Duration::hours(24)),
        severity: 200,
        reason: "integration-test brute force".into(),
        evidence_hash: [0u8; 32],
        source: BanSource::LocalDetector("test".into()),
        geo_info: None,
    };
    handle_a.announce_local_ban(&record);

    // Poll node B's ban store for up to ~6s.
    let mut provenance: Option<BanSource> = None;
    for _ in 0..60 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let st = state_b.lock().await;
        if let Some(rec) = st.ban_store().is_banned(&banned.addr()) {
            provenance = Some(rec.source.clone());
            break;
        }
    }

    match provenance {
        Some(BanSource::ClusterPeer(node)) => {
            assert_eq!(node, fp_a, "remote ban should be attributed to node A's id");
        }
        Some(other) => panic!("ban replicated but provenance wrong: {other:?} (expected ClusterPeer)"),
        None => panic!("ban issued on node A did not replicate to node B within timeout"),
    }
}

/// Anti-entropy: a ban that already existed on node A *before* node B connected
/// must be reconciled to B via the periodic digest exchange — i.e. a node that
/// was offline catches up on bans it missed. This is the key capability webhook
/// glue cannot provide.
#[tokio::test]
async fn preexisting_ban_reconciles_via_anti_entropy() {
    let _ = tracing_subscriber::fmt::try_init();

    let dir_a = tempfile::tempdir().unwrap();
    let dir_b = tempfile::tempdir().unwrap();

    let fp_a = NodeIdentity::generate(dir_a.path()).unwrap().node_id().to_string();
    let fp_b = NodeIdentity::generate(dir_b.path()).unwrap().node_id().to_string();

    let port_a = free_udp_port();
    let port_b = free_udp_port();

    let cfg_a = make_config("node-a", dir_a.path(), port_a, port_b, &fp_b);
    let cfg_b = make_config("node-b", dir_b.path(), port_b, port_a, &fp_a);

    let state_a = make_state(dir_a.path());
    let state_b = make_state(dir_b.path());

    // Seed a ban into node A's store *before* the cluster starts.
    let banned: IpNet = "185.243.218.99/32".parse().unwrap();
    {
        let mut st = state_a.lock().await;
        st.add_ban(BanRecord {
            subject: banned,
            created_at: Utc::now(),
            expires_at: None,
            severity: 180,
            reason: "pre-existing ban".into(),
            evidence_hash: [0u8; 32],
            source: BanSource::LocalDetector("seed".into()),
            geo_info: None,
        })
        .unwrap();
    }

    let (_sd_tx_a, sd_rx_a) = watch::channel(false);
    let (_sd_tx_b, sd_rx_b) = watch::channel(false);

    let _a = spawn_cluster(&cfg_a, state_a.clone(), make_enforcer(), None, sd_rx_a)
        .await
        .expect("node A cluster");
    let _b = spawn_cluster(&cfg_b, state_b.clone(), make_enforcer(), None, sd_rx_b)
        .await
        .expect("node B cluster");

    // No announce_local_ban call — reconciliation must happen purely via the
    // anti-entropy digest exchange. Poll up to ~10s (maintenance runs every 5s).
    let mut reconciled = false;
    for _ in 0..100 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let st = state_b.lock().await;
        if st.ban_store().is_banned(&banned.addr()).is_some() {
            reconciled = true;
            break;
        }
    }

    assert!(
        reconciled,
        "pre-existing ban on node A did not reconcile to node B via anti-entropy"
    );
}
