//! Startup ordering: the config whitelist must be applied to the ban store
//! *before* the ban set is pushed to the firewall.
//!
//! Regression cover for the production incident where 21 Applebot subnets
//! (`17.166.x.0/24`) reached nftables despite `17.0.0.0/8` sitting in the
//! config whitelist — the snapshot's stale whitelist was synced first.

use std::sync::Arc;

use async_trait::async_trait;
use hiveguard_core::ban_store::BanStore;
use hiveguard_core::models::{BanRecord, BanSource};
use hiveguard_core::errors::HiveGuardError;
use hiveguard_core::persistence::wal::WalSyncMode;
use hiveguard_core::persistence::StateManager;
use hiveguard_daemon::whitelist_sync;
use hiveguard_enforce::Enforcer;
use ipnet::IpNet;
use tempfile::TempDir;
use tokio::sync::Mutex;

/// Records what the daemon hands to the firewall.
#[derive(Default)]
struct RecordingEnforcer {
    synced: Arc<Mutex<Option<Vec<IpNet>>>>,
    removed: Arc<Mutex<Vec<IpNet>>>,
}

#[async_trait]
impl Enforcer for RecordingEnforcer {
    async fn apply_ban(&mut self, _subject: &IpNet) -> Result<(), HiveGuardError> {
        Ok(())
    }
    async fn remove_ban(&mut self, subject: &IpNet) -> Result<(), HiveGuardError> {
        self.removed.lock().await.push(*subject);
        Ok(())
    }
    async fn sync_full(&mut self, banned: &[IpNet]) -> Result<(), HiveGuardError> {
        *self.synced.lock().await = Some(banned.to_vec());
        Ok(())
    }
    async fn get_current_bans(&self) -> Result<Vec<IpNet>, HiveGuardError> {
        Ok(Vec::new())
    }
}

fn ban(cidr: &str) -> BanRecord {
    BanRecord {
        subject: cidr.parse().unwrap(),
        created_at: chrono::Utc::now(),
        expires_at: None,
        severity: 5,
        reason: "test".to_string(),
        evidence_hash: [0u8; 32],
        source: BanSource::LocalDetector("test".to_string()),
        geo_info: None,
    }
}

#[tokio::test]
async fn startup_applies_config_whitelist_before_enforcer_sync() {
    let dir = TempDir::new().unwrap();
    let mut sm = StateManager::new(dir.path(), WalSyncMode::None).unwrap();

    // State restored from a snapshot taken before `17.0.0.0/8` was whitelisted.
    sm.add_ban(ban("17.166.20.0/24")).unwrap();
    sm.add_ban(ban("17.166.237.0/24")).unwrap();
    sm.add_ban(ban("45.33.0.7/32")).unwrap();
    let state = Arc::new(Mutex::new(sm));

    let mut enforcer = RecordingEnforcer::default();
    let synced = enforcer.synced.clone();

    let config_whitelist: Vec<IpNet> = vec!["17.0.0.0/8".parse().unwrap()];
    whitelist_sync::init_whitelist_and_sync(&state, config_whitelist, &mut enforcer).await.unwrap();

    let synced = synced.lock().await.clone().expect("sync_full was called");
    assert_eq!(
        synced,
        vec!["45.33.0.7/32".parse::<IpNet>().unwrap()],
        "whitelisted subnets must never reach the firewall"
    );

    // And they are gone from the store, not merely filtered on the way out.
    let st = state.lock().await;
    assert_eq!(st.ban_store().get_all_bans().len(), 1);
}

#[tokio::test]
async fn startup_whitelist_narrower_than_ban_scope_still_protects() {
    let dir = TempDir::new().unwrap();
    let mut sm = StateManager::new(dir.path(), WalSyncMode::None).unwrap();

    // `distributed_slow` with ban_scope /24 caught the admin's own network.
    sm.add_ban(ban("100.64.229.0/24")).unwrap();
    let state = Arc::new(Mutex::new(sm));

    let mut enforcer = RecordingEnforcer::default();
    let synced = enforcer.synced.clone();

    let config_whitelist: Vec<IpNet> = vec!["100.64.229.178/32".parse().unwrap()];
    whitelist_sync::init_whitelist_and_sync(&state, config_whitelist, &mut enforcer).await.unwrap();

    assert!(
        synced.lock().await.as_deref() == Some(&[]),
        "empty sync must clear the last revoked ban from the firewall"
    );
    assert!(state.lock().await.ban_store().get_all_bans().is_empty());
}

#[tokio::test]
async fn runtime_whitelist_add_removes_bans_from_enforcer() {
    let dir = TempDir::new().unwrap();
    let mut sm = StateManager::new(dir.path(), WalSyncMode::None).unwrap();
    sm.add_ban(ban("17.166.20.0/24")).unwrap();
    let state = Arc::new(Mutex::new(sm));

    let enforcer_inner = RecordingEnforcer::default();
    let removed = enforcer_inner.removed.clone();
    let enforcer: Arc<Mutex<Box<dyn Enforcer>>> = Arc::new(Mutex::new(Box::new(enforcer_inner)));

    let revoked = {
        let mut st = state.lock().await;
        st.add_whitelist("17.0.0.0/8".parse().unwrap()).unwrap()
    };
    whitelist_sync::drop_from_enforcer(&enforcer, &revoked).await.unwrap();

    assert_eq!(
        *removed.lock().await,
        vec!["17.166.20.0/24".parse::<IpNet>().unwrap()]
    );
}
