use std::fs::OpenOptions;
use std::io::Write;

use chrono::Utc;
use hiveguard_core::ban_store::BanStore;
use hiveguard_core::models::{BanRecord, BanSource};
use hiveguard_core::persistence::{wal::WalSyncMode, StateManager};

#[test]
fn revocation_after_recovering_a_partial_tail_survives_the_next_restart() {
    let directory = tempfile::tempdir().unwrap();
    let old = BanRecord {
        subject: "11.22.33.44/32".parse().unwrap(),
        created_at: Utc::now() - chrono::Duration::hours(1),
        expires_at: Some(Utc::now() + chrono::Duration::hours(1)),
        severity: 150,
        reason: "test".into(),
        evidence_hash: [0; 32],
        source: BanSource::ManualAdmin,
        geo_info: None,
    };
    let mut state = StateManager::new(directory.path(), WalSyncMode::Sync).unwrap();
    state.add_ban(old.clone()).unwrap();
    drop(state);
    // Simulate power loss after only the next record's length was written.
    OpenOptions::new()
        .append(true)
        .open(directory.path().join("wal.bin"))
        .unwrap()
        .write_all(&100u32.to_le_bytes())
        .unwrap();
    let mut state = StateManager::new(directory.path(), WalSyncMode::Sync).unwrap();
    assert!(state.revoke_ban(&old.subject).unwrap());
    drop(state);
    let recovered = StateManager::new(directory.path(), WalSyncMode::Sync).unwrap();
    assert!(recovered.ban_store().get_all_bans().is_empty());
    assert!(!recovered.accepts_remote_ban(&old));
}
