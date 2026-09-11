use std::collections::HashMap;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use ipnet::IpNet;
use tracing::{info, warn};

use crate::ban_store::{BanStore, InMemoryBanStore};
use crate::crdt::CrdtBanRecord;
use crate::errors::HiveGuardError;
use crate::models::BanRecord;
use crate::whitelist::WhitelistManager;

use super::snapshot::{load_snapshot_v2, save_snapshot_with_revocations};
use super::wal::{WalEntry, WalReader, WalSyncMode, WalWriter};

/// A ban is only extended when the new expiry is at least this much later.
const MIN_BAN_EXTENSION: chrono::Duration = chrono::Duration::minutes(5);

/// Result of [`StateManager::admit_ban`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BanAdmission {
    /// No active ban covered the subject; the ban was stored.
    Added,
    /// The subject already had an active ban that ran out sooner; its expiry
    /// was pushed out. The firewall already holds the subject.
    Extended { previous_expiry: Option<DateTime<Utc>> },
    /// An active ban (the subject itself or a wider network) already lasts at
    /// least as long; nothing was stored.
    AlreadyCovered { by: IpNet, expires_at: Option<DateTime<Utc>> },
}

/// Coordinates persistence: in-memory state + WAL + snapshots.
/// Includes both legacy BanRecord store and CRDT ban record store.
pub struct StateManager {
    ban_store: InMemoryBanStore,
    whitelist: WhitelistManager,
    crdt_store: HashMap<IpNet, CrdtBanRecord>,
    revocations: HashMap<IpNet, chrono::DateTime<chrono::Utc>>,
    wal_writer: WalWriter,
    snapshot_path: PathBuf,
    data_dir: PathBuf,
}

impl StateManager {
    /// Create a new StateManager, recovering state from snapshot + WAL replay.
    pub fn new(data_dir: &Path, sync_mode: WalSyncMode) -> Result<Self, HiveGuardError> {
        let snapshot_path = data_dir.join("snapshot.bin");
        let wal_path = data_dir.join("wal.bin");

        let mut ban_store = InMemoryBanStore::new();
        let mut whitelist = WhitelistManager::new();
        let mut crdt_store: HashMap<IpNet, CrdtBanRecord> = HashMap::new();

        let mut revocations = HashMap::new();

        // 1. Try loading snapshot (v2 with CRDT support)
        if snapshot_path.exists() {
            match load_snapshot_v2(&snapshot_path) {
                Ok(result) => {
                    info!(
                        bans = result.bans.len(),
                        whitelist = result.whitelist.len(),
                        crdt_bans = result.crdt_bans.len(),
                        "Loaded snapshot"
                    );
                    revocations.extend(result.revocations);
                    for ban in result.bans {
                        ban_store.add_ban(ban)?;
                    }
                    for net in result.whitelist {
                        whitelist.add(net);
                    }
                    for crdt_ban in result.crdt_bans {
                        crdt_store.insert(crdt_ban.subject, crdt_ban);
                    }
                }
                Err(e) => {
                    return Err(HiveGuardError::Storage(format!(
                        "cannot recover snapshot {}; refusing to start with empty state: {e}",
                        snapshot_path.display()
                    )));
                }
            }
        }

        // 2. Replay WAL on top of snapshot state
        if wal_path.exists() {
            let entries = WalReader::replay(&wal_path)?;
            if !entries.is_empty() {
                info!(count = entries.len(), "Replaying WAL entries");
                for entry in entries {
                    match entry {
                        WalEntry::AddBan(record) => {
                            ban_store.add_ban(record)?;
                        }
                        WalEntry::RevokeBan(subject, cutoff) => {
                            revocations.insert(subject, cutoff);
                            ban_store.remove_ban(&subject)?;
                        }
                        WalEntry::RemoveBan(subject) => {
                            ban_store.remove_ban(&subject)?;
                        }
                        WalEntry::AddWhitelist(net) => {
                            whitelist.add(net);
                        }
                        WalEntry::RemoveWhitelist(net) => {
                            whitelist.remove(&net);
                        }
                        WalEntry::AddCrdtBan(record) => {
                            let subject = record.subject;
                            if let Some(existing) = crdt_store.get(&subject) {
                                if let Some(merged) = existing.merge(&record) {
                                    crdt_store.insert(subject, merged);
                                }
                            } else {
                                crdt_store.insert(subject, record);
                            }
                        }
                        WalEntry::TombstoneCrdtBan(subject) => {
                            if let Some(existing) = crdt_store.get_mut(&subject) {
                                existing.tombstone = true;
                            }
                        }
                    }
                }
            }
        }

        let wal_writer = WalWriter::open(data_dir, sync_mode)?;

        Ok(Self {
            ban_store,
            whitelist,
            crdt_store,
            revocations,
            wal_writer,
            snapshot_path,
            data_dir: data_dir.to_path_buf(),
        })
    }

    /// Add a ban: write to WAL first, then update in-memory store.
    pub fn add_ban(&mut self, mut record: BanRecord) -> Result<(), HiveGuardError> {
        record.subject = record.subject.trunc();
        if self.whitelist.overlaps(&record.subject) {
            return Err(HiveGuardError::Config(format!(
                "ban {} overlaps a protected network", record.subject
            )));
        }
        self.wal_writer.append(&WalEntry::AddBan(record.clone()))?;
        self.ban_store.add_ban(record)?;
        Ok(())
    }

    /// Add a ban unless an active ban already covers it for at least as long.
    ///
    /// Check and insert happen in one call, so a caller holding the state
    /// lock gets them atomically: a burst of signals for one subject (e.g. a
    /// scanner's 25 requests read from the log in one chunk) yields one ban,
    /// not one per request. A later, longer ban for the same subject extends
    /// the existing one instead of being dropped, and a shorter one no longer
    /// overwrites a longer ban (the plain `add_ban` overwrites unconditionally).
    pub fn admit_ban(
        &mut self,
        mut record: BanRecord,
        now: DateTime<Utc>,
    ) -> Result<BanAdmission, HiveGuardError> {
        let is_active = |b: &BanRecord| b.expires_at.map_or(true, |exp| exp > now);
        // Records built milliseconds apart in one burst differ in expiry by
        // those milliseconds; that must not count as an extension.
        let outlasts = |existing: Option<DateTime<Utc>>, new: Option<DateTime<Utc>>| match (existing, new) {
            (None, _) => true,
            (Some(_), None) => false,
            (Some(e), Some(n)) => e + MIN_BAN_EXTENSION >= n,
        };

        let covering = self.ban_store.covering_bans(&record.subject);
        if let Some(by) = covering
            .iter()
            .find(|b| is_active(b) && outlasts(b.expires_at, record.expires_at))
        {
            return Ok(BanAdmission::AlreadyCovered {
                by: by.subject,
                expires_at: by.expires_at,
            });
        }

        let extended_from = covering
            .iter()
            .find(|b| b.subject == record.subject && is_active(b))
            .map(|b| (b.created_at, b.expires_at));

        let outcome = match extended_from {
            Some((created_at, previous_expiry)) => {
                // Keep the original start so "banned since" stays truthful.
                record.created_at = created_at;
                BanAdmission::Extended { previous_expiry }
            }
            None => BanAdmission::Added,
        };
        self.add_ban(record)?;
        Ok(outcome)
    }

    /// Remove a ban: write to WAL first, then update in-memory store.
    pub fn remove_ban(&mut self, subject: &IpNet) -> Result<bool, HiveGuardError> {
        self.wal_writer.append(&WalEntry::RemoveBan(*subject))?;
        self.ban_store.remove_ban(subject)
    }

    /// Administrative unban: one durable entry both removes the ban and prevents
    /// peers from resurrecting an older decision, including after a restart.
    /// This is local policy, not a cluster-wide signed revocation protocol.
    pub fn revoke_ban(&mut self, subject: &IpNet) -> Result<bool, HiveGuardError> {
        let subject = subject.trunc();
        let mut cutoff = chrono::Utc::now();
        if let Some(record) = self.ban_store.get_all_bans().into_iter().find(|b| b.subject == subject) {
            cutoff = cutoff.max(record.created_at);
        }
        if let Some(previous) = self.revocations.get(&subject) {
            cutoff = cutoff.max(*previous);
        }
        self.wal_writer.append(&WalEntry::RevokeBan(subject, cutoff))?;
        self.revocations.insert(subject, cutoff);
        self.ban_store.remove_ban(&subject)
    }

    pub fn accepts_remote_ban(&self, record: &BanRecord) -> bool {
        !self.whitelist.overlaps(&record.subject)
            && !self.revocations.iter().any(|(subject, cutoff)| {
                (subject.contains(&record.subject.addr()) || record.subject.contains(&subject.addr()))
                    && record.created_at <= *cutoff
            })
    }

    /// Add a whitelist entry: write to WAL, update in-memory, then revoke any
    /// ban the new entry now covers.
    ///
    /// Returns the ban subjects that were revoked so the caller can drop them
    /// from the firewall too. A whitelist entry that leaves existing bans in
    /// place is not protection — the ban outlives the entry and comes back on
    /// every restart via the enforcer sync.
    pub fn add_whitelist(&mut self, net: IpNet) -> Result<Vec<IpNet>, HiveGuardError> {
        self.wal_writer.append(&WalEntry::AddWhitelist(net))?;
        self.whitelist.add(net);
        self.revoke_bans_covered_by_whitelist()
    }

    /// Remove every ban whose subject overlaps the whitelist (configured or
    /// immutable), returning the revoked subjects.
    ///
    /// Overlap — not address containment — is the test: a `/24` ban subject
    /// overlapping a `/32` whitelist entry must go, even though the ban's
    /// network address is not itself whitelisted.
    pub fn revoke_bans_covered_by_whitelist(&mut self) -> Result<Vec<IpNet>, HiveGuardError> {
        let covered: Vec<IpNet> = self
            .ban_store
            .get_all_bans()
            .iter()
            .map(|b| b.subject)
            .filter(|subject| self.whitelist.overlaps(subject))
            .collect();

        let mut revoked = Vec::with_capacity(covered.len());
        for subject in covered {
            if self.remove_ban(&subject)? {
                revoked.push(subject);
            }
            // Tombstone the CRDT record too, otherwise cluster anti-entropy
            // re-imports the ban we just revoked on the next gossip round.
            if self.crdt_store.contains_key(&subject) {
                self.tombstone_crdt_ban(subject)?;
            }
        }
        Ok(revoked)
    }

    /// Remove a whitelist entry: write to WAL, then update in-memory.
    pub fn remove_whitelist(&mut self, net: &IpNet) -> Result<(), HiveGuardError> {
        self.wal_writer.append(&WalEntry::RemoveWhitelist(*net))?;
        self.whitelist.remove(net);
        Ok(())
    }

    /// Add a CRDT ban record: write to WAL, then merge into in-memory store.
    pub fn add_crdt_ban(&mut self, record: CrdtBanRecord) -> Result<(), HiveGuardError> {
        self.wal_writer
            .append(&WalEntry::AddCrdtBan(record.clone()))?;
        let subject = record.subject;
        if let Some(existing) = self.crdt_store.get(&subject) {
            if let Some(merged) = existing.merge(&record) {
                self.crdt_store.insert(subject, merged);
            }
        } else {
            self.crdt_store.insert(subject, record);
        }
        Ok(())
    }

    /// Tombstone a CRDT ban record: write to WAL, then mark in-memory.
    pub fn tombstone_crdt_ban(&mut self, subject: IpNet) -> Result<bool, HiveGuardError> {
        self.wal_writer
            .append(&WalEntry::TombstoneCrdtBan(subject))?;
        if let Some(existing) = self.crdt_store.get_mut(&subject) {
            existing.tombstone = true;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Get all CRDT ban records (including tombstoned/expired).
    pub fn crdt_store(&self) -> &HashMap<IpNet, CrdtBanRecord> {
        &self.crdt_store
    }

    /// Get mutable reference to CRDT store.
    pub fn crdt_store_mut(&mut self) -> &mut HashMap<IpNet, CrdtBanRecord> {
        &mut self.crdt_store
    }

    /// Get active (non-tombstoned, non-expired) CRDT ban records.
    pub fn get_active_crdt_bans(&self, current_time_ms: u64) -> Vec<&CrdtBanRecord> {
        self.crdt_store
            .values()
            .filter(|r| r.is_active(current_time_ms))
            .collect()
    }

    /// Take a snapshot: save current state (including CRDT), then truncate WAL.
    pub fn take_snapshot(&mut self) -> Result<(), HiveGuardError> {
        let bans: Vec<BanRecord> = self.ban_store.get_all_bans().into_iter().cloned().collect();
        let whitelist: Vec<IpNet> = self.whitelist.entries().iter().cloned().collect();
        let crdt_bans: Vec<CrdtBanRecord> = self.crdt_store.values().cloned().collect();

        let revocations: Vec<_> = self.revocations.iter().map(|(s, t)| (*s, *t)).collect();
        save_snapshot_with_revocations(&self.snapshot_path, &bans, &whitelist, &crdt_bans, &revocations)?;
        self.wal_writer.truncate()?;

        info!(
            bans = bans.len(),
            whitelist = whitelist.len(),
            crdt_bans = crdt_bans.len(),
            "Snapshot saved"
        );
        Ok(())
    }

    /// Flush the WAL (sync to disk without truncating).
    pub fn flush_wal(&mut self) -> Result<(), HiveGuardError> {
        self.wal_writer.flush()
    }

    /// Access the in-memory ban store (immutable).
    pub fn ban_store(&self) -> &InMemoryBanStore {
        &self.ban_store
    }

    /// Access the in-memory ban store (mutable, e.g. for cleanup_expired).
    pub fn ban_store_mut(&mut self) -> &mut InMemoryBanStore {
        &mut self.ban_store
    }

    /// Access the whitelist manager (immutable).
    pub fn whitelist(&self) -> &WhitelistManager {
        &self.whitelist
    }

    /// Access the whitelist manager (mutable).
    pub fn whitelist_mut(&mut self) -> &mut WhitelistManager {
        &mut self.whitelist
    }

    /// Get the data directory path.
    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{BanRecord, BanSource};
    use chrono::Utc;
    use std::net::IpAddr;
    use tempfile::TempDir;

    fn make_ban(cidr: &str) -> BanRecord {
        BanRecord {
            subject: cidr.parse().unwrap(),
            created_at: Utc::now(),
            expires_at: Some(Utc::now() + chrono::Duration::hours(24)),
            severity: 150,
            reason: format!("test ban for {}", cidr),
            evidence_hash: [99u8; 32],
            source: BanSource::LocalDetector("test_detector".into()),
            geo_info: None,
        }
    }

    #[test]
    fn unreadable_snapshot_never_starts_with_empty_state_or_modifies_wal() {
        let dir = TempDir::new().unwrap();
        let bad = b"HVGD0004broken";
        std::fs::write(dir.path().join("snapshot.bin"), bad).unwrap();
        std::fs::write(dir.path().join("wal.bin"), b"partial tail").unwrap();
        assert!(StateManager::new(dir.path(), WalSyncMode::Sync).is_err());
        assert_eq!(std::fs::read(dir.path().join("snapshot.bin")).unwrap(), bad);
        assert_eq!(std::fs::read(dir.path().join("wal.bin")).unwrap(), b"partial tail");
    }

    #[test]
    fn protected_bans_are_rejected_before_wal_write() {
        let dir = TempDir::new().unwrap();
        let mut sm = StateManager::new(dir.path(), WalSyncMode::None).unwrap();
        sm.add_whitelist("11.22.33.5/32".parse().unwrap()).unwrap();
        sm.add_whitelist("2001:4860:1234::5/128".parse().unwrap()).unwrap();
        for subject in ["127.0.0.1/32", "10.0.0.1/32", "11.22.33.0/24", "2001:4860:1234::/48"] {
            assert!(sm.add_ban(make_ban(subject)).is_err(), "{subject}");
        }
        drop(sm);
        let recovered = StateManager::new(dir.path(), WalSyncMode::None).unwrap();
        assert!(recovered.ban_store().get_all_bans().is_empty());
    }

    #[test]
    fn administrative_revocation_survives_wal_and_snapshot_recovery() {
        let dir = TempDir::new().unwrap();
        let mut old = make_ban("11.22.33.5/32");
        old.created_at = Utc::now() - chrono::Duration::hours(1);
        let mut sm = StateManager::new(dir.path(), WalSyncMode::None).unwrap();
        sm.add_ban(old.clone()).unwrap();
        assert!(sm.revoke_ban(&old.subject).unwrap());
        for snapshot in [false, true] {
            if snapshot { sm.take_snapshot().unwrap(); }
            drop(sm);
            sm = StateManager::new(dir.path(), WalSyncMode::None).unwrap();
            assert!(sm.ban_store().get_all_bans().is_empty());
            assert!(!sm.accepts_remote_ban(&old));
            let mut wider = old.clone();
            wider.subject = "11.22.33.0/24".parse().unwrap();
            assert!(!sm.accepts_remote_ban(&wider));
            let mut fresh = old.clone();
            fresh.created_at = Utc::now() + chrono::Duration::seconds(1);
            assert!(sm.accepts_remote_ban(&fresh));
        }
    }

    #[test]
    fn add_bans_snapshot_restart_recovery() {
        let dir = TempDir::new().unwrap();

        // Phase 1: add bans + snapshot
        {
            let mut sm = StateManager::new(dir.path(), WalSyncMode::None).unwrap();
            sm.add_ban(make_ban("11.0.0.1/32")).unwrap();
            sm.add_ban(make_ban("193.168.1.0/24")).unwrap();
            sm.add_ban(make_ban("173.16.0.0/12")).unwrap();
            sm.take_snapshot().unwrap();
        }

        // Phase 2: restart — bans recovered from snapshot
        {
            let sm = StateManager::new(dir.path(), WalSyncMode::None).unwrap();
            let store = sm.ban_store();
            assert_eq!(store.get_all_bans().len(), 3);

            let ip: IpAddr = "11.0.0.1".parse().unwrap();
            assert!(store.is_banned(&ip).is_some());

            let ip2: IpAddr = "193.168.1.50".parse().unwrap();
            assert!(store.is_banned(&ip2).is_some());

            let ip3: IpAddr = "173.20.0.1".parse().unwrap();
            assert!(store.is_banned(&ip3).is_some());
        }
    }

    #[test]
    fn add_bans_no_snapshot_wal_replay_recovery() {
        let dir = TempDir::new().unwrap();

        // Phase 1: add bans WITHOUT snapshot
        {
            let mut sm = StateManager::new(dir.path(), WalSyncMode::None).unwrap();
            sm.add_ban(make_ban("11.0.0.1/32")).unwrap();
            sm.add_ban(make_ban("11.0.0.2/32")).unwrap();
            // No snapshot — only WAL
        }

        // Phase 2: restart — bans recovered from WAL replay
        {
            let sm = StateManager::new(dir.path(), WalSyncMode::None).unwrap();
            let store = sm.ban_store();
            assert_eq!(store.get_all_bans().len(), 2);

            let ip: IpAddr = "11.0.0.1".parse().unwrap();
            assert!(store.is_banned(&ip).is_some());

            let ip2: IpAddr = "11.0.0.2".parse().unwrap();
            assert!(store.is_banned(&ip2).is_some());
        }
    }

    #[test]
    fn snapshot_plus_wal_replay() {
        let dir = TempDir::new().unwrap();

        // Phase 1: add some bans, snapshot, then add more
        {
            let mut sm = StateManager::new(dir.path(), WalSyncMode::None).unwrap();
            sm.add_ban(make_ban("11.0.0.1/32")).unwrap();
            sm.take_snapshot().unwrap();
            // After snapshot, add more
            sm.add_ban(make_ban("11.0.0.2/32")).unwrap();
            sm.add_ban(make_ban("11.0.0.3/32")).unwrap();
            // These two are in WAL only (post-snapshot)
        }

        // Phase 2: restart — snapshot(1 ban) + WAL(2 bans) = 3 bans
        {
            let sm = StateManager::new(dir.path(), WalSyncMode::None).unwrap();
            assert_eq!(sm.ban_store().get_all_bans().len(), 3);
        }
    }

    #[test]
    fn remove_ban_persists() {
        let dir = TempDir::new().unwrap();

        {
            let mut sm = StateManager::new(dir.path(), WalSyncMode::None).unwrap();
            sm.add_ban(make_ban("11.0.0.1/32")).unwrap();
            sm.add_ban(make_ban("11.0.0.2/32")).unwrap();
            sm.remove_ban(&"11.0.0.1/32".parse().unwrap()).unwrap();
        }

        // Restart: WAL replay should show 1 ban (added 2, removed 1)
        {
            let sm = StateManager::new(dir.path(), WalSyncMode::None).unwrap();
            assert_eq!(sm.ban_store().get_all_bans().len(), 1);

            let ip: IpAddr = "11.0.0.2".parse().unwrap();
            assert!(sm.ban_store().is_banned(&ip).is_some());

            let removed_ip: IpAddr = "11.0.0.1".parse().unwrap();
            assert!(sm.ban_store().is_banned(&removed_ip).is_none());
        }
    }

    #[test]
    fn whitelist_persists_through_wal() {
        let dir = TempDir::new().unwrap();

        {
            let mut sm = StateManager::new(dir.path(), WalSyncMode::None).unwrap();
            sm.add_whitelist("127.0.0.0/8".parse().unwrap()).unwrap();
            sm.add_whitelist("11.0.0.0/8".parse().unwrap()).unwrap();
        }

        // Restart: whitelist recovered from WAL
        {
            let sm = StateManager::new(dir.path(), WalSyncMode::None).unwrap();
            let ip: IpAddr = "127.0.0.1".parse().unwrap();
            assert!(sm.whitelist().is_whitelisted(&ip));

            let ip2: IpAddr = "11.5.5.5".parse().unwrap();
            assert!(sm.whitelist().is_whitelisted(&ip2));
        }
    }

    /// Defect A: a whitelist entry added after the fact must invalidate the
    /// bans it covers, not wait for them to expire.
    #[test]
    fn whitelist_add_revokes_existing_overlapping_bans() {
        let dir = TempDir::new().unwrap();
        let mut sm = StateManager::new(dir.path(), WalSyncMode::None).unwrap();

        sm.add_ban(make_ban("17.166.20.0/24")).unwrap();
        sm.add_ban(make_ban("17.166.237.0/24")).unwrap();
        sm.add_ban(make_ban("45.33.0.9/32")).unwrap(); // untouched by the entry
        assert_eq!(sm.ban_store().get_all_bans().len(), 3);

        let revoked = sm.add_whitelist("17.0.0.0/8".parse().unwrap()).unwrap();

        assert_eq!(revoked.len(), 2, "both Applebot subnets should be revoked");
        let remaining = sm.ban_store().get_all_bans();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].subject.to_string(), "45.33.0.9/32");
    }

    /// Defect A + B together: the whitelist entry is *narrower* than the ban.
    #[test]
    fn whitelist_add_revokes_ban_wider_than_the_entry() {
        let dir = TempDir::new().unwrap();
        let mut sm = StateManager::new(dir.path(), WalSyncMode::None).unwrap();

        // distributed_slow bans a /24 that happens to contain the admin's IP.
        sm.add_ban(make_ban("100.64.229.0/24")).unwrap();

        let revoked = sm
            .add_whitelist("100.64.229.178/32".parse().unwrap())
            .unwrap();

        assert_eq!(revoked, vec!["100.64.229.0/24".parse::<IpNet>().unwrap()]);
        assert!(sm.ban_store().get_all_bans().is_empty());
    }

    #[test]
    fn revoked_bans_stay_revoked_after_restart() {
        let dir = TempDir::new().unwrap();
        {
            let mut sm = StateManager::new(dir.path(), WalSyncMode::None).unwrap();
            sm.add_ban(make_ban("17.166.20.0/24")).unwrap();
            sm.add_whitelist("17.0.0.0/8".parse().unwrap()).unwrap();
        }
        // WAL replay must not resurrect the ban — the revoke was journalled.
        let sm = StateManager::new(dir.path(), WalSyncMode::None).unwrap();
        assert!(sm.ban_store().get_all_bans().is_empty());
    }

    #[test]
    fn whitelist_add_leaves_unrelated_bans_alone() {
        let dir = TempDir::new().unwrap();
        let mut sm = StateManager::new(dir.path(), WalSyncMode::None).unwrap();

        sm.add_ban(make_ban("45.33.0.0/24")).unwrap();
        let revoked = sm.add_whitelist("17.0.0.0/8".parse().unwrap()).unwrap();

        assert!(revoked.is_empty());
        assert_eq!(sm.ban_store().get_all_bans().len(), 1);
    }

    #[test]
    fn whitelist_persists_through_snapshot() {
        let dir = TempDir::new().unwrap();

        {
            let mut sm = StateManager::new(dir.path(), WalSyncMode::None).unwrap();
            sm.add_whitelist("127.0.0.0/8".parse().unwrap()).unwrap();
            sm.take_snapshot().unwrap();
        }

        {
            let sm = StateManager::new(dir.path(), WalSyncMode::None).unwrap();
            let ip: IpAddr = "127.0.0.1".parse().unwrap();
            assert!(sm.whitelist().is_whitelisted(&ip));
        }
    }

    #[test]
    fn fresh_start_empty_state() {
        let dir = TempDir::new().unwrap();
        let sm = StateManager::new(dir.path(), WalSyncMode::None).unwrap();
        assert!(sm.ban_store().get_all_bans().is_empty());
        assert!(sm.whitelist().entries().is_empty());
    }

    #[test]
    fn snapshot_truncates_wal() {
        let dir = TempDir::new().unwrap();
        let wal_path = dir.path().join("wal.bin");

        {
            let mut sm = StateManager::new(dir.path(), WalSyncMode::None).unwrap();
            sm.add_ban(make_ban("11.0.0.1/32")).unwrap();
            sm.add_ban(make_ban("11.0.0.2/32")).unwrap();

            // WAL should have entries
            assert!(wal_path.exists());
            let wal_size_before = std::fs::metadata(&wal_path).unwrap().len();
            assert!(wal_size_before > 0);

            sm.take_snapshot().unwrap();

            // WAL should be truncated
            let wal_size_after = std::fs::metadata(&wal_path).unwrap().len();
            assert_eq!(wal_size_after, 0);
        }
    }

    #[test]
    fn multiple_snapshot_cycles() {
        let dir = TempDir::new().unwrap();

        {
            let mut sm = StateManager::new(dir.path(), WalSyncMode::None).unwrap();
            sm.add_ban(make_ban("11.0.0.1/32")).unwrap();
            sm.take_snapshot().unwrap();

            sm.add_ban(make_ban("11.0.0.2/32")).unwrap();
            sm.take_snapshot().unwrap();

            sm.add_ban(make_ban("11.0.0.3/32")).unwrap();
            // Last ban only in WAL
        }

        {
            let sm = StateManager::new(dir.path(), WalSyncMode::None).unwrap();
            assert_eq!(sm.ban_store().get_all_bans().len(), 3);
        }
    }

    // --- Phase 10: comprehensive coverage ---

    #[test]
    fn remove_whitelist_persists() {
        let dir = TempDir::new().unwrap();

        {
            let mut sm = StateManager::new(dir.path(), WalSyncMode::None).unwrap();
            sm.add_whitelist("5.0.0.0/8".parse().unwrap()).unwrap();
            sm.add_whitelist("6.0.0.0/8".parse().unwrap()).unwrap();
            sm.remove_whitelist(&"5.0.0.0/8".parse().unwrap()).unwrap();
        }

        {
            let sm = StateManager::new(dir.path(), WalSyncMode::None).unwrap();
            assert!(!sm.whitelist().is_whitelisted(&"5.5.5.5".parse().unwrap()));
            assert!(sm.whitelist().is_whitelisted(&"6.0.0.1".parse().unwrap()));
            assert_eq!(sm.whitelist().entries().len(), 1);
        }
    }

    #[test]
    fn mixed_operations_wal_replay() {
        let dir = TempDir::new().unwrap();

        {
            let mut sm = StateManager::new(dir.path(), WalSyncMode::None).unwrap();
            // Public subjects on purpose: RFC 1918 addresses are immutably
            // protected, and `add_whitelist` now revokes bans covering them.
            sm.add_ban(make_ban("45.33.0.1/32")).unwrap();
            sm.add_ban(make_ban("45.33.0.2/32")).unwrap();
            sm.add_whitelist("6.0.0.0/8".parse().unwrap()).unwrap();
            sm.remove_ban(&"45.33.0.1/32".parse().unwrap()).unwrap();
            sm.add_ban(make_ban("45.33.0.3/32")).unwrap();
            sm.add_whitelist("::1/128".parse().unwrap()).unwrap();
            sm.remove_whitelist(&"6.0.0.0/8".parse().unwrap()).unwrap();
        }

        {
            let sm = StateManager::new(dir.path(), WalSyncMode::None).unwrap();
            assert_eq!(sm.ban_store().get_all_bans().len(), 2); // .2 and .3
            assert!(sm.ban_store().is_banned(&"45.33.0.2".parse().unwrap()).is_some());
            assert!(sm.ban_store().is_banned(&"45.33.0.3".parse().unwrap()).is_some());
            assert!(sm.ban_store().is_banned(&"45.33.0.1".parse().unwrap()).is_none());

            assert!(sm.whitelist().is_whitelisted(&"::1".parse().unwrap()));
            assert!(!sm.whitelist().is_whitelisted(&"6.0.0.1".parse().unwrap()));
        }
    }

    #[test]
    fn ban_store_mut_cleanup_expired() {
        let dir = TempDir::new().unwrap();
        let mut sm = StateManager::new(dir.path(), WalSyncMode::None).unwrap();

        let past = Utc::now() - chrono::Duration::hours(1);
        let expired_ban = BanRecord {
            subject: "11.0.0.1/32".parse().unwrap(),
            created_at: past - chrono::Duration::hours(2),
            expires_at: Some(past),
            severity: 100,
            reason: "expired".into(),
            evidence_hash: [0u8; 32],
            source: BanSource::LocalDetector("test".into()),
            geo_info: None,
        };
        sm.add_ban(expired_ban).unwrap();
        sm.add_ban(make_ban("11.0.0.2/32")).unwrap();

        let removed = sm.ban_store_mut().cleanup_expired();
        assert_eq!(removed, 1);
        assert_eq!(sm.ban_store().get_all_bans().len(), 1);
    }

    #[test]
    fn data_dir_accessor() {
        let dir = TempDir::new().unwrap();
        let sm = StateManager::new(dir.path(), WalSyncMode::None).unwrap();
        assert_eq!(sm.data_dir(), dir.path());
    }

    #[test]
    fn snapshot_then_wal_then_snapshot_recovery() {
        let dir = TempDir::new().unwrap();

        {
            let mut sm = StateManager::new(dir.path(), WalSyncMode::None).unwrap();
            sm.add_ban(make_ban("11.0.0.1/32")).unwrap();
            sm.take_snapshot().unwrap();
            sm.add_ban(make_ban("11.0.0.2/32")).unwrap();
            sm.take_snapshot().unwrap();
        }

        // After second snapshot, everything should be in snapshot
        {
            let sm = StateManager::new(dir.path(), WalSyncMode::None).unwrap();
            assert_eq!(sm.ban_store().get_all_bans().len(), 2);
        }
    }

    #[test]
    fn ipv6_bans_persist() {
        let dir = TempDir::new().unwrap();

        {
            let mut sm = StateManager::new(dir.path(), WalSyncMode::None).unwrap();
            let ban = BanRecord {
                subject: "2001:db8::/32".parse().unwrap(),
                created_at: Utc::now(),
                expires_at: Some(Utc::now() + chrono::Duration::hours(24)),
                severity: 150,
                reason: "IPv6 test".into(),
                evidence_hash: [0xAB; 32],
                source: BanSource::LocalDetector("test".into()),
                geo_info: None,
            };
            sm.add_ban(ban).unwrap();
            sm.take_snapshot().unwrap();
        }

        {
            let sm = StateManager::new(dir.path(), WalSyncMode::None).unwrap();
            let ip: IpAddr = "2001:db8::dead:beef".parse().unwrap();
            assert!(sm.ban_store().is_banned(&ip).is_some());
        }
    }

    #[test]
    fn crash_simulation_wal_only_recovery() {
        // Simulate crash: add bans, drop StateManager without snapshot
        let dir = TempDir::new().unwrap();

        {
            let mut sm = StateManager::new(dir.path(), WalSyncMode::None).unwrap();
            sm.add_ban(make_ban("11.0.0.1/32")).unwrap();
            sm.add_ban(make_ban("11.0.0.2/32")).unwrap();
            sm.add_ban(make_ban("11.0.0.3/32")).unwrap();
            // Simulated crash: drop without snapshot
        }

        // Recovery: all bans from WAL
        {
            let sm = StateManager::new(dir.path(), WalSyncMode::None).unwrap();
            assert_eq!(sm.ban_store().get_all_bans().len(), 3);
        }
    }

    #[test]
    fn crash_simulation_snapshot_plus_wal() {
        // Simulate: snapshot, add more bans, crash
        let dir = TempDir::new().unwrap();

        {
            let mut sm = StateManager::new(dir.path(), WalSyncMode::None).unwrap();
            sm.add_ban(make_ban("11.0.0.1/32")).unwrap();
            sm.add_ban(make_ban("11.0.0.2/32")).unwrap();
            sm.take_snapshot().unwrap();

            // Post-snapshot operations (only in WAL)
            sm.add_ban(make_ban("11.0.0.3/32")).unwrap();
            sm.add_ban(make_ban("11.0.0.4/32")).unwrap();
            sm.remove_ban(&"11.0.0.1/32".parse().unwrap()).unwrap();
            // Crash: no final snapshot
        }

        // Recovery: snapshot(2) + WAL(add 2, remove 1) = 3 bans
        {
            let sm = StateManager::new(dir.path(), WalSyncMode::None).unwrap();
            assert_eq!(sm.ban_store().get_all_bans().len(), 3);
            assert!(sm.ban_store().is_banned(&"11.0.0.1".parse().unwrap()).is_none());
            assert!(sm.ban_store().is_banned(&"11.0.0.2".parse().unwrap()).is_some());
            assert!(sm.ban_store().is_banned(&"11.0.0.3".parse().unwrap()).is_some());
            assert!(sm.ban_store().is_banned(&"11.0.0.4".parse().unwrap()).is_some());
        }
    }

    #[test]
    fn crash_simulation_corrupt_wal_partial_recovery() {
        // Simulate crash with WAL corruption
        let dir = TempDir::new().unwrap();
        let wal_path = dir.path().join("wal.bin");

        {
            let mut sm = StateManager::new(dir.path(), WalSyncMode::None).unwrap();
            sm.add_ban(make_ban("11.0.0.1/32")).unwrap();
            sm.add_ban(make_ban("11.0.0.2/32")).unwrap();
            sm.add_ban(make_ban("11.0.0.3/32")).unwrap();
        }

        // Corrupt WAL: truncate last entry
        let data = std::fs::read(&wal_path).unwrap();
        let truncated = data.len() - 10;
        std::fs::write(&wal_path, &data[..truncated]).unwrap();

        // Recovery: 2 of 3 bans should survive
        {
            let sm = StateManager::new(dir.path(), WalSyncMode::None).unwrap();
            assert_eq!(sm.ban_store().get_all_bans().len(), 2);
        }
    }

    // --- Phase 19: CRDT persistence tests ---

    fn make_crdt_ban(cidr: &str, reason: &str) -> CrdtBanRecord {
        use crate::hlc::HlcTimestamp;
        use std::collections::HashSet;

        let node_hash = HlcTimestamp::hash_node_id("test-node");
        let now = HlcTimestamp::now(node_hash);
        let ban_until = HlcTimestamp::new(
            now.wall_time_ms + 86_400_000,
            0,
            node_hash,
        );
        CrdtBanRecord {
            subject: cidr.parse().unwrap(),
            first_seen: now.clone(),
            ban_until,
            severity: 150,
            reporters: {
                let mut s = HashSet::new();
                s.insert("test-node".to_string());
                s
            },
            evidence_hash: [42u8; 32],
            reason: reason.to_string(),
            tombstone_reporters: HashSet::new(),
            tombstone: false,
            last_modified: now,
        }
    }

    #[test]
    fn crdt_ban_add_and_query() {
        let dir = TempDir::new().unwrap();
        let mut sm = StateManager::new(dir.path(), WalSyncMode::None).unwrap();

        let ban = make_crdt_ban("11.0.0.1/32", "brute force");
        sm.add_crdt_ban(ban.clone()).unwrap();

        assert_eq!(sm.crdt_store().len(), 1);
        let stored = sm.crdt_store().get(&"11.0.0.1/32".parse::<IpNet>().unwrap());
        assert!(stored.is_some());
        assert_eq!(stored.unwrap().reason, "brute force");
    }

    #[test]
    fn crdt_ban_snapshot_recovery() {
        let dir = TempDir::new().unwrap();

        {
            let mut sm = StateManager::new(dir.path(), WalSyncMode::None).unwrap();
            sm.add_crdt_ban(make_crdt_ban("11.0.0.1/32", "ssh brute")).unwrap();
            sm.add_crdt_ban(make_crdt_ban("11.0.0.2/32", "path probe")).unwrap();
            sm.take_snapshot().unwrap();
        }

        // Recovery from snapshot
        {
            let sm = StateManager::new(dir.path(), WalSyncMode::None).unwrap();
            assert_eq!(sm.crdt_store().len(), 2);
            let b1 = sm.crdt_store().get(&"11.0.0.1/32".parse::<IpNet>().unwrap()).unwrap();
            assert_eq!(b1.reason, "ssh brute");
            let b2 = sm.crdt_store().get(&"11.0.0.2/32".parse::<IpNet>().unwrap()).unwrap();
            assert_eq!(b2.reason, "path probe");
        }
    }

    #[test]
    fn crdt_ban_wal_only_recovery() {
        let dir = TempDir::new().unwrap();

        {
            let mut sm = StateManager::new(dir.path(), WalSyncMode::None).unwrap();
            sm.add_crdt_ban(make_crdt_ban("11.0.0.1/32", "wal test")).unwrap();
            sm.add_crdt_ban(make_crdt_ban("11.0.0.2/32", "wal test 2")).unwrap();
            // No snapshot — crash simulation
        }

        // Recovery from WAL only
        {
            let sm = StateManager::new(dir.path(), WalSyncMode::None).unwrap();
            assert_eq!(sm.crdt_store().len(), 2);
        }
    }

    #[test]
    fn crdt_ban_snapshot_plus_wal_recovery() {
        let dir = TempDir::new().unwrap();

        {
            let mut sm = StateManager::new(dir.path(), WalSyncMode::None).unwrap();
            sm.add_crdt_ban(make_crdt_ban("11.0.0.1/32", "before snapshot")).unwrap();
            sm.take_snapshot().unwrap();

            sm.add_crdt_ban(make_crdt_ban("11.0.0.2/32", "after snapshot")).unwrap();
            // Crash: no final snapshot
        }

        // Recovery: snapshot(1 crdt) + WAL(1 crdt) = 2 crdt bans
        {
            let sm = StateManager::new(dir.path(), WalSyncMode::None).unwrap();
            assert_eq!(sm.crdt_store().len(), 2);
            assert!(sm.crdt_store().contains_key(&"11.0.0.1/32".parse::<IpNet>().unwrap()));
            assert!(sm.crdt_store().contains_key(&"11.0.0.2/32".parse::<IpNet>().unwrap()));
        }
    }

    #[test]
    fn crdt_ban_merge_during_wal_replay() {
        use crate::hlc::HlcTimestamp;
        use std::collections::HashSet;

        let dir = TempDir::new().unwrap();

        {
            let mut sm = StateManager::new(dir.path(), WalSyncMode::None).unwrap();

            // First version from node-a
            let mut ban1 = make_crdt_ban("11.0.0.1/32", "first");
            ban1.reporters = {
                let mut s = HashSet::new();
                s.insert("node-a".to_string());
                s
            };
            ban1.severity = 100;
            sm.add_crdt_ban(ban1).unwrap();

            // Second version from node-b with higher timestamp
            let mut ban2 = make_crdt_ban("11.0.0.1/32", "second");
            ban2.reporters = {
                let mut s = HashSet::new();
                s.insert("node-b".to_string());
                s
            };
            ban2.severity = 200;
            ban2.last_modified = HlcTimestamp::new(
                ban2.last_modified.wall_time_ms + 10_000,
                0,
                HlcTimestamp::hash_node_id("node-b"),
            );
            sm.add_crdt_ban(ban2).unwrap();

            // No snapshot — tests WAL replay merge
        }

        // Recovery: WAL replays both AddCrdtBan entries, merge combines them
        {
            let sm = StateManager::new(dir.path(), WalSyncMode::None).unwrap();
            assert_eq!(sm.crdt_store().len(), 1);
            let ban = sm.crdt_store().get(&"11.0.0.1/32".parse::<IpNet>().unwrap()).unwrap();
            // Merge takes max severity
            assert_eq!(ban.severity, 200);
            // Merge unions reporters
            assert!(ban.reporters.contains("node-a"));
            assert!(ban.reporters.contains("node-b"));
        }
    }

    #[test]
    fn crdt_tombstone_persists_via_wal() {
        let dir = TempDir::new().unwrap();

        {
            let mut sm = StateManager::new(dir.path(), WalSyncMode::None).unwrap();
            sm.add_crdt_ban(make_crdt_ban("11.0.0.1/32", "to be tombstoned")).unwrap();
            sm.add_crdt_ban(make_crdt_ban("11.0.0.2/32", "stays active")).unwrap();
            sm.tombstone_crdt_ban("11.0.0.1/32".parse().unwrap()).unwrap();
        }

        // Recovery: WAL replay should show tombstoned ban
        {
            let sm = StateManager::new(dir.path(), WalSyncMode::None).unwrap();
            assert_eq!(sm.crdt_store().len(), 2);
            let b1 = sm.crdt_store().get(&"11.0.0.1/32".parse::<IpNet>().unwrap()).unwrap();
            assert!(b1.tombstone, "Ban should be tombstoned");
            let b2 = sm.crdt_store().get(&"11.0.0.2/32".parse::<IpNet>().unwrap()).unwrap();
            assert!(!b2.tombstone, "Ban should NOT be tombstoned");
        }
    }

    #[test]
    fn crdt_tombstone_persists_via_snapshot() {
        let dir = TempDir::new().unwrap();

        {
            let mut sm = StateManager::new(dir.path(), WalSyncMode::None).unwrap();
            sm.add_crdt_ban(make_crdt_ban("11.0.0.1/32", "tomb via snap")).unwrap();
            sm.tombstone_crdt_ban("11.0.0.1/32".parse().unwrap()).unwrap();
            sm.take_snapshot().unwrap();
        }

        {
            let sm = StateManager::new(dir.path(), WalSyncMode::None).unwrap();
            let ban = sm.crdt_store().get(&"11.0.0.1/32".parse::<IpNet>().unwrap()).unwrap();
            assert!(ban.tombstone);
        }
    }

    #[test]
    fn crdt_get_active_bans() {
        let dir = TempDir::new().unwrap();
        let mut sm = StateManager::new(dir.path(), WalSyncMode::None).unwrap();

        sm.add_crdt_ban(make_crdt_ban("11.0.0.1/32", "active")).unwrap();
        sm.add_crdt_ban(make_crdt_ban("11.0.0.2/32", "will tomb")).unwrap();
        sm.tombstone_crdt_ban("11.0.0.2/32".parse().unwrap()).unwrap();

        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let active = sm.get_active_crdt_bans(now_ms);
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].reason, "active");
    }

    #[test]
    fn crdt_tombstone_nonexistent_is_noop() {
        let dir = TempDir::new().unwrap();
        let mut sm = StateManager::new(dir.path(), WalSyncMode::None).unwrap();

        // Tombstoning a non-existent ban should succeed (no-op)
        sm.tombstone_crdt_ban("11.0.0.1/32".parse().unwrap()).unwrap();
        assert!(sm.crdt_store().is_empty());
    }

    #[test]
    fn crdt_flush_wal() {
        let dir = TempDir::new().unwrap();
        let mut sm = StateManager::new(dir.path(), WalSyncMode::None).unwrap();

        sm.add_crdt_ban(make_crdt_ban("11.0.0.1/32", "flush test")).unwrap();
        sm.flush_wal().unwrap();

        // Recovery should work
        drop(sm);
        let sm2 = StateManager::new(dir.path(), WalSyncMode::None).unwrap();
        assert_eq!(sm2.crdt_store().len(), 1);
    }

    #[test]
    fn mixed_legacy_and_crdt_bans_persist() {
        let dir = TempDir::new().unwrap();

        {
            let mut sm = StateManager::new(dir.path(), WalSyncMode::None).unwrap();
            sm.add_ban(make_ban("11.0.0.1/32")).unwrap();
            sm.add_crdt_ban(make_crdt_ban("11.0.0.2/32", "crdt ban")).unwrap();
            sm.take_snapshot().unwrap();

            sm.add_ban(make_ban("11.0.0.3/32")).unwrap();
            sm.add_crdt_ban(make_crdt_ban("11.0.0.4/32", "crdt ban 2")).unwrap();
            // Crash
        }

        // Recovery: snapshot(1 legacy + 1 crdt) + WAL(1 legacy + 1 crdt)
        {
            let sm = StateManager::new(dir.path(), WalSyncMode::None).unwrap();
            assert_eq!(sm.ban_store().get_all_bans().len(), 2);
            assert_eq!(sm.crdt_store().len(), 2);
        }
    }

    #[test]
    fn crash_simulation_crdt_corrupt_wal_partial_recovery() {
        let dir = TempDir::new().unwrap();
        let wal_path = dir.path().join("wal.bin");

        {
            let mut sm = StateManager::new(dir.path(), WalSyncMode::None).unwrap();
            sm.add_crdt_ban(make_crdt_ban("11.0.0.1/32", "first crdt")).unwrap();
            sm.add_crdt_ban(make_crdt_ban("11.0.0.2/32", "second crdt")).unwrap();
            sm.add_crdt_ban(make_crdt_ban("11.0.0.3/32", "third crdt")).unwrap();
        }

        // Corrupt WAL: truncate last entry
        let data = std::fs::read(&wal_path).unwrap();
        let truncated = data.len() - 10;
        std::fs::write(&wal_path, &data[..truncated]).unwrap();

        // Recovery: at least 2 of 3 CRDT bans should survive
        {
            let sm = StateManager::new(dir.path(), WalSyncMode::None).unwrap();
            assert_eq!(sm.crdt_store().len(), 2);
        }
    }

    #[test]
    fn v1_snapshot_migration_to_v2() {
        use crate::persistence::snapshot::{save_snapshot, load_snapshot_v2};

        let dir = TempDir::new().unwrap();
        let snap_path = dir.path().join("snapshot.bin");

        // Create a v1 snapshot directly
        let bans = vec![make_ban("11.0.0.1/32")];
        let wl: Vec<IpNet> = vec!["127.0.0.0/8".parse().unwrap()];
        save_snapshot(&snap_path, &bans, &wl).unwrap();

        // Load as v2 — should get empty crdt_bans
        let result = load_snapshot_v2(&snap_path).unwrap();
        assert_eq!(result.bans.len(), 1);
        assert_eq!(result.whitelist.len(), 1);
        assert!(result.crdt_bans.is_empty(), "V1 snapshot should have no CRDT bans");

        // StateManager should handle this gracefully
        let sm = StateManager::new(dir.path(), WalSyncMode::None).unwrap();
        assert_eq!(sm.ban_store().get_all_bans().len(), 1);
        assert!(sm.crdt_store().is_empty());
    }

    fn ban_for(cidr: &str, ttl: chrono::Duration) -> BanRecord {
        BanRecord {
            expires_at: Some(Utc::now() + ttl),
            ..make_ban(cidr)
        }
    }

    #[test]
    fn admit_ban_burst_for_one_subject_yields_one_ban() {
        // Journal 2026-09-10 16:10:30 on node-d: 23 "Ban issued" for
        // 94.154.46.246/32 within 190 ms, one per probe request.
        let dir = TempDir::new().unwrap();
        let mut sm = StateManager::new(dir.path(), WalSyncMode::None).unwrap();
        let now = Utc::now();

        let outcomes: Vec<BanAdmission> = (0..23)
            .map(|_| sm.admit_ban(ban_for("94.154.46.246/32", chrono::Duration::days(3)), now).unwrap())
            .collect();

        assert_eq!(outcomes[0], BanAdmission::Added);
        assert!(outcomes[1..]
            .iter()
            .all(|o| matches!(o, BanAdmission::AlreadyCovered { .. })));
        assert_eq!(sm.ban_store().get_all_bans().len(), 1);
    }

    #[test]
    fn admit_ban_shorter_ban_does_not_shorten_active_one() {
        // Same burst: a 1-day honeypot ban used to overwrite the 3-day
        // path_probe ban issued 8 ms earlier.
        let dir = TempDir::new().unwrap();
        let mut sm = StateManager::new(dir.path(), WalSyncMode::None).unwrap();
        let now = Utc::now();
        let long = ban_for("94.154.46.246/32", chrono::Duration::days(3));
        let long_expiry = long.expires_at;
        assert_eq!(sm.admit_ban(long, now).unwrap(), BanAdmission::Added);

        let outcome = sm
            .admit_ban(ban_for("94.154.46.246/32", chrono::Duration::days(1)), now)
            .unwrap();

        assert!(matches!(outcome, BanAdmission::AlreadyCovered { .. }));
        let ip: IpAddr = "94.154.46.246".parse().unwrap();
        assert_eq!(sm.ban_store().is_banned(&ip).unwrap().expires_at, long_expiry);
    }

    #[test]
    fn admit_ban_longer_ban_extends_and_keeps_start() {
        let dir = TempDir::new().unwrap();
        let mut sm = StateManager::new(dir.path(), WalSyncMode::None).unwrap();
        let now = Utc::now();
        let short = ban_for("11.0.0.1/32", chrono::Duration::hours(1));
        let (created, short_expiry) = (short.created_at, short.expires_at);
        sm.admit_ban(short, now).unwrap();

        let long = ban_for("11.0.0.1/32", chrono::Duration::days(3));
        let long_expiry = long.expires_at;
        let outcome = sm.admit_ban(long, now).unwrap();

        assert_eq!(outcome, BanAdmission::Extended { previous_expiry: short_expiry });
        let rec = sm.ban_store().is_banned(&"11.0.0.1".parse().unwrap()).unwrap();
        assert_eq!(rec.expires_at, long_expiry);
        assert_eq!(rec.created_at, created);
        assert_eq!(sm.ban_store().get_all_bans().len(), 1);
    }

    #[test]
    fn admit_ban_wider_active_ban_covers_host() {
        let dir = TempDir::new().unwrap();
        let mut sm = StateManager::new(dir.path(), WalSyncMode::None).unwrap();
        let now = Utc::now();
        sm.admit_ban(ban_for("85.208.96.0/24", chrono::Duration::hours(12)), now).unwrap();

        let covered = sm
            .admit_ban(ban_for("85.208.96.7/32", chrono::Duration::hours(1)), now)
            .unwrap();
        assert_eq!(
            covered,
            BanAdmission::AlreadyCovered {
                by: "85.208.96.0/24".parse().unwrap(),
                expires_at: sm.ban_store().get_all_bans()[0].expires_at,
            }
        );

        // A host ban that outlives the subnet ban is still worth storing.
        let outliving = sm
            .admit_ban(ban_for("85.208.96.7/32", chrono::Duration::days(3)), now)
            .unwrap();
        assert_eq!(outliving, BanAdmission::Added);
        assert_eq!(sm.ban_store().get_all_bans().len(), 2);
    }

    #[test]
    fn admit_ban_expired_ban_does_not_block_recidivism() {
        // 85.208.96.0/24 is re-banned every ~12 h after the previous ban
        // expires; the expiry task may not have swept the old record yet.
        let dir = TempDir::new().unwrap();
        let mut sm = StateManager::new(dir.path(), WalSyncMode::None).unwrap();
        let mut stale = make_ban("85.208.96.0/24");
        stale.expires_at = Some(Utc::now() - chrono::Duration::seconds(1));
        sm.add_ban(stale).unwrap();

        let outcome = sm
            .admit_ban(ban_for("85.208.96.0/24", chrono::Duration::hours(12)), Utc::now())
            .unwrap();
        assert_eq!(outcome, BanAdmission::Added);
    }

    #[test]
    fn admit_ban_permanent_ban_covers_everything() {
        let dir = TempDir::new().unwrap();
        let mut sm = StateManager::new(dir.path(), WalSyncMode::None).unwrap();
        let now = Utc::now();
        let mut permanent = make_ban("11.0.0.0/8");
        permanent.expires_at = None;
        sm.admit_ban(permanent, now).unwrap();

        let mut other_permanent = make_ban("11.1.2.3/32");
        other_permanent.expires_at = None;
        assert!(matches!(
            sm.admit_ban(other_permanent, now).unwrap(),
            BanAdmission::AlreadyCovered { .. }
        ));
    }

    #[test]
    fn admit_ban_concurrent_callers_under_one_lock_add_once() {
        // Every ban path (pipeline, socket, REST, cluster) shares one
        // Mutex<StateManager>. With check-and-insert in a single call, racing
        // callers cannot both see "no active ban" and both insert.
        use std::sync::{Arc, Barrier, Mutex};

        let dir = TempDir::new().unwrap();
        let sm = Arc::new(Mutex::new(
            StateManager::new(dir.path(), WalSyncMode::None).unwrap(),
        ));
        let threads = 16;
        let barrier = Arc::new(Barrier::new(threads));
        let handles: Vec<_> = (0..threads)
            .map(|_| {
                let sm = Arc::clone(&sm);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    let record = ban_for("35.205.92.82/32", chrono::Duration::days(3));
                    barrier.wait();
                    sm.lock().unwrap().admit_ban(record, Utc::now()).unwrap()
                })
            })
            .collect();
        let outcomes: Vec<BanAdmission> = handles.into_iter().map(|h| h.join().unwrap()).collect();

        let added = outcomes.iter().filter(|o| **o == BanAdmission::Added).count();
        let covered = outcomes
            .iter()
            .filter(|o| matches!(o, BanAdmission::AlreadyCovered { .. }))
            .count();
        assert_eq!(added, 1, "exactly one caller may add the ban: {outcomes:?}");
        assert_eq!(covered, threads - 1, "{outcomes:?}");
        assert_eq!(sm.lock().unwrap().ban_store().get_all_bans().len(), 1);
    }

    #[test]
    fn admit_ban_survives_restart_via_wal() {
        let dir = TempDir::new().unwrap();
        let now = Utc::now();
        {
            let mut sm = StateManager::new(dir.path(), WalSyncMode::None).unwrap();
            sm.admit_ban(ban_for("11.0.0.1/32", chrono::Duration::hours(1)), now).unwrap();
            sm.admit_ban(ban_for("11.0.0.1/32", chrono::Duration::days(3)), now).unwrap();
            sm.admit_ban(ban_for("11.0.0.1/32", chrono::Duration::hours(2)), now).unwrap();
        }
        let sm = StateManager::new(dir.path(), WalSyncMode::None).unwrap();
        let rec = sm.ban_store().is_banned(&"11.0.0.1".parse().unwrap()).unwrap();
        assert!(rec.expires_at.unwrap() > now + chrono::Duration::days(2));
    }
}
