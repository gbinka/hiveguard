use std::collections::HashSet;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::hlc::HlcTimestamp;

/// CRDT-aware ban record for conflict-free replication across nodes.
///
/// Merge semantics (all commutative, associative, idempotent):
/// - `first_seen`: min(local, remote)
/// - `ban_until`: max(local, remote)
/// - `severity`: max(local, remote)
/// - `reporters`: union(local, remote)
/// - `tombstone_reporters`: union(local, remote)
/// - `tombstone`: true iff `tombstone_reporters.len() >= TOMBSTONE_QUORUM`
/// - `last_modified`: max(local, remote)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CrdtBanRecord {
    /// The banned IP/network subject.
    pub subject: IpNet,
    /// When the ban was first seen (min across all replicas).
    pub first_seen: HlcTimestamp,
    /// When the ban expires (max across all replicas).
    pub ban_until: HlcTimestamp,
    /// Severity level (max across replicas).
    pub severity: u8,
    /// Set of node IDs that reported this ban.
    pub reporters: HashSet<String>,
    /// Blake3 hash of original evidence.
    pub evidence_hash: [u8; 32],
    /// Reason string (kept from the highest last_modified).
    pub reason: String,
    /// Set of node IDs that voted to tombstone this ban.
    /// Tombstone is effective only when `tombstone_reporters.len() >= TOMBSTONE_QUORUM`.
    pub tombstone_reporters: HashSet<String>,
    /// Tombstone flag — effective when quorum of reporters agree.
    pub tombstone: bool,
    /// Last modification timestamp.
    pub last_modified: HlcTimestamp,
}

/// Minimum number of distinct nodes that must vote to tombstone a ban
/// before the tombstone takes effect. Prevents a single compromised node
/// from cancelling all bans in the cluster.
pub const TOMBSTONE_QUORUM: usize = 2;

impl CrdtBanRecord {
    /// Create a new CRDT ban record.
    pub fn new(
        subject: IpNet,
        severity: u8,
        reason: String,
        evidence_hash: [u8; 32],
        reporter: String,
        hlc: &mut crate::hlc::HlcTimestamp,
    ) -> Self {
        let now = hlc.tick();
        Self {
            subject,
            first_seen: now.clone(),
            ban_until: HlcTimestamp::new(
                now.wall_time_ms + 24 * 3600 * 1000, // Default 24h ban
                0,
                now.node_id_hash,
            ),
            severity,
            reporters: {
                let mut set = HashSet::new();
                set.insert(reporter);
                set
            },
            evidence_hash,
            reason,
            tombstone: false,
            tombstone_reporters: HashSet::new(),
            last_modified: now,
        }
    }

    /// Merge two CRDT ban records. Returns the merged result, or `None` if subjects differ.
    ///
    /// This is commutative, associative, and idempotent.
    pub fn merge(&self, other: &CrdtBanRecord) -> Option<CrdtBanRecord> {
        if self.subject != other.subject {
            tracing::warn!(
                local = %self.subject,
                remote = %other.subject,
                "Refusing to merge CRDT records with different subjects"
            );
            return None;
        }

        // Determine which has the later last_modified for reason selection
        let reason = if other.last_modified > self.last_modified {
            other.reason.clone()
        } else {
            self.reason.clone()
        };

        // Keep evidence_hash from the later modification
        let evidence_hash = if other.last_modified > self.last_modified {
            other.evidence_hash
        } else {
            self.evidence_hash
        };

        let merged_tombstone_reporters: HashSet<String> = self
            .tombstone_reporters
            .union(&other.tombstone_reporters)
            .cloned()
            .collect();
        let tombstone = merged_tombstone_reporters.len() >= TOMBSTONE_QUORUM;

        Some(CrdtBanRecord {
            subject: self.subject,
            first_seen: std::cmp::min(self.first_seen.clone(), other.first_seen.clone()),
            ban_until: std::cmp::max(self.ban_until.clone(), other.ban_until.clone()),
            severity: self.severity.max(other.severity),
            reporters: self.reporters.union(&other.reporters).cloned().collect(),
            evidence_hash,
            reason,
            tombstone_reporters: merged_tombstone_reporters,
            tombstone,
            last_modified: std::cmp::max(self.last_modified.clone(), other.last_modified.clone()),
        })
    }

    /// Check if this ban is still active (not tombstoned and not expired).
    pub fn is_active(&self, current_time_ms: u64) -> bool {
        !self.tombstone && self.ban_until.wall_time_ms > current_time_ms
    }

    /// Mark this record as tombstoned by a specific node.
    pub fn tombstone(&mut self, node_id: &str, hlc: &mut HlcTimestamp) {
        self.tombstone_reporters.insert(node_id.to_string());
        self.tombstone = self.tombstone_reporters.len() >= TOMBSTONE_QUORUM;
        self.last_modified = hlc.tick();
    }

    /// Extend the ban duration.
    pub fn extend_ban(&mut self, additional_ms: u64, hlc: &mut HlcTimestamp) {
        self.ban_until.wall_time_ms += additional_ms;
        self.last_modified = hlc.tick();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hlc::HlcTimestamp;

    fn make_hlc(node: &str) -> HlcTimestamp {
        HlcTimestamp::new(1000, 0, HlcTimestamp::hash_node_id(node))
    }

    fn make_record(ip: &str, node: &str, severity: u8) -> CrdtBanRecord {
        let mut hlc = make_hlc(node);
        CrdtBanRecord::new(
            ip.parse().unwrap(),
            severity,
            format!("detected by {node}"),
            [0u8; 32],
            node.to_string(),
            &mut hlc,
        )
    }

    #[test]
    fn merge_commutativity() {
        let a = make_record("10.0.0.1/32", "node-a", 100);
        let b = make_record("10.0.0.1/32", "node-b", 150);

        let ab = a.merge(&b).unwrap();
        let ba = b.merge(&a).unwrap();

        assert_eq!(ab.severity, ba.severity);
        assert_eq!(ab.first_seen, ba.first_seen);
        assert_eq!(ab.ban_until, ba.ban_until);
        assert_eq!(ab.reporters, ba.reporters);
        assert_eq!(ab.tombstone, ba.tombstone);
    }

    #[test]
    fn merge_associativity() {
        let a = make_record("10.0.0.1/32", "node-a", 100);
        let b = make_record("10.0.0.1/32", "node-b", 150);
        let c = make_record("10.0.0.1/32", "node-c", 120);

        let ab_c = a.merge(&b).unwrap().merge(&c).unwrap();
        let a_bc = a.merge(&b.merge(&c).unwrap()).unwrap();

        assert_eq!(ab_c.severity, a_bc.severity);
        assert_eq!(ab_c.first_seen, a_bc.first_seen);
        assert_eq!(ab_c.ban_until, a_bc.ban_until);
        assert_eq!(ab_c.reporters, a_bc.reporters);
    }

    #[test]
    fn merge_idempotency() {
        let a = make_record("10.0.0.1/32", "node-a", 100);
        let aa = a.merge(&a).unwrap();

        assert_eq!(aa.severity, a.severity);
        assert_eq!(aa.first_seen, a.first_seen);
        assert_eq!(aa.ban_until, a.ban_until);
        assert_eq!(aa.reporters, a.reporters);
    }

    #[test]
    fn merge_takes_max_severity() {
        let a = make_record("10.0.0.1/32", "node-a", 100);
        let b = make_record("10.0.0.1/32", "node-b", 200);

        let merged = a.merge(&b).unwrap();
        assert_eq!(merged.severity, 200);
    }

    #[test]
    fn merge_takes_min_first_seen() {
        let mut a = make_record("10.0.0.1/32", "node-a", 100);
        a.first_seen = HlcTimestamp::new(500, 0, 1);

        let mut b = make_record("10.0.0.1/32", "node-b", 100);
        b.first_seen = HlcTimestamp::new(1000, 0, 2);

        let merged = a.merge(&b).unwrap();
        assert_eq!(merged.first_seen.wall_time_ms, 500);
    }

    #[test]
    fn merge_takes_max_ban_until() {
        let mut a = make_record("10.0.0.1/32", "node-a", 100);
        a.ban_until = HlcTimestamp::new(5000, 0, 1);

        let mut b = make_record("10.0.0.1/32", "node-b", 100);
        b.ban_until = HlcTimestamp::new(10000, 0, 2);

        let merged = a.merge(&b).unwrap();
        assert_eq!(merged.ban_until.wall_time_ms, 10000);
    }

    #[test]
    fn merge_unions_reporters() {
        let a = make_record("10.0.0.1/32", "node-a", 100);
        let b = make_record("10.0.0.1/32", "node-b", 100);

        let merged = a.merge(&b).unwrap();
        assert!(merged.reporters.contains("node-a"));
        assert!(merged.reporters.contains("node-b"));
        assert_eq!(merged.reporters.len(), 2);
    }

    #[test]
    fn merge_tombstone_propagates() {
        let a = make_record("10.0.0.1/32", "node-a", 100);
        let mut b = make_record("10.0.0.1/32", "node-b", 100);
        // Single tombstone reporter — not enough for quorum
        b.tombstone_reporters.insert("node-x".to_string());
        b.tombstone = false; // below quorum

        let merged = a.merge(&b).unwrap();
        assert!(!merged.tombstone); // only 1 reporter, quorum is 2
        assert_eq!(merged.tombstone_reporters.len(), 1);

        // Now add a second tombstone reporter on a's side
        let mut a2 = a.clone();
        a2.tombstone_reporters.insert("node-y".to_string());

        let merged2 = a2.merge(&b).unwrap();
        assert!(merged2.tombstone); // 2 reporters meet quorum
        assert_eq!(merged2.tombstone_reporters.len(), 2);

        // Reverse direction — commutativity
        let merged3 = b.merge(&a2).unwrap();
        assert!(merged3.tombstone);
    }

    #[test]
    fn is_active_not_tombstoned() {
        let r = make_record("10.0.0.1/32", "node-a", 100);
        assert!(r.is_active(r.first_seen.wall_time_ms));
    }

    #[test]
    fn is_active_tombstoned() {
        let mut r = make_record("10.0.0.1/32", "node-a", 100);
        r.tombstone = true;
        assert!(!r.is_active(r.first_seen.wall_time_ms));
    }

    #[test]
    fn is_active_expired() {
        let r = make_record("10.0.0.1/32", "node-a", 100);
        // Far future timestamp — ban expired
        assert!(!r.is_active(r.ban_until.wall_time_ms + 1));
    }

    #[test]
    fn tombstone_marks_record() {
        let mut r = make_record("10.0.0.1/32", "node-a", 100);
        let mut hlc = make_hlc("node-a");
        assert!(!r.tombstone);
        // Single node tombstone — below quorum, not yet effective
        r.tombstone("node-a", &mut hlc);
        assert!(!r.tombstone);
        assert_eq!(r.tombstone_reporters.len(), 1);
        // Second node tombstone — meets quorum, now effective
        r.tombstone("node-b", &mut hlc);
        assert!(r.tombstone);
        assert_eq!(r.tombstone_reporters.len(), 2);
    }

    #[test]
    fn extend_ban_increases_duration() {
        let mut r = make_record("10.0.0.1/32", "node-a", 100);
        let original_ban_until = r.ban_until.wall_time_ms;
        let mut hlc = make_hlc("node-a");
        r.extend_ban(3600_000, &mut hlc);
        assert_eq!(r.ban_until.wall_time_ms, original_ban_until + 3600_000);
    }

    #[test]
    fn serialization_roundtrip() {
        let r = make_record("10.0.0.1/32", "node-a", 100);
        let json = serde_json::to_string(&r).unwrap();
        let parsed: CrdtBanRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(r.subject, parsed.subject);
        assert_eq!(r.severity, parsed.severity);
        assert_eq!(r.reporters, parsed.reporters);
    }

    #[test]
    fn merge_different_subjects_returns_none() {
        let a = make_record("10.0.0.1/32", "node-a", 100);
        let b = make_record("10.0.0.2/32", "node-b", 100);
        assert!(a.merge(&b).is_none());
    }

    #[test]
    fn merge_three_nodes_full() {
        let a = make_record("10.0.0.1/32", "node-a", 100);
        let b = make_record("10.0.0.1/32", "node-b", 200);
        let c = make_record("10.0.0.1/32", "node-c", 150);

        let merged = a.merge(&b).unwrap().merge(&c).unwrap();
        assert_eq!(merged.severity, 200);
        assert_eq!(merged.reporters.len(), 3);
        assert!(!merged.tombstone);
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use crate::hlc::HlcTimestamp;
    use proptest::prelude::*;
    use std::collections::HashSet;

    fn arb_hlc() -> impl Strategy<Value = HlcTimestamp> {
        (1u64..=u64::MAX, 0u32..1000u32, any::<u32>())
            .prop_map(|(w, c, n)| HlcTimestamp::new(w, c, n))
    }

    fn arb_crdt_record() -> impl Strategy<Value = CrdtBanRecord> {
        (
            arb_hlc(),    // first_seen
            arb_hlc(),    // ban_until
            any::<u8>(),  // severity
            proptest::collection::hash_set("[a-z]{1,8}", 1..5), // reporters
            proptest::collection::hash_set("[a-z]{1,8}", 0..4), // tombstone_reporters
            arb_hlc(),    // last_modified
        )
            .prop_map(|(first_seen, ban_until, severity, reporters, tombstone_reporters, last_modified)| {
                let tombstone = tombstone_reporters.len() >= TOMBSTONE_QUORUM;
                CrdtBanRecord {
                    subject: "10.0.0.1/32".parse().unwrap(),
                    first_seen,
                    ban_until,
                    severity,
                    reporters,
                    evidence_hash: [0u8; 32],
                    reason: "proptest".to_string(),
                    tombstone_reporters,
                    tombstone,
                    last_modified,
                }
            })
    }

    proptest! {
        #[test]
        fn merge_is_commutative(a in arb_crdt_record(), b in arb_crdt_record()) {
            let ab = a.merge(&b).unwrap();
            let ba = b.merge(&a).unwrap();
            prop_assert_eq!(ab.severity, ba.severity);
            prop_assert_eq!(ab.first_seen, ba.first_seen);
            prop_assert_eq!(ab.ban_until, ba.ban_until);
            prop_assert_eq!(ab.tombstone, ba.tombstone);
            prop_assert_eq!(ab.reporters, ba.reporters);
        }

        #[test]
        fn merge_is_associative(
            a in arb_crdt_record(),
            b in arb_crdt_record(),
            c in arb_crdt_record(),
        ) {
            let ab_c = a.merge(&b).unwrap().merge(&c).unwrap();
            let a_bc = a.merge(&b.merge(&c).unwrap()).unwrap();
            prop_assert_eq!(ab_c.severity, a_bc.severity);
            prop_assert_eq!(ab_c.first_seen, a_bc.first_seen);
            prop_assert_eq!(ab_c.ban_until, a_bc.ban_until);
            prop_assert_eq!(ab_c.tombstone, a_bc.tombstone);
            prop_assert_eq!(ab_c.reporters, a_bc.reporters);
        }

        #[test]
        fn merge_is_idempotent(a in arb_crdt_record()) {
            let aa = a.merge(&a).unwrap();
            prop_assert_eq!(aa.severity, a.severity);
            prop_assert_eq!(aa.first_seen, a.first_seen);
            prop_assert_eq!(aa.ban_until, a.ban_until);
            prop_assert_eq!(aa.tombstone, a.tombstone);
            prop_assert_eq!(aa.reporters, a.reporters);
        }

        #[test]
        fn merge_severity_is_max(a in arb_crdt_record(), b in arb_crdt_record()) {
            let merged = a.merge(&b).unwrap();
            prop_assert_eq!(merged.severity, a.severity.max(b.severity));
        }

        #[test]
        fn merge_first_seen_is_min(a in arb_crdt_record(), b in arb_crdt_record()) {
            let merged = a.merge(&b).unwrap();
            prop_assert_eq!(merged.first_seen, std::cmp::min(a.first_seen.clone(), b.first_seen.clone()));
        }

        #[test]
        fn merge_ban_until_is_max(a in arb_crdt_record(), b in arb_crdt_record()) {
            let merged = a.merge(&b).unwrap();
            prop_assert_eq!(merged.ban_until, std::cmp::max(a.ban_until.clone(), b.ban_until.clone()));
        }

        #[test]
        fn tombstone_is_quorum_based(a in arb_crdt_record(), b in arb_crdt_record()) {
            let merged = a.merge(&b).unwrap();
            let merged_tr: HashSet<String> = a.tombstone_reporters.union(&b.tombstone_reporters).cloned().collect();
            prop_assert_eq!(merged.tombstone, merged_tr.len() >= TOMBSTONE_QUORUM);
            prop_assert_eq!(merged.tombstone_reporters, merged_tr);
        }

        #[test]
        fn reporters_is_union(a in arb_crdt_record(), b in arb_crdt_record()) {
            let merged = a.merge(&b).unwrap();
            let expected: HashSet<String> = a.reporters.union(&b.reporters).cloned().collect();
            prop_assert_eq!(merged.reporters, expected);
        }

        #[test]
        fn different_subjects_returns_none(severity_a in any::<u8>(), severity_b in any::<u8>()) {
            let mut hlc_a = HlcTimestamp::new(1000, 0, 1);
            let mut hlc_b = HlcTimestamp::new(1000, 0, 2);
            let a = CrdtBanRecord::new(
                "10.0.0.1/32".parse().unwrap(), severity_a, "a".into(), [0u8; 32], "node-a".into(), &mut hlc_a,
            );
            let b = CrdtBanRecord::new(
                "10.0.0.2/32".parse().unwrap(), severity_b, "b".into(), [0u8; 32], "node-b".into(), &mut hlc_b,
            );
            prop_assert!(a.merge(&b).is_none());
        }
    }
}
