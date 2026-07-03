use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::crdt::CrdtBanRecord;
use crate::errors::HiveGuardError;
use crate::models::BanRecord;

const SNAPSHOT_MAGIC_V1: &[u8; 8] = b"HVGD0001";
const SNAPSHOT_MAGIC_V2: &[u8; 8] = b"HVGD0002";
const SNAPSHOT_MAGIC_V3: &[u8; 8] = b"HVGD0003";

/// Maximum snapshot file size: 256 MiB.
const SNAPSHOT_MAX_SIZE: u64 = 256 * 1024 * 1024;

#[derive(Serialize, Deserialize)]
struct SnapshotDataV1 {
    bans: Vec<BanRecord>,
    whitelist: Vec<IpNet>,
}

/// V2 snapshot data includes CRDT ban records with full state.
#[derive(Serialize, Deserialize)]
struct SnapshotDataV2 {
    bans: Vec<BanRecord>,
    whitelist: Vec<IpNet>,
    crdt_bans: Vec<CrdtBanRecord>,
}

/// Result of loading a snapshot, including optional CRDT state.
pub struct SnapshotResult {
    pub bans: Vec<BanRecord>,
    pub whitelist: Vec<IpNet>,
    pub crdt_bans: Vec<CrdtBanRecord>,
}

/// Save a v2 snapshot to disk atomically (write to temp file, then rename).
pub fn save_snapshot_v2(
    path: &Path,
    bans: &[BanRecord],
    whitelist: &[IpNet],
    crdt_bans: &[CrdtBanRecord],
) -> Result<(), HiveGuardError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(HiveGuardError::Io)?;
    }

    let data = SnapshotDataV2 {
        bans: bans.to_vec(),
        whitelist: whitelist.to_vec(),
        crdt_bans: crdt_bans.to_vec(),
    };

    let encoded = postcard::to_allocvec(&data)
        .map_err(|e| HiveGuardError::Storage(format!("snapshot serialize: {e}")))?;

    let tmp_path = path.with_extension("tmp");
    let mut file = File::create(&tmp_path).map_err(HiveGuardError::Io)?;
    file.write_all(SNAPSHOT_MAGIC_V3).map_err(HiveGuardError::Io)?;
    file.write_all(&encoded).map_err(HiveGuardError::Io)?;
    file.sync_all().map_err(HiveGuardError::Io)?;
    drop(file);

    fs::rename(&tmp_path, path).map_err(HiveGuardError::Io)?;

    Ok(())
}

/// Save a snapshot to disk atomically (v1 format, no CRDT state).
pub fn save_snapshot(
    path: &Path,
    bans: &[BanRecord],
    whitelist: &[IpNet],
) -> Result<(), HiveGuardError> {
    save_snapshot_v2(path, bans, whitelist, &[])
}

/// Load a snapshot from disk. Supports both v1 and v2 formats.
pub fn load_snapshot(path: &Path) -> Result<(Vec<BanRecord>, Vec<IpNet>), HiveGuardError> {
    let result = load_snapshot_v2(path)?;
    Ok((result.bans, result.whitelist))
}

/// Load a v2 snapshot from disk. Supports both v1 and v2 magic headers.
pub fn load_snapshot_v2(path: &Path) -> Result<SnapshotResult, HiveGuardError> {
    let metadata = fs::metadata(path).map_err(HiveGuardError::Io)?;
    if metadata.len() > SNAPSHOT_MAX_SIZE {
        return Err(HiveGuardError::Storage(format!(
            "snapshot file too large: {} bytes (max {})",
            metadata.len(),
            SNAPSHOT_MAX_SIZE
        )));
    }

    let mut file = File::open(path).map_err(HiveGuardError::Io)?;

    let mut magic = [0u8; 8];
    file.read_exact(&mut magic).map_err(HiveGuardError::Io)?;

    let mut encoded = Vec::new();
    file.read_to_end(&mut encoded).map_err(HiveGuardError::Io)?;

    if &magic == SNAPSHOT_MAGIC_V3 {
        let data: SnapshotDataV2 = postcard::from_bytes(&encoded)
            .map_err(|e| HiveGuardError::Storage(format!("snapshot deserialize: {e}")))?;
        Ok(SnapshotResult {
            bans: data.bans,
            whitelist: data.whitelist,
            crdt_bans: data.crdt_bans,
        })
    } else if &magic == SNAPSHOT_MAGIC_V2 {
        let data: SnapshotDataV2 = bincode::deserialize(&encoded)
            .map_err(|e| HiveGuardError::Storage(e.to_string()))?;
        Ok(SnapshotResult {
            bans: data.bans,
            whitelist: data.whitelist,
            crdt_bans: data.crdt_bans,
        })
    } else if &magic == SNAPSHOT_MAGIC_V1 {
        let data: SnapshotDataV1 = bincode::deserialize(&encoded)
            .map_err(|e| HiveGuardError::Storage(e.to_string()))?;
        Ok(SnapshotResult {
            bans: data.bans,
            whitelist: data.whitelist,
            crdt_bans: Vec::new(),
        })
    } else {
        Err(HiveGuardError::Storage(format!(
            "invalid snapshot magic: expected HVGD0001, HVGD0002 or HVGD0003, got {:?}",
            magic
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{BanRecord, BanSource};
    use chrono::Utc;
    use tempfile::TempDir;

    fn make_ban(cidr: &str) -> BanRecord {
        BanRecord {
            subject: cidr.parse().unwrap(),
            created_at: Utc::now(),
            expires_at: Some(Utc::now() + chrono::Duration::hours(24)),
            severity: 150,
            reason: "test ban".into(),
            evidence_hash: [7u8; 32],
            source: BanSource::LocalDetector("test".into()),
            geo_info: None,
        }
    }

    #[test]
    fn save_and_load_roundtrip() {
        let dir = TempDir::new().unwrap();
        let snap_path = dir.path().join("snapshot.bin");

        let bans = vec![
            make_ban("10.0.0.1/32"),
            make_ban("192.168.0.0/24"),
            make_ban("172.16.0.0/12"),
        ];
        let whitelist: Vec<IpNet> = vec![
            "127.0.0.0/8".parse().unwrap(),
            "::1/128".parse().unwrap(),
        ];

        save_snapshot(&snap_path, &bans, &whitelist).unwrap();
        let (loaded_bans, loaded_wl) = load_snapshot(&snap_path).unwrap();

        assert_eq!(loaded_bans.len(), 3);
        assert_eq!(loaded_wl.len(), 2);
        assert_eq!(loaded_bans[0].subject, bans[0].subject);
        assert_eq!(loaded_bans[1].subject, bans[1].subject);
        assert_eq!(loaded_bans[2].subject, bans[2].subject);
        assert_eq!(loaded_wl[0], whitelist[0]);
        assert_eq!(loaded_wl[1], whitelist[1]);
    }

    #[test]
    fn invalid_magic_returns_error() {
        let dir = TempDir::new().unwrap();
        let snap_path = dir.path().join("bad_snapshot.bin");

        let mut file = File::create(&snap_path).unwrap();
        file.write_all(b"BADMAGIC").unwrap();
        file.write_all(b"some data").unwrap();
        drop(file);

        let result = load_snapshot(&snap_path);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("invalid snapshot magic"));
    }

    #[test]
    fn empty_snapshot_roundtrip() {
        let dir = TempDir::new().unwrap();
        let snap_path = dir.path().join("empty.bin");

        save_snapshot(&snap_path, &[], &[]).unwrap();
        let (bans, wl) = load_snapshot(&snap_path).unwrap();

        assert!(bans.is_empty());
        assert!(wl.is_empty());
    }

    #[test]
    fn nonexistent_snapshot_returns_io_error() {
        let result = load_snapshot(Path::new("/nonexistent/snapshot.bin"));
        assert!(result.is_err());
    }

    #[test]
    fn atomic_write_no_partial_file() {
        let dir = TempDir::new().unwrap();
        let snap_path = dir.path().join("atomic.bin");

        // First save
        save_snapshot(&snap_path, &[make_ban("10.0.0.1/32")], &[]).unwrap();

        // Second save overwrites atomically
        save_snapshot(
            &snap_path,
            &[make_ban("10.0.0.2/32"), make_ban("10.0.0.3/32")],
            &["192.168.0.0/16".parse().unwrap()],
        )
        .unwrap();

        let (bans, wl) = load_snapshot(&snap_path).unwrap();
        assert_eq!(bans.len(), 2);
        assert_eq!(wl.len(), 1);

        // Temp file should not exist
        assert!(!dir.path().join("atomic.tmp").exists());
    }

    // --- Phase 10: comprehensive coverage ---

    #[test]
    fn snapshot_with_ipv6() {
        let dir = TempDir::new().unwrap();
        let snap_path = dir.path().join("v6.bin");

        let ban = BanRecord {
            subject: "2001:db8::/32".parse().unwrap(),
            created_at: Utc::now(),
            expires_at: None,
            severity: 200,
            reason: "IPv6 test".into(),
            evidence_hash: [0xAB; 32],
            source: BanSource::LocalDetector("test".into()),
            geo_info: None,
        };
        let whitelist: Vec<IpNet> = vec!["::1/128".parse().unwrap(), "fe80::/10".parse().unwrap()];

        save_snapshot(&snap_path, &[ban.clone()], &whitelist).unwrap();
        let (loaded_bans, loaded_wl) = load_snapshot(&snap_path).unwrap();

        assert_eq!(loaded_bans.len(), 1);
        assert_eq!(loaded_bans[0].subject, ban.subject);
        assert_eq!(loaded_wl.len(), 2);
    }

    #[test]
    fn snapshot_preserves_all_ban_fields() {
        let dir = TempDir::new().unwrap();
        let snap_path = dir.path().join("fields.bin");

        let now = Utc::now();
        let expires = now + chrono::Duration::hours(48);
        let ban = BanRecord {
            subject: "203.0.113.0/24".parse().unwrap(),
            created_at: now,
            expires_at: Some(expires),
            severity: 180,
            reason: "SSH user enumeration detected".into(),
            evidence_hash: [0xCD; 32],
            source: BanSource::ClusterPeer("node-2".into()),
            geo_info: None,
        };

        save_snapshot(&snap_path, &[ban.clone()], &[]).unwrap();
        let (loaded_bans, _) = load_snapshot(&snap_path).unwrap();

        assert_eq!(loaded_bans[0].severity, 180);
        assert_eq!(loaded_bans[0].reason, "SSH user enumeration detected");
        assert_eq!(loaded_bans[0].evidence_hash, [0xCD; 32]);
        assert_eq!(loaded_bans[0].source, BanSource::ClusterPeer("node-2".into()));
    }

    #[test]
    fn snapshot_permanent_ban() {
        let dir = TempDir::new().unwrap();
        let snap_path = dir.path().join("permanent.bin");

        let ban = BanRecord {
            subject: "10.0.0.1/32".parse().unwrap(),
            created_at: Utc::now(),
            expires_at: None, // permanent
            severity: 250,
            reason: "honeypot hit".into(),
            evidence_hash: [0xFF; 32],
            source: BanSource::ManualAdmin,
            geo_info: None,
        };

        save_snapshot(&snap_path, &[ban], &[]).unwrap();
        let (loaded_bans, _) = load_snapshot(&snap_path).unwrap();

        assert!(loaded_bans[0].expires_at.is_none());
        assert_eq!(loaded_bans[0].source, BanSource::ManualAdmin);
    }

    #[test]
    fn snapshot_large_number_of_bans() {
        let dir = TempDir::new().unwrap();
        let snap_path = dir.path().join("large.bin");

        let bans: Vec<BanRecord> = (0..100).map(|i| {
            BanRecord {
                subject: format!("10.0.{}.{}/32", i / 256, i % 256).parse().unwrap(),
                created_at: Utc::now(),
                expires_at: Some(Utc::now() + chrono::Duration::hours(24)),
                severity: (i % 255) as u8,
                reason: format!("ban {i}"),
                evidence_hash: [i as u8; 32],
                source: BanSource::LocalDetector("test".into()),
                geo_info: None,
            }
        }).collect();

        save_snapshot(&snap_path, &bans, &[]).unwrap();
        let (loaded_bans, _) = load_snapshot(&snap_path).unwrap();
        assert_eq!(loaded_bans.len(), 100);
    }

    // --- Phase 19: v2 snapshot tests ---

    fn make_crdt_ban(cidr: &str) -> CrdtBanRecord {
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
            reason: "crdt test ban".to_string(),
            tombstone_reporters: HashSet::new(),
            tombstone: false,
            last_modified: now,
        }
    }

    #[test]
    fn v2_snapshot_roundtrip_with_crdt_bans() {
        let dir = TempDir::new().unwrap();
        let snap_path = dir.path().join("v2.bin");

        let bans = vec![make_ban("10.0.0.1/32")];
        let wl: Vec<IpNet> = vec!["127.0.0.0/8".parse().unwrap()];
        let crdt_bans = vec![
            make_crdt_ban("10.0.0.2/32"),
            make_crdt_ban("10.0.0.3/32"),
        ];

        save_snapshot_v2(&snap_path, &bans, &wl, &crdt_bans).unwrap();
        let result = load_snapshot_v2(&snap_path).unwrap();

        assert_eq!(result.bans.len(), 1);
        assert_eq!(result.whitelist.len(), 1);
        assert_eq!(result.crdt_bans.len(), 2);
        assert_eq!(result.crdt_bans[0].subject, "10.0.0.2/32".parse::<IpNet>().unwrap());
        assert_eq!(result.crdt_bans[1].subject, "10.0.0.3/32".parse::<IpNet>().unwrap());
    }

    #[test]
    fn v2_snapshot_empty_crdt_bans() {
        let dir = TempDir::new().unwrap();
        let snap_path = dir.path().join("v2_empty.bin");

        let bans = vec![make_ban("10.0.0.1/32")];
        let wl: Vec<IpNet> = vec![];

        save_snapshot_v2(&snap_path, &bans, &wl, &[]).unwrap();
        let result = load_snapshot_v2(&snap_path).unwrap();

        assert_eq!(result.bans.len(), 1);
        assert!(result.crdt_bans.is_empty());
    }

    #[test]
    fn v1_snapshot_loaded_as_v2_has_no_crdt_bans() {
        let dir = TempDir::new().unwrap();
        let snap_path = dir.path().join("v1.bin");

        // Save as v1
        save_snapshot(&snap_path, &[make_ban("10.0.0.1/32")], &["127.0.0.0/8".parse().unwrap()]).unwrap();

        // Load as v2
        let result = load_snapshot_v2(&snap_path).unwrap();
        assert_eq!(result.bans.len(), 1);
        assert_eq!(result.whitelist.len(), 1);
        assert!(result.crdt_bans.is_empty(), "V1 snapshot should have no CRDT bans");
    }

    #[test]
    fn v2_snapshot_with_tombstoned_crdt_ban() {
        let dir = TempDir::new().unwrap();
        let snap_path = dir.path().join("v2_tomb.bin");

        let mut crdt_ban = make_crdt_ban("10.0.0.1/32");
        crdt_ban.tombstone = true;

        save_snapshot_v2(&snap_path, &[], &[], &[crdt_ban]).unwrap();
        let result = load_snapshot_v2(&snap_path).unwrap();

        assert_eq!(result.crdt_bans.len(), 1);
        assert!(result.crdt_bans[0].tombstone);
    }

    #[test]
    fn v2_snapshot_invalid_magic_returns_error() {
        let dir = TempDir::new().unwrap();
        let snap_path = dir.path().join("bad_v2.bin");

        let mut file = File::create(&snap_path).unwrap();
        file.write_all(b"BADMAGIC").unwrap();
        file.write_all(b"some data").unwrap();
        drop(file);

        let result = load_snapshot_v2(&snap_path);
        assert!(result.is_err());
    }
}
