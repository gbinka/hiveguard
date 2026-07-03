use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::crdt::CrdtBanRecord;
use crate::errors::HiveGuardError;
use crate::models::BanRecord;

/// WAL entry representing a state mutation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum WalEntry {
    AddBan(BanRecord),
    RemoveBan(IpNet),
    AddWhitelist(IpNet),
    RemoveWhitelist(IpNet),
    /// CRDT-aware ban record for cluster synchronization.
    AddCrdtBan(CrdtBanRecord),
    /// Tombstone a CRDT ban record.
    TombstoneCrdtBan(IpNet),
}

/// Sync mode for WAL writes.
#[derive(Debug, Clone, PartialEq)]
pub enum WalSyncMode {
    Fdatasync,
    Sync,
    None,
}

impl std::str::FromStr for WalSyncMode {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "sync" => WalSyncMode::Sync,
            "none" => WalSyncMode::None,
            _ => WalSyncMode::Fdatasync,
        })
    }
}

/// Record format: [4 bytes length LE][payload bytes][4 bytes CRC32 LE]
///
/// Maximum payload size is 16 MiB to prevent allocation bombs from corrupt data.
const WAL_MAX_RECORD_SIZE: usize = 16 * 1024 * 1024;

pub struct WalWriter {
    file: File,
    path: PathBuf,
    sync_mode: WalSyncMode,
}

impl WalWriter {
    /// Open or create WAL file in append mode.
    pub fn open(data_dir: &Path, sync_mode: WalSyncMode) -> Result<Self, HiveGuardError> {
        fs::create_dir_all(data_dir).map_err(HiveGuardError::Io)?;
        let path = data_dir.join("wal.bin");
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(HiveGuardError::Io)?;
        Ok(Self {
            file,
            path,
            sync_mode,
        })
    }

    /// Append a single WAL entry.
    pub fn append(&mut self, entry: &WalEntry) -> Result<(), HiveGuardError> {
        let payload = postcard::to_allocvec(entry)
            .map_err(|e| HiveGuardError::Storage(format!("WAL serialize error: {e}")))?;
        let length = payload.len() as u32;
        let crc = crc32fast::hash(&payload);

        self.file
            .write_all(&length.to_le_bytes())
            .map_err(HiveGuardError::Io)?;
        self.file.write_all(&payload).map_err(HiveGuardError::Io)?;
        self.file
            .write_all(&crc.to_le_bytes())
            .map_err(HiveGuardError::Io)?;

        match self.sync_mode {
            WalSyncMode::Fdatasync | WalSyncMode::Sync => {
                self.file.sync_data().map_err(HiveGuardError::Io)?;
            }
            WalSyncMode::None => {}
        }

        Ok(())
    }

    /// Truncate the WAL file (after snapshot).
    pub fn truncate(&mut self) -> Result<(), HiveGuardError> {
        self.file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&self.path)
            .map_err(HiveGuardError::Io)?;
        Ok(())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Flush WAL to disk without truncating.
    pub fn flush(&mut self) -> Result<(), HiveGuardError> {
        match self.sync_mode {
            WalSyncMode::Fdatasync | WalSyncMode::Sync => {
                self.file.sync_data().map_err(HiveGuardError::Io)?;
            }
            WalSyncMode::None => {
                self.file.flush().map_err(HiveGuardError::Io)?;
            }
        }
        Ok(())
    }
}

/// Reads and replays WAL entries from a file.
pub struct WalReader;

impl WalReader {
    /// Read all valid entries from a WAL file.
    /// Stops on EOF or corrupt record (logs warning for corrupt).
    pub fn replay(path: &Path) -> Result<Vec<WalEntry>, HiveGuardError> {
        if !path.exists() {
            return Ok(Vec::new());
        }

        let mut file = File::open(path).map_err(HiveGuardError::Io)?;
        let mut entries = Vec::new();
        let mut record_index = 0u64;

        loop {
            // Read 4-byte length
            let mut len_buf = [0u8; 4];
            match file.read_exact(&mut len_buf) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(HiveGuardError::Io(e)),
            }
            let length = u32::from_le_bytes(len_buf) as usize;

            // Guard against corrupted length fields causing huge allocations
            if length > WAL_MAX_RECORD_SIZE {
                warn!(
                    "WAL record {} has length {} exceeding max {}, stopping replay",
                    record_index, length, WAL_MAX_RECORD_SIZE
                );
                break;
            }

            // Read payload
            let mut payload = vec![0u8; length];
            match file.read_exact(&mut payload) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                    warn!(
                        "WAL record {} truncated (missing payload bytes), stopping replay",
                        record_index
                    );
                    break;
                }
                Err(e) => return Err(HiveGuardError::Io(e)),
            }

            // Read 4-byte CRC32
            let mut crc_buf = [0u8; 4];
            match file.read_exact(&mut crc_buf) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                    warn!(
                        "WAL record {} truncated (missing CRC), stopping replay",
                        record_index
                    );
                    break;
                }
                Err(e) => return Err(HiveGuardError::Io(e)),
            }
            let stored_crc = u32::from_le_bytes(crc_buf);
            let computed_crc = crc32fast::hash(&payload);

            if stored_crc != computed_crc {
                warn!(
                    "WAL record {} has CRC mismatch (stored={:#010x}, computed={:#010x}), stopping replay",
                    record_index, stored_crc, computed_crc
                );
                break;
            }

            match postcard::from_bytes::<WalEntry>(&payload) {
                Ok(entry) => entries.push(entry),
                Err(e) => {
                    warn!(
                        "WAL record {} deserialization failed: {}, stopping replay",
                        record_index, e
                    );
                    break;
                }
            }

            record_index += 1;
        }

        Ok(entries)
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
            reason: "test brute-force".into(),
            evidence_hash: [42u8; 32],
            source: BanSource::LocalDetector("ssh_bruteforce".into()),
            geo_info: None,
        }
    }

    #[test]
    fn write_and_read_10_entries() {
        let dir = TempDir::new().unwrap();
        let mut writer = WalWriter::open(dir.path(), WalSyncMode::None).unwrap();

        let mut expected = Vec::new();
        for i in 0..10 {
            let entry = match i % 4 {
                0 => WalEntry::AddBan(make_ban(&format!("10.0.0.{}/32", i))),
                1 => WalEntry::RemoveBan(format!("10.0.0.{}/32", i).parse().unwrap()),
                2 => WalEntry::AddWhitelist(format!("192.168.{}.0/24", i).parse().unwrap()),
                _ => WalEntry::RemoveWhitelist(format!("192.168.{}.0/24", i).parse().unwrap()),
            };
            writer.append(&entry).unwrap();
            expected.push(entry);
        }

        let replayed = WalReader::replay(&dir.path().join("wal.bin")).unwrap();
        assert_eq!(replayed.len(), 10);
        for (a, b) in expected.iter().zip(replayed.iter()) {
            assert_eq!(a, b);
        }
    }

    #[test]
    fn corrupt_last_entry_reads_earlier() {
        let dir = TempDir::new().unwrap();
        let wal_path = dir.path().join("wal.bin");
        let mut writer = WalWriter::open(dir.path(), WalSyncMode::None).unwrap();

        for i in 0..5 {
            let entry = WalEntry::AddBan(make_ban(&format!("10.0.0.{}/32", i)));
            writer.append(&entry).unwrap();
        }
        drop(writer);

        // Corrupt: truncate last few bytes to break the last record
        let data = fs::read(&wal_path).unwrap();
        let truncated_len = data.len() - 6; // remove part of last record
        fs::write(&wal_path, &data[..truncated_len]).unwrap();

        let replayed = WalReader::replay(&wal_path).unwrap();
        assert_eq!(replayed.len(), 4); // 4 of 5 records survive
    }

    #[test]
    fn replay_nonexistent_returns_empty() {
        let entries = WalReader::replay(Path::new("/nonexistent/wal.bin")).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn truncate_clears_wal() {
        let dir = TempDir::new().unwrap();
        let mut writer = WalWriter::open(dir.path(), WalSyncMode::None).unwrap();

        writer
            .append(&WalEntry::AddBan(make_ban("10.0.0.1/32")))
            .unwrap();
        writer.truncate().unwrap();

        let replayed = WalReader::replay(&dir.path().join("wal.bin")).unwrap();
        assert!(replayed.is_empty());
    }

    #[test]
    fn crc_mismatch_stops_replay() {
        let dir = TempDir::new().unwrap();
        let wal_path = dir.path().join("wal.bin");
        let mut writer = WalWriter::open(dir.path(), WalSyncMode::None).unwrap();

        for i in 0..3 {
            writer
                .append(&WalEntry::AddBan(make_ban(&format!("10.0.0.{}/32", i))))
                .unwrap();
        }
        drop(writer);

        // Corrupt CRC of 2nd record: flip a byte in the middle
        let mut data = fs::read(&wal_path).unwrap();
        // Find roughly where 2nd record's payload is and flip a byte
        // First record: 4 (len) + payload + 4 (crc)
        let first_payload_len = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
        let second_start = 4 + first_payload_len + 4;
        let second_payload_len =
            u32::from_le_bytes(data[second_start..second_start + 4].try_into().unwrap()) as usize;
        // Flip a byte in the second record's payload
        let flip_pos = second_start + 4 + second_payload_len / 2;
        data[flip_pos] ^= 0xFF;
        fs::write(&wal_path, &data).unwrap();

        let replayed = WalReader::replay(&wal_path).unwrap();
        assert_eq!(replayed.len(), 1); // only first record survives
    }

    #[test]
    fn empty_wal_replays_empty() {
        let dir = TempDir::new().unwrap();
        let wal_path = dir.path().join("wal.bin");
        File::create(&wal_path).unwrap();

        let replayed = WalReader::replay(&wal_path).unwrap();
        assert!(replayed.is_empty());
    }

    // --- Phase 10: comprehensive coverage ---

    #[test]
    fn single_entry_write_read() {
        let dir = TempDir::new().unwrap();
        let mut writer = WalWriter::open(dir.path(), WalSyncMode::None).unwrap();

        let entry = WalEntry::AddWhitelist("10.0.0.0/8".parse().unwrap());
        writer.append(&entry).unwrap();

        let replayed = WalReader::replay(&dir.path().join("wal.bin")).unwrap();
        assert_eq!(replayed.len(), 1);
        assert_eq!(replayed[0], entry);
    }

    #[test]
    fn all_entry_types_roundtrip() {
        let dir = TempDir::new().unwrap();
        let mut writer = WalWriter::open(dir.path(), WalSyncMode::None).unwrap();

        let entries = vec![
            WalEntry::AddBan(make_ban("10.0.0.1/32")),
            WalEntry::RemoveBan("10.0.0.1/32".parse().unwrap()),
            WalEntry::AddWhitelist("192.168.0.0/16".parse().unwrap()),
            WalEntry::RemoveWhitelist("192.168.0.0/16".parse().unwrap()),
        ];

        for entry in &entries {
            writer.append(entry).unwrap();
        }

        let replayed = WalReader::replay(&dir.path().join("wal.bin")).unwrap();
        assert_eq!(replayed, entries);
    }

    #[test]
    fn wal_sync_mode_from_str() {
        assert_eq!("fdatasync".parse::<WalSyncMode>().unwrap(), WalSyncMode::Fdatasync);
        assert_eq!("sync".parse::<WalSyncMode>().unwrap(), WalSyncMode::Sync);
        assert_eq!("none".parse::<WalSyncMode>().unwrap(), WalSyncMode::None);
        assert_eq!("anything_else".parse::<WalSyncMode>().unwrap(), WalSyncMode::Fdatasync);
    }

    #[test]
    fn wal_append_after_truncate() {
        let dir = TempDir::new().unwrap();
        let mut writer = WalWriter::open(dir.path(), WalSyncMode::None).unwrap();

        writer.append(&WalEntry::AddBan(make_ban("10.0.0.1/32"))).unwrap();
        writer.truncate().unwrap();

        // Append after truncate should work
        let ban = make_ban("10.0.0.2/32");
        writer.append(&WalEntry::AddBan(ban)).unwrap();

        let replayed = WalReader::replay(&dir.path().join("wal.bin")).unwrap();
        assert_eq!(replayed.len(), 1);
        match &replayed[0] {
            WalEntry::AddBan(b) => assert_eq!(b.subject, "10.0.0.2/32".parse::<IpNet>().unwrap()),
            _ => panic!("Expected AddBan"),
        }
    }

    #[test]
    fn wal_ipv6_entries() {
        let dir = TempDir::new().unwrap();
        let mut writer = WalWriter::open(dir.path(), WalSyncMode::None).unwrap();

        let ban = BanRecord {
            subject: "2001:db8::/32".parse().unwrap(),
            created_at: Utc::now(),
            expires_at: Some(Utc::now() + chrono::Duration::hours(24)),
            severity: 150,
            reason: "test IPv6".into(),
            evidence_hash: [42u8; 32],
            source: BanSource::LocalDetector("test".into()),
            geo_info: None,
        };

        writer.append(&WalEntry::AddBan(ban.clone())).unwrap();
        writer.append(&WalEntry::AddWhitelist("::1/128".parse().unwrap())).unwrap();

        let replayed = WalReader::replay(&dir.path().join("wal.bin")).unwrap();
        assert_eq!(replayed.len(), 2);
    }

    #[test]
    fn wal_path_accessor() {
        let dir = TempDir::new().unwrap();
        let writer = WalWriter::open(dir.path(), WalSyncMode::None).unwrap();
        assert_eq!(writer.path(), dir.path().join("wal.bin"));
    }

    #[test]
    fn wal_creates_directory() {
        let dir = TempDir::new().unwrap();
        let subdir = dir.path().join("nested").join("data");

        let writer = WalWriter::open(&subdir, WalSyncMode::None).unwrap();
        assert!(writer.path().exists() || subdir.join("wal.bin").parent().unwrap().exists());
    }
}
