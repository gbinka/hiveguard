//! In-memory TTL cache for CTI enrichment results, with disk persistence.
//!
//! Entries expire after a configurable TTL (default 6 hours).  On startup the
//! cache is populated from `<data_dir>/cti_cache.bin` (bincode-encoded), and it
//! is flushed back to disk on explicit [`CtiCache::flush`] calls.

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use crate::abuseipdb::AbuseIpReport;

/// Default time-to-live for cache entries.
pub const DEFAULT_TTL_SECS: u64 = 6 * 3600; // 6 hours

/// Default maximum number of entries in the cache.
pub const DEFAULT_MAX_ENTRIES: usize = 100_000;

/// Filename used for disk persistence.
const CACHE_FILENAME: &str = "cti_cache.bin";

// ---------------------------------------------------------------------------
// Disk serialisation helpers
// ---------------------------------------------------------------------------

/// A single serialisable cache entry for disk persistence.
#[derive(Serialize, Deserialize)]
struct DiskEntry {
    report: AbuseIpReport,
    /// Seconds since UNIX_EPOCH when the entry was fetched.
    fetched_at_unix: u64,
}

/// The full structure serialised to `cti_cache.bin`.
#[derive(Serialize, Deserialize, Default)]
struct DiskCache {
    entries: Vec<(IpAddrBytes, DiskEntry)>,
}

/// Byte-array representation of an IP address (for bincode compat).
#[derive(Serialize, Deserialize, Clone)]
struct IpAddrBytes(Vec<u8>);

impl From<IpAddr> for IpAddrBytes {
    fn from(ip: IpAddr) -> Self {
        let bytes = match ip {
            IpAddr::V4(v4) => v4.octets().to_vec(),
            IpAddr::V6(v6) => v6.octets().to_vec(),
        };
        IpAddrBytes(bytes)
    }
}

impl TryFrom<IpAddrBytes> for IpAddr {
    type Error = ();
    fn try_from(b: IpAddrBytes) -> Result<Self, Self::Error> {
        match b.0.len() {
            4 => {
                let arr: [u8; 4] = b.0.try_into().map_err(|_| ())?;
                Ok(IpAddr::from(arr))
            }
            16 => {
                let arr: [u8; 16] = b.0.try_into().map_err(|_| ())?;
                Ok(IpAddr::from(arr))
            }
            _ => Err(()),
        }
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ---------------------------------------------------------------------------
// Cache entry
// ---------------------------------------------------------------------------

struct Entry {
    report: AbuseIpReport,
    fetched_at_unix: u64,
}

impl Entry {
    fn is_expired(&self, ttl: Duration) -> bool {
        let age_secs = now_unix().saturating_sub(self.fetched_at_unix);
        age_secs >= ttl.as_secs()
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// In-memory TTL cache for [`AbuseIpReport`] results.
///
/// **Thread-safety:** wrap in `tokio::sync::Mutex` when sharing across tasks.
pub struct CtiCache {
    entries: HashMap<IpAddr, Entry>,
    ttl: Duration,
    max_entries: usize,
    data_path: PathBuf,
}

impl CtiCache {
    /// Create a new cache with default settings.
    ///
    /// `data_dir` is the daemon's data directory; the cache file is stored
    /// at `<data_dir>/cti_cache.bin`.
    pub fn new(data_dir: &Path) -> Self {
        Self::with_options(
            data_dir,
            Duration::from_secs(DEFAULT_TTL_SECS),
            DEFAULT_MAX_ENTRIES,
        )
    }

    /// Create a cache with custom TTL and maximum entry count.
    pub fn with_options(data_dir: &Path, ttl: Duration, max_entries: usize) -> Self {
        Self {
            entries: HashMap::new(),
            ttl,
            max_entries,
            data_path: data_dir.join(CACHE_FILENAME),
        }
    }

    /// Load persistent cache from disk, ignoring expired entries.
    ///
    /// Silently succeeds if the file does not exist yet.
    pub fn load_from_disk(&mut self) {
        let bytes = match std::fs::read(&self.data_path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
            Err(e) => {
                warn!("Failed to read CTI cache from {:?}: {}", self.data_path, e);
                return;
            }
        };

        let disk: DiskCache = match bincode::deserialize(&bytes) {
            Ok(d) => d,
            Err(e) => {
                warn!("Failed to deserialize CTI cache: {}", e);
                return;
            }
        };

        let now = now_unix();
        let ttl_secs = self.ttl.as_secs();
        let mut loaded = 0usize;

        for (ip_bytes, disk_entry) in disk.entries {
            if now.saturating_sub(disk_entry.fetched_at_unix) >= ttl_secs {
                continue; // skip expired
            }
            if let Ok(ip) = IpAddr::try_from(ip_bytes) {
                self.entries.insert(
                    ip,
                    Entry {
                        report: disk_entry.report,
                        fetched_at_unix: disk_entry.fetched_at_unix,
                    },
                );
                loaded += 1;
            }
        }

        debug!("Loaded {} non-expired CTI cache entries from disk", loaded);
    }

    /// Flush the cache to disk (only non-expired entries are written).
    pub fn flush_to_disk(&self) {
        let now = now_unix();
        let ttl_secs = self.ttl.as_secs();

        let disk_entries: Vec<(IpAddrBytes, DiskEntry)> = self
            .entries
            .iter()
            .filter(|(_, e)| now.saturating_sub(e.fetched_at_unix) < ttl_secs)
            .map(|(ip, e)| {
                (
                    IpAddrBytes::from(*ip),
                    DiskEntry {
                        report: e.report.clone(),
                        fetched_at_unix: e.fetched_at_unix,
                    },
                )
            })
            .collect();

        let disk = DiskCache {
            entries: disk_entries,
        };

        match bincode::serialize(&disk) {
            Ok(bytes) => {
                let tmp = self.data_path.with_extension("bin.tmp");
                if let Err(e) = std::fs::write(&tmp, &bytes) {
                    warn!("Failed to write CTI cache to {:?}: {}", tmp, e);
                    return;
                }
                if let Err(e) = std::fs::rename(&tmp, &self.data_path) {
                    warn!("Failed to rename CTI cache file: {}", e);
                }
            }
            Err(e) => warn!("Failed to serialize CTI cache: {}", e),
        }
    }

    /// Look up a cached report.  Returns `None` if not found or expired.
    pub fn get(&mut self, ip: IpAddr) -> Option<&AbuseIpReport> {
        let ttl = self.ttl;
        let entry = self.entries.get(&ip)?;
        if entry.is_expired(ttl) {
            self.entries.remove(&ip);
            return None;
        }
        self.entries.get(&ip).map(|e| &e.report)
    }

    /// Insert or update a cache entry with the current timestamp.
    pub fn insert(&mut self, ip: IpAddr, report: AbuseIpReport) {
        // Evict oldest entries if at capacity
        if self.entries.len() >= self.max_entries {
            self.evict_oldest();
        }
        self.entries.insert(
            ip,
            Entry {
                report,
                fetched_at_unix: now_unix(),
            },
        );
    }

    /// Returns the number of live (non-expired) entries in the cache.
    pub fn live_count(&self) -> usize {
        let now = now_unix();
        let ttl_secs = self.ttl.as_secs();
        self.entries
            .values()
            .filter(|e| now.saturating_sub(e.fetched_at_unix) < ttl_secs)
            .count()
    }

    // ------------------------------------------------------------------
    // Private helpers
    // ------------------------------------------------------------------

    fn evict_oldest(&mut self) {
        // Remove ~10% of entries, keeping the most recently fetched ones.
        let target_remove = (self.max_entries / 10).max(1);
        let mut keys: Vec<(IpAddr, u64)> = self
            .entries
            .iter()
            .map(|(ip, e)| (*ip, e.fetched_at_unix))
            .collect();
        keys.sort_unstable_by_key(|(_ip, ts)| *ts);
        for (ip, _) in keys.into_iter().take(target_remove) {
            self.entries.remove(&ip);
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use tempfile::TempDir;

    fn make_report(ip: IpAddr, score: u8) -> AbuseIpReport {
        AbuseIpReport {
            ip_address: ip,
            confidence_score: score,
            total_reports: 1,
            last_reported_at: None,
            usage_type: None,
            country_code: None,
            isp: None,
        }
    }

    #[test]
    fn insert_and_get() {
        let dir = TempDir::new().unwrap();
        let mut cache = CtiCache::new(dir.path());
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        cache.insert(ip, make_report(ip, 90));
        assert_eq!(cache.get(ip).unwrap().confidence_score, 90);
    }

    #[test]
    fn expired_entry_returns_none() {
        let dir = TempDir::new().unwrap();
        let mut cache =
            CtiCache::with_options(dir.path(), Duration::from_secs(0), DEFAULT_MAX_ENTRIES);
        let ip = IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8));
        cache.insert(ip, make_report(ip, 50));
        // TTL=0 means immediately expired
        assert!(cache.get(ip).is_none());
    }

    #[test]
    fn disk_roundtrip() {
        let dir = TempDir::new().unwrap();
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        {
            let mut cache = CtiCache::new(dir.path());
            cache.insert(ip, make_report(ip, 75));
            cache.flush_to_disk();
        }

        {
            let mut cache = CtiCache::new(dir.path());
            cache.load_from_disk();
            assert_eq!(cache.get(ip).unwrap().confidence_score, 75);
        }
    }

    #[test]
    fn evict_oldest_on_overflow() {
        let dir = TempDir::new().unwrap();
        let mut cache = CtiCache::with_options(dir.path(), Duration::from_secs(3600), 5);
        for i in 0u8..6 {
            let ip = IpAddr::V4(Ipv4Addr::new(1, 0, 0, i));
            cache.insert(ip, make_report(ip, i));
        }
        // Should have evicted at least one old entry
        assert!(cache.entries.len() <= 5);
    }
}
