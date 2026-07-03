use std::collections::HashSet;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;

use arc_swap::ArcSwap;
use maxminddb::Reader;
use tracing::{info, warn};

use hiveguard_core::models::GeoIpInfo;

/// Thread-safe, hot-reloadable GeoIP database handle.
///
/// The inner `Option<GeoIpDb>` is `None` when no database files are available.
/// Use [`ArcSwap::store`] to atomically swap in a freshly loaded database.
pub type SharedGeoIpDb = Arc<ArcSwap<Option<GeoIpDb>>>;

/// Well-known datacenter / cloud-provider ASNs.
///
/// An IP whose ASN appears in this set has `is_datacenter = true`.  The list
/// is intentionally conservative — false-positives (marking a residential ISP
/// as a datacenter) are worse than false-negatives.
const DATACENTER_ASNS: &[u32] = &[
    16509, 14618, // AWS
    15169, 396982, // Google Cloud
    8075, 8069,  // Microsoft Azure
    14061,       // DigitalOcean
    63949,       // Linode / Akamai
    20473,       // Vultr
    16276, 35540, // OVH
    24940,       // Hetzner
    60068,       // Datacamp / CDN77
    174,         // Cogent
    3356,        // Lumen (Level 3)
];

/// GeoIP database — wraps both the Country and ASN MaxMind GeoLite2 readers.
///
/// Only one of the two readers needs to be present; the other fields will
/// simply be `None` in the returned [`GeoIpInfo`].
pub struct GeoIpDb {
    country_reader: Option<Reader<Vec<u8>>>,
    asn_reader: Option<Reader<Vec<u8>>>,
    datacenter_asns: HashSet<u32>,
}

impl GeoIpDb {
    /// Load both GeoLite2-Country.mmdb and GeoLite2-ASN.mmdb from
    /// `<data_dir>/geoip/`.  Missing files produce a warning but do **not**
    /// cause an error — the corresponding lookups simply return `None`.
    pub fn load(data_dir: &Path) -> Result<Self, GeoIpError> {
        let geoip_dir = data_dir.join("geoip");

        let country_path = geoip_dir.join("GeoLite2-Country.mmdb");
        let asn_path = geoip_dir.join("GeoLite2-ASN.mmdb");

        let country_reader = if country_path.exists() {
            match Reader::open_readfile(&country_path) {
                Ok(r) => {
                    info!("Loaded GeoLite2-Country from {:?}", country_path);
                    Some(r)
                }
                Err(e) => {
                    warn!("Failed to load GeoLite2-Country.mmdb: {}", e);
                    None
                }
            }
        } else {
            warn!(
                "GeoLite2-Country.mmdb not found at {:?} — country enrichment disabled",
                country_path
            );
            None
        };

        let asn_reader = if asn_path.exists() {
            match Reader::open_readfile(&asn_path) {
                Ok(r) => {
                    info!("Loaded GeoLite2-ASN from {:?}", asn_path);
                    Some(r)
                }
                Err(e) => {
                    warn!("Failed to load GeoLite2-ASN.mmdb: {}", e);
                    None
                }
            }
        } else {
            warn!(
                "GeoLite2-ASN.mmdb not found at {:?} — ASN enrichment disabled",
                asn_path
            );
            None
        };

        let datacenter_asns: HashSet<u32> = DATACENTER_ASNS.iter().cloned().collect();

        Ok(Self {
            country_reader,
            asn_reader,
            datacenter_asns,
        })
    }

    /// Attempt to load databases from `<data_dir>/geoip/`.
    ///
    /// Returns `None` if neither database file is present (rather than logging
    /// duplicate warnings — callers should check availability before calling).
    pub fn try_load(data_dir: &Path) -> Option<Self> {
        let geoip_dir = data_dir.join("geoip");
        let has_country = geoip_dir.join("GeoLite2-Country.mmdb").exists();
        let has_asn = geoip_dir.join("GeoLite2-ASN.mmdb").exists();
        if !has_country && !has_asn {
            return None;
        }
        Self::load(data_dir).ok()
    }

    /// Look up [`GeoIpInfo`] for the given IP address.
    ///
    /// Always succeeds; missing databases or unknown IPs result in `None`
    /// fields inside the returned struct.
    pub fn lookup(&self, ip: IpAddr) -> GeoIpInfo {
        let country_iso = self.lookup_country(ip);
        let (asn, asn_org) = self.lookup_asn(ip);
        let is_datacenter = asn
            .map(|n| self.datacenter_asns.contains(&n))
            .unwrap_or(false);

        GeoIpInfo {
            country_iso,
            asn,
            asn_org,
            is_datacenter,
        }
    }

    /// Returns `true` if `asn` is in the built-in datacenter ASN set.
    pub fn is_datacenter_asn(&self, asn: u32) -> bool {
        self.datacenter_asns.contains(&asn)
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    fn lookup_country(&self, ip: IpAddr) -> Option<String> {
        let reader = self.country_reader.as_ref()?;
        let record: maxminddb::geoip2::Country = reader.lookup(ip).ok()?;
        record
            .country
            .and_then(|c| c.iso_code)
            .map(|s| s.to_string())
    }

    fn lookup_asn(&self, ip: IpAddr) -> (Option<u32>, Option<String>) {
        let reader = match self.asn_reader.as_ref() {
            Some(r) => r,
            None => return (None, None),
        };

        let record: maxminddb::geoip2::Asn = match reader.lookup(ip) {
            Ok(r) => r,
            Err(_) => return (None, None),
        };

        let asn_number = record.autonomous_system_number;
        let asn_org = record
            .autonomous_system_organization
            .map(|s| s.to_string());

        (asn_number, asn_org)
    }
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors that can occur while loading GeoIP databases.
#[derive(Debug, thiserror::Error)]
pub enum GeoIpError {
    #[error("MaxMind DB error: {0}")]
    MaxMind(#[from] maxminddb::MaxMindDBError),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use tempfile::TempDir;

    /// Verify that `GeoIpDb::load` gracefully handles a missing geoip directory.
    #[test]
    fn load_missing_files_returns_ok_with_no_readers() {
        let dir = TempDir::new().unwrap();
        let db = GeoIpDb::load(dir.path()).unwrap();
        assert!(db.country_reader.is_none());
        assert!(db.asn_reader.is_none());
    }

    /// Verify lookup on a stub (no readers) returns empty GeoIpInfo.
    #[test]
    fn lookup_without_readers_returns_empty() {
        let dir = TempDir::new().unwrap();
        let db = GeoIpDb::load(dir.path()).unwrap();

        let info = db.lookup(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
        assert_eq!(info.country_iso, None);
        assert_eq!(info.asn, None);
        assert_eq!(info.asn_org, None);
        assert!(!info.is_datacenter);
    }

    /// Verify that Google's ASN (15169) is classified as a datacenter.
    #[test]
    fn google_asn_is_datacenter() {
        let dir = TempDir::new().unwrap();
        let db = GeoIpDb::load(dir.path()).unwrap();
        assert!(db.is_datacenter_asn(15169));
        assert!(db.is_datacenter_asn(16509)); // AWS
        assert!(!db.is_datacenter_asn(1234)); // random ISP
    }

    /// Verify IPv6 loopback lookup doesn't panic.
    #[test]
    fn lookup_ipv6_loopback_no_panic() {
        let dir = TempDir::new().unwrap();
        let db = GeoIpDb::load(dir.path()).unwrap();
        let info = db.lookup(IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert_eq!(info.country_iso, None);
    }

    /// Verify SharedGeoIpDb hot-reload works.
    #[test]
    fn shared_geoip_db_hot_reload() {
        let dir = TempDir::new().unwrap();
        let db = GeoIpDb::load(dir.path()).unwrap();
        let shared: SharedGeoIpDb = Arc::new(ArcSwap::new(Arc::new(Some(db))));

        // Simulate hot reload
        let new_db = GeoIpDb::load(dir.path()).unwrap();
        shared.store(Arc::new(Some(new_db)));

        // Should still be accessible
        let guard = shared.load();
        assert!(guard.is_some());
    }
}
