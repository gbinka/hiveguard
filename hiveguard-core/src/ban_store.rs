use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::IpNet;

use crate::errors::HiveGuardError;
use crate::models::BanRecord;

type Result<T> = std::result::Result<T, HiveGuardError>;

/// Trait for ban storage backends.
pub trait BanStore: Send + Sync {
    fn add_ban(&mut self, record: BanRecord) -> Result<()>;
    fn remove_ban(&mut self, subject: &IpNet) -> Result<bool>;
    fn is_banned(&self, ip: &IpAddr) -> Option<&BanRecord>;
    fn get_all_bans(&self) -> Vec<&BanRecord>;
    fn cleanup_expired(&mut self) -> usize;
}

/// In-memory ban store with O(k) CIDR lookup where k = number of distinct prefix
/// lengths with active bans (typically 1–3).
///
/// For each lookup IP, computes at most k candidate CIDR keys and checks the
/// HashMap. For the common case (only /32 bans), this is a single O(1) lookup.
pub struct InMemoryBanStore {
    bans: HashMap<IpNet, BanRecord>,
    /// Count of bans per IPv4 prefix length (index 0–32)
    v4_prefix_counts: [u32; 33],
    /// Count of bans per IPv6 prefix length (index 0–128)
    v6_prefix_counts: [u32; 129],
}

impl InMemoryBanStore {
    pub fn new() -> Self {
        Self {
            bans: HashMap::new(),
            v4_prefix_counts: [0; 33],
            v6_prefix_counts: [0; 129],
        }
    }

    fn inc_prefix(&mut self, net: &IpNet) {
        match net {
            IpNet::V4(n) => self.v4_prefix_counts[n.prefix_len() as usize] += 1,
            IpNet::V6(n) => self.v6_prefix_counts[n.prefix_len() as usize] += 1,
        }
    }

    fn dec_prefix(&mut self, net: &IpNet) {
        match net {
            IpNet::V4(n) => {
                let idx = n.prefix_len() as usize;
                self.v4_prefix_counts[idx] = self.v4_prefix_counts[idx].saturating_sub(1);
            }
            IpNet::V6(n) => {
                let idx = n.prefix_len() as usize;
                self.v6_prefix_counts[idx] = self.v6_prefix_counts[idx].saturating_sub(1);
            }
        }
    }

    fn rebuild_prefix_counts(&mut self) {
        self.v4_prefix_counts = [0; 33];
        self.v6_prefix_counts = [0; 129];
        for net in self.bans.keys() {
            match net {
                IpNet::V4(n) => self.v4_prefix_counts[n.prefix_len() as usize] += 1,
                IpNet::V6(n) => self.v6_prefix_counts[n.prefix_len() as usize] += 1,
            }
        }
    }
}

impl Default for InMemoryBanStore {
    fn default() -> Self {
        Self::new()
    }
}

impl BanStore for InMemoryBanStore {
    fn add_ban(&mut self, record: BanRecord) -> Result<()> {
        let net = record.subject;
        if let Some(_old) = self.bans.insert(net, record) {
            // Overwrite — prefix count unchanged
        } else {
            self.inc_prefix(&net);
        }
        Ok(())
    }

    fn remove_ban(&mut self, subject: &IpNet) -> Result<bool> {
        if self.bans.remove(subject).is_some() {
            self.dec_prefix(subject);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn is_banned(&self, ip: &IpAddr) -> Option<&BanRecord> {
        match ip {
            IpAddr::V4(v4) => {
                let ip_val = u32::from(*v4);
                // Check from longest prefix (most specific) to shortest
                for prefix_len in (0..=32u8).rev() {
                    if self.v4_prefix_counts[prefix_len as usize] == 0 {
                        continue;
                    }
                    let mask = if prefix_len == 0 {
                        0u32
                    } else {
                        u32::MAX << (32 - prefix_len)
                    };
                    let network = Ipv4Addr::from(ip_val & mask);
                    if let Ok(cidr) = ipnet::Ipv4Net::new(network, prefix_len) {
                        if let Some(record) = self.bans.get(&IpNet::V4(cidr)) {
                            return Some(record);
                        }
                    }
                }
                None
            }
            IpAddr::V6(v6) => {
                let ip_val = u128::from(*v6);
                for prefix_len in (0..=128u8).rev() {
                    if self.v6_prefix_counts[prefix_len as usize] == 0 {
                        continue;
                    }
                    let mask = if prefix_len == 0 {
                        0u128
                    } else {
                        u128::MAX << (128 - prefix_len)
                    };
                    let network = Ipv6Addr::from(ip_val & mask);
                    if let Ok(cidr) = ipnet::Ipv6Net::new(network, prefix_len) {
                        if let Some(record) = self.bans.get(&IpNet::V6(cidr)) {
                            return Some(record);
                        }
                    }
                }
                None
            }
        }
    }

    fn get_all_bans(&self) -> Vec<&BanRecord> {
        self.bans.values().collect()
    }

    fn cleanup_expired(&mut self) -> usize {
        let now = chrono::Utc::now();
        let before = self.bans.len();
        self.bans.retain(|_, record| {
            record
                .expires_at
                .map(|exp| exp > now)
                .unwrap_or(true) // permanent bans never expire
        });
        let removed = before - self.bans.len();
        if removed > 0 {
            self.rebuild_prefix_counts();
        }
        removed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{BanRecord, BanSource};
    use chrono::Utc;
    use std::net::IpAddr;

    fn make_ban(cidr: &str, expires_at: Option<chrono::DateTime<Utc>>) -> BanRecord {
        BanRecord {
            subject: cidr.parse().unwrap(),
            created_at: Utc::now(),
            expires_at,
            severity: 5,
            reason: "test ban".into(),
            evidence_hash: [0u8; 32],
            source: BanSource::LocalDetector("test".into()),
            geo_info: None,
        }
    }

    #[test]
    fn test_add_and_is_banned() {
        let mut store = InMemoryBanStore::new();
        let ban = make_ban("192.168.1.0/24", None);
        store.add_ban(ban).unwrap();

        let ip: IpAddr = "192.168.1.42".parse().unwrap();
        assert!(store.is_banned(&ip).is_some());

        let ip_outside: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(store.is_banned(&ip_outside).is_none());
    }

    #[test]
    fn test_remove_ban() {
        let mut store = InMemoryBanStore::new();
        let cidr: IpNet = "10.0.0.0/8".parse().unwrap();
        let ban = make_ban("10.0.0.0/8", None);
        store.add_ban(ban).unwrap();

        assert!(store.remove_ban(&cidr).unwrap());
        assert!(!store.remove_ban(&cidr).unwrap());
    }

    #[test]
    fn test_get_all_bans() {
        let mut store = InMemoryBanStore::new();
        store.add_ban(make_ban("10.0.0.0/8", None)).unwrap();
        store.add_ban(make_ban("192.168.0.0/16", None)).unwrap();
        assert_eq!(store.get_all_bans().len(), 2);
    }

    #[test]
    fn test_cleanup_expired() {
        let mut store = InMemoryBanStore::new();
        let past = Utc::now() - chrono::Duration::hours(1);
        let future = Utc::now() + chrono::Duration::hours(1);

        store.add_ban(make_ban("10.0.0.0/8", Some(past))).unwrap();
        store
            .add_ban(make_ban("192.168.0.0/16", Some(future)))
            .unwrap();
        store.add_ban(make_ban("172.16.0.0/12", None)).unwrap(); // permanent

        let removed = store.cleanup_expired();
        assert_eq!(removed, 1);
        assert_eq!(store.get_all_bans().len(), 2);
    }

    #[test]
    fn test_single_ip_ban() {
        let mut store = InMemoryBanStore::new();
        let ban = make_ban("1.2.3.4/32", None);
        store.add_ban(ban).unwrap();

        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        assert!(store.is_banned(&ip).is_some());

        let other: IpAddr = "1.2.3.5".parse().unwrap();
        assert!(store.is_banned(&other).is_none());
    }

    // --- Phase 10: comprehensive coverage ---

    #[test]
    fn test_ipv6_ban() {
        let mut store = InMemoryBanStore::new();
        let ban = make_ban("2001:db8::1/128", None);
        store.add_ban(ban).unwrap();

        let ip: IpAddr = "2001:db8::1".parse().unwrap();
        assert!(store.is_banned(&ip).is_some());

        let other: IpAddr = "2001:db8::2".parse().unwrap();
        assert!(store.is_banned(&other).is_none());
    }

    #[test]
    fn test_ipv6_cidr_ban() {
        let mut store = InMemoryBanStore::new();
        let ban = make_ban("2001:db8::/32", None);
        store.add_ban(ban).unwrap();

        let inside: IpAddr = "2001:db8::abcd".parse().unwrap();
        assert!(store.is_banned(&inside).is_some());

        let inside2: IpAddr = "2001:db8:1::1".parse().unwrap();
        assert!(store.is_banned(&inside2).is_some());

        let outside: IpAddr = "2001:db9::1".parse().unwrap();
        assert!(store.is_banned(&outside).is_none());
    }

    #[test]
    fn test_cidr_24_containment() {
        let mut store = InMemoryBanStore::new();
        let ban = make_ban("192.168.1.0/24", None);
        store.add_ban(ban).unwrap();

        // All 256 IPs in the /24 should be banned
        for i in 0..=255u8 {
            let ip: IpAddr = format!("192.168.1.{i}").parse().unwrap();
            assert!(store.is_banned(&ip).is_some(), "192.168.1.{i} should be banned");
        }

        // Adjacent /24 should NOT be banned
        let outside: IpAddr = "192.168.2.1".parse().unwrap();
        assert!(store.is_banned(&outside).is_none());
        let outside2: IpAddr = "192.168.0.255".parse().unwrap();
        assert!(store.is_banned(&outside2).is_none());
    }

    #[test]
    fn test_cidr_16_containment() {
        let mut store = InMemoryBanStore::new();
        let ban = make_ban("10.10.0.0/16", None);
        store.add_ban(ban).unwrap();

        let inside: IpAddr = "10.10.0.1".parse().unwrap();
        assert!(store.is_banned(&inside).is_some());
        let inside2: IpAddr = "10.10.255.255".parse().unwrap();
        assert!(store.is_banned(&inside2).is_some());

        let outside: IpAddr = "10.11.0.1".parse().unwrap();
        assert!(store.is_banned(&outside).is_none());
        let outside2: IpAddr = "10.9.255.255".parse().unwrap();
        assert!(store.is_banned(&outside2).is_none());
    }

    #[test]
    fn test_cidr_8_containment() {
        let mut store = InMemoryBanStore::new();
        let ban = make_ban("10.0.0.0/8", None);
        store.add_ban(ban).unwrap();

        let inside: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(store.is_banned(&inside).is_some());
        let inside2: IpAddr = "10.255.255.255".parse().unwrap();
        assert!(store.is_banned(&inside2).is_some());
        let inside3: IpAddr = "10.128.64.32".parse().unwrap();
        assert!(store.is_banned(&inside3).is_some());

        let outside: IpAddr = "11.0.0.1".parse().unwrap();
        assert!(store.is_banned(&outside).is_none());
        let outside2: IpAddr = "9.255.255.255".parse().unwrap();
        assert!(store.is_banned(&outside2).is_none());
    }

    #[test]
    fn test_multiple_cidrs_overlap() {
        let mut store = InMemoryBanStore::new();
        store.add_ban(make_ban("192.168.0.0/16", None)).unwrap();
        store.add_ban(make_ban("10.0.0.0/8", None)).unwrap();
        store.add_ban(make_ban("2001:db8::/32", None)).unwrap();

        // IPv4 in first CIDR
        let ip1: IpAddr = "192.168.5.5".parse().unwrap();
        assert!(store.is_banned(&ip1).is_some());

        // IPv4 in second CIDR
        let ip2: IpAddr = "10.99.99.99".parse().unwrap();
        assert!(store.is_banned(&ip2).is_some());

        // IPv6 in third CIDR
        let ip3: IpAddr = "2001:db8::dead:beef".parse().unwrap();
        assert!(store.is_banned(&ip3).is_some());

        // Not in any
        let ip4: IpAddr = "172.16.0.1".parse().unwrap();
        assert!(store.is_banned(&ip4).is_none());
    }

    #[test]
    fn test_overwrite_existing_ban() {
        let mut store = InMemoryBanStore::new();
        let ban1 = make_ban("10.0.0.0/8", None);
        store.add_ban(ban1).unwrap();

        let future = Utc::now() + chrono::Duration::hours(2);
        let ban2 = BanRecord {
            subject: "10.0.0.0/8".parse().unwrap(),
            created_at: Utc::now(),
            expires_at: Some(future),
            severity: 200,
            reason: "updated ban".into(),
            evidence_hash: [1u8; 32],
            source: BanSource::ManualAdmin,
            geo_info: None,
        };
        store.add_ban(ban2).unwrap();

        assert_eq!(store.get_all_bans().len(), 1);
        let record = store.is_banned(&"10.5.5.5".parse().unwrap()).unwrap();
        assert_eq!(record.severity, 200);
        assert_eq!(record.reason, "updated ban");
    }

    #[test]
    fn test_permanent_ban_survives_cleanup() {
        let mut store = InMemoryBanStore::new();
        store.add_ban(make_ban("10.0.0.0/8", None)).unwrap(); // permanent

        let removed = store.cleanup_expired();
        assert_eq!(removed, 0);
        assert_eq!(store.get_all_bans().len(), 1);
    }

    #[test]
    fn test_cleanup_only_expired() {
        let mut store = InMemoryBanStore::new();
        let past = Utc::now() - chrono::Duration::hours(1);
        let future = Utc::now() + chrono::Duration::hours(1);

        store.add_ban(make_ban("10.0.0.0/8", Some(past))).unwrap(); // expired
        store.add_ban(make_ban("172.16.0.0/12", Some(future))).unwrap(); // active
        store.add_ban(make_ban("192.168.0.0/16", None)).unwrap(); // permanent

        let removed = store.cleanup_expired();
        assert_eq!(removed, 1);
        assert_eq!(store.get_all_bans().len(), 2);

        // expired one is gone
        let ip: IpAddr = "10.5.5.5".parse().unwrap();
        assert!(store.is_banned(&ip).is_none());

        // active one is still there
        let ip2: IpAddr = "172.20.0.1".parse().unwrap();
        assert!(store.is_banned(&ip2).is_some());
    }

    #[test]
    fn test_remove_nonexistent_ban() {
        let mut store = InMemoryBanStore::new();
        let cidr: IpNet = "10.0.0.0/8".parse().unwrap();
        assert!(!store.remove_ban(&cidr).unwrap());
    }

    #[test]
    fn test_remove_exact_cidr_required() {
        let mut store = InMemoryBanStore::new();
        store.add_ban(make_ban("10.0.0.0/8", None)).unwrap();

        // Removing a different CIDR (even overlapping) should not remove the ban
        let different: IpNet = "10.0.0.0/16".parse().unwrap();
        assert!(!store.remove_ban(&different).unwrap());
        assert_eq!(store.get_all_bans().len(), 1);

        // Removing the exact CIDR should work
        let exact: IpNet = "10.0.0.0/8".parse().unwrap();
        assert!(store.remove_ban(&exact).unwrap());
        assert_eq!(store.get_all_bans().len(), 0);
    }

    #[test]
    fn test_default_constructor() {
        let store = InMemoryBanStore::default();
        assert!(store.get_all_bans().is_empty());
    }

    #[test]
    fn test_is_banned_returns_record_details() {
        let mut store = InMemoryBanStore::new();
        let ban = BanRecord {
            subject: "1.2.3.4/32".parse().unwrap(),
            created_at: Utc::now(),
            expires_at: None,
            severity: 200,
            reason: "brute-force attack".into(),
            evidence_hash: [42u8; 32],
            source: BanSource::LocalDetector("ssh_bruteforce".into()),
            geo_info: None,
        };
        store.add_ban(ban).unwrap();

        let record = store.is_banned(&"1.2.3.4".parse().unwrap()).unwrap();
        assert_eq!(record.severity, 200);
        assert_eq!(record.reason, "brute-force attack");
        assert!(record.expires_at.is_none());
        assert_eq!(record.evidence_hash, [42u8; 32]);
    }

    #[test]
    fn test_cleanup_all_expired() {
        let mut store = InMemoryBanStore::new();
        let past = Utc::now() - chrono::Duration::hours(1);

        for i in 0..5 {
            store.add_ban(make_ban(&format!("10.0.0.{i}/32"), Some(past))).unwrap();
        }

        let removed = store.cleanup_expired();
        assert_eq!(removed, 5);
        assert!(store.get_all_bans().is_empty());
    }
}
