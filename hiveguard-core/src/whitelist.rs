use std::collections::HashSet;
use std::net::IpAddr;

use ipnet::IpNet;

/// Hard-coded networks that can NEVER be banned, regardless of cluster messages.
///
/// Includes RFC 1918 private ranges, loopback, link-local, documentation ranges,
/// and IANA-reserved special-purpose blocks.  These are checked independently of
/// the user-configured whitelist entries and cannot be overridden at runtime.
const IMMUTABLE_PROTECTED: &[&str] = &[
    // Loopback
    "127.0.0.0/8",
    "::1/128",
    // RFC 1918 private ranges
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    // Link-local
    "169.254.0.0/16",
    "fe80::/10",
    // RFC 5737 documentation ranges (should never appear in production traffic)
    "192.0.2.0/24",
    "198.51.100.0/24",
    "203.0.113.0/24",
    // RFC 3927 / 4291 unspecified
    "0.0.0.0/8",
    "::/128",
    // Multicast
    "224.0.0.0/4",
    "ff00::/8",
    // Unique Local (IPv6 RFC 4193)
    "fc00::/7",
];

/// Manages a whitelist of IP networks that should never be banned.
///
/// Two layers:
/// 1. **Immutable** — hard-coded ranges (`IMMUTABLE_PROTECTED`) that cannot be
///    removed or overridden, protecting RFC 1918, loopback and similar ranges
///    from Self-DoS cluster attacks.
/// 2. **Configured** — user/admin-defined entries loaded from YAML config or
///    added at runtime via the API.
#[derive(Clone)]
pub struct WhitelistManager {
    entries: HashSet<IpNet>,
    immutable: Vec<IpNet>,
}

impl WhitelistManager {
    pub fn new() -> Self {
        let immutable: Vec<IpNet> = IMMUTABLE_PROTECTED
            .iter()
            .filter_map(|s| s.parse::<IpNet>().ok())
            .collect();
        Self {
            entries: HashSet::new(),
            immutable,
        }
    }

    pub fn add(&mut self, net: IpNet) {
        self.entries.insert(net);
    }

    pub fn remove(&mut self, net: &IpNet) -> bool {
        self.entries.remove(net)
    }

    /// Check if an IP is covered by any network in the immutable protected list.
    /// These bans are always rejected regardless of source.
    pub fn is_immutably_protected(&self, ip: &IpAddr) -> bool {
        self.immutable.iter().any(|net| net.contains(ip))
    }

    /// Check if an IP is covered by any whitelisted network (CIDR containment).
    /// Returns true for both immutable and configured entries.
    pub fn is_whitelisted(&self, ip: &IpAddr) -> bool {
        self.is_immutably_protected(ip)
            || self.entries.iter().any(|net| net.contains(ip))
    }

    pub fn entries(&self) -> &HashSet<IpNet> {
        &self.entries
    }

    /// Immutable protected ranges (read-only).
    pub fn immutable_entries(&self) -> &[IpNet] {
        &self.immutable
    }
}

impl Default for WhitelistManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_whitelist_basic() {
        let mut wl = WhitelistManager::new();
        wl.add("8.8.0.0/16".parse().unwrap());

        assert!(wl.is_whitelisted(&"8.8.8.8".parse().unwrap()));
        // 1.1.1.1 is not in the configured or immutable list
        assert!(!wl.is_whitelisted(&"1.1.1.1".parse().unwrap()));
    }

    #[test]
    fn test_whitelist_remove() {
        let mut wl = WhitelistManager::new();
        let net: IpNet = "8.8.0.0/16".parse().unwrap();
        wl.add(net);
        assert!(wl.remove(&net));
        assert!(!wl.remove(&net));

        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        assert!(!wl.is_whitelisted(&ip));
    }

    // --- Phase 10: comprehensive coverage ---

    #[test]
    fn test_cidr_containment_8() {
        let mut wl = WhitelistManager::new();
        wl.add("5.0.0.0/8".parse().unwrap());

        assert!(wl.is_whitelisted(&"5.1.2.3".parse().unwrap()));
        assert!(wl.is_whitelisted(&"5.0.0.1".parse().unwrap()));
        assert!(wl.is_whitelisted(&"5.255.255.255".parse().unwrap()));

        // Outside /8
        assert!(!wl.is_whitelisted(&"6.0.0.1".parse().unwrap()));
        assert!(!wl.is_whitelisted(&"4.255.255.255".parse().unwrap()));
    }

    #[test]
    fn test_cidr_containment_24() {
        let mut wl = WhitelistManager::new();
        wl.add("203.0.114.0/24".parse().unwrap());

        assert!(wl.is_whitelisted(&"203.0.114.0".parse().unwrap()));
        assert!(wl.is_whitelisted(&"203.0.114.128".parse().unwrap()));
        assert!(wl.is_whitelisted(&"203.0.114.255".parse().unwrap()));

        assert!(!wl.is_whitelisted(&"203.0.115.1".parse().unwrap()));
    }

    #[test]
    fn test_cidr_containment_16() {
        let mut wl = WhitelistManager::new();
        wl.add("8.8.0.0/16".parse().unwrap());

        assert!(wl.is_whitelisted(&"8.8.0.1".parse().unwrap()));
        assert!(wl.is_whitelisted(&"8.8.255.255".parse().unwrap()));
        assert!(!wl.is_whitelisted(&"8.9.0.1".parse().unwrap()));
    }

    #[test]
    fn test_ipv6_whitelist() {
        let mut wl = WhitelistManager::new();
        wl.add("2001:db8::/32".parse().unwrap());

        assert!(wl.is_whitelisted(&"2001:db8::1".parse().unwrap()));
        assert!(wl.is_whitelisted(&"2001:db8:ffff::1".parse().unwrap()));
        assert!(!wl.is_whitelisted(&"2001:db9::1".parse().unwrap()));
    }

    #[test]
    fn test_single_ip_whitelist() {
        let mut wl = WhitelistManager::new();
        wl.add("1.2.3.4/32".parse().unwrap());

        assert!(wl.is_whitelisted(&"1.2.3.4".parse().unwrap()));
        assert!(!wl.is_whitelisted(&"1.2.3.5".parse().unwrap()));
    }

    #[test]
    fn test_single_ipv6_whitelist() {
        let mut wl = WhitelistManager::new();
        wl.add("2001:db8::1/128".parse().unwrap());

        assert!(wl.is_whitelisted(&"2001:db8::1".parse().unwrap()));
        assert!(!wl.is_whitelisted(&"2001:db8::2".parse().unwrap()));
    }

    #[test]
    fn test_multiple_whitelist_entries() {
        let mut wl = WhitelistManager::new();
        wl.add("5.0.0.0/8".parse().unwrap());
        wl.add("6.0.0.0/8".parse().unwrap());
        wl.add("2001:db8::/32".parse().unwrap());

        assert!(wl.is_whitelisted(&"5.5.5.5".parse().unwrap()));
        assert!(wl.is_whitelisted(&"6.99.1.1".parse().unwrap()));
        assert!(wl.is_whitelisted(&"2001:db8::1".parse().unwrap()));
        assert!(!wl.is_whitelisted(&"7.0.0.1".parse().unwrap()));
    }

    #[test]
    fn test_entries_returns_all() {
        let mut wl = WhitelistManager::new();
        wl.add("5.0.0.0/8".parse().unwrap());
        wl.add("6.0.0.0/8".parse().unwrap());

        assert_eq!(wl.entries().len(), 2);
    }

    #[test]
    fn test_duplicate_add() {
        let mut wl = WhitelistManager::new();
        wl.add("5.0.0.0/8".parse().unwrap());
        wl.add("5.0.0.0/8".parse().unwrap());

        assert_eq!(wl.entries().len(), 1);
    }

    #[test]
    fn test_empty_whitelist() {
        let wl = WhitelistManager::new();
        assert!(!wl.is_whitelisted(&"1.2.3.4".parse().unwrap()));
        assert!(wl.entries().is_empty());
    }

    #[test]
    fn test_default_constructor() {
        let wl = WhitelistManager::default();
        assert!(wl.entries().is_empty());
    }

    #[test]
    fn test_remove_nonexistent() {
        let mut wl = WhitelistManager::new();
        assert!(!wl.remove(&"5.0.0.0/8".parse().unwrap()));
    }

    #[test]
    fn test_remove_only_exact_cidr() {
        let mut wl = WhitelistManager::new();
        wl.add("5.0.0.0/8".parse().unwrap());

        assert!(!wl.remove(&"5.0.0.0/16".parse().unwrap()));
        assert_eq!(wl.entries().len(), 1);
        assert!(wl.is_whitelisted(&"5.5.5.5".parse().unwrap()));

        assert!(wl.remove(&"5.0.0.0/8".parse().unwrap()));
        assert!(!wl.is_whitelisted(&"5.5.5.5".parse().unwrap()));
    }

    #[test]
    fn test_clone() {
        let mut wl = WhitelistManager::new();
        wl.add("5.0.0.0/8".parse().unwrap());

        let cloned = wl.clone();
        assert!(cloned.is_whitelisted(&"5.5.5.5".parse().unwrap()));
        assert_eq!(cloned.entries().len(), 1);
    }

    // ----- Immutable protection tests -----

    #[test]
    fn loopback_always_protected() {
        let wl = WhitelistManager::new();
        assert!(wl.is_immutably_protected(&"127.0.0.1".parse().unwrap()));
        assert!(wl.is_whitelisted(&"127.0.0.1".parse().unwrap()));
    }

    #[test]
    fn rfc1918_always_protected() {
        let wl = WhitelistManager::new();
        for ip in &["10.1.2.3", "172.20.0.1", "192.168.100.1"] {
            let parsed: IpAddr = ip.parse().unwrap();
            assert!(
                wl.is_immutably_protected(&parsed),
                "{ip} should be immutably protected"
            );
        }
    }

    #[test]
    fn public_ip_not_immutably_protected() {
        let wl = WhitelistManager::new();
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        assert!(!wl.is_immutably_protected(&ip));
    }

    #[test]
    fn rfc1918_protected_even_without_configured_entry() {
        let wl = WhitelistManager::new();
        // No configured entries — but RFC 1918 must still be protected
        assert!(wl.is_whitelisted(&"10.0.0.1".parse().unwrap()));
        assert!(wl.is_whitelisted(&"192.168.0.1".parse().unwrap()));
        assert!(wl.is_whitelisted(&"172.16.0.1".parse().unwrap()));
    }

    #[test]
    fn rfc1918_cannot_be_banned_via_cluster() {
        let wl = WhitelistManager::new();
        // Simulate a cluster ban attempt on an RFC 1918 address —
        // the whitelist check always blocks it.
        let targets = ["10.42.0.1", "172.31.255.254", "192.168.1.1"];
        for t in &targets {
            let ip: IpAddr = t.parse().unwrap();
            assert!(
                wl.is_whitelisted(&ip),
                "Cluster ban on {t} must be blocked by whitelist"
            );
        }
    }

    #[test]
    fn immutable_entries_list_is_non_empty() {
        let wl = WhitelistManager::new();
        assert!(!wl.immutable_entries().is_empty());
    }

    #[test]
    fn ipv6_loopback_protected() {
        let wl = WhitelistManager::new();
        assert!(wl.is_immutably_protected(&"::1".parse().unwrap()));
    }

    #[test]
    fn link_local_protected() {
        let wl = WhitelistManager::new();
        assert!(wl.is_immutably_protected(&"169.254.1.1".parse().unwrap()));
    }
}

