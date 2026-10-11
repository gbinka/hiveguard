//! Helpers that turn a source address into the *counting / ban key* of a
//! detector.
//!
//! IPv6 attackers routinely rotate through the addresses of one /64 (one
//! subscriber or one VM gets a whole /64), so per-address counters never
//! reach a threshold. Detectors therefore count IPv6 sources per prefix
//! (`ipv6_prefix`, default /64) and ban that prefix; IPv4 stays per host.
//!
//! All returned networks are truncated (`trunc()`): the scoring engine keys
//! its buckets by `IpNet::addr()`, so signals for the same subnet must carry
//! the same network address or they would land in different buckets (and a
//! non-truncated subnet would ban only the member that happened to fire).

use std::net::IpAddr;

use ipnet::{IpNet, Ipv4Net, Ipv6Net};

/// Default IPv6 aggregation prefix for per-source counters.
pub const DEFAULT_IPV6_PREFIX: u8 = 64;

/// Narrowest IPv6 prefix accepted for aggregation (wider is refused: peers
/// reject bans wider than /48, and a /32 is a whole ISP).
pub const MIN_IPV6_PREFIX: u8 = 48;

/// Narrowest IPv4 prefix accepted for subnet aggregation (wider than /16 is
/// refused; peers replicate at most a /24).
pub const MIN_IPV4_SUBNET_PREFIX: u8 = 16;

/// Counting key for `ip`: `/32` for IPv4, the truncated `/ipv6_prefix` for
/// IPv6 (`ipv6_prefix` of 0 or >= 128 means per address, `/128`).
pub fn source_key(ip: IpAddr, ipv6_prefix: u8) -> IpNet {
    match ip {
        IpAddr::V4(v4) => IpNet::V4(Ipv4Net::new(v4, 32).expect("/32 is valid")),
        IpAddr::V6(v6) => {
            let p = if ipv6_prefix == 0 || ipv6_prefix >= 128 { 128 } else { ipv6_prefix };
            IpNet::V6(Ipv6Net::new(v6, p).expect("prefix <= 128").trunc())
        }
    }
}

/// Truncated subnet of `ip` for the address family's prefix; `None` when the
/// prefix for that family is 0 (aggregation disabled).
pub fn subnet_of(ip: IpAddr, v4_prefix: u8, v6_prefix: u8) -> Option<IpNet> {
    match ip {
        IpAddr::V4(v4) if v4_prefix > 0 => {
            Some(IpNet::V4(Ipv4Net::new(v4, v4_prefix.min(32)).ok()?.trunc()))
        }
        IpAddr::V6(v6) if v6_prefix > 0 => {
            Some(IpNet::V6(Ipv6Net::new(v6, v6_prefix.min(128)).ok()?.trunc()))
        }
        _ => None,
    }
}

/// Validate an `ipv6_prefix` key (0 = per address, else 48..=128).
pub fn validate_ipv6_prefix(key: &str, prefix: u8) -> Result<(), String> {
    if prefix == 0 || (MIN_IPV6_PREFIX..=128).contains(&prefix) {
        Ok(())
    } else {
        Err(format!("{key} must be 0 (per address) or {MIN_IPV6_PREFIX}..=128, got {prefix}"))
    }
}

/// Validate an IPv4 subnet-aggregation prefix (0 = off, else 16..=32).
pub fn validate_v4_subnet_prefix(key: &str, prefix: u8) -> Result<(), String> {
    if prefix == 0 || (MIN_IPV4_SUBNET_PREFIX..=32).contains(&prefix) {
        Ok(())
    } else {
        Err(format!("{key} must be 0 (off) or {MIN_IPV4_SUBNET_PREFIX}..=32, got {prefix}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v4_is_always_host() {
        let ip: IpAddr = "100.64.1.7".parse().unwrap();
        assert_eq!(source_key(ip, 64).to_string(), "100.64.1.7/32");
    }

    #[test]
    fn v6_is_truncated_to_prefix() {
        let ip: IpAddr = "fd00:1:2:3:aaaa:bbbb:cccc:dddd".parse().unwrap();
        assert_eq!(source_key(ip, 64).to_string(), "fd00:1:2:3::/64");
        assert_eq!(source_key(ip, 0).prefix_len(), 128);
        assert_eq!(source_key(ip, 128).prefix_len(), 128);
    }

    #[test]
    fn subnet_is_truncated_and_optional() {
        let v4: IpAddr = "100.64.53.200".parse().unwrap();
        assert_eq!(subnet_of(v4, 24, 0).unwrap().to_string(), "100.64.53.0/24");
        assert!(subnet_of(v4, 0, 64).is_none());
        let v6: IpAddr = "fd00:1:2:3::9".parse().unwrap();
        assert_eq!(subnet_of(v6, 24, 48).unwrap().to_string(), "fd00:1:2::/48");
        assert!(subnet_of(v6, 24, 0).is_none());
    }

    #[test]
    fn validation_bounds() {
        assert!(validate_ipv6_prefix("x", 0).is_ok());
        assert!(validate_ipv6_prefix("x", 64).is_ok());
        assert!(validate_ipv6_prefix("x", 32).is_err());
        assert!(validate_v4_subnet_prefix("x", 0).is_ok());
        assert!(validate_v4_subnet_prefix("x", 24).is_ok());
        assert!(validate_v4_subnet_prefix("x", 8).is_err());
    }
}
