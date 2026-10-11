use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use ipnet::IpNet;

use crate::detector::Detector;
use crate::detectors::netkey::{source_key, subnet_of, DEFAULT_IPV6_PREFIX};
use crate::models::{Action, DetectionSignal, EventType, NormalizedEvent};

/// Sweep expired per-IP state every this many port events.
const SWEEP_EVERY: u64 = 4096;

/// Port scan detector — detects hosts accessing many different ports.
///
/// Note: Full implementation requires netlink/conntrack integration.
/// This version works with `EventType::PortAccess` events from custom parsers.
/// Default: >=6 unique ports in 10 min → ban 48h. The window is long because
/// firewall logs are rate-limited samples (UFW logs ~3 blocks/min host-wide),
/// so slow scanners only ever show a few ports per minute.
///
/// A second, **long-window tier** catches scans spread over hours (e.g.
/// 1757 ports in 24 h at a couple of ports per 10 min, which never reaches
/// the short threshold): `>= long_threshold` distinct ports within
/// `long_window` (default 25 ports / 6 h → ban 7 days, detector name
/// `port_scan_slow`). Each IP keeps at most `long_threshold` entries (it
/// fires and resets on reaching it) and at most `max_tracked_ips` IPs are
/// tracked per tier, so memory stays bounded under heavy scanning.
///
/// IPv6 sources are counted per `/ipv6_prefix` (default /64) in both tiers
/// and banned as that prefix: scanners rotate addresses inside their /64.
///
/// Optional **distributed slow tier** (`long_subnet_v4_prefix`, off by
/// default): distinct ports probed by all addresses of one IPv4 subnet within
/// `long_window`; fires (subnet ban, `port_scan_slow`) at
/// `long_subnet_threshold` ports seen from at least `long_subnet_min_ips`
/// addresses — several hosts of one /24 each staying under the per-IP limit.
pub struct PortScanDetector {
    /// Window for tracking port access.
    window: Duration,
    /// Number of distinct ports to trigger detection.
    threshold: usize,
    /// Ban duration.
    ban_duration: Duration,
    /// Per-IP: (port, last seen) entries, at most one per distinct port.
    port_access: DashMap<IpAddr, Vec<(u16, DateTime<Utc>)>>,
    /// Long-window tier (0 threshold = disabled).
    long_window: Duration,
    long_threshold: usize,
    long_ban_duration: Duration,
    long_access: DashMap<IpAddr, Vec<(u16, DateTime<Utc>)>>,
    /// Cap of IPs tracked per tier.
    max_tracked_ips: usize,
    /// IPv6 aggregation prefix (0/128 = per address).
    ipv6_prefix: u8,
    /// Distributed slow tier over IPv4 subnets (prefix 0 = off).
    long_subnet_v4_prefix: u8,
    long_subnet_threshold: usize,
    long_subnet_min_ips: usize,
    /// Per subnet: (port, source, last seen), one entry per (port, source).
    long_subnet_access: DashMap<IpNet, Vec<(u16, IpAddr, DateTime<Utc>)>>,
    events: AtomicU64,
}

pub const DEFAULT_LONG_WINDOW_SECS: u64 = 6 * 3600;
pub const DEFAULT_LONG_THRESHOLD: usize = 25;
pub const DEFAULT_LONG_BAN_SECS: u64 = 7 * 24 * 3600;
pub const DEFAULT_MAX_TRACKED_IPS: usize = 50_000;
pub const DEFAULT_LONG_SUBNET_THRESHOLD: usize = 40;
pub const DEFAULT_LONG_SUBNET_MIN_IPS: usize = 3;

impl PortScanDetector {
    pub fn new() -> Self {
        Self::with_config(Duration::from_secs(600), 6, Duration::from_secs(48 * 3600))
    }

    pub fn with_config(window: Duration, threshold: usize, ban_duration: Duration) -> Self {
        Self {
            window,
            threshold,
            ban_duration,
            port_access: DashMap::new(),
            long_window: Duration::from_secs(DEFAULT_LONG_WINDOW_SECS),
            long_threshold: DEFAULT_LONG_THRESHOLD,
            long_ban_duration: Duration::from_secs(DEFAULT_LONG_BAN_SECS),
            long_access: DashMap::new(),
            max_tracked_ips: DEFAULT_MAX_TRACKED_IPS,
            ipv6_prefix: DEFAULT_IPV6_PREFIX,
            long_subnet_v4_prefix: 0,
            long_subnet_threshold: DEFAULT_LONG_SUBNET_THRESHOLD,
            long_subnet_min_ips: DEFAULT_LONG_SUBNET_MIN_IPS,
            long_subnet_access: DashMap::new(),
            events: AtomicU64::new(0),
        }
    }

    /// Count (and ban) IPv6 sources per this prefix; 0 or 128 = per address.
    pub fn with_ipv6_prefix(mut self, prefix: u8) -> Self {
        self.ipv6_prefix = prefix;
        self
    }

    /// Enable the distributed slow tier over IPv4 `/v4_prefix` subnets
    /// (0 = off). Uses the long tier's window and ban duration.
    pub fn with_long_subnet_tier(mut self, v4_prefix: u8, threshold: usize, min_ips: usize) -> Self {
        self.long_subnet_v4_prefix = v4_prefix.min(32);
        self.long_subnet_threshold = threshold;
        self.long_subnet_min_ips = min_ips.max(1);
        self
    }

    /// Configure the long-window tier; `threshold == 0` disables it.
    pub fn with_long_tier(mut self, window: Duration, threshold: usize, ban_duration: Duration) -> Self {
        self.long_window = window;
        self.long_threshold = threshold;
        self.long_ban_duration = ban_duration;
        self
    }

    /// Cap the number of IPs tracked per tier (min 1).
    pub fn with_max_tracked_ips(mut self, max: usize) -> Self {
        self.max_tracked_ips = max.max(1);
        self
    }

    /// Counting key (= ban subject) of a source address.
    fn key(&self, ip: IpAddr) -> IpNet {
        source_key(ip, self.ipv6_prefix)
    }

    fn cutoff(now: DateTime<Utc>, window: Duration) -> DateTime<Utc> {
        now - chrono::Duration::from_std(window).unwrap_or(chrono::Duration::seconds(30))
    }

    fn cleanup_old_entries(&self, ip: &IpAddr, now: DateTime<Utc>) {
        if let Some(mut entries) = self.port_access.get_mut(ip) {
            let cutoff = Self::cutoff(now, self.window);
            entries.retain(|(_, t)| *t > cutoff);
            if entries.is_empty() {
                drop(entries);
                self.port_access.remove(ip);
            }
        }
    }

    fn maybe_sweep(&self, now: DateTime<Utc>) {
        if self.events.fetch_add(1, Ordering::Relaxed) % SWEEP_EVERY != SWEEP_EVERY - 1 {
            return;
        }
        self.sweep(now);
    }

    fn sweep(&self, now: DateTime<Utc>) {
        let short = Self::cutoff(now, self.window);
        self.port_access.retain(|_, v| v.iter().any(|(_, t)| *t > short));
        let long = Self::cutoff(now, self.long_window);
        self.long_access.retain(|_, v| v.iter().any(|(_, t)| *t > long));
        self.long_subnet_access
            .retain(|_, v| v.iter().any(|(_, _, t)| *t > long));
    }

    /// Distributed slow tier: record `(port, ip)` for the IPv4 subnet and
    /// fire once the subnet reached the distinct-port and distinct-IP minima.
    fn long_subnet_tier(&self, ip: IpAddr, port: u16, now: DateTime<Utc>) -> Option<DetectionSignal> {
        if self.long_subnet_threshold == 0 || !ip.is_ipv4() {
            return None;
        }
        let subnet = subnet_of(ip, self.long_subnet_v4_prefix, 0)?;
        if self.long_subnet_access.len() >= self.max_tracked_ips
            && !self.long_subnet_access.contains_key(&subnet)
        {
            self.sweep(now);
            if self.long_subnet_access.len() >= self.max_tracked_ips {
                return None;
            }
        }
        let cutoff = Self::cutoff(now, self.long_window);
        let cap = self.long_subnet_threshold * 4 + 64;
        let mut entries = self.long_subnet_access.entry(subnet).or_default();
        entries.retain(|(p, a, t)| *t > cutoff && !(*p == port && *a == ip));
        entries.push((port, ip, now));
        if entries.len() > cap {
            let excess = entries.len() - cap;
            entries.drain(..excess);
        }
        let mut ports: Vec<u16> = entries.iter().map(|(p, _, _)| *p).collect();
        ports.sort_unstable();
        ports.dedup();
        if ports.len() < self.long_subnet_threshold {
            return None;
        }
        let mut ips: Vec<IpAddr> = entries.iter().map(|(_, a, _)| *a).collect();
        ips.sort_unstable();
        ips.dedup();
        if ips.len() < self.long_subnet_min_ips {
            return None;
        }
        let (n_ports, n_ips) = (ports.len(), ips.len());
        entries.clear();
        drop(entries);
        self.long_subnet_access.remove(&subnet);
        let evidence = format!("{subnet}:port_scan_slow:subnet:{n_ports}_ports:{}", now.timestamp() / 60);
        Some(DetectionSignal {
            source_ip: subnet,
            severity: 200,
            confidence: 0.9,
            reason: format!(
                "Distributed slow port scan: {n_ports} unique ports from {n_ips} addresses in {subnet} in {}s",
                self.long_window.as_secs()
            ),
            evidence_hash: *blake3::hash(evidence.as_bytes()).as_bytes(),
            suggested_action: Action::Ban(self.long_ban_duration),
            detector_name: "port_scan_slow".into(),
            timestamp: now,
        })
    }

    /// May a new IP be added to `map`? Sweeps once when full; fails open
    /// (new IP not tracked) if the map is still full of live scanners.
    fn admit(&self, map: &DashMap<IpAddr, Vec<(u16, DateTime<Utc>)>>, ip: &IpAddr, now: DateTime<Utc>) -> bool {
        if map.len() < self.max_tracked_ips || map.contains_key(ip) {
            return true;
        }
        self.sweep(now);
        map.len() < self.max_tracked_ips
    }

    fn long_tier(&self, key: IpNet, port: u16, now: DateTime<Utc>) -> Option<DetectionSignal> {
        let ip = key.addr();
        if self.long_threshold == 0 || !self.admit(&self.long_access, &ip, now) {
            return None;
        }
        let cutoff = Self::cutoff(now, self.long_window);
        let mut entries = self.long_access.entry(ip).or_default();
        entries.retain(|(p, t)| *t > cutoff && *p != port);
        entries.push((port, now));
        let unique = entries.len();
        if unique < self.long_threshold {
            return None;
        }
        entries.clear();
        drop(entries);
        self.long_access.remove(&ip);
        let evidence = format!("{}:port_scan_slow:{}_ports:{}", key, unique, now.timestamp() / 60);
        Some(DetectionSignal {
            source_ip: key,
            severity: 200,
            confidence: 0.9,
            reason: format!(
                "Slow port scan detected: {} unique ports in {}s",
                unique,
                self.long_window.as_secs()
            ),
            evidence_hash: *blake3::hash(evidence.as_bytes()).as_bytes(),
            suggested_action: Action::Ban(self.long_ban_duration),
            detector_name: "port_scan_slow".into(),
            timestamp: now,
        })
    }
}

impl Default for PortScanDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for PortScanDetector {
    fn name(&self) -> &str {
        "port_scan"
    }

    fn process(&self, event: &NormalizedEvent) -> Option<DetectionSignal> {
        if event.event_type != EventType::PortAccess {
            return None;
        }

        let port: u16 = event.metadata.get("port")?.parse().ok()?;
        // IPv6: one key per /ipv6_prefix, so address rotation inside the
        // prefix keeps adding to the same counters.
        let key = self.key(event.source_ip);
        let ip = key.addr();

        self.maybe_sweep(event.timestamp);
        self.cleanup_old_entries(&ip, event.timestamp);

        // The subnet tier sees every event; its (wider) ban wins.
        let subnet_signal = self.long_subnet_tier(event.source_ip, port, event.timestamp);

        if !self.admit(&self.port_access, &ip, event.timestamp) {
            return subnet_signal.or_else(|| self.long_tier(key, port, event.timestamp));
        }
        let mut entries = self.port_access.entry(ip).or_default();
        // Keep one entry per port so repeated hits on the same port cannot
        // grow the list over the (long) window.
        entries.retain(|(p, _)| *p != port);
        entries.push((port, event.timestamp));
        let unique_ports = entries.len();

        if unique_ports >= self.threshold {
            let evidence = format!("{}:port_scan:{}_ports", key, unique_ports);
            // Clear the entries to avoid repeated firing
            entries.clear();
            drop(entries);
            // The short-tier ban covers the slow tier too.
            self.long_access.remove(&ip);

            subnet_signal.or(Some(DetectionSignal {
                source_ip: key,
                severity: 200,
                confidence: 0.9,
                reason: format!("Port scan detected: {} unique ports in {}s", unique_ports, self.window.as_secs()),
                evidence_hash: *blake3::hash(evidence.as_bytes()).as_bytes(),
                suggested_action: Action::Ban(self.ban_duration),
                detector_name: "port_scan".into(),
                timestamp: event.timestamp,
            }))
        } else {
            drop(entries);
            subnet_signal.or_else(|| self.long_tier(key, port, event.timestamp))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use std::collections::HashMap;

    fn make_port_event(ip: &str, port: u16, ts: DateTime<Utc>) -> NormalizedEvent {
        let mut metadata = HashMap::new();
        metadata.insert("port".to_string(), port.to_string());
        NormalizedEvent {
            timestamp: ts,
            source_ip: ip.parse().unwrap(),
            event_type: EventType::PortAccess,
            source_name: "test".into(),
            raw_line: format!("port {port}"),
            metadata,
        }
    }

    #[test]
    fn detect_port_scan() {
        let mut d = PortScanDetector::with_config(Duration::from_secs(30), 5, Duration::from_secs(3600));
        let base = Utc::now();

        for port in 0..4 {
            let event = make_port_event("10.0.0.1", 1000 + port, base);
            assert!(d.process(&event).is_none());
        }

        // 5th unique port triggers detection
        let event = make_port_event("10.0.0.1", 1004, base);
        let result = d.process(&event);
        assert!(result.is_some());
        let s = result.unwrap();
        assert_eq!(s.severity, 200);
        assert!((s.confidence - 0.9).abs() < f32::EPSILON);
    }

    #[test]
    fn same_port_no_scan() {
        let mut d = PortScanDetector::with_config(Duration::from_secs(30), 5, Duration::from_secs(3600));
        let base = Utc::now();

        // Same port repeated — only 1 unique port
        for _ in 0..10 {
            let event = make_port_event("10.0.0.1", 80, base);
            assert!(d.process(&event).is_none());
        }
    }

    #[test]
    fn ignores_non_port_events() {
        let mut d = PortScanDetector::new();
        let event = NormalizedEvent {
            timestamp: Utc::now(),
            source_ip: "10.0.0.1".parse().unwrap(),
            event_type: EventType::HttpRequest,
            source_name: "test".into(),
            raw_line: "GET /".into(),
            metadata: HashMap::new(),
        };
        assert!(d.process(&event).is_none());
    }

    #[test]
    fn separate_ips_tracked_independently() {
        let mut d = PortScanDetector::with_config(Duration::from_secs(30), 3, Duration::from_secs(3600));
        let base = Utc::now();

        // IP1: 2 ports
        d.process(&make_port_event("10.0.0.1", 80, base));
        d.process(&make_port_event("10.0.0.1", 443, base));

        // IP2: 3 ports → triggers
        d.process(&make_port_event("10.0.0.2", 80, base));
        d.process(&make_port_event("10.0.0.2", 443, base));
        let result = d.process(&make_port_event("10.0.0.2", 8080, base));
        assert!(result.is_some());

        // IP1: still only 2 ports, no trigger
        assert!(d.process(&make_port_event("10.0.0.1", 80, base)).is_none());
    }

    // --- Phase 20: comprehensive coverage ---

    #[test]
    fn default_threshold_6_ports_in_10m() {
        let d = PortScanDetector::new();
        let base = Utc::now();

        // 5 unique ports spread over 9 minutes → no ban
        for port in 0..5 {
            let event = make_port_event("10.0.0.1", 1000 + port, base + chrono::Duration::seconds(port as i64 * 108));
            assert!(d.process(&event).is_none());
        }

        // 6th unique port within the 10 min window → ban
        let event = make_port_event("10.0.0.1", 1005, base + chrono::Duration::seconds(590));
        let result = d.process(&event);
        assert!(result.is_some());
        let s = result.unwrap();
        assert_eq!(s.suggested_action, Action::Ban(Duration::from_secs(48 * 3600)));
    }

    #[test]
    fn ports_outside_window_no_trigger() {
        let mut d = PortScanDetector::with_config(Duration::from_secs(30), 5, Duration::from_secs(3600));
        let base = Utc::now();

        // 3 ports at time 0
        for port in 0..3 {
            let event = make_port_event("10.0.0.1", 1000 + port, base);
            d.process(&event);
        }

        // 3 ports at time +60s (outside 30s window)
        let late = base + chrono::Duration::seconds(60);
        for port in 3..6 {
            let event = make_port_event("10.0.0.1", 1000 + port, late);
            // Only 3 unique ports in the window now
            assert!(d.process(&event).is_none());
        }
    }

    #[test]
    fn port_scan_ipv6() {
        let mut d = PortScanDetector::with_config(Duration::from_secs(30), 3, Duration::from_secs(3600));
        let base = Utc::now();

        for port in 0..3 {
            let event = make_port_event("2001:db8::1", 1000 + port, base);
            if port == 2 {
                let result = d.process(&event);
                assert!(result.is_some());
                let s = result.unwrap();
                assert!(s.source_ip.addr().to_string().contains("2001:db8"));
            } else {
                d.process(&event);
            }
        }
    }

    #[test]
    fn port_scan_clears_after_trigger() {
        let mut d = PortScanDetector::with_config(Duration::from_secs(30), 3, Duration::from_secs(3600));
        let base = Utc::now();

        // Trigger first scan
        for port in 0..3 {
            d.process(&make_port_event("10.0.0.1", 1000 + port, base));
        }

        // After trigger, window is cleared — need 3 more
        let event = make_port_event("10.0.0.1", 2000, base);
        assert!(d.process(&event).is_none());
    }

    #[test]
    fn port_scan_missing_port_metadata() {
        let mut d = PortScanDetector::new();
        let event = NormalizedEvent {
            timestamp: Utc::now(),
            source_ip: "10.0.0.1".parse().unwrap(),
            event_type: EventType::PortAccess,
            source_name: "test".into(),
            raw_line: "port access".into(),
            metadata: HashMap::new(), // no "port" key
        };
        assert!(d.process(&event).is_none());
    }

    #[test]
    fn port_scan_invalid_port_value() {
        let mut d = PortScanDetector::new();
        let mut metadata = HashMap::new();
        metadata.insert("port".to_string(), "not_a_number".to_string());
        let event = NormalizedEvent {
            timestamp: Utc::now(),
            source_ip: "10.0.0.1".parse().unwrap(),
            event_type: EventType::PortAccess,
            source_name: "test".into(),
            raw_line: "port access".into(),
            metadata,
        };
        assert!(d.process(&event).is_none());
    }

    #[test]
    fn port_scan_default_constructor() {
        let d = PortScanDetector::default();
        assert_eq!(d.name(), "port_scan");
        assert_eq!(d.threshold, 6);
        assert_eq!(d.window, Duration::from_secs(600));
        assert_eq!(d.ban_duration, Duration::from_secs(48 * 3600));
    }

    #[test]
    fn repeated_hits_on_one_port_do_not_accumulate() {
        let d = PortScanDetector::with_config(Duration::from_secs(600), 3, Duration::from_secs(3600));
        let base = Utc::now();
        for i in 0..1000 {
            assert!(d.process(&make_port_event("10.0.0.1", 23, base + chrono::Duration::milliseconds(i))).is_none());
        }
        assert_eq!(d.port_access.get(&"10.0.0.1".parse::<IpAddr>().unwrap()).unwrap().len(), 1);
    }

    /// Scenario C: 147.45.112.16 — 1757 blocked ports in 24 h, sampled by
    /// ufw at ~1.2 ports/min, i.e. never 6 distinct ports in 10 min.
    #[test]
    fn scenario_c_slow_scan_caught_by_long_tier() {
        let d = PortScanDetector::new();
        let base: DateTime<Utc> = "2026-10-09T10:43:00Z".parse().unwrap();
        let mut fired = None;
        for i in 0..1757u32 {
            // one port every 49 s → ≤ 13 per 10 min; make the short tier blind
            // by feeding only every 3rd port to it (5 per 10 min, like ufw sampling)
            if i % 3 != 0 {
                continue;
            }
            let ts = base + chrono::Duration::seconds(49 * i as i64);
            if let Some(s) = d.process(&make_port_event("147.45.112.16", (1024 + i) as u16, ts)) {
                fired = Some((s, ts));
                break;
            }
        }
        let (s, ts) = fired.expect("slow scan must be caught");
        eprintln!("scenario C (147.45.112.16): ban after {}s", (ts - base).num_seconds());
        assert_eq!(s.detector_name, "port_scan_slow");
        assert_eq!(s.source_ip.prefix_len(), 32);
        assert_eq!(s.suggested_action, Action::Ban(Duration::from_secs(DEFAULT_LONG_BAN_SECS)));
        // 25 distinct ports at ~2.45 min each ≈ 60 min.
        assert!(ts - base <= chrono::Duration::minutes(65), "after {:?}", ts - base);
    }

    /// 169.255.58.185 — 502 ports / 24 h (~1 per 2.9 min): caught in ~70 min.
    #[test]
    fn scenario_c_second_scanner() {
        let d = PortScanDetector::new();
        let base: DateTime<Utc> = "2026-10-09T10:43:00Z".parse().unwrap();
        let step = 86_400 / 502;
        let mut fired_at = None;
        for i in 0..502u32 {
            let ts = base + chrono::Duration::seconds(step * i as i64);
            if d.process(&make_port_event("169.255.58.185", (2000 + i) as u16, ts)).is_some() {
                fired_at = Some(ts);
                break;
            }
        }
        let ts = fired_at.expect("caught");
        eprintln!("scenario C (169.255.58.185): ban after {}s", (ts - base).num_seconds());
        assert!(ts - base <= chrono::Duration::minutes(75), "after {:?}", ts - base);
    }

    #[test]
    fn long_tier_can_be_disabled_and_respects_window() {
        let d = PortScanDetector::new().with_long_tier(Duration::from_secs(3600), 0, Duration::from_secs(60));
        let base = Utc::now();
        for i in 0..200u32 {
            let ts = base + chrono::Duration::seconds(300 * i as i64);
            assert!(d.process(&make_port_event("10.0.0.9", (1000 + i) as u16, ts)).is_none());
        }
        // Enabled, 10 ports / 1 h, but only 1 port per 10 min → max 6-7 in any hour.
        let d = PortScanDetector::new().with_long_tier(Duration::from_secs(3600), 10, Duration::from_secs(60));
        for i in 0..200u32 {
            let ts = base + chrono::Duration::seconds(600 * i as i64);
            assert!(d.process(&make_port_event("10.0.0.9", (1000 + i) as u16, ts)).is_none());
        }
    }

    #[test]
    fn long_tier_memory_bounded() {
        let d = PortScanDetector::new().with_max_tracked_ips(100);
        let base = Utc::now();
        for i in 0..10_000u32 {
            let ip = format!("10.{}.{}.{}", i >> 16 & 255, i >> 8 & 255, i & 255);
            d.process(&make_port_event(&ip, 22, base));
        }
        assert!(d.port_access.len() <= 100);
        assert!(d.long_access.len() <= 100);
        // Per-IP entries never exceed the long threshold.
        let d = PortScanDetector::with_config(Duration::from_secs(1), 1000, Duration::from_secs(60));
        for i in 0..5000u32 {
            let ts = base + chrono::Duration::seconds(i as i64 * 2);
            d.process(&make_port_event("10.1.1.1", (i % 60000) as u16, ts));
        }
        assert!(d.long_access.get(&"10.1.1.1".parse::<IpAddr>().unwrap()).map_or(0, |v| v.len()) < DEFAULT_LONG_THRESHOLD);
    }

    #[test]
    fn short_tier_ban_resets_long_tier() {
        let d = PortScanDetector::new();
        let base = Utc::now();
        for p in 0..6u16 {
            let r = d.process(&make_port_event("10.0.0.1", 100 + p, base));
            if p == 5 {
                assert_eq!(r.unwrap().detector_name, "port_scan");
            }
        }
        assert!(d.long_access.get(&"10.0.0.1".parse::<IpAddr>().unwrap()).is_none());
    }

    #[test]
    fn port_scan_reason_contains_count() {
        let mut d = PortScanDetector::with_config(Duration::from_secs(30), 3, Duration::from_secs(3600));
        let base = Utc::now();

        let mut last = None;
        for port in 0..3 {
            last = d.process(&make_port_event("10.0.0.1", 1000 + port, base));
        }
        let s = last.unwrap();
        assert!(s.reason.contains("3 unique ports"));
    }

    #[test]
    fn ipv6_rotation_inside_a_slash64_is_one_scanner() {
        let d = PortScanDetector::new(); // threshold 6, ipv6_prefix 64
        let base = Utc::now();
        let mut fired = None;
        for i in 1..=6u16 {
            // A new address of the same /64 for every port.
            let ip = format!("2001:db8:8000:1::{i:x}");
            fired = d.process(&make_port_event(&ip, 1000 + i, base));
        }
        let s = fired.expect("aggregated over the /64");
        assert_eq!(s.source_ip.to_string(), "2001:db8:8000:1::/64");
        assert_eq!(s.detector_name, "port_scan");
    }

    #[test]
    fn ipv6_prefix_128_keeps_per_address_counting() {
        let d = PortScanDetector::new().with_ipv6_prefix(128);
        let base = Utc::now();
        for i in 1..=6u16 {
            let ip = format!("2001:db8:8000:1::{i:x}");
            assert!(d.process(&make_port_event(&ip, 1000 + i, base)).is_none());
        }
    }

    #[test]
    fn ipv6_long_tier_aggregates_prefix() {
        let d = PortScanDetector::with_config(Duration::from_secs(60), 1000, Duration::from_secs(3600))
            .with_long_tier(Duration::from_secs(6 * 3600), 25, Duration::from_secs(7 * 86400));
        let base = Utc::now();
        let mut fired = None;
        for i in 0..25u16 {
            let ip = format!("2001:db8:8000:1::{:x}", 100 + i);
            let ts = base + chrono::Duration::seconds(i as i64 * 600);
            fired = d.process(&make_port_event(&ip, 2000 + i, ts));
        }
        let s = fired.expect("slow tier over the /64");
        assert_eq!(s.detector_name, "port_scan_slow");
        assert_eq!(s.source_ip.to_string(), "2001:db8:8000:1::/64");
    }

    #[test]
    fn distributed_slow_scan_from_one_slash24_bans_subnet() {
        // 7 hosts of one /24, ~20 ports each over 6 h: per-IP slow tier (25)
        // never fires; the subnet tier (40 ports, >= 3 IPs) does.
        let d = PortScanDetector::new().with_long_subnet_tier(24, 40, 3);
        let base = Utc::now();
        let mut fired = None;
        // Each host probes one port every 15 min (never 6 in the 10-min
        // short window); the 7 hosts interleave over 5 h.
        'outer: for k in 0..20u16 {
            for host in 1..=7u16 {
                let ip = format!("100.64.49.{host}");
                let port = 1000 + host * 100 + k;
                let ts = base + chrono::Duration::seconds(k as i64 * 900 + host as i64 * 60);
                if let Some(s) = d.process(&make_port_event(&ip, port, ts)) {
                    fired = Some(s);
                    break 'outer;
                }
            }
        }
        let s = fired.expect("subnet slow tier");
        assert_eq!(s.detector_name, "port_scan_slow");
        assert_eq!(s.source_ip.to_string(), "100.64.49.0/24");
        assert!(s.reason.contains("addresses"));
    }

    #[test]
    fn subnet_tier_off_by_default_and_needs_min_ips() {
        let base = Utc::now();
        let d = PortScanDetector::new();
        for k in 0..20u16 {
            for host in 1..=7u16 {
                let ts = base + chrono::Duration::seconds(k as i64 * 900 + host as i64 * 60);
                assert!(d
                    .process(&make_port_event(&format!("100.64.49.{host}"), 1000 + host * 100 + k, ts))
                    .is_none());
            }
        }
        // Enabled, but all ports come from 2 addresses only.
        let d = PortScanDetector::new()
            .with_long_tier(Duration::from_secs(6 * 3600), 0, Duration::from_secs(3600))
            .with_long_subnet_tier(24, 10, 3);
        for k in 0..30u16 {
            let ts = base + chrono::Duration::seconds(k as i64 * 600);
            let ip = format!("100.64.49.{}", 1 + (k % 2));
            assert!(d.process(&make_port_event(&ip, 3000 + k, ts)).is_none());
        }
    }
}
