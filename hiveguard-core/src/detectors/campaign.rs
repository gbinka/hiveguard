//! Cross-IP campaign detector (distributed low-and-slow credential stuffing).
//!
//! Every other HTTP detector is keyed by source IP, so a botnet / residential
//! proxy pool that spreads `POST /wp-login.php` over thousands of addresses
//! (a handful of requests per IP per day, all answered `200`) stays invisible.
//! This detector instead keys requests to *sensitive endpoints* by a
//! **fingerprint** shared by all participants:
//!
//! * `ua` key — `(User-Agent, method, endpoint)`: catches a pool driven by one
//!   tool (e.g. `Goosee-Audit/1.0` on 1612 IPs);
//! * optional `vhost` key — `(vhost, method, endpoint)`: catches a pool with
//!   randomised User-Agents aimed at one site (needs the trailing `"$host"`
//!   field in the nginx log, exposed as `metadata["vhost"]`).
//!
//! When one key collects `>= min_distinct_ips` distinct IPs **and**
//! `>= min_requests` requests inside the sliding `window`, the campaign becomes
//! *hot* for `hot_duration` (extended by every further hit). While hot:
//!
//! * the IP of every new matching request is signalled on its first hit;
//! * all IPs already seen in the window are signalled retroactively
//!   ("retro bans"), drained at most `retro_batch` per processed event so a
//!   large campaign does not stall the pipeline with hundreds of nft syncs.
//!
//! Signals are always host-scoped (`/32`, `/128`), never subnets.
//! Successful WordPress logins answer `302`; with `ignore_redirects` (default)
//! `3xx` responses neither count nor get banned. Known-good User-Agents
//! (`ignore_user_agents`, case-insensitive substrings) are skipped entirely.
//! Memory is bounded by `max_keys`, `max_hits_per_key`, the per-campaign
//! flagged-set cap and the retro queue cap.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::Duration;

use chrono::{DateTime, Utc};
use ipnet::IpNet;

use crate::detector::Detector;
use crate::models::{Action, DetectionSignal, EventType, NormalizedEvent};

/// Sweep idle keys every this many matching events.
const SWEEP_EVERY: u64 = 4096;
/// Upper bound of IPs remembered as "already signalled" per hot campaign.
const MAX_FLAGGED_PER_KEY: usize = 50_000;
/// Upper bound of the global retro-ban queue.
const MAX_PENDING: usize = 20_000;

/// Tunables of [`CampaignDetector`].
#[derive(Debug, Clone)]
pub struct CampaignConfig {
    /// Sensitive endpoints (prefix match on the path without query string).
    pub paths: Vec<String>,
    /// HTTP methods that count (case-insensitive).
    pub methods: Vec<String>,
    /// Sliding window for the trigger counters.
    pub window: Duration,
    /// Distinct source IPs per fingerprint needed to flag a campaign.
    pub min_distinct_ips: usize,
    /// Requests per fingerprint needed to flag a campaign.
    pub min_requests: usize,
    /// How long a flagged campaign stays hot after its last hit.
    pub hot_duration: Duration,
    /// Ban duration suggested for participants.
    pub ban_duration: Duration,
    /// Case-insensitive User-Agent substrings that are never counted.
    pub ignore_user_agents: Vec<String>,
    /// Hosts (vhost metadata, lower-case, exact) that are never counted.
    pub ignore_vhosts: Vec<String>,
    /// Skip `3xx` responses (successful WordPress logins redirect).
    pub ignore_redirects: bool,
    /// Distinct IPs per `(vhost, endpoint)` regardless of UA (0 = off).
    pub vhost_min_distinct_ips: usize,
    /// Signal the IPs seen before the campaign was flagged.
    pub retro_ban: bool,
    /// Max retro signals queued per campaign trigger.
    pub max_retro_bans: usize,
    /// Max retro signals emitted per processed event.
    pub retro_batch: usize,
    /// Max fingerprints tracked at once.
    pub max_keys: usize,
    /// Max remembered hits per fingerprint (oldest dropped first).
    pub max_hits_per_key: usize,
}

pub fn default_campaign_paths() -> Vec<String> {
    vec!["/wp-login.php".into(), "/xmlrpc.php".into()]
}

pub fn default_campaign_ignore_user_agents() -> Vec<String> {
    [
        "Googlebot",
        "bingbot",
        "Jetpack",
        "WordPress/",
        "UptimeRobot",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

impl Default for CampaignConfig {
    fn default() -> Self {
        Self {
            paths: default_campaign_paths(),
            methods: vec!["POST".into()],
            window: Duration::from_secs(1800),
            min_distinct_ips: 20,
            min_requests: 30,
            hot_duration: Duration::from_secs(6 * 3600),
            ban_duration: Duration::from_secs(24 * 3600),
            ignore_user_agents: default_campaign_ignore_user_agents(),
            ignore_vhosts: Vec::new(),
            ignore_redirects: true,
            vhost_min_distinct_ips: 0,
            retro_ban: true,
            max_retro_bans: 2000,
            retro_batch: 32,
            max_keys: 5000,
            max_hits_per_key: 4096,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyKind {
    UserAgent,
    Vhost,
}

struct KeyState {
    kind: KeyKind,
    /// Human-readable fingerprint for the ban reason.
    label: String,
    hits: VecDeque<(DateTime<Utc>, IpAddr)>,
    ip_counts: HashMap<IpAddr, u32>,
    last_seen: DateTime<Utc>,
    hot_until: Option<DateTime<Utc>>,
    /// IPs already signalled during the current hot period.
    flagged: HashSet<IpAddr>,
}

impl KeyState {
    fn new(kind: KeyKind, label: String, now: DateTime<Utc>) -> Self {
        Self {
            kind,
            label,
            hits: VecDeque::new(),
            ip_counts: HashMap::new(),
            last_seen: now,
            hot_until: None,
            flagged: HashSet::new(),
        }
    }

    fn pop_front(&mut self) {
        if let Some((_, ip)) = self.hits.pop_front() {
            if let Some(c) = self.ip_counts.get_mut(&ip) {
                *c -= 1;
                if *c == 0 {
                    self.ip_counts.remove(&ip);
                }
            }
        }
    }

    fn prune(&mut self, cutoff: DateTime<Utc>) {
        while matches!(self.hits.front(), Some((t, _)) if *t < cutoff) {
            self.pop_front();
        }
    }

    fn is_hot(&self, now: DateTime<Utc>) -> bool {
        matches!(self.hot_until, Some(t) if t >= now)
    }
}

struct Pending {
    ip: IpAddr,
    reason: String,
}

#[derive(Default)]
struct Inner {
    keys: HashMap<String, KeyState>,
    pending: VecDeque<Pending>,
    matched_events: u64,
}

/// See the module documentation.
pub struct CampaignDetector {
    cfg: CampaignConfig,
    methods_upper: Vec<String>,
    ignore_ua_lower: Vec<String>,
    inner: Mutex<Inner>,
}

impl CampaignDetector {
    pub fn new() -> Self {
        Self::with_config(CampaignConfig::default())
    }

    pub fn with_config(cfg: CampaignConfig) -> Self {
        let methods_upper = cfg.methods.iter().map(|m| m.to_ascii_uppercase()).collect();
        let ignore_ua_lower = cfg
            .ignore_user_agents
            .iter()
            .map(|u| u.to_ascii_lowercase())
            .filter(|u| !u.is_empty())
            .collect();
        let mut cfg = cfg;
        cfg.ignore_vhosts = cfg
            .ignore_vhosts
            .iter()
            .map(|v| v.to_ascii_lowercase())
            .collect();
        cfg.max_keys = cfg.max_keys.max(1);
        cfg.max_hits_per_key = cfg.max_hits_per_key.max(1);
        cfg.retro_batch = cfg.retro_batch.max(1);
        Self {
            cfg,
            methods_upper,
            ignore_ua_lower,
            inner: Mutex::new(Inner::default()),
        }
    }

    fn host_net(ip: IpAddr) -> IpNet {
        IpNet::from(ip)
    }

    fn signal(&self, ip: IpAddr, reason: &str, ts: DateTime<Utc>) -> DetectionSignal {
        let evidence = format!("{ip}:campaign:{reason}");
        DetectionSignal {
            source_ip: Self::host_net(ip),
            severity: 200,
            confidence: 0.9,
            reason: reason.to_string(),
            evidence_hash: *blake3::hash(evidence.as_bytes()).as_bytes(),
            suggested_action: Action::Ban(self.cfg.ban_duration),
            detector_name: "campaign".into(),
            timestamp: ts,
        }
    }

    /// The configured endpoint matched by `path` (query string ignored).
    fn matched_endpoint<'a>(&'a self, path: &str) -> Option<&'a str> {
        let path = path.split(['?', '#']).next().unwrap_or(path);
        self.cfg
            .paths
            .iter()
            .find(|p| path.len() >= p.len() && path[..p.len()].eq_ignore_ascii_case(p))
            .map(String::as_str)
    }

    fn ua_ignored(&self, ua: &str) -> bool {
        if self.ignore_ua_lower.is_empty() {
            return false;
        }
        let lower = ua.to_ascii_lowercase();
        self.ignore_ua_lower
            .iter()
            .any(|u| lower.contains(u.as_str()))
    }

    fn truncate(s: &str, max: usize) -> &str {
        match s.char_indices().nth(max) {
            Some((i, _)) => &s[..i],
            None => s,
        }
    }

    fn sweep(&self, inner: &mut Inner, now: DateTime<Utc>) {
        let idle =
            chrono::Duration::from_std(self.cfg.window).unwrap_or(chrono::Duration::hours(1));
        inner
            .keys
            .retain(|_, k| k.is_hot(now) || now.signed_duration_since(k.last_seen) < idle);
    }

    /// Make room for one more key: drop idle keys, then the least recently
    /// seen non-hot key, then the least recently seen key.
    fn make_room(&self, inner: &mut Inner, now: DateTime<Utc>) {
        if inner.keys.len() < self.cfg.max_keys {
            return;
        }
        self.sweep(inner, now);
        while inner.keys.len() >= self.cfg.max_keys {
            let victim = inner
                .keys
                .iter()
                .min_by_key(|(_, k)| (k.is_hot(now), k.last_seen))
                .map(|(key, _)| key.clone());
            match victim {
                Some(v) => {
                    inner.keys.remove(&v);
                }
                None => break,
            }
        }
    }

    /// Record one hit for `key` and return the signals it produces.
    #[allow(clippy::too_many_arguments)]
    fn hit(
        &self,
        inner: &mut Inner,
        key: String,
        kind: KeyKind,
        label: String,
        min_ips: usize,
        ip: IpAddr,
        now: DateTime<Utc>,
        out: &mut Vec<DetectionSignal>,
    ) {
        if !inner.keys.contains_key(&key) {
            self.make_room(inner, now);
        }
        let window =
            chrono::Duration::from_std(self.cfg.window).unwrap_or(chrono::Duration::minutes(30));
        let hot =
            chrono::Duration::from_std(self.cfg.hot_duration).unwrap_or(chrono::Duration::hours(6));
        let max_hits = self.cfg.max_hits_per_key;

        let state = inner
            .keys
            .entry(key)
            .or_insert_with(|| KeyState::new(kind, label, now));
        state.prune(now - window);
        if state.hits.len() >= max_hits {
            state.pop_front();
        }
        state.hits.push_back((now, ip));
        *state.ip_counts.entry(ip).or_insert(0) += 1;
        state.last_seen = now;

        if state.hot_until.is_some() && !state.is_hot(now) {
            // Previous hot period expired: start fresh.
            state.hot_until = None;
            state.flagged.clear();
        }

        let kind_label = match state.kind {
            KeyKind::UserAgent => "fingerprint",
            KeyKind::Vhost => "vhost",
        };

        if state.is_hot(now) {
            state.hot_until = Some(now + hot);
            if state.flagged.len() < MAX_FLAGGED_PER_KEY && state.flagged.insert(ip) {
                let reason = format!(
                    "Distributed login campaign ({kind_label} {}) — new participant",
                    state.label
                );
                out.push(self.signal(ip, &reason, now));
            }
            return;
        }

        let distinct = state.ip_counts.len();
        let requests = state.hits.len();
        if distinct < min_ips || requests < self.cfg.min_requests {
            return;
        }

        // Campaign flagged.
        state.hot_until = Some(now + hot);
        let reason = format!(
            "Distributed login campaign ({kind_label} {}): {} IPs / {} requests in {}s",
            state.label,
            distinct,
            requests,
            self.cfg.window.as_secs()
        );
        state.flagged.insert(ip);
        out.push(self.signal(ip, &reason, now));

        if self.cfg.retro_ban {
            let participants: Vec<IpAddr> = state
                .ip_counts
                .keys()
                .copied()
                .filter(|p| *p != ip)
                .take(self.cfg.max_retro_bans)
                .collect();
            for p in participants {
                if state.flagged.len() >= MAX_FLAGGED_PER_KEY {
                    break;
                }
                if state.flagged.insert(p) && inner.pending.len() < MAX_PENDING {
                    inner.pending.push_back(Pending {
                        ip: p,
                        reason: reason.clone(),
                    });
                }
            }
        }
    }

    /// Number of fingerprints currently tracked (tests / introspection).
    pub fn tracked_keys(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .keys
            .len()
    }

    /// Number of queued retro signals (tests / introspection).
    pub fn pending_retro(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .pending
            .len()
    }
}

impl Default for CampaignDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for CampaignDetector {
    fn name(&self) -> &str {
        "campaign"
    }

    /// Single-signal view; the pipeline uses [`Detector::process_multi`].
    fn process(&self, event: &NormalizedEvent) -> Option<DetectionSignal> {
        self.process_multi(event).into_iter().next()
    }

    fn process_multi(&self, event: &NormalizedEvent) -> Vec<DetectionSignal> {
        let mut out = Vec::new();
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let now = event.timestamp;

        // Drain queued retro signals on every event (any source), bounded.
        for _ in 0..self.cfg.retro_batch {
            match inner.pending.pop_front() {
                Some(p) => out.push(self.signal(p.ip, &p.reason, now)),
                None => break,
            }
        }

        if matches!(
            event.event_type,
            EventType::HttpRequest | EventType::Http4xx | EventType::Http5xx
        ) {
            self.process_http(&mut inner, event, &mut out);
        }
        drop(inner);

        if out.len() > 1 {
            let mut seen = HashSet::new();
            out.retain(|s| seen.insert(s.source_ip));
        }
        out
    }
}

impl CampaignDetector {
    fn process_http(
        &self,
        inner: &mut Inner,
        event: &NormalizedEvent,
        out: &mut Vec<DetectionSignal>,
    ) {
        let Some(method) = event.metadata.get("method") else {
            return;
        };
        let method = method.to_ascii_uppercase();
        if !self.methods_upper.contains(&method) {
            return;
        }
        let Some(endpoint) = event
            .metadata
            .get("path")
            .and_then(|p| self.matched_endpoint(p))
        else {
            return;
        };
        if self.cfg.ignore_redirects {
            if let Some(code) = event
                .metadata
                .get("status_code")
                .and_then(|s| s.parse::<u16>().ok())
            {
                if (300..400).contains(&code) {
                    return;
                }
            }
        }
        let ua = event
            .metadata
            .get("user_agent")
            .map(String::as_str)
            .unwrap_or("");
        if self.ua_ignored(ua) {
            return;
        }
        let vhost = event.metadata.get("vhost").map(|v| v.to_ascii_lowercase());
        if let Some(ref v) = vhost {
            if self.cfg.ignore_vhosts.iter().any(|i| i == v) {
                return;
            }
        }

        let now = event.timestamp;
        let ip = event.source_ip;
        inner.matched_events += 1;
        if inner.matched_events.is_multiple_of(SWEEP_EVERY) {
            self.sweep(inner, now);
        }

        let ua_norm = if ua.trim().is_empty() { "-" } else { ua.trim() };
        let endpoint = endpoint.to_ascii_lowercase();
        let ua_key = format!("ua\u{1f}{method}\u{1f}{endpoint}\u{1f}{ua_norm}");
        let ua_label = format!("UA='{}' {method} {endpoint}", Self::truncate(ua_norm, 80));
        self.hit(
            inner,
            ua_key,
            KeyKind::UserAgent,
            ua_label,
            self.cfg.min_distinct_ips,
            ip,
            now,
            out,
        );

        if self.cfg.vhost_min_distinct_ips > 0 {
            if let Some(v) = vhost {
                let key = format!("vh\u{1f}{method}\u{1f}{endpoint}\u{1f}{v}");
                let label = format!("{method} {v}{endpoint}");
                self.hit(
                    inner,
                    key,
                    KeyKind::Vhost,
                    label,
                    self.cfg.vhost_min_distinct_ips,
                    ip,
                    now,
                    out,
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap as Map;
    use std::net::Ipv4Addr;

    const GOOSEE: &str = "Goosee-Audit/1.0 (+internal-security-audit)";

    fn login(ip: IpAddr, ts: DateTime<Utc>, ua: &str, status: u16, vhost: &str) -> NormalizedEvent {
        let mut metadata = Map::new();
        metadata.insert("method".into(), "POST".into());
        metadata.insert("path".into(), "/wp-login.php".into());
        metadata.insert("user_agent".into(), ua.into());
        metadata.insert("status_code".into(), status.to_string());
        metadata.insert("vhost".into(), vhost.into());
        NormalizedEvent {
            timestamp: ts,
            source_ip: ip,
            event_type: EventType::HttpRequest,
            source_name: "nginx".into(),
            raw_line: String::new(),
            metadata,
        }
    }

    /// Residential-pool style address: spread over many /24s (~2 per /24).
    fn pool_ip(i: u32) -> IpAddr {
        let blocks = [(65u8, 111u8), (104, 207), (209, 50), (216, 26)];
        let (a, b) = blocks[(i % 4) as usize];
        let n = i / 4;
        IpAddr::V4(Ipv4Addr::new(
            a,
            b,
            (n / 2 % 250) as u8,
            (n % 2 * 100 + n / 500) as u8 + 1,
        ))
    }

    fn base() -> DateTime<Utc> {
        "2026-10-09T10:43:00Z".parse().unwrap()
    }

    /// Scenario A: 7 bursts × ~427 POSTs over ~10 min, every 3.5 h, from a
    /// pool of 1612 IPs (≤ 6 hits per IP), one shared UA, all 200.
    #[test]
    fn scenario_a_goosee_campaign_is_caught_and_participants_banned() {
        let d = CampaignDetector::new();
        let mut banned: HashSet<IpAddr> = HashSet::new();
        let mut first_ban_at: Option<DateTime<Utc>> = None;
        let mut total = 0u32;
        for burst in 0..7u32 {
            let start = base() + chrono::Duration::minutes(210 * burst as i64);
            for k in 0..427u32 {
                let ip = pool_ip((burst * 427 + k) % 1612);
                let ts = start + chrono::Duration::milliseconds(k as i64 * 1405); // ~10 min
                total += 1;
                for s in d.process_multi(&login(ip, ts, GOOSEE, 200, "site-a.example.org")) {
                    assert_eq!(
                        s.source_ip.prefix_len(),
                        32,
                        "campaign bans are host-scoped"
                    );
                    assert_eq!(s.detector_name, "campaign");
                    assert!(s.severity as f32 * s.confidence >= 100.0);
                    first_ban_at.get_or_insert(ts);
                    banned.insert(s.source_ip.addr());
                }
            }
        }
        // Flagged within the first burst after min_distinct_ips (20) distinct IPs → ~28 s.
        let t = first_ban_at.expect("campaign must be flagged");
        eprintln!(
            "scenario A: first ban after {}s, {} IPs banned of {} requests",
            (t - base()).num_seconds(),
            banned.len(),
            total
        );
        assert!(
            t - base() < chrono::Duration::minutes(1),
            "flagged after {:?}",
            t - base()
        );
        // Every pool member that showed up gets banned (retro + on first hit while hot).
        assert_eq!(banned.len(), 1612.min(total as usize));
        assert_eq!(d.pending_retro(), 0);
    }

    #[test]
    fn retro_bans_are_drained_in_batches() {
        let cfg = CampaignConfig {
            min_distinct_ips: 100,
            min_requests: 100,
            retro_batch: 10,
            ..Default::default()
        };
        let d = CampaignDetector::with_config(cfg);
        let mut n = 0;
        for i in 0..99u32 {
            n += d
                .process_multi(&login(pool_ip(i), base(), GOOSEE, 200, "a.pl"))
                .len();
        }
        assert_eq!(n, 0);
        let out = d.process_multi(&login(pool_ip(99), base(), GOOSEE, 200, "a.pl"));
        assert_eq!(out.len(), 1, "trigger event signals only its own IP");
        assert_eq!(d.pending_retro(), 99);
        // Any later event (even unrelated) drains up to retro_batch.
        let mut other = login(pool_ip(5000), base(), "Mozilla/5.0", 200, "a.pl");
        other.metadata.insert("method".into(), "GET".into());
        assert_eq!(d.process_multi(&other).len(), 10);
        assert_eq!(d.pending_retro(), 89);
    }

    #[test]
    fn below_threshold_no_signal() {
        let d = CampaignDetector::new();
        for i in 0..19u32 {
            for r in 0..3 {
                let ts = base() + chrono::Duration::seconds((i * 3 + r) as i64);
                assert!(d
                    .process_multi(&login(pool_ip(i), ts, GOOSEE, 200, "a.pl"))
                    .is_empty());
            }
        }
    }

    #[test]
    fn spread_beyond_window_no_signal() {
        let d = CampaignDetector::new();
        // 40 IPs, but one every 2 minutes → at most 15 in any 30-min window.
        for i in 0..40u32 {
            let ts = base() + chrono::Duration::minutes(2 * i as i64);
            assert!(d
                .process_multi(&login(pool_ip(i), ts, GOOSEE, 200, "a.pl"))
                .is_empty());
        }
    }

    #[test]
    fn successful_logins_and_known_good_uas_are_ignored() {
        let mut cfg = CampaignConfig::default();
        cfg.ignore_user_agents.push("site-monitor".into());
        let d = CampaignDetector::with_config(cfg);
        for i in 0..100u32 {
            let ip = pool_ip(i);
            assert!(d
                .process_multi(&login(ip, base(), GOOSEE, 302, "a.pl"))
                .is_empty());
            let wp = "WordPress/6.6.2; https://site-a.example.org";
            assert!(d
                .process_multi(&login(ip, base(), wp, 200, "a.pl"))
                .is_empty());
            assert!(d
                .process_multi(&login(ip, base(), "site-monitor/1.0", 200, "a.pl"))
                .is_empty());
        }
        assert_eq!(d.tracked_keys(), 0);
    }

    #[test]
    fn get_requests_do_not_count() {
        let d = CampaignDetector::new();
        for i in 0..100u32 {
            let mut e = login(pool_ip(i), base(), GOOSEE, 200, "a.pl");
            e.metadata.insert("method".into(), "GET".into());
            assert!(d.process_multi(&e).is_empty());
        }
    }

    #[test]
    fn vhost_key_catches_randomised_user_agents() {
        let cfg = CampaignConfig {
            vhost_min_distinct_ips: 25,
            ..Default::default()
        };
        let d = CampaignDetector::with_config(cfg);
        let mut fired = 0;
        for i in 0..40u32 {
            let ua = format!("Mozilla/5.0 (X11; rv:{i}.0) Gecko/20100101 Firefox/{i}.0");
            let ts = base() + chrono::Duration::seconds(i as i64 * 5);
            fired += d
                .process_multi(&login(pool_ip(i), ts, &ua, 200, "site-a.example.org"))
                .len();
        }
        // Flagged at the 30th request (min_requests), 29 retro queued + new ones.
        assert!(fired >= 11, "fired {fired}");
        // Off by default.
        let d = CampaignDetector::new();
        for i in 0..40u32 {
            let ua = format!("UA-{i}");
            assert!(d
                .process_multi(&login(pool_ip(i), base(), &ua, 200, "site-a.example.org"))
                .is_empty());
        }
    }

    #[test]
    fn hot_campaign_expires() {
        let cfg = CampaignConfig {
            hot_duration: Duration::from_secs(3600),
            retro_ban: false,
            ..Default::default()
        };
        let d = CampaignDetector::with_config(cfg);
        for i in 0..30u32 {
            d.process_multi(&login(pool_ip(i), base(), GOOSEE, 200, "a.pl"));
        }
        // Still hot after 50 min → new IP banned on first hit.
        let t1 = base() + chrono::Duration::minutes(50);
        assert_eq!(
            d.process_multi(&login(pool_ip(500), t1, GOOSEE, 200, "a.pl"))
                .len(),
            1
        );
        // Same IP again → not re-signalled.
        assert!(d
            .process_multi(&login(pool_ip(500), t1, GOOSEE, 200, "a.pl"))
            .is_empty());
        // 2 h of silence → cold; a single new IP does not trigger.
        let t2 = t1 + chrono::Duration::hours(2);
        assert!(d
            .process_multi(&login(pool_ip(600), t2, GOOSEE, 200, "a.pl"))
            .is_empty());
    }

    #[test]
    fn memory_is_bounded() {
        let cfg = CampaignConfig {
            max_keys: 50,
            max_hits_per_key: 16,
            ..Default::default()
        };
        let d = CampaignDetector::with_config(cfg);
        for i in 0..5000u32 {
            let ua = format!("random-ua-{i}");
            d.process_multi(&login(pool_ip(i), base(), &ua, 200, "a.pl"));
        }
        assert!(d.tracked_keys() <= 50);
        for i in 0..5000u32 {
            d.process_multi(&login(pool_ip(i), base(), "one-ua", 200, "a.pl"));
        }
        let inner = d.inner.lock().unwrap();
        assert!(inner
            .keys
            .values()
            .all(|k| k.hits.len() <= 16 && k.ip_counts.len() <= 16));
    }

    #[test]
    fn query_string_and_case_do_not_split_fingerprint() {
        let d = CampaignDetector::with_config(CampaignConfig {
            min_distinct_ips: 3,
            min_requests: 3,
            ..Default::default()
        });
        let mut e1 = login(pool_ip(1), base(), GOOSEE, 200, "a.pl");
        e1.metadata
            .insert("path".into(), "/WP-LOGIN.php?redirect_to=x".into());
        let mut e2 = login(pool_ip(2), base(), GOOSEE, 200, "b.pl");
        e2.metadata.insert("method".into(), "post".into());
        let e3 = login(pool_ip(3), base(), GOOSEE, 200, "c.pl");
        assert!(d.process_multi(&e1).is_empty());
        assert!(d.process_multi(&e2).is_empty());
        assert_eq!(d.process_multi(&e3).len(), 1);
        assert_eq!(d.tracked_keys(), 1);
    }
}
