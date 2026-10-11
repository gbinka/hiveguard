//! Webshell / backdoor filename probing detector.
//!
//! Scanners looking for dropped webshells request hundreds of *distinct*
//! random-looking PHP files (`/0.php`, `/bro.php`, `/scx.php7`,
//! `/wp-content/plugins/hellopress/wp_filemanager.php`, …), slowly (a few per
//! minute) and often twice (http → 301, https → 404). Catch-all vhosts answer
//! `200` for any path, so neither the 4xx-rate detectors nor the fixed list
//! of `path_probe` see them.
//!
//! This detector keeps, per source IP and over a long sliding `window`, the
//! set of distinct **PHP-like paths that are not a legitimate WordPress
//! entry point** and scores each new one:
//!
//! | feature | points |
//! |---|---|
//! | base, response not 2xx (3xx/4xx/5xx) | 1.0 |
//! | base, response 2xx (catch-all vhost or a real page) | 0.5 |
//! | empty User-Agent (`""` / `"-"`) | +1.0 |
//! | unusual extension (`.php7`, `.phtml`, `.phar`, `.PhP`, trailing `/`) | +1.5 |
//! | random-looking or shell-like name (`/222.php`, `/3PJcpMFsD8B.php`, `wso`, `filemanager`) | +1.0 |
//! | PHP under `/wp-content/uploads/` | +2.0 |
//! | same path already probed by `>= shared_path_min_ips` other IPs | +1.0 |
//!
//! It fires when the IP has `>= min_distinct_paths` distinct paths **and**
//! `>= score_threshold` points. Status codes only weight the score, so a
//! scanner answered 200 by a catch-all vhost is still caught. Signals are
//! host-scoped for IPv4 (`/32`); IPv6 sources are counted and banned per
//! `ipv6_prefix` (default `/64`) because scanners rotate inside their /64.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::Duration;

use chrono::{DateTime, Utc};
use ipnet::IpNet;

use crate::detector::Detector;
use crate::detectors::netkey::{source_key, DEFAULT_IPV6_PREFIX};
use crate::models::{Action, DetectionSignal, EventType, NormalizedEvent};

/// Sweep idle state every this many matching events.
const SWEEP_EVERY: u64 = 4096;
/// Max distinct paths remembered per IP (oldest dropped first).
const MAX_PATHS_PER_IP: usize = 256;

/// Tunables of [`WebshellProbeDetector`].
#[derive(Debug, Clone)]
pub struct WebshellProbeConfig {
    pub window: Duration,
    pub min_distinct_paths: usize,
    pub score_threshold: f32,
    pub ban_duration: Duration,
    /// Legitimate PHP paths. Rule per entry: `/dir/` (leading and trailing
    /// slash) = any path containing that segment; `/x.php` = exact path;
    /// `x.php` (no slash) = that basename at any depth outside `/wp-content/`.
    pub legit_paths: Vec<String>,
    /// Case-insensitive User-Agent substrings never counted (crawlers).
    pub ignore_user_agents: Vec<String>,
    /// Vhosts (exact, lower-case) never counted (e.g. a legacy PHP site).
    pub ignore_vhosts: Vec<String>,
    /// Bonus when that many other IPs probed the same path (0 = off).
    pub shared_path_min_ips: usize,
    pub max_tracked_ips: usize,
    pub max_tracked_paths: usize,
    /// IPv6 counting/ban prefix (0 or 128 = per address).
    pub ipv6_prefix: u8,
}

pub fn default_legit_php_paths() -> Vec<String> {
    [
        "/index.php",
        "wp-login.php",
        "wp-cron.php",
        "xmlrpc.php",
        "wp-comments-post.php",
        "wp-signup.php",
        "wp-activate.php",
        "wp-trackback.php",
        "wp-links-opml.php",
        "wp-mail.php",
        "/wp-admin/",
        "/wp-json/",
        "/wp-includes/js/tinymce/",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

pub fn default_webshell_ignore_user_agents() -> Vec<String> {
    [
        "Googlebot",
        "bingbot",
        "YandexBot",
        "DuckDuckBot",
        "Applebot",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

impl Default for WebshellProbeConfig {
    fn default() -> Self {
        Self {
            window: Duration::from_secs(6 * 3600),
            min_distinct_paths: 6,
            score_threshold: 12.0,
            ban_duration: Duration::from_secs(72 * 3600),
            legit_paths: default_legit_php_paths(),
            ignore_user_agents: default_webshell_ignore_user_agents(),
            ignore_vhosts: Vec::new(),
            shared_path_min_ips: 3,
            max_tracked_ips: 50_000,
            max_tracked_paths: 20_000,
            ipv6_prefix: DEFAULT_IPV6_PREFIX,
        }
    }
}

enum LegitRule {
    Segment(String),
    Exact(String),
    Basename(String),
}

struct IpState {
    /// (path hash, points, first seen)
    paths: VecDeque<(u64, f32, DateTime<Utc>)>,
    last_seen: DateTime<Utc>,
}

struct PathState {
    ips: Vec<IpAddr>,
    last_seen: DateTime<Utc>,
}

#[derive(Default)]
struct Inner {
    ips: HashMap<IpAddr, IpState>,
    paths: HashMap<u64, PathState>,
    matched_events: u64,
}

/// See the module documentation.
pub struct WebshellProbeDetector {
    cfg: WebshellProbeConfig,
    legit: Vec<LegitRule>,
    ignore_ua_lower: Vec<String>,
    inner: Mutex<Inner>,
}

const SHELL_WORDS: &[&str] = &[
    "shell",
    "wso",
    "alfa",
    "c99",
    "r57",
    "b374k",
    "filemanager",
    "file_manager",
    "uploader",
    "bypass",
    "backdoor",
    "priv8",
    "xleet",
    "gecko",
    "webadmin",
    "cmd",
    "symlink",
    "mini",
];

/// Facts about a PHP-like path.
#[derive(Debug, PartialEq)]
struct PhpPath {
    /// Lower-cased path without query string and trailing slashes.
    norm: String,
    unusual_ext: bool,
    suspicious_name: bool,
    in_uploads: bool,
}

fn classify_php_path(raw: &str) -> Option<PhpPath> {
    let path = raw.split(['?', '#']).next().unwrap_or(raw);
    let trimmed = path.trim_end_matches('/');
    let trailing_slash = trimmed.len() != path.len();
    let seg = trimmed.rsplit('/').next().unwrap_or(trimmed);
    let dot = seg.rfind('.')?;
    let (stem, ext) = (&seg[..dot], &seg[dot + 1..]);
    let ext_lower = ext.to_ascii_lowercase();
    let php_like = match ext_lower.strip_prefix("php") {
        Some(rest) => rest.len() <= 1 && rest.chars().all(|c| c.is_ascii_digit()),
        None => matches!(ext_lower.as_str(), "phtml" | "phar" | "pht" | "phps"),
    };
    if !php_like {
        return None;
    }
    let unusual_ext = ext != "php" || trailing_slash;
    let stem_lower = stem.to_ascii_lowercase();
    let all_digits = !stem.is_empty() && stem.chars().all(|c| c.is_ascii_digit());
    let has_upper = stem.chars().any(|c| c.is_ascii_uppercase());
    let has_lower = stem.chars().any(|c| c.is_ascii_lowercase());
    let has_digit = stem.chars().any(|c| c.is_ascii_digit());
    let random_mixed = stem.len() >= 8 && has_upper && has_lower && has_digit;
    // Long run of letters without vowels-ish structure (e.g. "ajiwhbfuyhawfaw")
    // is too fuzzy; keep to cheap, low false-positive signals.
    let shell_word = SHELL_WORDS.iter().any(|w| stem_lower.contains(w));
    let norm = trimmed.to_ascii_lowercase();
    let in_uploads = norm.contains("/wp-content/uploads/");
    Some(PhpPath {
        norm,
        unusual_ext,
        suspicious_name: all_digits || random_mixed || shell_word,
        in_uploads,
    })
}

impl WebshellProbeDetector {
    pub fn new() -> Self {
        Self::with_config(WebshellProbeConfig::default())
    }

    pub fn with_config(mut cfg: WebshellProbeConfig) -> Self {
        let legit = cfg
            .legit_paths
            .iter()
            .filter(|p| !p.is_empty())
            .map(|p| {
                let p = p.to_ascii_lowercase();
                if p.starts_with('/') && p.ends_with('/') && p.len() > 1 {
                    LegitRule::Segment(p)
                } else if p.starts_with('/') {
                    LegitRule::Exact(p)
                } else {
                    LegitRule::Basename(p)
                }
            })
            .collect();
        let ignore_ua_lower = cfg
            .ignore_user_agents
            .iter()
            .map(|u| u.to_ascii_lowercase())
            .filter(|u| !u.is_empty())
            .collect();
        cfg.ignore_vhosts = cfg
            .ignore_vhosts
            .iter()
            .map(|v| v.to_ascii_lowercase())
            .collect();
        cfg.max_tracked_ips = cfg.max_tracked_ips.max(1);
        cfg.max_tracked_paths = cfg.max_tracked_paths.max(1);
        cfg.min_distinct_paths = cfg.min_distinct_paths.max(1);
        Self {
            cfg,
            legit,
            ignore_ua_lower,
            inner: Mutex::new(Inner::default()),
        }
    }

    fn is_legit(&self, norm: &str) -> bool {
        let basename = norm.rsplit('/').next().unwrap_or(norm);
        self.legit.iter().any(|r| match r {
            LegitRule::Segment(s) => norm.contains(s.as_str()),
            LegitRule::Exact(e) => norm == e,
            LegitRule::Basename(b) => basename == b && !norm.contains("/wp-content/"),
        })
    }

    fn path_hash(norm: &str) -> u64 {
        let h = blake3::hash(norm.as_bytes());
        u64::from_le_bytes(h.as_bytes()[..8].try_into().expect("8 bytes"))
    }

    fn window(&self) -> chrono::Duration {
        chrono::Duration::from_std(self.cfg.window).unwrap_or(chrono::Duration::hours(6))
    }

    fn sweep(&self, inner: &mut Inner, now: DateTime<Utc>) {
        let cutoff = now - self.window();
        inner.ips.retain(|_, s| s.last_seen >= cutoff);
        inner.paths.retain(|_, s| s.last_seen >= cutoff);
    }

    /// Evict ~10 % least recently seen entries when a map is full.
    fn evict_oldest<K: Clone + std::hash::Hash + Eq, V>(
        map: &mut HashMap<K, V>,
        last_seen: impl Fn(&V) -> DateTime<Utc>,
    ) {
        let n = (map.len() / 10).max(1);
        let mut ages: Vec<(DateTime<Utc>, K)> =
            map.iter().map(|(k, v)| (last_seen(v), k.clone())).collect();
        ages.select_nth_unstable_by_key(n - 1, |(t, _)| *t);
        for (_, k) in ages.into_iter().take(n) {
            map.remove(&k);
        }
    }

    /// Distinct IPs tracked (tests / introspection).
    pub fn tracked_ips(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .ips
            .len()
    }

    /// Distinct probe paths tracked (tests / introspection).
    pub fn tracked_paths(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .paths
            .len()
    }
}

impl Default for WebshellProbeDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for WebshellProbeDetector {
    fn name(&self) -> &str {
        "webshell_probe"
    }

    fn process(&self, event: &NormalizedEvent) -> Option<DetectionSignal> {
        match event.event_type {
            EventType::HttpRequest | EventType::Http4xx | EventType::Http5xx => {}
            _ => return None,
        }
        let php = classify_php_path(event.metadata.get("path")?)?;
        if self.is_legit(&php.norm) {
            return None;
        }
        let ua = event
            .metadata
            .get("user_agent")
            .map(String::as_str)
            .unwrap_or("");
        if !self.ignore_ua_lower.is_empty() {
            let lower = ua.to_ascii_lowercase();
            if self
                .ignore_ua_lower
                .iter()
                .any(|u| lower.contains(u.as_str()))
            {
                return None;
            }
        }
        if let Some(v) = event.metadata.get("vhost") {
            if !self.cfg.ignore_vhosts.is_empty()
                && self.cfg.ignore_vhosts.contains(&v.to_ascii_lowercase())
            {
                return None;
            }
        }

        // IPv6: all addresses of one /ipv6_prefix are one source.
        let key: IpNet = source_key(event.source_ip, self.cfg.ipv6_prefix);
        let ip = key.addr();
        let now = event.timestamp;
        let status: u16 = event
            .metadata
            .get("status_code")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let hash = Self::path_hash(&php.norm);

        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.matched_events += 1;
        if inner.matched_events.is_multiple_of(SWEEP_EVERY) {
            self.sweep(&mut inner, now);
        }
        let cutoff = now - self.window();

        // Cross-IP view: how many *other* IPs probed this path recently.
        let mut shared_bonus = 0.0;
        if self.cfg.shared_path_min_ips > 0 {
            if !inner.paths.contains_key(&hash) && inner.paths.len() >= self.cfg.max_tracked_paths {
                self.sweep(&mut inner, now);
                if inner.paths.len() >= self.cfg.max_tracked_paths {
                    Self::evict_oldest(&mut inner.paths, |s| s.last_seen);
                }
            }
            let cap = self.cfg.shared_path_min_ips + 1;
            let ps = inner.paths.entry(hash).or_insert_with(|| PathState {
                ips: Vec::new(),
                last_seen: now,
            });
            if ps.last_seen < cutoff {
                ps.ips.clear();
            }
            ps.last_seen = now;
            let others = ps.ips.iter().filter(|p| **p != ip).count();
            if others >= self.cfg.shared_path_min_ips {
                shared_bonus = 1.0;
            }
            if !ps.ips.contains(&ip) {
                if ps.ips.len() >= cap {
                    ps.ips.remove(0);
                }
                ps.ips.push(ip);
            }
        }

        if !inner.ips.contains_key(&ip) && inner.ips.len() >= self.cfg.max_tracked_ips {
            self.sweep(&mut inner, now);
            if inner.ips.len() >= self.cfg.max_tracked_ips {
                Self::evict_oldest(&mut inner.ips, |s| s.last_seen);
            }
        }
        let state = inner.ips.entry(ip).or_insert_with(|| IpState {
            paths: VecDeque::new(),
            last_seen: now,
        });
        state.last_seen = now;
        while matches!(state.paths.front(), Some((_, _, t)) if *t < cutoff) {
            state.paths.pop_front();
        }
        if state.paths.iter().any(|(h, _, _)| *h == hash) {
            return None; // already counted (e.g. the https repeat of an http probe)
        }

        let mut points = if (200..300).contains(&status) {
            0.5
        } else {
            1.0
        };
        let ua_t = ua.trim();
        if ua_t.is_empty() || ua_t == "-" {
            points += 1.0;
        }
        if php.unusual_ext {
            points += 1.5;
        }
        if php.suspicious_name {
            points += 1.0;
        }
        if php.in_uploads {
            points += 2.0;
        }
        points += shared_bonus;

        if state.paths.len() >= MAX_PATHS_PER_IP {
            state.paths.pop_front();
        }
        state.paths.push_back((hash, points, now));

        let distinct = state.paths.len();
        let score: f32 = state.paths.iter().map(|(_, p, _)| *p).sum();
        if distinct < self.cfg.min_distinct_paths || score < self.cfg.score_threshold {
            return None;
        }
        state.paths.clear();
        drop(inner);

        let evidence = format!("{key}:webshell_probe:{distinct}:{}", now.timestamp() / 60);
        Some(DetectionSignal {
            source_ip: key,
            severity: 200,
            confidence: 0.9,
            reason: format!(
                "Webshell/backdoor probing: {distinct} distinct suspicious PHP paths (score {score:.1}, last '{}') in {}s",
                php.norm,
                self.cfg.window.as_secs()
            ),
            evidence_hash: *blake3::hash(evidence.as_bytes()).as_bytes(),
            suggested_action: Action::Ban(self.cfg.ban_duration),
            detector_name: "webshell_probe".into(),
            timestamp: now,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(
        ip: &str,
        path: &str,
        status: u16,
        ua: &str,
        vhost: &str,
        ts: DateTime<Utc>,
    ) -> NormalizedEvent {
        let mut metadata = std::collections::HashMap::new();
        metadata.insert("method".into(), "GET".into());
        metadata.insert("path".into(), path.into());
        metadata.insert("status_code".into(), status.to_string());
        metadata.insert("user_agent".into(), ua.into());
        metadata.insert("vhost".into(), vhost.into());
        NormalizedEvent {
            timestamp: ts,
            source_ip: ip.parse().unwrap(),
            event_type: match status {
                400..=499 => EventType::Http4xx,
                500..=599 => EventType::Http5xx,
                _ => EventType::HttpRequest,
            },
            source_name: "nginx".into(),
            raw_line: String::new(),
            metadata,
        }
    }

    fn base() -> DateTime<Utc> {
        "2026-10-10T00:00:00Z".parse().unwrap()
    }

    /// Probe list from the 2026-10-10 production review.
    const PROBES: &[&str] = &[
        "/0.php",
        "/bro.php",
        "/222.php",
        "/file52.php",
        "/wp-freya.php",
        "/scx.php7",
        "/scx.php7/",
        "/adminfuns.php",
        "/txets.php",
        "/this_is_a_new_hello_world.php",
        "/wp-content/plugins/hellopress/wp_filemanager.php",
        "/wp-content/themes/index.php",
        "/ajiwhbfuyhawfaw.php",
        "/3PJcpMFsD8B.php",
        "/h.php",
        "/about.php",
        "/wp-good.php",
        "/goat.php",
        "/xmrlpc.php",
        "/inputs.php",
        "/ioxi.php",
        "/wp-conflg.php",
        "/alfa.php",
        "/wso112233.php",
        "/class.php",
        "/1.php",
        "/lock.php",
        "/mini.php",
        "/admin.php",
    ];

    #[test]
    fn classify_examples() {
        let p = classify_php_path("/scx.php7/").unwrap();
        assert!(p.unusual_ext);
        assert_eq!(p.norm, "/scx.php7");
        assert!(classify_php_path("/x.phP8").unwrap().unusual_ext);
        assert!(!classify_php_path("/bro.php").unwrap().unusual_ext);
        assert!(classify_php_path("/222.php").unwrap().suspicious_name);
        assert!(
            classify_php_path("/3PJcpMFsD8B.php")
                .unwrap()
                .suspicious_name
        );
        assert!(
            classify_php_path("/wp-content/plugins/hellopress/wp_filemanager.php")
                .unwrap()
                .suspicious_name
        );
        assert!(
            classify_php_path("/wp-content/uploads/2024/x.php")
                .unwrap()
                .in_uploads
        );
        assert!(classify_php_path("/style.css").is_none());
        assert!(classify_php_path("/index.php/foo").is_none());
        assert!(classify_php_path("/x.phpinfo").is_none());
        assert!(classify_php_path("/a.php?x=1").is_some());
    }

    #[test]
    fn legit_wordpress_entrypoints_ignored() {
        let d = WebshellProbeDetector::new();
        let legit = [
            "/index.php",
            "/wp-login.php",
            "/wp-cron.php?doing_wp_cron=1",
            "/xmlrpc.php",
            "/wp-admin/admin-ajax.php",
            "/wp-admin/post.php",
            "/wp-comments-post.php",
            "/blog/wp-login.php",
            "/wp-json/wp/v2/posts",
            "/wp-includes/js/tinymce/wp-tinymce.php",
            "/wp-admin/load-scripts.php",
            "/wp-signup.php",
        ];
        for (i, p) in legit.iter().enumerate() {
            let ts = base() + chrono::Duration::seconds(i as i64);
            assert!(
                d.process(&req("40.74.77.37", p, 404, "-", "a.pl", ts))
                    .is_none(),
                "{p}"
            );
        }
        assert_eq!(d.tracked_ips(), 0);
        // wp-login.php as a basename under wp-content is NOT legit.
        assert!(!d.is_legit("/wp-content/plugins/x/wp-login.php"));
    }

    /// Scenario B: slow (~1 req / 2 min), each probe twice (http 301 then
    /// https 404/200), empty UA, mix of catch-all 200 and 404.
    #[test]
    fn scenario_b_slow_azure_probe_caught_despite_catch_all() {
        let d = WebshellProbeDetector::new();
        let mut t = base();
        let mut fired_at = None;
        for (i, p) in PROBES.iter().enumerate() {
            // http → 301
            let a = req("52.141.3.247", p, 301, "-", "site-b.example.org", t);
            t += chrono::Duration::seconds(60);
            // https → catch-all 200 on odd probes, 404 otherwise
            let status = if i % 2 == 1 { 200 } else { 404 };
            let b = req("52.141.3.247", p, status, "-", "site-b.example.org", t);
            t += chrono::Duration::seconds(60);
            for e in [a, b] {
                if let Some(s) = d.process(&e) {
                    assert_eq!(s.detector_name, "webshell_probe");
                    assert_eq!(s.source_ip.prefix_len(), 32);
                    assert!(s.severity as f32 * s.confidence >= 100.0);
                    fired_at.get_or_insert((i, e.timestamp));
                }
            }
        }
        let (idx, ts) = fired_at.expect("probe must be detected");
        eprintln!(
            "scenario B: ban after {} distinct paths, {}s",
            idx + 1,
            (ts - base()).num_seconds()
        );
        assert!(idx < 8, "fired after {idx} distinct paths");
        assert!(
            ts - base() <= chrono::Duration::minutes(16),
            "fired after {:?}",
            ts - base()
        );
    }

    #[test]
    fn catch_all_only_200_still_caught() {
        let d = WebshellProbeDetector::new();
        let mut fired = false;
        for (i, p) in PROBES.iter().enumerate() {
            let ts = base() + chrono::Duration::minutes(3 * i as i64);
            fired |= d
                .process(&req("40.74.77.37", p, 200, "-", "catchall.example.org", ts))
                .is_some();
        }
        assert!(fired);
    }

    #[test]
    fn browser_on_legacy_php_site_not_banned() {
        // A visitor with a real UA browsing 15 pages of an old PHP site (200).
        let d = WebshellProbeDetector::new();
        let ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/129.0 Safari/537.36";
        let pages = [
            "/news.php",
            "/gallery.php",
            "/contact.php",
            "/about.php",
            "/team.php",
            "/links.php",
            "/history.php",
            "/events.php",
            "/archive.php",
            "/search.php",
            "/map.php",
            "/faq.php",
            "/press.php",
            "/jobs.php",
            "/partners.php",
        ];
        for (i, p) in pages.iter().enumerate() {
            let ts = base() + chrono::Duration::minutes(i as i64);
            assert!(
                d.process(&req("83.10.1.1", p, 200, ua, "oldsite.pl", ts))
                    .is_none(),
                "{p}"
            );
        }
    }

    #[test]
    fn ignored_vhost_and_crawler() {
        let cfg = WebshellProbeConfig {
            ignore_vhosts: vec!["OldSite.pl".into()],
            ..Default::default()
        };
        let d = WebshellProbeDetector::with_config(cfg);
        for (i, p) in PROBES.iter().enumerate() {
            let ts = base() + chrono::Duration::seconds(i as i64);
            assert!(d
                .process(&req("1.2.3.4", p, 404, "-", "oldsite.pl", ts))
                .is_none());
            let gb = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)";
            assert!(d.process(&req("1.2.3.5", p, 404, gb, "a.pl", ts)).is_none());
        }
    }

    #[test]
    fn repeated_same_path_counts_once() {
        let d = WebshellProbeDetector::new();
        for i in 0..500 {
            let ts = base() + chrono::Duration::seconds(i);
            assert!(d
                .process(&req("1.2.3.4", "/x.php7", 404, "-", "a.pl", ts))
                .is_none());
        }
    }

    #[test]
    fn paths_outside_window_expire() {
        let d = WebshellProbeDetector::with_config(WebshellProbeConfig {
            window: Duration::from_secs(3600),
            shared_path_min_ips: 0,
            ..Default::default()
        });
        // 5 distinct per 2 h → never 6 within 1 h.
        for (i, p) in PROBES.iter().enumerate() {
            let ts = base() + chrono::Duration::minutes(25 * i as i64);
            assert!(
                d.process(&req("1.2.3.4", p, 404, "-", "a.pl", ts))
                    .is_none(),
                "{p}"
            );
        }
    }

    #[test]
    fn shared_probe_list_speeds_up_detection() {
        let d = WebshellProbeDetector::new();
        let ips = ["20.213.164.192", "40.74.77.37", "20.239.176.5"];
        // Three IPs probe the first 3 paths (no ban yet: 3 paths each).
        for ip in ips {
            for p in &PROBES[..3] {
                assert!(d
                    .process(&req(ip, p, 404, "Mozilla/5.0", "a.pl", base()))
                    .is_none());
            }
        }
        // A 4th IP with a browser-like UA: 1 + 1 (shared) + name bonus per path.
        let mut n = 0;
        let mut fired = false;
        for p in &PROBES[..3] {
            n += 1;
            fired |= d
                .process(&req(
                    "158.23.176.177",
                    p,
                    404,
                    "Mozilla/5.0",
                    "a.pl",
                    base(),
                ))
                .is_some();
        }
        assert!(!fired, "min_distinct_paths still applies ({n})");
        assert!(d.tracked_paths() >= 3);
    }

    #[test]
    fn memory_is_bounded() {
        let d = WebshellProbeDetector::with_config(WebshellProbeConfig {
            max_tracked_ips: 100,
            max_tracked_paths: 100,
            ..Default::default()
        });
        for i in 0..5000u32 {
            let ip = format!("10.{}.{}.{}", i >> 16 & 255, i >> 8 & 255, i & 255);
            let p = format!("/rnd{i}.php");
            d.process(&req(&ip, &p, 404, "Mozilla/5.0", "a.pl", base()));
        }
        assert!(d.tracked_ips() <= 100);
        assert!(d.tracked_paths() <= 100);
    }

    #[test]
    fn ipv6_rotation_inside_slash64_is_one_prober() {
        let d = WebshellProbeDetector::new();
        let mut fired = None;
        for (i, p) in PROBES.iter().enumerate() {
            let ip = format!("2001:db8:aa:bb::{:x}", i + 1);
            let ts = base() + chrono::Duration::seconds(i as i64 * 30);
            if let Some(s) = d.process(&req(&ip, p, 404, "-", "a.pl", ts)) {
                fired = Some(s);
                break;
            }
        }
        assert_eq!(fired.expect("aggregated").source_ip.to_string(), "2001:db8:aa:bb::/64");
    }
}
