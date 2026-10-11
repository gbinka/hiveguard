//! Distributed crawl ("residential proxy") detector — **never bans**.
//!
//! A crawler behind a residential-proxy network sends about one request per
//! IP: tens of thousands of IPs a day across hundreds of ASNs. Per-IP and
//! per-subnet bans cannot stop it. What *is* visible is the shape of the
//! traffic on expensive endpoints (catalogue search, faceted shop listings):
//! many IPs whose **first** request in a long time goes straight to such an
//! endpoint, without loading the page's static assets.
//!
//! The detector counts, over a sliding `window`, distinct source keys (IPv4
//! address or IPv6 `/ipv6_prefix`) that
//!
//! 1. request a path starting with one of `path_prefixes`,
//! 2. have not been seen at all (any HTTP request) within `fresh_ip_memory`,
//! 3. optionally carry no `Referer` (`require_no_referer`; needs a parser that
//!    fills the `referer` metadata key), and
//! 4. with `exclude_static_fetchers`, have not fetched a static asset
//!    (`.css`, `.js`, images, fonts…) afterwards inside the window — a real
//!    browser loading the page does, a headless HTML crawler usually not.
//!
//! When that count exceeds `fresh_ip_threshold` the detector switches to
//! **under attack**; it switches back when the count stays below
//! `off_threshold` for `cooldown`. The state is consumed by the plugin
//! (`detector.distributed_crawl`), which writes a flag file for the web
//! server (e.g. nginx enables a JS/cookie challenge while it exists),
//! publishes a gauge and logs a WARN on every change. No signal is ever
//! emitted, so nothing reaches scoring or the firewall.
//!
//! Memory is bounded: the "seen" set is two generations of hash sets rotated
//! every `fresh_ip_memory / 2` (or earlier when a generation reaches
//! `max_tracked_ips / 2`), so an IP is remembered for between half and the
//! full memory period; candidates are capped at `max_tracked_ips`.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::Duration;

use chrono::{DateTime, Utc};

use crate::detector::Detector;
use crate::detectors::http_flood::default_ignore_extensions;
use crate::detectors::netkey::{source_key, DEFAULT_IPV6_PREFIX};
use crate::models::{DetectionSignal, EventType, NormalizedEvent};

/// Tunables of [`DistributedCrawlDetector`].
#[derive(Debug, Clone)]
pub struct DistributedCrawlConfig {
    pub window: Duration,
    pub path_prefixes: Vec<String>,
    pub fresh_ip_memory: Duration,
    pub fresh_ip_threshold: usize,
    pub off_threshold: usize,
    pub cooldown: Duration,
    pub max_tracked_ips: usize,
    pub exclude_static_fetchers: bool,
    pub static_extensions: Vec<String>,
    pub require_no_referer: bool,
    pub ipv6_prefix: u8,
}

impl Default for DistributedCrawlConfig {
    fn default() -> Self {
        Self {
            window: Duration::from_secs(300),
            path_prefixes: Vec::new(),
            fresh_ip_memory: Duration::from_secs(86_400),
            fresh_ip_threshold: 30,
            off_threshold: 10,
            cooldown: Duration::from_secs(900),
            max_tracked_ips: 500_000,
            exclude_static_fetchers: true,
            static_extensions: default_ignore_extensions(),
            require_no_referer: false,
            ipv6_prefix: DEFAULT_IPV6_PREFIX,
        }
    }
}

/// A state change reported by [`DistributedCrawlDetector::evaluate`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrawlTransition {
    /// Fresh-IP count exceeded the threshold: under attack.
    On { fresh_ips: usize },
    /// Count stayed below `off_threshold` for the cooldown: back to normal.
    Off { fresh_ips: usize },
}

/// Result of one evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CrawlStatus {
    pub under_attack: bool,
    pub fresh_ips: usize,
    pub transition: Option<CrawlTransition>,
}

struct Inner {
    seen_cur: HashSet<IpAddr>,
    seen_prev: HashSet<IpAddr>,
    generation_started: Option<DateTime<Utc>>,
    /// Fresh candidates inside the window: key → first hit.
    candidates: HashMap<IpAddr, DateTime<Utc>>,
    /// Insertion order of candidates (may hold stale entries).
    order: VecDeque<(DateTime<Utc>, IpAddr)>,
    on: bool,
    below_since: Option<DateTime<Utc>>,
}

pub struct DistributedCrawlDetector {
    cfg: DistributedCrawlConfig,
    inner: Mutex<Inner>,
}

impl DistributedCrawlDetector {
    pub fn with_config(mut cfg: DistributedCrawlConfig) -> Self {
        cfg.static_extensions = cfg
            .static_extensions
            .into_iter()
            .map(|e| e.to_ascii_lowercase())
            .collect();
        cfg.max_tracked_ips = cfg.max_tracked_ips.max(2);
        Self {
            cfg,
            inner: Mutex::new(Inner {
                seen_cur: HashSet::new(),
                seen_prev: HashSet::new(),
                generation_started: None,
                candidates: HashMap::new(),
                order: VecDeque::new(),
                on: false,
                below_since: None,
            }),
        }
    }

    pub fn config(&self) -> &DistributedCrawlConfig {
        &self.cfg
    }

    fn is_static(&self, path: &str) -> bool {
        let path = path.split(['?', '#']).next().unwrap_or(path);
        let lower = path.to_ascii_lowercase();
        self.cfg.static_extensions.iter().any(|ext| lower.ends_with(ext.as_str()))
    }

    fn matches_prefix(&self, path: &str) -> bool {
        self.cfg.path_prefixes.iter().any(|p| path.starts_with(p.as_str()))
    }

    fn chrono(d: Duration) -> chrono::Duration {
        chrono::Duration::from_std(d).unwrap_or(chrono::Duration::zero())
    }

    /// Rotate the seen-set generations when due; then mark `key` as seen.
    /// Returns whether `key` had been seen before.
    fn mark_seen(&self, inner: &mut Inner, key: IpAddr, now: DateTime<Utc>) -> bool {
        let half = Self::chrono(self.cfg.fresh_ip_memory / 2);
        let started = *inner.generation_started.get_or_insert(now);
        if now.signed_duration_since(started) >= half
            || inner.seen_cur.len() >= self.cfg.max_tracked_ips / 2
        {
            inner.seen_prev = std::mem::take(&mut inner.seen_cur);
            inner.generation_started = Some(now);
        }
        let known = inner.seen_cur.contains(&key) || inner.seen_prev.contains(&key);
        inner.seen_cur.insert(key);
        known
    }

    /// Feed one event (any event type; only HTTP ones count).
    pub fn record(&self, event: &NormalizedEvent) {
        match event.event_type {
            EventType::HttpRequest | EventType::Http4xx | EventType::Http5xx => {}
            _ => return,
        }
        let Some(path) = event.metadata.get("path") else {
            return;
        };
        let key = source_key(event.source_ip, self.cfg.ipv6_prefix).addr();
        let now = event.timestamp;
        let Ok(mut inner) = self.inner.lock() else {
            return;
        };

        if self.cfg.exclude_static_fetchers && self.is_static(path) {
            // A browser rendering the page: not a headless crawler.
            inner.candidates.remove(&key);
            self.mark_seen(&mut inner, key, now);
            return;
        }

        let counted = self.matches_prefix(path)
            && !(self.cfg.require_no_referer
                && event
                    .metadata
                    .get("referer")
                    .is_some_and(|r| !r.trim().is_empty() && r.trim() != "-"));
        let known = self.mark_seen(&mut inner, key, now);
        if !counted || known || inner.candidates.contains_key(&key) {
            return;
        }
        if inner.candidates.len() >= self.cfg.max_tracked_ips {
            // Drop the oldest live candidate to stay bounded.
            while let Some((ts, ip)) = inner.order.pop_front() {
                if inner.candidates.get(&ip) == Some(&ts) {
                    inner.candidates.remove(&ip);
                    break;
                }
            }
        }
        inner.candidates.insert(key, now);
        inner.order.push_back((now, key));
    }

    /// Prune the window at `now`, update the hysteresis state machine and
    /// report the current count (plus a transition, if one happened).
    pub fn evaluate(&self, now: DateTime<Utc>) -> CrawlStatus {
        let Ok(mut inner) = self.inner.lock() else {
            return CrawlStatus { under_attack: false, fresh_ips: 0, transition: None };
        };
        let cutoff = now - Self::chrono(self.cfg.window);
        while let Some(&(ts, ip)) = inner.order.front() {
            if ts >= cutoff {
                break;
            }
            inner.order.pop_front();
            if inner.candidates.get(&ip) == Some(&ts) {
                inner.candidates.remove(&ip);
            }
        }
        // Candidates removed by a static fetch leave stale `order` entries;
        // compact when they dominate so `order` stays bounded too.
        if inner.order.len() > 2 * inner.candidates.len() + 1024 {
            let Inner { order, candidates, .. } = &mut *inner;
            order.retain(|(ts, ip)| candidates.get(ip) == Some(ts));
        }
        let fresh_ips = inner.candidates.len();

        let mut transition = None;
        if !inner.on {
            if fresh_ips > self.cfg.fresh_ip_threshold {
                inner.on = true;
                inner.below_since = None;
                transition = Some(CrawlTransition::On { fresh_ips });
            }
        } else if fresh_ips < self.cfg.off_threshold {
            let since = *inner.below_since.get_or_insert(now);
            if now.signed_duration_since(since) >= Self::chrono(self.cfg.cooldown) {
                inner.on = false;
                inner.below_since = None;
                transition = Some(CrawlTransition::Off { fresh_ips });
            }
        } else {
            inner.below_since = None;
        }

        CrawlStatus { under_attack: inner.on, fresh_ips, transition }
    }

    /// Distinct keys currently remembered as seen (both generations).
    pub fn tracked_ips(&self) -> usize {
        self.inner
            .lock()
            .map(|i| i.seen_cur.len() + i.seen_prev.len())
            .unwrap_or(0)
    }
}

impl Detector for DistributedCrawlDetector {
    fn name(&self) -> &str {
        "distributed_crawl"
    }

    /// Records the event; never returns a signal (this detector does not ban).
    fn process(&self, event: &NormalizedEvent) -> Option<DetectionSignal> {
        self.record(event);
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap as Map;

    fn base() -> DateTime<Utc> {
        "2026-10-11T00:00:00Z".parse().unwrap()
    }

    fn req(ip: &str, path: &str, ts: DateTime<Utc>) -> NormalizedEvent {
        req_ref(ip, path, None, ts)
    }

    fn req_ref(ip: &str, path: &str, referer: Option<&str>, ts: DateTime<Utc>) -> NormalizedEvent {
        let mut metadata = Map::new();
        metadata.insert("path".to_string(), path.to_string());
        metadata.insert("method".to_string(), "GET".to_string());
        metadata.insert("status_code".to_string(), "200".to_string());
        if let Some(r) = referer {
            metadata.insert("referer".to_string(), r.to_string());
        }
        NormalizedEvent {
            timestamp: ts,
            source_ip: ip.parse().unwrap(),
            event_type: EventType::HttpRequest,
            source_name: "nginx".into(),
            raw_line: String::new(),
            metadata,
        }
    }

    fn detector(threshold: usize, off: usize, cooldown_secs: u64) -> DistributedCrawlDetector {
        DistributedCrawlDetector::with_config(DistributedCrawlConfig {
            path_prefixes: vec!["/cgi-bin/koha/opac-search.pl".into(), "/catalogsearch/".into()],
            fresh_ip_threshold: threshold,
            off_threshold: off,
            cooldown: Duration::from_secs(cooldown_secs),
            ..Default::default()
        })
    }

    const SEARCH: &str = "/cgi-bin/koha/opac-search.pl?q=kw:etnografia";

    #[test]
    fn many_fresh_ips_switch_on_and_never_emit_signals() {
        let d = detector(5, 2, 60);
        let t = base();
        for i in 0..6 {
            let ev = req(&format!("100.64.{i}.1"), SEARCH, t);
            assert!(d.process(&ev).is_none(), "never a ban signal");
        }
        let st = d.evaluate(t);
        assert_eq!(st.fresh_ips, 6);
        assert!(st.under_attack);
        assert_eq!(st.transition, Some(CrawlTransition::On { fresh_ips: 6 }));
        // No repeated transition while it stays on.
        assert_eq!(d.evaluate(t).transition, None);
    }

    #[test]
    fn at_threshold_stays_off() {
        let d = detector(5, 2, 60);
        let t = base();
        for i in 0..5 {
            d.record(&req(&format!("100.64.{i}.1"), SEARCH, t));
        }
        let st = d.evaluate(t);
        assert_eq!(st.fresh_ips, 5);
        assert!(!st.under_attack);
    }

    #[test]
    fn known_visitors_are_not_fresh() {
        let d = detector(2, 1, 60);
        let t = base();
        for i in 0..5 {
            let ip = format!("100.64.{i}.1");
            d.record(&req(&ip, "/", t)); // home page first
            d.record(&req(&ip, SEARCH, t + chrono::Duration::seconds(5)));
        }
        assert_eq!(d.evaluate(t + chrono::Duration::seconds(5)).fresh_ips, 0);
    }

    #[test]
    fn same_ip_counts_once_and_other_paths_do_not_count() {
        let d = detector(2, 1, 60);
        let t = base();
        for _ in 0..10 {
            d.record(&req("100.64.0.1", SEARCH, t));
        }
        d.record(&req("100.64.0.2", "/about", t));
        d.record(&req("100.64.0.3", "/catalogsearch/result/?q=x", t));
        assert_eq!(d.evaluate(t).fresh_ips, 2);
    }

    #[test]
    fn static_asset_fetch_removes_candidate() {
        let d = detector(2, 1, 60);
        let t = base();
        d.record(&req("100.64.0.1", SEARCH, t));
        d.record(&req("100.64.0.2", SEARCH, t));
        d.record(&req("100.64.0.1", "/opac-tmpl/bootstrap/css/opac.css?v=1", t));
        assert_eq!(d.evaluate(t).fresh_ips, 1);
    }

    #[test]
    fn referer_filter_is_optional() {
        let t = base();
        let plain = detector(1, 0, 60);
        plain.record(&req_ref("100.64.0.1", SEARCH, Some("https://www.example.org/"), t));
        assert_eq!(plain.evaluate(t).fresh_ips, 1);

        let strict = DistributedCrawlDetector::with_config(DistributedCrawlConfig {
            path_prefixes: vec!["/cgi-bin/koha/opac-search.pl".into()],
            require_no_referer: true,
            ..Default::default()
        });
        strict.record(&req_ref("100.64.0.1", SEARCH, Some("https://www.example.org/"), t));
        strict.record(&req_ref("100.64.0.2", SEARCH, Some("-"), t));
        strict.record(&req("100.64.0.3", SEARCH, t));
        assert_eq!(strict.evaluate(t).fresh_ips, 2);
    }

    #[test]
    fn window_expiry_and_hysteresis_cooldown() {
        let d = detector(3, 2, 120);
        let t = base();
        for i in 0..4 {
            d.record(&req(&format!("100.64.{i}.1"), SEARCH, t));
        }
        assert!(d.evaluate(t).under_attack);

        // 400 s later the window (300 s) is empty: below off_threshold, but
        // the cooldown has only just started.
        let t1 = t + chrono::Duration::seconds(400);
        let st = d.evaluate(t1);
        assert_eq!(st.fresh_ips, 0);
        assert!(st.under_attack);
        assert_eq!(st.transition, None);

        // A burst between off and on thresholds resets the cooldown.
        let t2 = t1 + chrono::Duration::seconds(60);
        for i in 10..12 {
            d.record(&req(&format!("100.64.{i}.1"), SEARCH, t2));
        }
        assert_eq!(d.evaluate(t2).fresh_ips, 2);
        assert!(d.evaluate(t2).under_attack);

        // Window empties again; cooldown must run in full from here.
        let t3 = t2 + chrono::Duration::seconds(301);
        assert!(d.evaluate(t3).under_attack);
        let t4 = t3 + chrono::Duration::seconds(121);
        let st = d.evaluate(t4);
        assert!(!st.under_attack);
        assert_eq!(st.transition, Some(CrawlTransition::Off { fresh_ips: 0 }));
    }

    #[test]
    fn ipv6_addresses_in_one_prefix_count_once() {
        let d = detector(1, 0, 60);
        let t = base();
        for i in 1..=20 {
            d.record(&req(&format!("2001:db8:1:2::{i:x}"), SEARCH, t));
        }
        assert_eq!(d.evaluate(t).fresh_ips, 1);
    }

    #[test]
    fn memory_is_bounded() {
        let d = DistributedCrawlDetector::with_config(DistributedCrawlConfig {
            path_prefixes: vec!["/s".into()],
            max_tracked_ips: 100,
            fresh_ip_threshold: 1_000_000,
            ..Default::default()
        });
        let t = base();
        for i in 0..5000u32 {
            let ip = std::net::Ipv4Addr::from(0x6440_0000 + i).to_string();
            d.record(&req(&ip, "/s?q=1", t));
        }
        assert!(d.tracked_ips() <= 100);
        assert!(d.evaluate(t).fresh_ips <= 100);
    }

    #[test]
    fn fresh_memory_expires() {
        let d = DistributedCrawlDetector::with_config(DistributedCrawlConfig {
            path_prefixes: vec!["/s".into()],
            fresh_ip_memory: Duration::from_secs(600),
            ..Default::default()
        });
        let t = base();
        d.record(&req("100.64.0.1", "/", t));
        // Two rotations (2 × 300 s) later the IP is forgotten → fresh again.
        d.record(&req("100.64.9.9", "/", t + chrono::Duration::seconds(301)));
        d.record(&req("100.64.9.9", "/", t + chrono::Duration::seconds(602)));
        let t2 = t + chrono::Duration::seconds(603);
        d.record(&req("100.64.0.1", "/s?q=1", t2));
        assert_eq!(d.evaluate(t2).fresh_ips, 1);
    }
}
