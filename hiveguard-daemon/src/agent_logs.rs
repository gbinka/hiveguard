//! Log analysis engine behind the agent API (`/api/agent/logs/*`,
//! `/api/agent/journal`, the `logs` part of `/api/agent/ip`).
//! Contract: `docs/AGENT_API.md` §2–§4.
//!
//! Design notes:
//! - Only an allow-list of sources derived from the config can be read:
//!   files of `source.file.*` / `source.firewall` plugin entries plus
//!   `agent.log_sources`, and journal units from `agent.journal_units` plus
//!   the units of `source.journald` entries.
//! - Files are scanned **backwards from EOF** in 1 MiB chunks, so "the last
//!   hour of a 2 GiB access log" only reads the tail. A scan stops when 200
//!   consecutive lines (with their own timestamp) are older than `since`, or
//!   when `agent.max_scan_bytes` has been read (`truncated: true`). When the
//!   live file is exhausted first, `<path>.1` (plain text only) is continued
//!   under the same byte budget (`agent.include_rotated`).
//! - Timestamps without a zone (traditional syslog `Oct  9 06:12:01`, ISO
//!   `2026-10-09 06:12:01`) are taken as UTC; traditional syslog gets the
//!   current year, or the previous one if that would land in the future.
//! - All file/journal work runs on the blocking thread pool; regexes are
//!   compiled per request with a 1 MiB compiled-size cap.

use std::collections::{BTreeMap, HashMap};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Datelike, NaiveDateTime, SecondsFormat, TimeDelta, TimeZone, Utc};
use hiveguard_core::config::HiveGuardConfig;
use hiveguard_core::models::EventType;
use hiveguard_ingest::nginx_parser::{parse_nginx_line, NginxPattern};
use hiveguard_ingest::postfix_parser::{parse_postfix_line, PostfixPatterns};
use hiveguard_ingest::ssh_parser::{parse_ssh_line, SshPatterns};
use ipnet::IpNet;
use regex::{Regex, RegexBuilder};
use serde_json::{json, Map, Value};
use tracing::{debug, warn};

type Dt = DateTime<Utc>;

/// Backward read chunk size.
const CHUNK: u64 = 1 << 20;
/// Stop the backward scan after this many consecutive lines older than `since`
/// (tolerates slightly out-of-order logs).
const OLDER_STREAK_STOP: u32 = 200;
/// A single "line" longer than this (no newline) is dropped.
const MAX_CARRY: usize = 8 << 20;
/// `raw` in returned items is cut to this many bytes.
const MAX_RAW_BYTES: usize = 8192;
/// Compiled-size cap for user supplied regexes.
const REGEX_SIZE_LIMIT: usize = 1 << 20;
/// Distinct values tracked per group (extras / profile counters).
const DISTINCT_CAP: usize = 10_000;
/// Distinct values tracked across all groups of one stats request.
const GLOBAL_DISTINCT_BUDGET: usize = 1_000_000;
/// Max groups in one stats request; further keys are counted as `other`.
const MAX_GROUPS: usize = 100_000;
/// Max time-series buckets in one stats request.
const MAX_SERIES_BUCKETS: i64 = 10_000;
/// Max journal entries fetched per request.
const JOURNAL_FETCH_CAP: usize = 20_000;

const DEFAULT_LIMIT: usize = 200;
const DEFAULT_TOP: usize = 25;
const MAX_TOP: usize = 500;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum AgentError {
    BadRequest(String),
    NotFound(String),
    Unavailable(String),
    Internal(String),
}

impl std::fmt::Display for AgentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AgentError::BadRequest(m) => write!(f, "bad request: {m}"),
            AgentError::NotFound(m) => write!(f, "not found: {m}"),
            AgentError::Unavailable(m) => write!(f, "unavailable: {m}"),
            AgentError::Internal(m) => write!(f, "internal error: {m}"),
        }
    }
}

impl std::error::Error for AgentError {}

fn bad(msg: impl Into<String>) -> AgentError {
    AgentError::BadRequest(msg.into())
}

// ---------------------------------------------------------------------------
// Sources
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Format {
    Nginx,
    Ssh,
    Postfix,
    Ufw,
    Syslog,
    Raw,
}

impl Format {
    fn parse(s: &str) -> Option<Self> {
        Some(match s.trim().to_ascii_lowercase().as_str() {
            "nginx" => Format::Nginx,
            "ssh" => Format::Ssh,
            "postfix" => Format::Postfix,
            "ufw" | "firewall" => Format::Ufw,
            "syslog" => Format::Syslog,
            "raw" => Format::Raw,
            _ => return None,
        })
    }

    fn as_str(self) -> &'static str {
        match self {
            Format::Nginx => "nginx",
            Format::Ssh => "ssh",
            Format::Postfix => "postfix",
            Format::Ufw => "ufw",
            Format::Syslog => "syslog",
            Format::Raw => "raw",
        }
    }

    /// Field names usable in `fields` filters and `group_by` for this format.
    fn field_keys(self) -> &'static [&'static str] {
        match self {
            Format::Nginx => &["method", "path", "protocol", "status", "bytes", "user_agent"],
            Format::Ssh => &["user", "invalid_user", "src_port"],
            Format::Postfix => &["mechanism"],
            Format::Ufw => &["action", "in", "out", "dst", "proto", "spt", "port", "flags"],
            Format::Syslog => &["host", "program", "pid"],
            Format::Raw => &[],
        }
    }

    /// Fields whose distinct values are profiled per IP group (`extras`).
    fn profile_fields(self) -> &'static [&'static str] {
        match self {
            Format::Nginx => &["path", "user_agent"],
            Format::Ssh => &["user"],
            Format::Ufw => &["port"],
            Format::Postfix => &["mechanism"],
            Format::Syslog => &["program"],
            Format::Raw => &[],
        }
    }
}

#[derive(Debug, Clone)]
struct FileSource {
    name: String,
    path: PathBuf,
    format: Format,
}

struct Inner {
    files: Vec<FileSource>,
    journal_units: Vec<String>,
    max_scan_bytes: u64,
    max_results: usize,
    journal_timeout_secs: u64,
    include_rotated: bool,
}

impl Inner {
    fn file(&self, name: &str) -> Result<FileSource, AgentError> {
        if let Some(f) = self.files.iter().find(|f| f.name == name) {
            return Ok(f.clone());
        }
        if let Some(unit) = name.strip_prefix("journal:") {
            if self.journal_units.iter().any(|u| u == unit) {
                return Err(bad(format!(
                    "source `{name}` is a journal; use /api/agent/journal?unit={unit}"
                )));
            }
        }
        Err(AgentError::NotFound(format!("unknown log source `{name}`")))
    }
}

/// Log query / aggregation engine for the agent API. Cheap to clone-share
/// (`Send + Sync`, state behind an `Arc`).
pub struct LogEngine {
    inner: Arc<Inner>,
}

impl LogEngine {
    /// Discover sources from `cfg.plugins` (table in AGENT_API.md §2) +
    /// `cfg.agent.log_sources` + journal units (`cfg.agent.journal_units` ∪
    /// units of every `source.journald` entry).
    pub fn from_config(cfg: &HiveGuardConfig) -> Self {
        let mut files: Vec<FileSource> = Vec::new();
        let mut units: Vec<String> = Vec::new();

        let push_file = |files: &mut Vec<FileSource>, name: String, path: PathBuf, format: Format| {
            if files.iter().any(|f| f.path == path) {
                debug!(path = %path.display(), "agent: log path already registered, skipping duplicate");
                return;
            }
            let mut unique = name.clone();
            let mut n = 2;
            while files.iter().any(|f| f.name == unique) {
                unique = format!("{name}_{n}");
                n += 1;
            }
            files.push(FileSource { name: unique, path, format });
        };

        for entry in &cfg.plugins {
            let path = entry
                .config
                .get("path")
                .and_then(|p| p.as_str())
                .filter(|p| !p.is_empty())
                .map(PathBuf::from);
            let named = |default: &str| entry.name.clone().unwrap_or_else(|| default.to_string());
            match entry.id.as_str() {
                "source.file.nginx" | "source.file.ssh" | "source.file.postfix" | "source.file.custom" => {
                    let Some(path) = path else {
                        warn!(plugin = %entry.id, "agent: file source without `path`, not exposed");
                        continue;
                    };
                    let (default, format) = match entry.id.as_str() {
                        "source.file.nginx" => ("nginx", Format::Nginx),
                        "source.file.ssh" => ("ssh", Format::Ssh),
                        "source.file.postfix" => ("postfix", Format::Postfix),
                        _ => ("custom", Format::Raw),
                    };
                    push_file(&mut files, named(default), path, format);
                }
                "source.firewall" => {
                    let path = path.unwrap_or_else(|| PathBuf::from("/var/log/ufw.log"));
                    push_file(&mut files, named("firewall"), path, Format::Ufw);
                }
                "source.journald" => {
                    if let Some(list) = entry.config.get("units").and_then(|u| u.as_array()) {
                        for u in list.iter().filter_map(|u| u.as_str()) {
                            if !u.is_empty() && !units.iter().any(|x| x == u) {
                                units.push(u.to_string());
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        for extra in &cfg.agent.log_sources {
            let format = Format::parse(&extra.format).unwrap_or_else(|| {
                warn!(source = %extra.name, format = %extra.format, "agent: unknown log format, using raw");
                Format::Raw
            });
            push_file(&mut files, extra.name.clone(), extra.path.clone(), format);
        }

        for u in &cfg.agent.journal_units {
            if !u.is_empty() && !units.iter().any(|x| x == u) {
                units.push(u.clone());
            }
        }

        debug!(files = files.len(), journal_units = units.len(), "agent log sources discovered");

        LogEngine {
            inner: Arc::new(Inner {
                files,
                journal_units: units,
                max_scan_bytes: cfg.agent.max_scan_bytes.max(1),
                max_results: cfg.agent.max_results.max(1),
                journal_timeout_secs: cfg.agent.journal_timeout_secs.max(1),
                include_rotated: cfg.agent.include_rotated,
            }),
        }
    }

    /// Names of all sources (files as their name, journals as "journal:<unit>").
    pub fn source_names(&self) -> Vec<String> {
        let mut v: Vec<String> = self.inner.files.iter().map(|f| f.name.clone()).collect();
        v.extend(self.inner.journal_units.iter().map(|u| format!("journal:{u}")));
        v
    }

    /// §3.4 body: `{"sources":[...]}`.
    pub fn list_sources(&self) -> Value {
        let mut out = Vec::new();
        for f in &self.inner.files {
            let mut o = Map::new();
            o.insert("name".into(), json!(f.name));
            o.insert("kind".into(), json!("file"));
            o.insert("format".into(), json!(f.format.as_str()));
            o.insert("path".into(), json!(f.path.display().to_string()));
            match std::fs::metadata(&f.path) {
                Ok(m) => {
                    o.insert("exists".into(), json!(true));
                    o.insert("size_bytes".into(), json!(m.len()));
                    let modified = m.modified().ok().map(|t| fmt_ts(DateTime::<Utc>::from(t)));
                    o.insert("modified".into(), json!(modified));
                }
                Err(e) => {
                    o.insert("exists".into(), json!(false));
                    if e.kind() != std::io::ErrorKind::NotFound {
                        o.insert("error".into(), json!(e.to_string()));
                    }
                }
            }
            o.insert("rotated_available".into(), json!(rotated_readable(&f.path)));
            out.push(Value::Object(o));
        }
        for u in &self.inner.journal_units {
            out.push(json!({"name": format!("journal:{u}"), "kind": "journal", "units": [u]}));
        }
        json!({ "sources": out })
    }

    /// §3.5 `POST /api/agent/logs/query`.
    pub async fn query(&self, params: Value) -> Result<Value, AgentError> {
        let inner = self.inner.clone();
        let now = Utc::now();
        let req = QueryRequest::from_params(&inner, &params, now)?;
        run_blocking(move || run_query(&inner, req, now)).await
    }

    /// §3.6 `POST /api/agent/logs/stats` (without the `banned`/`whitelisted`
    /// extras, which the caller adds from the ban store).
    pub async fn stats(&self, params: Value) -> Result<Value, AgentError> {
        let inner = self.inner.clone();
        let now = Utc::now();
        let req = StatsRequest::from_params(&inner, &params, now)?;
        run_blocking(move || run_stats(&inner, req, now)).await
    }

    /// §3.7 `"logs"` sub-object: per file source, what the lines of `ip` say.
    pub async fn ip_profile_logs(&self, ip: IpAddr, since: Option<&str>) -> Result<Value, AgentError> {
        let inner = self.inner.clone();
        let now = Utc::now();
        let since = parse_time_spec(since.unwrap_or("24h"), now).map_err(bad)?;
        run_blocking(move || run_ip_profile(&inner, ip, since, now)).await
    }

    /// §3.8 `GET /api/agent/journal`.
    pub async fn journal(&self, params: Value) -> Result<Value, AgentError> {
        let now = Utc::now();
        let req = JournalRequest::from_params(&self.inner, &params, now)?;
        let args = journal_args(&req);
        debug!(?args, "agent: running journalctl");
        let mut cmd = tokio::process::Command::new("journalctl");
        cmd.args(&args)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true);
        let timeout = Duration::from_secs(self.inner.journal_timeout_secs);
        let output = match tokio::time::timeout(timeout, cmd.output()).await {
            Err(_) => {
                return Err(AgentError::Unavailable(format!(
                    "journalctl timed out after {}s",
                    timeout.as_secs()
                )))
            }
            Ok(Err(e)) => return Err(AgentError::Unavailable(format!("cannot run journalctl: {e}"))),
            Ok(Ok(o)) => o,
        };
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(AgentError::Unavailable(format!(
                "journalctl exited with {}: {}",
                output.status,
                stderr.trim()
            )));
        }
        let stdout = output.stdout;
        run_blocking(move || Ok(build_journal_response(&req, &stdout))).await
    }
}

async fn run_blocking<F>(f: F) -> Result<Value, AgentError>
where
    F: FnOnce() -> Result<Value, AgentError> + Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| AgentError::Internal(format!("log scan task failed: {e}")))?
}

// ---------------------------------------------------------------------------
// Time handling
// ---------------------------------------------------------------------------

fn fmt_ts(t: Dt) -> String {
    t.to_rfc3339_opts(SecondsFormat::Secs, true)
}

/// Parse a relative duration `90s|15m|6h|7d` into seconds.
fn parse_duration_secs(s: &str) -> Option<i64> {
    let s = s.trim();
    if s.len() < 2 || !s.is_ascii() {
        return None;
    }
    let (num, unit) = s.split_at(s.len() - 1);
    let n: i64 = num.parse().ok()?;
    if n < 0 {
        return None;
    }
    let mult = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86_400,
        _ => return None,
    };
    n.checked_mul(mult).filter(|v| *v <= 100 * 365 * 86_400)
}

/// Parse "RFC3339" or relative "90s|15m|6h|7d" (= `now` minus that) into an
/// absolute time. `now` is also accepted.
pub fn parse_time_spec(s: &str, now: DateTime<Utc>) -> Result<DateTime<Utc>, String> {
    let t = s.trim();
    if t.is_empty() {
        return Err("empty time value".to_string());
    }
    if t.eq_ignore_ascii_case("now") {
        return Ok(now);
    }
    if let Ok(dt) = DateTime::parse_from_rfc3339(t) {
        return Ok(dt.with_timezone(&Utc));
    }
    if let Some(secs) = parse_duration_secs(t) {
        let delta = TimeDelta::try_seconds(secs).ok_or_else(|| format!("time value `{t}` out of range"))?;
        return now
            .checked_sub_signed(delta)
            .ok_or_else(|| format!("time value `{t}` out of range"));
    }
    Err(format!(
        "invalid time `{t}`: expected RFC 3339 (2026-10-09T05:00:00Z) or a relative age like 90s, 15m, 6h, 7d"
    ))
}

/// Traditional syslog `Oct  9 06:12:01` (no year, assumed UTC): current year,
/// or the previous one when that would be more than a day in the future.
fn parse_traditional_syslog(head: &str, now: Dt) -> Option<Dt> {
    let year = now.year();
    for y in [year, year - 1] {
        let candidate = format!("{y} {head}");
        if let Ok(naive) = NaiveDateTime::parse_from_str(&candidate, "%Y %b %e %H:%M:%S") {
            let t = naive.and_utc();
            if t <= now + TimeDelta::days(1) {
                return Some(t);
            }
        }
    }
    None
}

/// Detect the timestamp of a log line: RFC 3339 prefix, ISO `YYYY-MM-DD
/// HH:MM:SS` / `YYYY/MM/DD HH:MM:SS` prefix (UTC), traditional syslog prefix,
/// or an nginx `[dd/Mon/yyyy:HH:mm:ss +zzzz]` field.
fn detect_ts(line: &str, now: Dt) -> Option<Dt> {
    let b = line.as_bytes();
    if b.first().is_some_and(|c| c.is_ascii_digit()) {
        if let Some(first) = line.split_ascii_whitespace().next() {
            if first.len() >= 20 && first.as_bytes().get(10) == Some(&b'T') {
                if let Ok(dt) = DateTime::parse_from_rfc3339(first) {
                    return Some(dt.with_timezone(&Utc));
                }
            }
        }
        if let Some(head) = line.get(..19) {
            for f in ["%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"] {
                if let Ok(n) = NaiveDateTime::parse_from_str(head, f) {
                    return Some(n.and_utc());
                }
            }
        }
    } else if b.first().is_some_and(|c| c.is_ascii_uppercase()) && b.len() >= 15 {
        if let Some(head) = line.get(..15) {
            if let Some(t) = parse_traditional_syslog(head, now) {
                return Some(t);
            }
        }
    }
    // nginx access log: `... [09/Oct/2026:05:12:01 +0000] ...`
    let scope = line.get(..line.len().min(256)).unwrap_or(line);
    let mut rest = scope;
    while let Some(open) = rest.find('[') {
        let after = &rest[open + 1..];
        if let Some(inner) = after.get(..26) {
            if inner.as_bytes().get(2) == Some(&b'/') {
                if let Ok(dt) = DateTime::parse_from_str(inner, "%d/%b/%Y:%H:%M:%S %z") {
                    return Some(dt.with_timezone(&Utc));
                }
            }
        }
        rest = after;
    }
    None
}

// ---------------------------------------------------------------------------
// IP helpers
// ---------------------------------------------------------------------------

fn parse_ip_or_cidr(s: &str) -> Result<IpNet, AgentError> {
    let s = s.trim();
    if let Ok(net) = s.parse::<IpNet>() {
        return Ok(net.trunc());
    }
    s.parse::<IpAddr>()
        .map(IpNet::from)
        .map_err(|_| bad(format!("invalid ip/cidr `{s}`")))
}

fn is_ip_char(c: char) -> bool {
    c.is_ascii_hexdigit() || c == '.' || c == ':'
}

fn token_to_ip(tok: &str) -> Option<IpAddr> {
    let tok = tok.trim_matches(|c| c == '.');
    if tok.len() < 3 {
        return None;
    }
    if tok.contains('.') {
        // IPv4, possibly with `:port` suffix, or IPv4-mapped IPv6.
        if let Ok(ip) = tok.parse::<IpAddr>() {
            return Some(ip);
        }
        let host = tok.trim_end_matches(':');
        if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
            return Some(IpAddr::V4(ip));
        }
        if let Some((h, port)) = host.rsplit_once(':') {
            if port.bytes().all(|c| c.is_ascii_digit()) {
                if let Ok(ip) = h.parse::<std::net::Ipv4Addr>() {
                    return Some(IpAddr::V4(ip));
                }
            }
        }
        return None;
    }
    let tok = tok.trim_end_matches(':');
    if tok.matches(':').count() < 2 {
        return None;
    }
    // Reject short compressed forms like `d::` (e.g. from `std::io`).
    let groups = tok.split(':').filter(|g| !g.is_empty()).count();
    if groups < 2 {
        return None;
    }
    tok.parse::<std::net::Ipv6Addr>().ok().map(IpAddr::V6)
}

/// Best-effort IPv4/IPv6 tokens in free text.
fn extract_ips(line: &str) -> impl Iterator<Item = IpAddr> + '_ {
    line.split(|c: char| !is_ip_char(c)).filter_map(token_to_ip)
}

fn ip_prefix_key(ip: IpAddr, v4_len: u8, v6_len: u8) -> String {
    let net = match ip {
        IpAddr::V4(_) => IpNet::new(ip, v4_len),
        IpAddr::V6(_) => IpNet::new(ip, v6_len),
    };
    net.map(|n| n.trunc().to_string()).unwrap_or_else(|_| ip.to_string())
}

// ---------------------------------------------------------------------------
// Line parsing
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
struct Parsed {
    ip: Option<IpAddr>,
    /// `ip` came from a format parser (exact); otherwise best-effort token.
    structured: bool,
    event_type: Option<String>,
    fields: Vec<(&'static str, String)>,
}

impl Parsed {
    fn get(&self, key: &str) -> Option<&str> {
        match key {
            "event_type" => self.event_type.as_deref(),
            "ip" => None,
            _ => self.fields.iter().find(|(k, _)| *k == key).map(|(_, v)| v.as_str()),
        }
    }

    fn ip_matches(&self, net: &IpNet, raw: &str) -> bool {
        if self.structured {
            return self.ip.is_some_and(|ip| net.contains(&ip));
        }
        extract_ips(raw).any(|ip| net.contains(&ip))
    }
}

fn event_type_name(e: &EventType) -> String {
    match e {
        EventType::Custom(s) => s.clone(),
        other => format!("{other:?}"),
    }
}

enum Parsers {
    Nginx(NginxPattern),
    Ssh(SshPatterns),
    Postfix(PostfixPatterns),
    Plain(Format),
}

impl Parsers {
    fn new(format: Format) -> Self {
        match format {
            Format::Nginx => Parsers::Nginx(NginxPattern::new()),
            Format::Ssh => Parsers::Ssh(SshPatterns::new()),
            Format::Postfix => Parsers::Postfix(PostfixPatterns::new()),
            other => Parsers::Plain(other),
        }
    }

    fn parse(&self, line: &str) -> Parsed {
        let mut p = Parsed::default();
        match self {
            Parsers::Nginx(pat) => {
                if let Some(ev) = parse_nginx_line(line, pat) {
                    p.ip = Some(ev.source_ip);
                    p.structured = true;
                    p.event_type = Some(
                        match ev.status_code {
                            400..=499 => "Http4xx",
                            500..=599 => "Http5xx",
                            _ => "HttpRequest",
                        }
                        .to_string(),
                    );
                    p.fields = vec![
                        ("method", ev.method),
                        ("path", ev.path),
                        ("protocol", ev.protocol),
                        ("status", ev.status_code.to_string()),
                        ("bytes", ev.body_bytes_sent.to_string()),
                        ("user_agent", ev.user_agent),
                    ];
                    return p;
                }
            }
            Parsers::Ssh(pat) => {
                if let Some(ev) = parse_ssh_line(line, pat) {
                    p.ip = Some(ev.source_ip);
                    p.structured = true;
                    p.event_type = Some(event_type_name(&ev.event_type));
                    p.fields = vec![("user", ev.user), ("invalid_user", ev.invalid_user.to_string())];
                    if let Some(port) = ssh_src_port(line) {
                        p.fields.push(("src_port", port));
                    }
                    return p;
                }
            }
            Parsers::Postfix(pat) => {
                if let Some(ev) = parse_postfix_line(line, pat) {
                    p.ip = Some(ev.source_ip);
                    p.structured = true;
                    p.event_type = Some("SmtpAuthFailure".to_string());
                    p.fields = vec![("mechanism", ev.mechanism)];
                    return p;
                }
            }
            Parsers::Plain(Format::Ufw) => {
                if let Some(parsed) = parse_ufw(line) {
                    return parsed;
                }
            }
            Parsers::Plain(Format::Syslog) => {
                if let Some((host, program, pid)) = syslog_header(line) {
                    p.fields.push(("host", host.to_string()));
                    p.fields.push(("program", program.to_string()));
                    if let Some(pid) = pid {
                        p.fields.push(("pid", pid.to_string()));
                    }
                }
            }
            Parsers::Plain(_) => {}
        }
        p.ip = extract_ips(line).next();
        p
    }
}

/// `... from 1.2.3.4 port 50022 ssh2` → `50022`.
fn ssh_src_port(line: &str) -> Option<String> {
    let idx = line.rfind(" port ")?;
    let digits: String = line[idx + 6..].chars().take_while(|c| c.is_ascii_digit()).collect();
    (!digits.is_empty()).then_some(digits)
}

/// Value of a `KEY=VALUE` token in a kernel firewall log line.
fn kv_field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let needle = format!("{key}=");
    let start = if line.starts_with(&needle) {
        0
    } else {
        line.find(&format!(" {needle}"))? + 1
    };
    let rest = &line[start + needle.len()..];
    let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
    Some(&rest[..end])
}

fn parse_ufw(line: &str) -> Option<Parsed> {
    let ip: IpAddr = kv_field(line, "SRC")?.parse().ok()?;
    let mut fields: Vec<(&'static str, String)> = Vec::new();
    if let Some(i) = line.find("[UFW ") {
        if let Some(end) = line[i + 5..].find(']') {
            fields.push(("action", line[i + 5..i + 5 + end].to_string()));
        }
    }
    for (key, name) in [("IN", "in"), ("OUT", "out"), ("DST", "dst")] {
        if let Some(v) = kv_field(line, key) {
            fields.push((name, v.to_string()));
        }
    }
    if let Some(v) = kv_field(line, "PROTO") {
        fields.push(("proto", v.to_ascii_uppercase()));
    }
    if let Some(v) = kv_field(line, "SPT") {
        fields.push(("spt", v.to_string()));
    }
    let dpt = kv_field(line, "DPT");
    if let Some(v) = dpt {
        fields.push(("port", v.to_string()));
    }
    let flags: Vec<&str> = line
        .split_ascii_whitespace()
        .filter(|t| matches!(*t, "SYN" | "ACK" | "FIN" | "RST" | "PSH" | "URG"))
        .collect();
    if !flags.is_empty() {
        fields.push(("flags", flags.join(" ")));
    }
    Some(Parsed {
        ip: Some(ip),
        structured: true,
        event_type: Some(if dpt.is_some() { "PortAccess" } else { "ConnectionEvent" }.to_string()),
        fields,
    })
}

/// `<ts> host program[pid]: message` → (host, program, pid).
fn syslog_header(line: &str) -> Option<(&str, &str, Option<&str>)> {
    let rest = if line.as_bytes().first()?.is_ascii_digit() {
        line.split_once(char::is_whitespace)?.1
    } else {
        line.get(15..)?
    };
    let mut it = rest.split_ascii_whitespace();
    let host = it.next()?;
    let tag = it.next()?;
    let tag = tag.strip_suffix(':')?;
    match tag.split_once('[') {
        Some((prog, pid)) => Some((host, prog, pid.strip_suffix(']'))),
        None => Some((host, tag, None)),
    }
}

// ---------------------------------------------------------------------------
// Filters
// ---------------------------------------------------------------------------

enum Matcher {
    Exact(String),
    Re(Regex),
    StatusClass(u8),
}

impl Matcher {
    fn matches(&self, v: &str) -> bool {
        match self {
            Matcher::Exact(e) => v.eq_ignore_ascii_case(e),
            Matcher::Re(r) => r.is_match(v),
            Matcher::StatusClass(c) => v.len() == 3 && v.as_bytes()[0] == *c,
        }
    }
}

fn build_regex(p: &str) -> Result<Regex, AgentError> {
    RegexBuilder::new(p)
        .size_limit(REGEX_SIZE_LIMIT)
        .build()
        .map_err(|e| bad(format!("invalid regex `{p}`: {e}")))
}

#[derive(Default)]
struct Filter {
    grep: Option<Regex>,
    ip: Option<IpNet>,
    fields: Vec<(String, Matcher)>,
}

impl Filter {
    fn from_value(v: &Value, format: Format) -> Result<Self, AgentError> {
        let mut f = Filter::default();
        if let Some(g) = opt_str(v, "grep")? {
            if !g.is_empty() {
                f.grep = Some(build_regex(&g)?);
            }
        }
        if let Some(ip) = opt_str(v, "ip")? {
            if !ip.is_empty() {
                f.ip = Some(parse_ip_or_cidr(&ip)?);
            }
        }
        match v.get("fields") {
            None | Some(Value::Null) => {}
            Some(Value::Object(map)) => {
                for (k, val) in map {
                    let key = if k == "status_code" { "status" } else { k.as_str() };
                    if key != "event_type" && !format.field_keys().contains(&key) {
                        return Err(bad(format!(
                            "field `{k}` is not available for format `{}` (known: event_type, {})",
                            format.as_str(),
                            format.field_keys().join(", ")
                        )));
                    }
                    let s = match val {
                        Value::String(s) => s.clone(),
                        Value::Number(n) => n.to_string(),
                        Value::Bool(b) => b.to_string(),
                        Value::Null => continue,
                        _ => return Err(bad(format!("field `{k}`: expected string"))),
                    };
                    let m = if key == "status"
                        && s.len() == 3
                        && s.as_bytes()[0].is_ascii_digit()
                        && s[1..].eq_ignore_ascii_case("xx")
                    {
                        Matcher::StatusClass(s.as_bytes()[0])
                    } else if s.starts_with('^') || s.contains('|') || s.ends_with('$') {
                        Matcher::Re(build_regex(&s)?)
                    } else {
                        Matcher::Exact(s)
                    };
                    f.fields.push((key.to_string(), m));
                }
            }
            Some(_) => return Err(bad("`fields` must be an object")),
        }
        Ok(f)
    }

    fn needs_parse(&self) -> bool {
        self.ip.is_some() || !self.fields.is_empty()
    }

    fn grep_ok(&self, raw: &str) -> bool {
        self.grep.as_ref().is_none_or(|r| r.is_match(raw))
    }

    fn parsed_ok(&self, raw: &str, p: &Parsed) -> bool {
        if let Some(net) = &self.ip {
            if !p.ip_matches(net, raw) {
                return false;
            }
        }
        self.fields
            .iter()
            .all(|(k, m)| p.get(k).is_some_and(|v| m.matches(v)))
    }
}

// ---------------------------------------------------------------------------
// Parameter helpers
// ---------------------------------------------------------------------------

fn opt_str(v: &Value, key: &str) -> Result<Option<String>, AgentError> {
    match v.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.clone())),
        Some(Value::Number(n)) => Ok(Some(n.to_string())),
        Some(Value::Bool(b)) => Ok(Some(b.to_string())),
        Some(_) => Err(bad(format!("`{key}` must be a string"))),
    }
}

fn opt_usize(v: &Value, key: &str) -> Result<Option<usize>, AgentError> {
    match v.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(n)) => n
            .as_u64()
            .map(|n| Some(n as usize))
            .ok_or_else(|| bad(format!("`{key}` must be a non-negative integer"))),
        Some(Value::String(s)) if s.is_empty() => Ok(None),
        Some(Value::String(s)) => s
            .trim()
            .parse::<usize>()
            .map(Some)
            .map_err(|_| bad(format!("`{key}` must be a non-negative integer"))),
        Some(_) => Err(bad(format!("`{key}` must be a non-negative integer"))),
    }
}

fn opt_bool(v: &Value, key: &str) -> Result<Option<bool>, AgentError> {
    match v.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Bool(b)) => Ok(Some(*b)),
        Some(Value::String(s)) => match s.trim().to_ascii_lowercase().as_str() {
            "true" | "1" | "yes" => Ok(Some(true)),
            "false" | "0" | "no" => Ok(Some(false)),
            "" => Ok(None),
            _ => Err(bad(format!("`{key}` must be a boolean"))),
        },
        Some(_) => Err(bad(format!("`{key}` must be a boolean"))),
    }
}

fn window(params: &Value, default_since: &str, now: Dt) -> Result<(Dt, Dt), AgentError> {
    let since = parse_time_spec(opt_str(params, "since")?.as_deref().unwrap_or(default_since), now).map_err(bad)?;
    let until = match opt_str(params, "until")? {
        Some(u) if !u.is_empty() => parse_time_spec(&u, now).map_err(bad)?,
        _ => now,
    };
    if since > until {
        return Err(bad("`since` is after `until`"));
    }
    Ok((since, until))
}

// ---------------------------------------------------------------------------
// Backward scanner
// ---------------------------------------------------------------------------

struct ScanWindow {
    since: Dt,
    until: Dt,
    budget: u64,
    include_rotated: bool,
    now: Dt,
}

#[derive(Default)]
struct ScanOutcome {
    lines: u64,
    bytes: u64,
    budget_hit: bool,
    reached_since: bool,
    oldest: Option<Dt>,
    newest: Option<Dt>,
    files: Vec<String>,
}

#[derive(Default)]
struct WalkState {
    inherited: Option<Dt>,
    older_streak: u32,
}

fn rotated_path(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(".1");
    PathBuf::from(s)
}

/// `<path>.1` exists, is a regular file and is not gzip-compressed.
fn rotated_readable(path: &Path) -> bool {
    let rot = rotated_path(path);
    let Ok(meta) = std::fs::metadata(&rot) else { return false };
    if !meta.is_file() {
        return false;
    }
    let mut magic = [0u8; 2];
    match File::open(&rot).and_then(|mut f| f.read(&mut magic)) {
        Ok(2) => magic != [0x1f, 0x8b],
        Ok(_) => true,
        Err(_) => false,
    }
}

/// Visit every line of `path` (then `<path>.1`) whose (own or inherited)
/// timestamp lies within the window, **newest first**.
fn scan_source(
    path: &Path,
    w: &ScanWindow,
    mut visit: impl FnMut(&str, Option<Dt>),
) -> Result<ScanOutcome, AgentError> {
    let mut out = ScanOutcome::default();
    let mut state = WalkState::default();
    let file = File::open(path).map_err(|e| {
        AgentError::Unavailable(format!("cannot open {}: {e}", path.display()))
    })?;
    out.files.push(path.display().to_string());
    scan_file(file, w, &mut out, &mut state, &mut visit)
        .map_err(|e| AgentError::Unavailable(format!("error reading {}: {e}", path.display())))?;
    if !out.reached_since && !out.budget_hit && w.include_rotated && rotated_readable(path) {
        let rot = rotated_path(path);
        match File::open(&rot) {
            Ok(f) => {
                out.files.push(rot.display().to_string());
                if let Err(e) = scan_file(f, w, &mut out, &mut state, &mut visit) {
                    warn!(path = %rot.display(), error = %e, "agent: error reading rotated log");
                }
            }
            Err(e) => debug!(path = %rot.display(), error = %e, "agent: rotated log not readable"),
        }
    }
    Ok(out)
}

/// Returns `false` when the scan should stop (window start reached).
fn handle_line(
    bytes: &[u8],
    w: &ScanWindow,
    out: &mut ScanOutcome,
    state: &mut WalkState,
    visit: &mut impl FnMut(&str, Option<Dt>),
) -> bool {
    let bytes = bytes.strip_suffix(b"\r").unwrap_or(bytes);
    if bytes.is_empty() {
        return true;
    }
    let line = String::from_utf8_lossy(bytes);
    out.lines += 1;
    let own = detect_ts(&line, w.now);
    if let Some(t) = own {
        state.inherited = Some(t);
        if out.oldest.is_none_or(|o| t < o) {
            out.oldest = Some(t);
        }
        if out.newest.is_none_or(|n| t > n) {
            out.newest = Some(t);
        }
    }
    let eff = own.or(state.inherited);
    if let Some(t) = eff {
        if t > w.until {
            return true;
        }
        if t < w.since {
            if own.is_some() {
                state.older_streak += 1;
                if state.older_streak >= OLDER_STREAK_STOP {
                    out.reached_since = true;
                    return false;
                }
            }
            return true;
        }
        if own.is_some() {
            state.older_streak = 0;
        }
    }
    visit(&line, eff);
    true
}

fn scan_file(
    mut file: File,
    w: &ScanWindow,
    out: &mut ScanOutcome,
    state: &mut WalkState,
    visit: &mut impl FnMut(&str, Option<Dt>),
) -> std::io::Result<()> {
    let mut pos = file.metadata()?.len();
    let mut carry: Vec<u8> = Vec::new();
    let mut buf: Vec<u8> = Vec::new();
    while pos > 0 {
        let remaining = w.budget.saturating_sub(out.bytes);
        if remaining == 0 {
            out.budget_hit = true;
            return Ok(());
        }
        let want = CHUNK.min(pos).min(remaining);
        pos -= want;
        file.seek(SeekFrom::Start(pos))?;
        buf.clear();
        buf.resize(want as usize, 0);
        file.read_exact(&mut buf)?;
        out.bytes += want;
        buf.extend_from_slice(&carry);
        carry.clear();
        let mut end = buf.len();
        while let Some(i) = buf[..end].iter().rposition(|&b| b == b'\n') {
            if !handle_line(&buf[i + 1..end], w, out, state, visit) {
                return Ok(());
            }
            end = i;
        }
        if pos == 0 {
            if !handle_line(&buf[..end], w, out, state, visit) {
                return Ok(());
            }
        } else if end > MAX_CARRY {
            debug!(bytes = end, "agent: dropping overlong log line");
        } else {
            carry.extend_from_slice(&buf[..end]);
        }
    }
    Ok(())
}

fn window_json(w: &ScanWindow, o: &ScanOutcome) -> Value {
    json!({
        "since": fmt_ts(w.since),
        "until": fmt_ts(w.until),
        "first_line_ts": o.oldest.map(fmt_ts),
        "last_line_ts": o.newest.map(fmt_ts),
        "files": o.files,
    })
}

fn truncate_raw(s: &str) -> String {
    if s.len() <= MAX_RAW_BYTES {
        return s.to_string();
    }
    let mut end = MAX_RAW_BYTES;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &s[..end])
}

// ---------------------------------------------------------------------------
// Query (§3.5)
// ---------------------------------------------------------------------------

struct QueryRequest {
    src: FileSource,
    since: Dt,
    until: Dt,
    filter: Filter,
    limit: usize,
    parse: bool,
}

impl QueryRequest {
    fn from_params(inner: &Inner, params: &Value, now: Dt) -> Result<Self, AgentError> {
        let name = opt_str(params, "source")?.ok_or_else(|| bad("`source` is required"))?;
        let src = inner.file(&name)?;
        let (since, until) = window(params, "1h", now)?;
        let filter = Filter::from_value(params, src.format)?;
        let limit = opt_usize(params, "limit")?.unwrap_or(DEFAULT_LIMIT).min(inner.max_results);
        let parse = opt_bool(params, "parse")?.unwrap_or(true);
        Ok(QueryRequest { src, since, until, filter, limit, parse })
    }
}

fn item_json(raw: &str, ts: Option<Dt>, parsed: Option<&Parsed>) -> Value {
    let mut o = Map::new();
    o.insert("ts".into(), json!(ts.map(fmt_ts)));
    if let Some(p) = parsed {
        o.insert("ip".into(), json!(p.ip.map(|i| i.to_string())));
        o.insert("event_type".into(), json!(p.event_type));
        let fields: Map<String, Value> =
            p.fields.iter().map(|(k, v)| (k.to_string(), Value::String(v.clone()))).collect();
        o.insert("fields".into(), Value::Object(fields));
    }
    o.insert("raw".into(), json!(truncate_raw(raw)));
    Value::Object(o)
}

fn run_query(inner: &Inner, req: QueryRequest, now: Dt) -> Result<Value, AgentError> {
    let w = ScanWindow {
        since: req.since,
        until: req.until,
        budget: inner.max_scan_bytes,
        include_rotated: inner.include_rotated,
        now,
    };
    let parsers = Parsers::new(req.src.format);
    let mut matched: u64 = 0;
    let mut items: Vec<Value> = Vec::new();
    let outcome = scan_source(&req.src.path, &w, |line, ts| {
        if !req.filter.grep_ok(line) {
            return;
        }
        let mut parsed = None;
        if req.filter.needs_parse() {
            let p = parsers.parse(line);
            if !req.filter.parsed_ok(line, &p) {
                return;
            }
            parsed = Some(p);
        }
        matched += 1;
        if items.len() < req.limit {
            if req.parse && parsed.is_none() {
                parsed = Some(parsers.parse(line));
            }
            items.push(item_json(line, ts, if req.parse { parsed.as_ref() } else { None }));
        }
    })?;
    items.reverse();
    debug!(source = %req.src.name, lines = outcome.lines, bytes = outcome.bytes, matched, "agent log query");
    Ok(json!({
        "source": req.src.name,
        "format": req.src.format.as_str(),
        "scanned_lines": outcome.lines,
        "scanned_bytes": outcome.bytes,
        "matched": matched,
        "returned": items.len(),
        "truncated": outcome.budget_hit || matched > items.len() as u64,
        "scan_capped": outcome.budget_hit,
        "window": window_json(&w, &outcome),
        "items": items,
    }))
}

// ---------------------------------------------------------------------------
// Stats (§3.6)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GroupBy {
    Ip,
    Ip24,
    Ip48,
    Field(&'static str),
    EventType,
    Hour,
    Minute,
    Day,
}

impl GroupBy {
    fn parse(s: &str, format: Format) -> Result<Self, AgentError> {
        let g = match s {
            "ip" => GroupBy::Ip,
            "ip24" => GroupBy::Ip24,
            "ip48" => GroupBy::Ip48,
            "event_type" => GroupBy::EventType,
            "hour" => GroupBy::Hour,
            "minute" => GroupBy::Minute,
            "day" => GroupBy::Day,
            other => {
                let other = if other == "status_code" { "status" } else { other };
                match format.field_keys().iter().find(|k| **k == other) {
                    Some(k) => GroupBy::Field(k),
                    None => {
                        return Err(bad(format!(
                            "unknown group_by `{s}` for format `{}` (use ip, ip24, ip48, event_type, hour, minute, day{}{})",
                            format.as_str(),
                            if format.field_keys().is_empty() { "" } else { ", " },
                            format.field_keys().join(", ")
                        )))
                    }
                }
            }
        };
        Ok(g)
    }

    fn is_ip(self) -> bool {
        matches!(self, GroupBy::Ip | GroupBy::Ip24 | GroupBy::Ip48)
    }

    fn is_time(self) -> bool {
        matches!(self, GroupBy::Hour | GroupBy::Minute | GroupBy::Day)
    }

    fn needs_parse(self) -> bool {
        !self.is_time()
    }
}

struct StatsRequest {
    src: FileSource,
    since: Dt,
    until: Dt,
    filter: Filter,
    group_by: GroupBy,
    top: usize,
    bucket_secs: Option<i64>,
}

impl StatsRequest {
    fn from_params(inner: &Inner, params: &Value, now: Dt) -> Result<Self, AgentError> {
        let name = opt_str(params, "source")?.ok_or_else(|| bad("`source` is required"))?;
        let src = inner.file(&name)?;
        let (since, until) = window(params, "1h", now)?;
        // Filters live under `filter`; top-level grep/ip/fields are accepted too.
        let filter = match params.get("filter") {
            Some(f @ Value::Object(_)) => Filter::from_value(f, src.format)?,
            None | Some(Value::Null) => Filter::from_value(params, src.format)?,
            Some(_) => return Err(bad("`filter` must be an object")),
        };
        let group_by = GroupBy::parse(opt_str(params, "group_by")?.as_deref().unwrap_or("ip"), src.format)?;
        let default_top = if group_by.is_time() { MAX_TOP } else { DEFAULT_TOP };
        let top = opt_usize(params, "top")?.unwrap_or(default_top).min(MAX_TOP);
        let bucket_secs = match opt_str(params, "buckets")? {
            Some(b) if !b.is_empty() => {
                let secs = parse_duration_secs(&b)
                    .filter(|s| *s >= 60)
                    .ok_or_else(|| bad(format!("invalid buckets `{b}` (e.g. 5m, 15m, 1h, 1d; minimum 1m)")))?;
                let span = (until - since).num_seconds() / secs + 1;
                if span > MAX_SERIES_BUCKETS {
                    return Err(bad(format!("buckets `{b}` gives {span} buckets (max {MAX_SERIES_BUCKETS})")));
                }
                Some(secs)
            }
            _ => None,
        };
        Ok(StatsRequest { src, since, until, filter, group_by, top, bucket_secs })
    }
}

/// Bounded distinct-value counter.
#[derive(Default)]
struct Capped {
    map: HashMap<String, u64>,
    capped: bool,
}

impl Capped {
    fn add(&mut self, v: &str, budget: &mut usize) {
        if let Some(c) = self.map.get_mut(v) {
            *c += 1;
        } else if self.map.len() < DISTINCT_CAP && *budget > 0 {
            *budget -= 1;
            self.map.insert(v.to_string(), 1);
        } else {
            self.capped = true;
        }
    }

    fn top(&self, n: usize) -> Vec<(String, u64)> {
        let mut v: Vec<(String, u64)> = self.map.iter().map(|(k, c)| (k.clone(), *c)).collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        v.truncate(n);
        v
    }
}

#[derive(Default)]
struct GroupAcc {
    count: u64,
    first: Option<Dt>,
    last: Option<Dt>,
    s4xx: u64,
    s5xx: u64,
    profile: Vec<Capped>,
    ips: Capped,
}

fn touch_times(first: &mut Option<Dt>, last: &mut Option<Dt>, ts: Option<Dt>) {
    if let Some(t) = ts {
        if first.is_none_or(|f| t < f) {
            *first = Some(t);
        }
        if last.is_none_or(|l| t > l) {
            *last = Some(t);
        }
    }
}

fn time_key(ts: Dt, g: GroupBy) -> String {
    let secs = match g {
        GroupBy::Minute => 60,
        GroupBy::Hour => 3600,
        _ => 86_400,
    };
    let start = ts.timestamp().div_euclid(secs) * secs;
    Utc.timestamp_opt(start, 0).single().map(fmt_ts).unwrap_or_default()
}

fn pct(count: u64, total: u64) -> f64 {
    if total == 0 {
        return 0.0;
    }
    ((count as f64) * 1000.0 / (total as f64)).round() / 10.0
}

fn run_stats(inner: &Inner, req: StatsRequest, now: Dt) -> Result<Value, AgentError> {
    let w = ScanWindow {
        since: req.since,
        until: req.until,
        budget: inner.max_scan_bytes,
        include_rotated: inner.include_rotated,
        now,
    };
    let format = req.src.format;
    let parsers = Parsers::new(format);
    let profile_fields = format.profile_fields();
    let g = req.group_by;
    let need_parse = req.filter.needs_parse() || g.needs_parse();

    let mut matched: u64 = 0;
    let mut no_key: u64 = 0;
    let mut other: u64 = 0;
    let mut groups: HashMap<String, GroupAcc> = HashMap::new();
    let mut series: BTreeMap<i64, u64> = BTreeMap::new();
    let mut budget = GLOBAL_DISTINCT_BUDGET;

    let outcome = scan_source(&req.src.path, &w, |line, ts| {
        if !req.filter.grep_ok(line) {
            return;
        }
        let parsed = if need_parse { Some(parsers.parse(line)) } else { None };
        if let Some(p) = &parsed {
            if !req.filter.parsed_ok(line, p) {
                return;
            }
        }
        matched += 1;
        if let (Some(b), Some(t)) = (req.bucket_secs, ts) {
            *series.entry(t.timestamp().div_euclid(b) * b).or_default() += 1;
        }
        let key = match (g, parsed.as_ref()) {
            (GroupBy::Ip, Some(p)) => p.ip.map(|i| i.to_string()),
            (GroupBy::Ip24, Some(p)) => p.ip.map(|i| ip_prefix_key(i, 24, 64)),
            (GroupBy::Ip48, Some(p)) => p.ip.map(|i| ip_prefix_key(i, 16, 48)),
            (GroupBy::EventType, Some(p)) => p.event_type.clone(),
            (GroupBy::Field(f), Some(p)) => p.get(f).map(str::to_string),
            (gb, _) if gb.is_time() => ts.map(|t| time_key(t, gb)),
            _ => None,
        };
        let Some(key) = key else {
            no_key += 1;
            return;
        };
        if !groups.contains_key(&key) && groups.len() >= MAX_GROUPS {
            other += 1;
            return;
        }
        let acc = groups.entry(key).or_insert_with(|| GroupAcc {
            profile: if g.is_ip() { profile_fields.iter().map(|_| Capped::default()).collect() } else { Vec::new() },
            ..GroupAcc::default()
        });
        acc.count += 1;
        touch_times(&mut acc.first, &mut acc.last, ts);
        if let Some(p) = &parsed {
            if g.is_ip() {
                if format == Format::Nginx {
                    match p.get("status").and_then(|s| s.as_bytes().first()) {
                        Some(b'4') => acc.s4xx += 1,
                        Some(b'5') => acc.s5xx += 1,
                        _ => {}
                    }
                }
                for (i, f) in profile_fields.iter().enumerate() {
                    if let Some(v) = p.get(f) {
                        acc.profile[i].add(v, &mut budget);
                    }
                }
            } else if g == GroupBy::Field("path") {
                if let Some(ip) = p.ip {
                    acc.ips.add(&ip.to_string(), &mut budget);
                }
            }
        }
    })?;

    let distinct = groups.len();
    let mut list: Vec<(String, GroupAcc)> = groups.into_iter().collect();
    if g.is_time() {
        list.sort_by(|a, b| a.0.cmp(&b.0));
        if list.len() > req.top {
            list.drain(..list.len() - req.top);
        }
    } else {
        list.sort_by(|a, b| b.1.count.cmp(&a.1.count).then_with(|| a.0.cmp(&b.0)));
        list.truncate(req.top);
    }

    let groups_json: Vec<Value> = list
        .into_iter()
        .map(|(key, acc)| {
            let mut extras = Map::new();
            if g.is_ip() {
                if format == Format::Nginx {
                    extras.insert("status_4xx".into(), json!(acc.s4xx));
                    extras.insert("status_5xx".into(), json!(acc.s5xx));
                }
                let mut capped = false;
                for (i, f) in profile_fields.iter().enumerate() {
                    let c = &acc.profile[i];
                    capped |= c.capped;
                    extras.insert(format!("distinct_{f}s"), json!(c.map.len()));
                    extras.insert(format!("sample_{f}"), json!(c.top(1).first().map(|(k, _)| k.clone())));
                }
                if capped {
                    extras.insert("distinct_capped".into(), json!(true));
                }
            } else if g == GroupBy::Field("path") {
                extras.insert("distinct_ips".into(), json!(acc.ips.map.len()));
                if acc.ips.capped {
                    extras.insert("distinct_capped".into(), json!(true));
                }
            }
            json!({
                "key": key,
                "count": acc.count,
                "pct": pct(acc.count, matched),
                "first_seen": acc.first.map(fmt_ts),
                "last_seen": acc.last.map(fmt_ts),
                "extras": extras,
            })
        })
        .collect();

    let series_json: Option<Vec<Value>> = req.bucket_secs.map(|b| {
        let start = req.since.timestamp().div_euclid(b) * b;
        let end = req.until.timestamp().div_euclid(b) * b;
        let mut v = Vec::new();
        let mut t = start;
        while t <= end {
            let count = series.get(&t).copied().unwrap_or(0);
            if let Some(dt) = Utc.timestamp_opt(t, 0).single() {
                v.push(json!({"bucket": fmt_ts(dt), "count": count}));
            }
            t += b;
        }
        v
    });

    let mut out = json!({
        "source": req.src.name,
        "format": format.as_str(),
        "group_by": opt_group_name(g),
        "scanned_lines": outcome.lines,
        "scanned_bytes": outcome.bytes,
        "matched": matched,
        "distinct": distinct,
        "no_key": no_key,
        "groups": groups_json,
        "truncated": outcome.budget_hit,
        "window": window_json(&w, &outcome),
    });
    if other > 0 {
        out["other"] = json!(other);
        out["groups_capped"] = json!(true);
    }
    if let Some(s) = series_json {
        out["series"] = Value::Array(s);
    }
    Ok(out)
}

fn opt_group_name(g: GroupBy) -> &'static str {
    match g {
        GroupBy::Ip => "ip",
        GroupBy::Ip24 => "ip24",
        GroupBy::Ip48 => "ip48",
        GroupBy::Field(f) => f,
        GroupBy::EventType => "event_type",
        GroupBy::Hour => "hour",
        GroupBy::Minute => "minute",
        GroupBy::Day => "day",
    }
}

// ---------------------------------------------------------------------------
// IP profile (§3.7 "logs")
// ---------------------------------------------------------------------------

#[derive(Default)]
struct ProfileAcc {
    count: u64,
    first: Option<Dt>,
    last: Option<Dt>,
    status: BTreeMap<String, u64>,
    event_types: BTreeMap<String, u64>,
    paths: Capped,
    uas: Capped,
    ports: Capped,
    users: Capped,
}

fn pairs(v: Vec<(String, u64)>) -> Value {
    Value::Array(v.into_iter().map(|(k, n)| json!([k, n])).collect())
}

fn profile_one(src: &FileSource, ip: IpAddr, w: &ScanWindow) -> Value {
    let net = IpNet::from(ip);
    let parsers = Parsers::new(src.format);
    let ip_text = ip.to_string();
    let mut acc = ProfileAcc::default();
    let mut budget = GLOBAL_DISTINCT_BUDGET;
    let res = scan_source(&src.path, w, |line, ts| {
        // Cheap textual pre-filter (IPv6 may be written differently, so only for v4).
        if ip.is_ipv4() && !line.contains(&ip_text) {
            return;
        }
        let p = parsers.parse(line);
        if !p.ip_matches(&net, line) {
            return;
        }
        acc.count += 1;
        touch_times(&mut acc.first, &mut acc.last, ts);
        if let Some(e) = &p.event_type {
            *acc.event_types.entry(e.clone()).or_default() += 1;
        }
        if let Some(s) = p.get("status") {
            *acc.status.entry(s.to_string()).or_default() += 1;
        }
        if let Some(v) = p.get("path") {
            acc.paths.add(v, &mut budget);
        }
        if let Some(v) = p.get("user_agent") {
            acc.uas.add(v, &mut budget);
        }
        if let Some(v) = p.get("port") {
            acc.ports.add(v, &mut budget);
        }
        if let Some(v) = p.get("user") {
            acc.users.add(v, &mut budget);
        }
    });
    let outcome = match res {
        Ok(o) => o,
        Err(e) => return json!({"count": 0, "error": e.to_string()}),
    };
    if acc.count == 0 {
        let mut o = json!({"count": 0});
        if outcome.budget_hit {
            o["truncated"] = json!(true);
        }
        return o;
    }
    let mut o = Map::new();
    o.insert("count".into(), json!(acc.count));
    o.insert("first_seen".into(), json!(acc.first.map(fmt_ts)));
    o.insert("last_seen".into(), json!(acc.last.map(fmt_ts)));
    match src.format {
        Format::Nginx => {
            o.insert("status".into(), json!(acc.status));
            o.insert("top_paths".into(), pairs(acc.paths.top(10)));
            o.insert(
                "user_agents".into(),
                json!(acc.uas.top(5).into_iter().map(|(k, _)| k).collect::<Vec<_>>()),
            );
            o.insert("event_types".into(), json!(acc.event_types));
        }
        Format::Ssh => {
            o.insert("users".into(), pairs(acc.users.top(10)));
            o.insert("event_types".into(), json!(acc.event_types));
        }
        Format::Ufw => {
            o.insert("ports".into(), pairs(acc.ports.top(20)));
            o.insert("event_types".into(), json!(acc.event_types));
        }
        Format::Postfix => {
            o.insert("event_types".into(), json!(acc.event_types));
        }
        Format::Syslog | Format::Raw => {}
    }
    if outcome.budget_hit {
        o.insert("truncated".into(), json!(true));
    }
    Value::Object(o)
}

fn run_ip_profile(inner: &Inner, ip: IpAddr, since: Dt, now: Dt) -> Result<Value, AgentError> {
    let w = ScanWindow {
        since,
        until: now,
        budget: inner.max_scan_bytes,
        include_rotated: inner.include_rotated,
        now,
    };
    let mut out = Map::new();
    for src in &inner.files {
        out.insert(src.name.clone(), profile_one(src, ip, &w));
    }
    Ok(Value::Object(out))
}

// ---------------------------------------------------------------------------
// Journal (§3.8)
// ---------------------------------------------------------------------------

struct JournalRequest {
    unit: String,
    since: Dt,
    until: Option<Dt>,
    priority: Option<u8>,
    grep: Option<Regex>,
    limit: usize,
}

fn parse_priority(s: &str) -> Option<u8> {
    let s = s.trim().to_ascii_lowercase();
    if let Ok(n) = s.parse::<u8>() {
        return (n <= 7).then_some(n);
    }
    Some(match s.as_str() {
        "emerg" => 0,
        "alert" => 1,
        "crit" => 2,
        "err" | "error" => 3,
        "warning" | "warn" => 4,
        "notice" => 5,
        "info" => 6,
        "debug" => 7,
        _ => return None,
    })
}

impl JournalRequest {
    fn from_params(inner: &Inner, params: &Value, now: Dt) -> Result<Self, AgentError> {
        let unit = opt_str(params, "unit")?.filter(|u| !u.is_empty()).unwrap_or_else(|| "hiveguard".into());
        let unit = unit.strip_prefix("journal:").map(str::to_string).unwrap_or(unit);
        if !inner.journal_units.contains(&unit) {
            return Err(AgentError::NotFound(format!(
                "journal unit `{unit}` is not allowed (allowed: {})",
                inner.journal_units.join(", ")
            )));
        }
        let since = parse_time_spec(opt_str(params, "since")?.as_deref().unwrap_or("1h"), now).map_err(bad)?;
        let until = match opt_str(params, "until")? {
            Some(u) if !u.is_empty() => Some(parse_time_spec(&u, now).map_err(bad)?),
            _ => None,
        };
        if until.is_some_and(|u| u < since) {
            return Err(bad("`since` is after `until`"));
        }
        let priority = match opt_str(params, "priority")? {
            Some(p) if !p.is_empty() => {
                Some(parse_priority(&p).ok_or_else(|| bad(format!("invalid priority `{p}`")))?)
            }
            _ => None,
        };
        let grep = match opt_str(params, "grep")? {
            Some(g) if !g.is_empty() => Some(build_regex(&g)?),
            _ => None,
        };
        let limit = opt_usize(params, "limit")?.unwrap_or(DEFAULT_LIMIT).min(inner.max_results);
        Ok(JournalRequest { unit, since, until, priority, grep, limit })
    }

    fn fetch_cap(&self) -> usize {
        if self.grep.is_some() {
            JOURNAL_FETCH_CAP
        } else {
            (self.limit + 1).min(JOURNAL_FETCH_CAP)
        }
    }
}

fn journal_time(t: Dt) -> String {
    t.format("%Y-%m-%d %H:%M:%S UTC").to_string()
}

fn journal_args(req: &JournalRequest) -> Vec<String> {
    let mut a = vec![
        "--no-pager".to_string(),
        "-o".into(),
        "json".into(),
        "-u".into(),
        req.unit.clone(),
        "--since".into(),
        journal_time(req.since),
    ];
    if let Some(u) = req.until {
        a.push("--until".into());
        a.push(journal_time(u));
    }
    if let Some(p) = req.priority {
        a.push("-p".into());
        a.push(p.to_string());
    }
    a.push("-n".into());
    a.push(req.fetch_cap().to_string());
    a
}

fn journal_value_text(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        // Non-UTF-8 / binary fields are rendered as byte arrays by `-o json`.
        Value::Array(bytes) => {
            let b: Vec<u8> = bytes.iter().filter_map(|x| x.as_u64().map(|n| n as u8)).collect();
            Some(String::from_utf8_lossy(&b).into_owned())
        }
        Value::Null => None,
        other => Some(other.to_string()),
    }
}

/// Map one `journalctl -o json` line to `{ts, priority, message, pid}`.
fn map_journal_line(line: &str) -> Option<Value> {
    let line = line.trim();
    if !line.starts_with('{') {
        return None;
    }
    let v: Value = serde_json::from_str(line).ok()?;
    let ts = v
        .get("__REALTIME_TIMESTAMP")
        .and_then(journal_value_text)
        .and_then(|s| s.parse::<i64>().ok())
        .and_then(|us| Utc.timestamp_micros(us).single())
        .map(fmt_ts);
    let priority = v
        .get("PRIORITY")
        .and_then(journal_value_text)
        .and_then(|s| s.parse::<u8>().ok());
    let message = v.get("MESSAGE").and_then(journal_value_text).unwrap_or_default();
    let pid = v.get("_PID").and_then(journal_value_text);
    Some(json!({"ts": ts, "priority": priority, "message": message, "pid": pid}))
}

fn build_journal_response(req: &JournalRequest, stdout: &[u8]) -> Value {
    let text = String::from_utf8_lossy(stdout);
    let mut fetched = 0usize;
    let mut items: Vec<Value> = Vec::new();
    for line in text.lines() {
        let Some(item) = map_journal_line(line) else { continue };
        fetched += 1;
        if let Some(re) = &req.grep {
            if !item["message"].as_str().is_some_and(|m| re.is_match(m)) {
                continue;
            }
        }
        items.push(item);
    }
    let matched = items.len();
    if items.len() > req.limit {
        items.drain(..items.len() - req.limit);
    }
    json!({
        "unit": req.unit,
        "matched": matched,
        "returned": items.len(),
        "truncated": matched > items.len() || fetched >= req.fetch_cap(),
        "items": items,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Timelike;
    use std::io::Write;

    fn now() -> Dt {
        DateTime::parse_from_rfc3339("2026-10-09T12:00:00Z").unwrap().with_timezone(&Utc)
    }

    fn cfg_from_yaml(extra: &str) -> HiveGuardConfig {
        let yaml = format!("node:\n  name: test\n{extra}");
        serde_yaml::from_str(&yaml).unwrap()
    }

    fn engine_for(path: &Path, format: &str, max_scan: u64, rotated: bool) -> LogEngine {
        let cfg = cfg_from_yaml(&format!(
            "agent:\n  max_scan_bytes: {max_scan}\n  include_rotated: {rotated}\n  log_sources:\n    - name: src\n      path: {}\n      format: {format}\n",
            path.display()
        ));
        LogEngine::from_config(&cfg)
    }

    fn nginx_line(ts: Dt, ip: &str, path: &str, status: u16, ua: &str) -> String {
        format!(
            "{ip} - - [{}] \"GET {path} HTTP/1.1\" {status} 123 \"-\" \"{ua}\"",
            ts.format("%d/%b/%Y:%H:%M:%S +0000")
        )
    }

    /// One line per second ending at `end`, `n` lines; ip/status vary.
    fn write_nginx(path: &Path, end: Dt, n: i64) {
        let mut f = std::io::BufWriter::new(File::create(path).unwrap());
        for i in 0..n {
            let ts = end - TimeDelta::seconds(n - 1 - i);
            let ip = format!("45.{}.{}.{}", i % 3, (i / 3) % 200, 1 + i % 7);
            let status = if i % 10 == 0 { 404 } else { 200 };
            let padding = "x".repeat(60);
            writeln!(f, "{}", nginx_line(ts, &ip, &format!("/p/{}/{padding}", i % 50), status, "curl/8")).unwrap();
        }
    }

    #[test]
    fn time_spec_parsing() {
        let n = now();
        assert_eq!(
            parse_time_spec("2026-10-09T05:00:00Z", n).unwrap(),
            DateTime::parse_from_rfc3339("2026-10-09T05:00:00Z").unwrap()
        );
        assert_eq!(parse_time_spec("15m", n).unwrap(), n - TimeDelta::minutes(15));
        assert_eq!(parse_time_spec("6h", n).unwrap(), n - TimeDelta::hours(6));
        assert_eq!(parse_time_spec("7d", n).unwrap(), n - TimeDelta::days(7));
        assert_eq!(parse_time_spec("90s", n).unwrap(), n - TimeDelta::seconds(90));
        assert_eq!(parse_time_spec("now", n).unwrap(), n);
        for g in ["garbage", "", "15x", "-5m", "h", "99999999999999d"] {
            assert!(parse_time_spec(g, n).is_err(), "{g}");
        }
    }

    #[test]
    fn source_discovery() {
        let cfg = cfg_from_yaml(
            r#"
plugins:
  - id: source.file.nginx
    name: nginx-main
    config: { path: /var/log/nginx/access.log }
  - id: source.file.nginx
    config: { path: /var/log/nginx/other.log }
  - id: source.file.ssh
    config: { path: /var/log/auth.log }
  - id: source.firewall
    config: {}
  - id: source.journald
    config: { units: [ssh, nginx] }
  - id: detector.port_scan
    config: {}
agent:
  journal_units: [hiveguard, ssh]
  log_sources:
    - name: nginx_error
      path: /var/log/nginx/error.log
"#,
        );
        let e = LogEngine::from_config(&cfg);
        assert_eq!(
            e.source_names(),
            vec![
                "nginx-main",
                "nginx",
                "ssh",
                "firewall",
                "nginx_error",
                "journal:ssh",
                "journal:nginx",
                "journal:hiveguard"
            ]
        );
        let fw = e.inner.files.iter().find(|f| f.name == "firewall").unwrap();
        assert_eq!(fw.path, PathBuf::from("/var/log/ufw.log"));
        assert_eq!(fw.format, Format::Ufw);
        let err = e.inner.files.iter().find(|f| f.name == "nginx_error").unwrap();
        assert_eq!(err.format, Format::Raw);
        let list = e.list_sources();
        let arr = list["sources"].as_array().unwrap();
        assert_eq!(arr.len(), 8);
        assert_eq!(arr[0]["kind"], "file");
        assert_eq!(arr[7]["kind"], "journal");
        assert_eq!(arr[7]["units"][0], "hiveguard");
    }

    #[tokio::test]
    async fn backward_scan_window_limit_and_order() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("access.log");
        let end = Utc::now();
        // ~40k lines * ~140 B ≈ 5.6 MiB, 1 line/s → 11 h of log.
        write_nginx(&path, end, 40_000);
        let size = std::fs::metadata(&path).unwrap().len();
        assert!(size > 4 << 20);
        let e = engine_for(&path, "nginx", 1 << 30, true);

        let r = e.query(json!({"source": "src", "since": "1h", "limit": 50})).await.unwrap();
        // boundary line may fall just outside (sub-second `now`)
        assert!((3600..=3601).contains(&r["matched"].as_u64().unwrap()));
        assert_eq!(r["returned"], 50);
        assert_eq!(r["truncated"], true);
        assert_eq!(r["scan_capped"], false);
        assert!(r["scanned_bytes"].as_u64().unwrap() < size);
        let items = r["items"].as_array().unwrap();
        let ts: Vec<&str> = items.iter().map(|i| i["ts"].as_str().unwrap()).collect();
        let mut sorted = ts.clone();
        sorted.sort();
        assert_eq!(ts, sorted, "chronological");
        assert_eq!(*ts.last().unwrap(), fmt_ts(end.with_nanosecond(0).unwrap()));
        assert_eq!(items[0]["fields"]["method"], "GET");
        assert!(items[0]["fields"]["status"].is_string());
        assert!(items[0]["ip"].as_str().unwrap().starts_with("45."));

        // Scan cap → truncated, window shows how far back we got.
        let e2 = engine_for(&path, "nginx", 1 << 20, true);
        let r = e2.query(json!({"source": "src", "since": "1d", "limit": 10})).await.unwrap();
        assert_eq!(r["scan_capped"], true);
        assert_eq!(r["truncated"], true);
        assert_eq!(r["scanned_bytes"], 1 << 20);
        let first = parse_time_spec(r["window"]["first_line_ts"].as_str().unwrap(), end).unwrap();
        assert!(first > end - TimeDelta::hours(3));

        // Unknown source / bad regex / bad time.
        assert!(matches!(e.query(json!({"source": "nope"})).await, Err(AgentError::NotFound(_))));
        assert!(matches!(
            e.query(json!({"source": "src", "grep": "("})).await,
            Err(AgentError::BadRequest(_))
        ));
        assert!(matches!(
            e.query(json!({"source": "src", "since": "yesterday"})).await,
            Err(AgentError::BadRequest(_))
        ));
        assert!(matches!(
            e.query(json!({"source": "src", "fields": {"user": "root"}})).await,
            Err(AgentError::BadRequest(_))
        ));
    }

    #[tokio::test]
    async fn rotated_continuation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("access.log");
        let end = Utc::now();
        let mut live = File::create(&path).unwrap();
        let mut rot = File::create(rotated_path(&path)).unwrap();
        for i in 0..30 {
            // rotated: 60..31 min ago, live: 30..1 min ago
            let t_rot = end - TimeDelta::minutes(60 - i);
            let t_live = end - TimeDelta::minutes(30 - i);
            writeln!(rot, "{}", nginx_line(t_rot, "45.1.1.1", "/old", 200, "a")).unwrap();
            writeln!(live, "{}", nginx_line(t_live, "45.1.1.2", "/new", 200, "a")).unwrap();
        }
        drop((live, rot));
        let e = engine_for(&path, "nginx", 1 << 30, true);
        let r = e.query(json!({"source": "src", "since": "45m", "limit": 1000})).await.unwrap();
        assert!((44..=45).contains(&r["matched"].as_u64().unwrap()));
        assert_eq!(r["window"]["files"].as_array().unwrap().len(), 2);
        let items = r["items"].as_array().unwrap();
        assert_eq!(items[0]["fields"]["path"], "/old");
        assert_eq!(items.last().unwrap()["fields"]["path"], "/new");

        let e = engine_for(&path, "nginx", 1 << 30, false);
        let r = e.query(json!({"source": "src", "since": "45m"})).await.unwrap();
        assert_eq!(r["matched"], 30);
        assert_eq!(e.list_sources()["sources"][0]["rotated_available"], true);
    }

    #[tokio::test]
    async fn query_filters() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("access.log");
        let end = Utc::now();
        let mut f = File::create(&path).unwrap();
        let lines = [
            ("45.10.0.1", "/wp-login.php", 403),
            ("45.10.0.2", "/xmlrpc.php", 404),
            ("45.10.1.3", "/wp-login.php", 200),
            ("11.0.0.1", "/index.html", 200),
            ("11.0.0.1", "/err", 502),
        ];
        for (i, (ip, p, s)) in lines.iter().enumerate() {
            let ts = end - TimeDelta::seconds(10 - i as i64);
            writeln!(f, "{}", nginx_line(ts, ip, p, *s, "python-requests/2.31")).unwrap();
        }
        writeln!(f, "garbage line mentioning 45.10.0.9 without timestamp").unwrap();
        drop(f);
        let e = engine_for(&path, "nginx", 1 << 30, false);
        let q = |v: Value| {
            let e = &e;
            async move { e.query(v).await.unwrap() }
        };
        let r = q(json!({"source": "src", "grep": "wp-login|xmlrpc"})).await;
        assert_eq!(r["matched"], 3);
        let r = q(json!({"source": "src", "ip": "45.10.0.0/24"})).await;
        // two parsed lines + the unparsed one (textual fallback)
        assert_eq!(r["matched"], 3);
        let r = q(json!({"source": "src", "ip": "45.10.0.0/24", "fields": {"status": "4xx"}})).await;
        assert_eq!(r["matched"], 2);
        let r = q(json!({"source": "src", "fields": {"status": "5xx"}})).await;
        assert_eq!(r["matched"], 1);
        assert_eq!(r["items"][0]["event_type"], "Http5xx");
        let r = q(json!({"source": "src", "fields": {"path": "^/wp-", "method": "get"}})).await;
        assert_eq!(r["matched"], 2);
        let r = q(json!({"source": "src", "ip": "11.0.0.1", "parse": false})).await;
        assert_eq!(r["matched"], 2);
        assert!(r["items"][0].get("fields").is_none());
        assert!(r["items"][0]["raw"].as_str().unwrap().starts_with("11.0.0.1"));
    }

    #[tokio::test]
    async fn stats_group_by_ip_and_buckets() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("access.log");
        let end = Utc::now();
        let mut f = File::create(&path).unwrap();
        for i in 0..100i64 {
            let ts = end - TimeDelta::minutes(100 - i);
            let (ip, p, s) = if i % 4 == 0 {
                ("11.2.3.4", "/index.html", 200)
            } else {
                ("203.0.113.5", if i % 2 == 0 { "/wp-login.php" } else { "/.env" }, 404)
            };
            writeln!(f, "{}", nginx_line(ts, ip, p, s, "python-requests/2.31")).unwrap();
        }
        drop(f);
        let e = engine_for(&path, "nginx", 1 << 30, false);
        let r = e
            .stats(json!({"source": "src", "since": "3h", "group_by": "ip", "buckets": "1h"}))
            .await
            .unwrap();
        assert_eq!(r["matched"], 100);
        assert_eq!(r["distinct"], 2);
        let g0 = &r["groups"][0];
        assert_eq!(g0["key"], "203.0.113.5");
        assert_eq!(g0["count"], 75);
        assert_eq!(g0["pct"], 75.0);
        assert_eq!(g0["extras"]["status_4xx"], 75);
        assert_eq!(g0["extras"]["status_5xx"], 0);
        assert_eq!(g0["extras"]["distinct_paths"], 2);
        assert_eq!(g0["extras"]["distinct_user_agents"], 1);
        assert_eq!(g0["extras"]["sample_user_agent"], "python-requests/2.31");
        let series = r["series"].as_array().unwrap();
        assert!(series.len() >= 3 && series.len() <= 5);
        let total: u64 = series.iter().map(|s| s["count"].as_u64().unwrap()).sum();
        assert_eq!(total, 100);

        let r = e
            .stats(json!({"source": "src", "since": "3h", "group_by": "ip24", "filter": {"fields": {"status": "4xx"}}}))
            .await
            .unwrap();
        assert_eq!(r["matched"], 75);
        assert_eq!(r["groups"][0]["key"], "203.0.113.0/24");

        let r = e.stats(json!({"source": "src", "since": "3h", "group_by": "path"})).await.unwrap();
        assert_eq!(r["groups"][0]["extras"]["distinct_ips"], 1);

        let r = e.stats(json!({"source": "src", "since": "3h", "group_by": "hour"})).await.unwrap();
        let keys: Vec<&str> = r["groups"].as_array().unwrap().iter().map(|g| g["key"].as_str().unwrap()).collect();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(keys, sorted);

        assert!(matches!(
            e.stats(json!({"source": "src", "group_by": "nonsense"})).await,
            Err(AgentError::BadRequest(_))
        ));

        let prof = e.ip_profile_logs("203.0.113.5".parse().unwrap(), Some("3h")).await.unwrap();
        assert_eq!(prof["src"]["count"], 75);
        assert_eq!(prof["src"]["status"]["404"], 75);
        assert_eq!(prof["src"]["top_paths"].as_array().unwrap().len(), 2);
        let prof = e.ip_profile_logs("45.0.0.1".parse().unwrap(), None).await.unwrap();
        assert_eq!(prof["src"], json!({"count": 0}));
    }

    #[test]
    fn ufw_parsing_both_timestamp_styles() {
        let n = now();
        let trad = "Oct  9 11:34:56 host kernel: [12345.678901] [UFW BLOCK] IN=eth0 OUT= MAC=00:11 SRC=203.0.113.5 DST=10.0.0.1 LEN=40 TOS=0x00 PREC=0x00 TTL=243 ID=54321 PROTO=TCP SPT=51000 DPT=23 WINDOW=1024 RES=0x00 SYN URGP=0";
        let rfc = "2026-10-05T13:13:54.213419+00:00 host kernel: [UFW BLOCK] SRC=203.0.113.9 DST=10.0.0.1 PROTO=UDP SPT=51234 DPT=5060 LEN=120";
        assert_eq!(fmt_ts(detect_ts(trad, n).unwrap()), "2026-10-09T11:34:56Z");
        assert_eq!(fmt_ts(detect_ts(rfc, n).unwrap()), "2026-10-05T13:13:54Z");
        let p = Parsers::new(Format::Ufw);
        let a = p.parse(trad);
        assert_eq!(a.ip, Some("203.0.113.5".parse().unwrap()));
        assert_eq!(a.get("port"), Some("23"));
        assert_eq!(a.get("proto"), Some("TCP"));
        assert_eq!(a.get("action"), Some("BLOCK"));
        assert_eq!(a.get("flags"), Some("SYN"));
        assert_eq!(a.get("dst"), Some("10.0.0.1"));
        assert_eq!(a.event_type.as_deref(), Some("PortAccess"));
        let b = p.parse(rfc);
        assert_eq!(b.get("proto"), Some("UDP"));
        assert_eq!(b.get("port"), Some("5060"));
        assert_eq!(b.get("spt"), Some("51234"));
    }

    #[test]
    fn traditional_syslog_year_inference() {
        let jan = DateTime::parse_from_rfc3339("2027-01-02T00:30:00Z").unwrap().with_timezone(&Utc);
        let t = detect_ts("Dec 31 23:00:00 host sshd[1]: x", jan).unwrap();
        assert_eq!(fmt_ts(t), "2026-12-31T23:00:00Z");
        let t = detect_ts("Jan  1 23:00:00 host sshd[1]: x", jan).unwrap();
        assert_eq!(fmt_ts(t), "2027-01-01T23:00:00Z");

        let p = Parsers::new(Format::Ssh);
        let line = "Oct  9 06:12:01 host sshd[123]: Failed password for invalid user admin from 45.9.8.7 port 50022 ssh2";
        let parsed = p.parse(line);
        assert_eq!(parsed.ip, Some("45.9.8.7".parse().unwrap()));
        assert_eq!(parsed.get("user"), Some("admin"));
        assert_eq!(parsed.get("invalid_user"), Some("true"));
        assert_eq!(parsed.get("src_port"), Some("50022"));
        assert_eq!(parsed.event_type.as_deref(), Some("AuthFailure"));
        assert_eq!(fmt_ts(detect_ts(line, now()).unwrap()), "2026-10-09T06:12:01Z");
        // Unparsed sshd line: best-effort IP, no event type.
        let other = p.parse("Oct  9 06:12:02 host sshd[123]: Connection closed by 45.9.8.7 port 50022 [preauth]");
        assert!(!other.structured);
        assert_eq!(other.ip, Some("45.9.8.7".parse().unwrap()));
        assert!(other.event_type.is_none());
    }

    #[test]
    fn misc_timestamp_and_ip_detection() {
        let n = now();
        assert_eq!(
            fmt_ts(detect_ts("2026-10-09 06:12:01 [error] 123#0: something", n).unwrap()),
            "2026-10-09T06:12:01Z"
        );
        assert_eq!(fmt_ts(detect_ts("2026/10/09 06:12:01 [error] x", n).unwrap()), "2026-10-09T06:12:01Z");
        assert!(detect_ts("no timestamp here", n).is_none());
        let ips: Vec<IpAddr> = extract_ips("std::io error from 2001:db8::1 and 45.1.2.3:443, MAC=00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd").collect();
        assert_eq!(ips, vec!["2001:db8::1".parse::<IpAddr>().unwrap(), "45.1.2.3".parse().unwrap()]);
        assert_eq!(ip_prefix_key("45.1.2.3".parse().unwrap(), 24, 64), "45.1.2.0/24");
        assert_eq!(ip_prefix_key("2001:db8:1:2:3::1".parse().unwrap(), 24, 64), "2001:db8:1:2::/64");
        assert_eq!(ip_prefix_key("45.1.2.3".parse().unwrap(), 16, 48), "45.1.0.0/16");
        let (h, prog, pid) = syslog_header("Oct  9 06:12:01 web1 CRON[4242]: (root) CMD (x)").unwrap();
        assert_eq!((h, prog, pid), ("web1", "CRON", Some("4242")));
    }

    #[tokio::test]
    async fn journal_smoke_real_journalctl() {
        // Works with or without journalctl on the build host.
        let e = LogEngine::from_config(&cfg_from_yaml(""));
        match e.journal(json!({"since": "10m", "limit": "3"})).await {
            Ok(v) => {
                assert_eq!(v["unit"], "hiveguard");
                assert!(v["items"].as_array().unwrap().len() <= 3);
            }
            Err(AgentError::Unavailable(_)) => {}
            Err(other) => panic!("unexpected {other}"),
        }
    }

    #[test]
    fn journal_json_mapping() {
        let l1 = r#"{"__REALTIME_TIMESTAMP":"1791547921000000","PRIORITY":"4","MESSAGE":"ban applied 45.1.2.3","_PID":"1234","_SYSTEMD_UNIT":"hiveguard.service"}"#;
        let v = map_journal_line(l1).unwrap();
        assert_eq!(v["priority"], 4);
        assert_eq!(v["message"], "ban applied 45.1.2.3");
        assert_eq!(v["pid"], "1234");
        let expected = Utc.timestamp_micros(1_791_547_921_000_000).single().unwrap();
        assert_eq!(v["ts"], fmt_ts(expected));
        let l2 = r#"{"__REALTIME_TIMESTAMP":"1791547922000000","PRIORITY":"6","MESSAGE":[104,105,255]}"#;
        let v = map_journal_line(l2).unwrap();
        assert_eq!(v["message"], "hi\u{fffd}");
        assert!(v["pid"].is_null());
        assert!(map_journal_line("-- No entries --").is_none());

        let req = JournalRequest {
            unit: "hiveguard".into(),
            since: now() - TimeDelta::hours(1),
            until: None,
            priority: Some(4),
            grep: Some(build_regex("ban").unwrap()),
            limit: 1,
        };
        let out = format!("{l1}\n{l2}\n{l1}\n");
        let r = build_journal_response(&req, out.as_bytes());
        assert_eq!(r["matched"], 2);
        assert_eq!(r["returned"], 1);
        assert_eq!(r["truncated"], true);
        let args = journal_args(&req);
        assert!(args.contains(&"2026-10-09 11:00:00 UTC".to_string()));
        assert!(args.windows(2).any(|w| w[0] == "-p" && w[1] == "4"));
        assert_eq!(parse_priority("warning"), Some(4));
        assert_eq!(parse_priority("9"), None);

        let e = LogEngine::from_config(&cfg_from_yaml(""));
        let inner = &e.inner;
        assert!(matches!(
            JournalRequest::from_params(inner, &json!({"unit": "sshd"}), now()),
            Err(AgentError::NotFound(_))
        ));
        assert!(JournalRequest::from_params(inner, &json!({"limit": "5"}), now()).is_ok());
    }
}
