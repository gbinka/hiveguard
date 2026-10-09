//! Daemon-side logic behind the `/api/agent/*` analysis surface
//! (`docs/AGENT_API.md`). Pure functions over snapshots so they are easy to
//! unit-test; `DaemonUiApi` only gathers the inputs (ban store, threat ring
//! buffer, metrics text, plugin entries) and delegates here. Log scanning
//! lives in `agent_logs.rs`.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
use ipnet::IpNet;
use serde_json::{json, Map, Value};
use tokio::sync::broadcast;

use hiveguard_core::config::{HiveGuardConfig, PluginConfigEntry};
use hiveguard_core::models::{BanRecord, BanSource};
use hiveguard_plugin_api::registry::{find_descriptor, iter_descriptors};
use hiveguard_plugin_api::{plugin_kind_name, AgentEvent, BanInfo, PluginError, ThreatInfo};

use crate::agent_logs::{parse_time_spec, AgentError, LogEngine};

/// Broadcast capacity for incremental agent events. A busy node emits a few
/// signals per second; a slow SSE consumer lags (and is told so) rather than
/// stalling the pipeline.
pub const AGENT_EVENT_CHANNEL_CAP: usize = 1024;

/// Everything `DaemonUiApi` needs to serve the agent surface.
pub struct AgentSupport {
    /// `plugins:` entries from the loaded config (effective detector config).
    pub plugin_entries: Vec<PluginConfigEntry>,
    /// Log scanning engine; `None` when the daemon was built without one.
    pub log_engine: Option<Arc<LogEngine>>,
    /// Incremental event fan-out (`/api/agent/stream`).
    pub events: broadcast::Sender<AgentEvent>,
    /// Subjects seen in the previous ban snapshot, for add/remove diffing.
    pub last_subjects: std::sync::Mutex<Option<HashSet<String>>>,
}

impl AgentSupport {
    pub fn new(plugin_entries: Vec<PluginConfigEntry>, log_engine: Option<LogEngine>) -> Self {
        let (events, _) = broadcast::channel(AGENT_EVENT_CHANNEL_CAP);
        Self {
            plugin_entries,
            log_engine: log_engine.map(Arc::new),
            events,
            last_subjects: std::sync::Mutex::new(None),
        }
    }

    /// Build a support object with no config knowledge (tests, minimal hosts).
    pub fn empty() -> Self {
        Self::new(Vec::new(), None)
    }

    /// Emit a detection signal to agent subscribers.
    pub fn emit_signal(&self, info: &ThreatInfo) {
        let _ = self.events.send(AgentEvent::Signal(info.clone()));
    }

    /// Diff the current ban snapshot against the previous one and emit
    /// `ban_added` / `ban_removed` events. The first call only primes the
    /// baseline (no burst of 1500 "added" events on startup).
    pub fn emit_ban_diff(&self, current: &[BanInfo]) {
        let now: HashSet<String> = current.iter().map(|b| b.subject.clone()).collect();
        let mut guard = self.last_subjects.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(prev) = guard.as_ref() {
            if self.events.receiver_count() > 0 {
                for b in current.iter().filter(|b| !prev.contains(&b.subject)) {
                    let _ = self.events.send(AgentEvent::BanAdded(b.clone()));
                }
                for subject in prev.difference(&now) {
                    let _ = self.events.send(AgentEvent::BanRemoved { subject: subject.clone() });
                }
            }
        }
        *guard = Some(now);
    }
}

/// Map an engine error onto the plugin error the REST layer understands
/// (`ConfigValidation` → 400, `NotFound` → 404, `Runtime` → 503).
pub fn to_plugin_error(e: AgentError) -> PluginError {
    match e {
        AgentError::BadRequest(m) => PluginError::ConfigValidation(m),
        AgentError::NotFound(m) => PluginError::NotFound(m),
        AgentError::Unavailable(m) | AgentError::Internal(m) => PluginError::Runtime(m),
    }
}

// ---------------------------------------------------------------------------
// Parameter helpers (query params arrive as a JSON object of strings; bodies
// may carry real JSON types — accept both).
// ---------------------------------------------------------------------------

fn p_str(params: &Value, key: &str) -> Option<String> {
    match params.get(key)? {
        Value::String(s) if !s.trim().is_empty() => Some(s.trim().to_string()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

fn p_bool(params: &Value, key: &str) -> Result<bool, AgentError> {
    match params.get(key) {
        None | Some(Value::Null) => Ok(false),
        Some(Value::Bool(b)) => Ok(*b),
        Some(Value::String(s)) => match s.to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => Ok(true),
            "0" | "false" | "no" | "off" | "" => Ok(false),
            other => Err(AgentError::BadRequest(format!("`{key}`: expected boolean, got `{other}`"))),
        },
        Some(other) => Err(AgentError::BadRequest(format!("`{key}`: expected boolean, got {other}"))),
    }
}

fn p_usize(params: &Value, key: &str, default: usize, max: usize) -> Result<usize, AgentError> {
    let v = match params.get(key) {
        None | Some(Value::Null) => return Ok(default),
        Some(Value::Number(n)) => n
            .as_u64()
            .ok_or_else(|| AgentError::BadRequest(format!("`{key}` must be a non-negative integer")))?,
        Some(Value::String(s)) => s
            .trim()
            .parse::<u64>()
            .map_err(|_| AgentError::BadRequest(format!("`{key}` must be a non-negative integer")))?,
        Some(other) => return Err(AgentError::BadRequest(format!("`{key}`: unexpected value {other}"))),
    };
    Ok((v as usize).min(max))
}

fn p_time(params: &Value, key: &str, now: DateTime<Utc>) -> Result<Option<DateTime<Utc>>, AgentError> {
    match p_str(params, key) {
        None => Ok(None),
        Some(s) => parse_time_spec(&s, now)
            .map(Some)
            .map_err(|e| AgentError::BadRequest(format!("`{key}`: {e}"))),
    }
}

fn rfc3339(t: &DateTime<Utc>) -> String {
    t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

fn parse_rfc3339(s: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s).ok().map(|t| t.with_timezone(&Utc))
}

fn source_kind(src: &BanSource) -> &'static str {
    match src {
        BanSource::LocalDetector(_) => "detector",
        BanSource::ClusterPeer(_) => "peer",
        BanSource::ManualAdmin => "admin",
    }
}

fn is_subnet(net: &IpNet) -> bool {
    net.prefix_len() < net.max_prefix_len()
}

fn sorted_counts(map: HashMap<String, u64>) -> Value {
    let mut v: Vec<(String, u64)> = map.into_iter().collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    Value::Object(v.into_iter().map(|(k, n)| (k, json!(n))).collect())
}

// ---------------------------------------------------------------------------
// Bans
// ---------------------------------------------------------------------------

/// `bans` block of the overview.
pub fn bans_overview(records: &[BanRecord], now: DateTime<Utc>) -> Value {
    let h1 = now - Duration::hours(1);
    let h24 = now - Duration::hours(24);
    let mut by_source: HashMap<String, u64> = HashMap::new();
    let mut by_detector: HashMap<String, u64> = HashMap::new();
    let (mut permanent, mut subnets, mut expiring_1h, mut created_1h, mut created_24h) = (0, 0, 0, 0, 0);
    for r in records {
        *by_source.entry(source_kind(&r.source).to_string()).or_default() += 1;
        if let BanSource::LocalDetector(d) = &r.source {
            *by_detector.entry(d.clone()).or_default() += 1;
        }
        match r.expires_at {
            None => permanent += 1,
            Some(e) if e <= now + Duration::hours(1) => expiring_1h += 1,
            _ => {}
        }
        if is_subnet(&r.subject) {
            subnets += 1;
        }
        if r.created_at >= h1 {
            created_1h += 1;
        }
        if r.created_at >= h24 {
            created_24h += 1;
        }
    }
    json!({
        "total": records.len(),
        "permanent": permanent,
        "subnets": subnets,
        "expiring_1h": expiring_1h,
        "created_1h": created_1h,
        "created_24h": created_24h,
        "by_source": sorted_counts(by_source),
        "by_detector": sorted_counts(by_detector),
    })
}

/// `GET /api/agent/bans` (§3.2).
pub fn filter_bans(
    records: Vec<BanRecord>,
    params: &Value,
    now: DateTime<Utc>,
    max_results: usize,
    to_info: impl Fn(BanRecord) -> BanInfo,
) -> Result<Value, AgentError> {
    let total = records.len();
    let source = p_str(params, "source").map(|s| s.to_ascii_lowercase());
    if let Some(s) = &source {
        if !matches!(s.as_str(), "detector" | "peer" | "admin") {
            return Err(AgentError::BadRequest(format!(
                "`source` must be one of detector|peer|admin, got `{s}`"
            )));
        }
    }
    let detector = p_str(params, "detector");
    let since = p_time(params, "since", now)?;
    let until = p_time(params, "until", now)?;
    let subnet_only = p_bool(params, "subnet_only")?;
    let permanent_only = p_bool(params, "permanent_only")?;
    let q = p_str(params, "q").map(|s| s.to_ascii_lowercase());
    let sort = p_str(params, "sort").unwrap_or_else(|| "created_at".into());
    if !matches!(sort.as_str(), "created_at" | "expires_at" | "severity" | "subject") {
        return Err(AgentError::BadRequest(format!(
            "`sort` must be one of created_at|expires_at|severity|subject, got `{sort}`"
        )));
    }
    let order = p_str(params, "order").unwrap_or_else(|| "desc".into()).to_ascii_lowercase();
    if !matches!(order.as_str(), "asc" | "desc") {
        return Err(AgentError::BadRequest("`order` must be asc|desc".into()));
    }
    let limit = p_usize(params, "limit", 100, max_results)?;
    let offset = p_usize(params, "offset", 0, usize::MAX)?;

    let mut matched: Vec<BanRecord> = records
        .into_iter()
        .filter(|r| source.as_deref().is_none_or(|s| source_kind(&r.source) == s))
        .filter(|r| {
            detector.as_deref().is_none_or(|d| matches!(&r.source, BanSource::LocalDetector(n) if n == d))
        })
        .filter(|r| since.is_none_or(|t| r.created_at >= t))
        .filter(|r| until.is_none_or(|t| r.created_at <= t))
        .filter(|r| !subnet_only || is_subnet(&r.subject))
        .filter(|r| !permanent_only || r.expires_at.is_none())
        .filter(|r| {
            q.as_deref().is_none_or(|q| {
                r.subject.to_string().contains(q) || r.reason.to_ascii_lowercase().contains(q)
            })
        })
        .collect();

    let mut by_source: HashMap<String, u64> = HashMap::new();
    let mut by_detector: HashMap<String, u64> = HashMap::new();
    for r in &matched {
        *by_source.entry(source_kind(&r.source).to_string()).or_default() += 1;
        if let BanSource::LocalDetector(d) = &r.source {
            *by_detector.entry(d.clone()).or_default() += 1;
        }
    }

    matched.sort_by(|a, b| {
        let ord = match sort.as_str() {
            "expires_at" => a.expires_at.cmp(&b.expires_at),
            "severity" => a.severity.cmp(&b.severity),
            "subject" => a.subject.cmp(&b.subject),
            _ => a.created_at.cmp(&b.created_at),
        };
        if order == "desc" { ord.reverse() } else { ord }
    });

    let matched_n = matched.len();
    let items: Vec<BanInfo> = matched.into_iter().skip(offset).take(limit).map(to_info).collect();
    Ok(json!({
        "total": total,
        "matched": matched_n,
        "limit": limit,
        "offset": offset,
        "by_source": sorted_counts(by_source),
        "by_detector": sorted_counts(by_detector),
        "items": items,
    }))
}

// ---------------------------------------------------------------------------
// Threats (recent detection signals)
// ---------------------------------------------------------------------------

struct IpAgg {
    count: u64,
    max_severity: u8,
    detectors: BTreeMap<String, u64>,
    first: Option<DateTime<Utc>>,
    last: Option<DateTime<Utc>>,
}

fn top_ips(threats: &[&ThreatInfo], top: usize) -> Value {
    let mut by_ip: HashMap<String, IpAgg> = HashMap::new();
    for t in threats {
        let ts = parse_rfc3339(&t.timestamp);
        let e = by_ip.entry(t.ip.clone()).or_insert(IpAgg {
            count: 0,
            max_severity: 0,
            detectors: BTreeMap::new(),
            first: None,
            last: None,
        });
        e.count += 1;
        e.max_severity = e.max_severity.max(t.severity);
        *e.detectors.entry(t.detector.clone()).or_default() += 1;
        if let Some(ts) = ts {
            e.first = Some(e.first.map_or(ts, |f| f.min(ts)));
            e.last = Some(e.last.map_or(ts, |l| l.max(ts)));
        }
    }
    let mut v: Vec<(String, IpAgg)> = by_ip.into_iter().collect();
    v.sort_by(|a, b| b.1.count.cmp(&a.1.count).then_with(|| b.1.max_severity.cmp(&a.1.max_severity)));
    Value::Array(
        v.into_iter()
            .take(top)
            .map(|(ip, a)| {
                json!({
                    "ip": ip,
                    "count": a.count,
                    "max_severity": a.max_severity,
                    "detectors": a.detectors.keys().cloned().collect::<Vec<_>>(),
                    "first_seen": a.first.as_ref().map(rfc3339),
                    "last_seen": a.last.as_ref().map(rfc3339),
                })
            })
            .collect(),
    )
}

fn by_detector(threats: &[&ThreatInfo]) -> Value {
    let mut m: HashMap<String, u64> = HashMap::new();
    for t in threats {
        *m.entry(t.detector.clone()).or_default() += 1;
    }
    sorted_counts(m)
}

/// `threats` block of the overview. `threats` is newest-first.
pub fn threats_overview(threats: &[ThreatInfo], now: DateTime<Utc>) -> Value {
    let h1 = now - Duration::hours(1);
    let h24 = now - Duration::hours(24);
    let all: Vec<&ThreatInfo> = threats.iter().collect();
    let last_1h = all.iter().filter(|t| parse_rfc3339(&t.timestamp).is_some_and(|ts| ts >= h1)).count();
    let last_24h = all.iter().filter(|t| parse_rfc3339(&t.timestamp).is_some_and(|ts| ts >= h24)).count();
    json!({
        "buffered": threats.len(),
        "last_1h": last_1h,
        "last_24h": last_24h,
        "by_detector": by_detector(&all),
        "top_ips": top_ips(&all, 10),
    })
}

/// `GET /api/agent/threats` (§3.3). `threats` is newest-first; the default
/// window is the last hour.
pub fn filter_threats(
    threats: &[ThreatInfo],
    params: &Value,
    now: DateTime<Utc>,
    max_results: usize,
) -> Result<Value, AgentError> {
    let since = p_time(params, "since", now)?.unwrap_or(now - Duration::hours(1));
    let until = p_time(params, "until", now)?;
    let detector = p_str(params, "detector");
    let ip_filter: Option<IpNet> = match p_str(params, "ip") {
        None => None,
        Some(s) => Some(
            s.parse::<IpNet>()
                .or_else(|_| s.parse::<IpAddr>().map(IpNet::from))
                .map_err(|_| AgentError::BadRequest(format!("`ip`: not an IP or CIDR: `{s}`")))?,
        ),
    };
    let min_severity = p_usize(params, "min_severity", 0, 255)? as u8;
    let limit = p_usize(params, "limit", 200, max_results)?;
    let offset = p_usize(params, "offset", 0, usize::MAX)?;

    let matched: Vec<&ThreatInfo> = threats
        .iter()
        .filter(|t| {
            let ts = parse_rfc3339(&t.timestamp);
            ts.is_none_or(|ts| ts >= since) && until.is_none_or(|u| ts.is_none_or(|ts| ts <= u))
        })
        .filter(|t| detector.as_deref().is_none_or(|d| t.detector == d))
        .filter(|t| {
            ip_filter.is_none_or(|net| t.ip.parse::<IpAddr>().is_ok_and(|ip| net.contains(&ip)))
        })
        .filter(|t| t.severity >= min_severity)
        .collect();

    let items: Vec<&ThreatInfo> = matched.iter().copied().skip(offset).take(limit).collect();
    Ok(json!({
        "buffered": threats.len(),
        "matched": matched.len(),
        "limit": limit,
        "offset": offset,
        "window": { "since": rfc3339(&since), "until": until.as_ref().map(rfc3339) },
        "by_detector": by_detector(&matched),
        "top_ips": top_ips(&matched, 25),
        "items": items,
    }))
}

// ---------------------------------------------------------------------------
// Metrics text → counters block
// ---------------------------------------------------------------------------

/// One sample from the OpenMetrics exposition.
#[derive(Debug, Clone, PartialEq)]
pub struct MetricSample {
    pub name: String,
    pub labels: BTreeMap<String, String>,
    pub value: f64,
}

/// Minimal OpenMetrics/Prometheus text parser (enough for our own registry
/// output: `name{a="b",c="d"} 12` / `name 12`, `# …` comments, `# EOF`).
pub fn parse_metrics_text(text: &str) -> Vec<MetricSample> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (head, rest) = match line.find('{') {
            Some(i) => {
                let close = match line[i..].find('}') {
                    Some(c) => i + c,
                    None => continue,
                };
                (&line[..i], Some((&line[i + 1..close], line[close + 1..].trim())))
            }
            None => (line, None),
        };
        let (name, labels, value_str) = match rest {
            Some((labels_raw, value_part)) => (head, parse_labels(labels_raw), value_part),
            None => {
                let mut it = head.split_whitespace();
                let n = match it.next() {
                    Some(n) => n,
                    None => continue,
                };
                (n, BTreeMap::new(), it.next().unwrap_or(""))
            }
        };
        let value_str = value_str.split_whitespace().next().unwrap_or("");
        let Ok(value) = value_str.parse::<f64>() else { continue };
        out.push(MetricSample { name: name.to_string(), labels, value });
    }
    out
}

fn parse_labels(raw: &str) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    let mut rest = raw;
    while let Some(eq) = rest.find('=') {
        let key = rest[..eq].trim().trim_start_matches(',').trim().to_string();
        let after = &rest[eq + 1..];
        let Some(after) = after.strip_prefix('"') else { break };
        // find closing unescaped quote
        let mut end = None;
        let mut escaped = false;
        for (i, ch) in after.char_indices() {
            match ch {
                '\\' if !escaped => escaped = true,
                '"' if !escaped => {
                    end = Some(i);
                    break;
                }
                _ => escaped = false,
            }
        }
        let Some(end) = end else { break };
        let val = after[..end].replace("\\\"", "\"").replace("\\\\", "\\");
        m.insert(key, val);
        rest = &after[end + 1..];
    }
    m
}

/// `counters` block of the overview from the rendered metrics text.
pub fn counters_from_metrics(text: &str) -> Value {
    let samples = parse_metrics_text(text);
    let mut events: BTreeMap<String, f64> = BTreeMap::new();
    let mut signals: BTreeMap<String, f64> = BTreeMap::new();
    let mut bans_created: BTreeMap<String, f64> = BTreeMap::new();
    let (mut bans_expired, mut peer_count, mut memory, mut whitelisted, mut active) = (0.0, 0.0, 0.0, 0.0, 0.0);
    for s in samples {
        match s.name.as_str() {
            "hiveguard_events_processed_total" => {
                if let Some(l) = s.labels.get("source") {
                    *events.entry(l.clone()).or_default() += s.value;
                }
            }
            "hiveguard_detection_signals_total" => {
                if let Some(l) = s.labels.get("detector") {
                    *signals.entry(l.clone()).or_default() += s.value;
                }
            }
            "hiveguard_bans_created_total" => {
                if let Some(l) = s.labels.get("detector") {
                    *bans_created.entry(l.clone()).or_default() += s.value;
                }
            }
            "hiveguard_bans_expired_total" => bans_expired = s.value,
            "hiveguard_peer_count" => peer_count = s.value,
            "hiveguard_memory_usage_bytes" => memory = s.value,
            "hiveguard_whitelisted_count" => whitelisted = s.value,
            "hiveguard_active_bans" => active = s.value,
            _ => {}
        }
    }
    let to_obj = |m: BTreeMap<String, f64>| -> Value {
        Value::Object(m.into_iter().map(|(k, v)| (k, json!(v as u64))).collect())
    };
    json!({
        "events_processed": to_obj(events),
        "detection_signals": to_obj(signals),
        "bans_created": to_obj(bans_created),
        "bans_expired": bans_expired as u64,
        "active_bans": active as u64,
        "peer_count": peer_count as i64,
        "memory_bytes": memory as u64,
        "whitelisted": whitelisted as u64,
    })
}

// ---------------------------------------------------------------------------
// Detectors + catalogue
// ---------------------------------------------------------------------------

/// Summarise a plugin's draft-07 `schema.json` into `{key: {type, default, description, enum}}`.
pub fn schema_summary(schema_json: &str) -> Map<String, Value> {
    let mut out = Map::new();
    let Ok(schema) = serde_json::from_str::<Value>(schema_json) else { return out };
    let Some(props) = schema.get("properties").and_then(Value::as_object) else { return out };
    let required: HashSet<String> = schema
        .get("required")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
        .unwrap_or_default();
    for (k, v) in props {
        let mut entry = Map::new();
        if let Some(t) = v.get("type") {
            entry.insert("type".into(), t.clone());
        }
        if let Some(d) = v.get("default") {
            entry.insert("default".into(), d.clone());
        }
        if let Some(d) = v.get("description") {
            entry.insert("description".into(), d.clone());
        }
        if let Some(e) = v.get("enum") {
            entry.insert("enum".into(), e.clone());
        }
        for bound in ["minimum", "maximum"] {
            if let Some(b) = v.get(bound) {
                entry.insert(bound.into(), b.clone());
            }
        }
        if required.contains(k) {
            entry.insert("required".into(), json!(true));
        }
        out.insert(k.clone(), Value::Object(entry));
    }
    out
}

/// Core detector name for a detector plugin id (`detector.ssh_bruteforce` →
/// `ssh_bruteforce`). Matches every built-in detector; `bans_created_total`
/// and `BanSource::LocalDetector` use this name.
pub fn core_detector_name(plugin_id: &str) -> &str {
    plugin_id.strip_prefix("detector.").unwrap_or(plugin_id)
}

/// `GET /api/agent/detectors` (§3.9).
pub fn detectors_view(entries: &[PluginConfigEntry], metrics_text: Option<&str>) -> Value {
    let counters = metrics_text.map(counters_from_metrics).unwrap_or(json!({}));
    let signals = counters.get("detection_signals").cloned().unwrap_or(json!({}));
    let bans = counters.get("bans_created").cloned().unwrap_or(json!({}));

    let mut detectors = Vec::new();
    let mut scoring = Value::Null;
    for e in entries {
        let desc = find_descriptor(&e.id);
        let manifest = desc.map(|d| (d.manifest)());
        if e.id.starts_with("detector.") {
            let core = core_detector_name(&e.id);
            detectors.push(json!({
                "id": e.id,
                "name": e.name,
                "detector_name": core,
                "description": manifest.as_ref().map(|m| m.description),
                "version": manifest.as_ref().map(|m| m.version),
                "linked": desc.is_some(),
                "optional": e.optional,
                "config": e.config,
                "schema": desc.map(|d| Value::Object(schema_summary(d.config_schema))).unwrap_or(json!({})),
                "signals_total": signals.get(&e.id).cloned().unwrap_or(json!(0)),
                "bans_total": bans.get(core).cloned().unwrap_or(json!(0)),
            }));
        } else if e.id.starts_with("scoring.") {
            // The daemon uses the LAST scoring entry.
            scoring = json!({
                "id": e.id,
                "config": e.config,
                "schema": desc.map(|d| Value::Object(schema_summary(d.config_schema))).unwrap_or(json!({})),
            });
        }
    }
    json!({ "detectors": detectors, "scoring": scoring })
}

/// `GET /api/agent/catalog` (§3.10): every descriptor linked into the binary.
pub fn catalog_view(entries: &[PluginConfigEntry], kind: Option<&str>) -> Result<Value, AgentError> {
    let kind_filter = kind.map(|k| k.trim().to_ascii_lowercase()).filter(|k| !k.is_empty());
    if let Some(k) = &kind_filter {
        let known = ["source", "detector", "enforcer", "notifier", "siemsink", "cti", "scoringengine", "uiserver"];
        if !known.contains(&k.as_str()) {
            return Err(AgentError::BadRequest(format!(
                "`kind` must be one of Source|Detector|Enforcer|Notifier|SiemSink|Cti|ScoringEngine|UiServer, got `{k}`"
            )));
        }
    }
    let mut instances: HashMap<&str, usize> = HashMap::new();
    for e in entries {
        *instances.entry(e.id.as_str()).or_default() += 1;
    }
    let mut plugins: Vec<Value> = iter_descriptors()
        .filter(|d| {
            kind_filter
                .as_deref()
                .is_none_or(|k| plugin_kind_name(d.kind).to_ascii_lowercase() == k)
        })
        .map(|d| {
            let m = (d.manifest)();
            let n = instances.get(d.id).copied().unwrap_or(0);
            let keys: Vec<Value> = schema_summary(d.config_schema)
                .into_iter()
                .map(|(name, mut v)| {
                    if let Value::Object(ref mut o) = v {
                        o.insert("name".into(), json!(name));
                    }
                    v
                })
                .collect();
            json!({
                "id": d.id,
                "kind": plugin_kind_name(d.kind),
                "version": m.version,
                "description": m.description,
                "docs_url": m.docs_url,
                "enabled": n > 0,
                "instances": n,
                "config_keys": keys,
            })
        })
        .collect();
    plugins.sort_by(|a, b| {
        a["kind"].as_str().cmp(&b["kind"].as_str()).then_with(|| a["id"].as_str().cmp(&b["id"].as_str()))
    });
    Ok(json!({ "plugins": plugins }))
}

// ---------------------------------------------------------------------------
// Config validation (dry run)
// ---------------------------------------------------------------------------

const KNOWN_TOP_LEVEL: &[&str] = &[
    "node", "whitelist", "sources", "detectors", "scoring", "trust", "enforcement", "persistence",
    "bots", "cti", "alerting", "siem", "sigma", "plugins", "agent",
];
const LEGACY_SECTIONS: &[&str] = &["sources", "detectors", "enforcement", "scoring"];
const PLUGIN_ENTRY_KEYS: &[&str] = &["id", "name", "config", "optional"];

/// `POST /api/agent/config/validate` (§3.11). Never writes anything.
pub fn validate_config(content: &str) -> Value {
    let mut errors: Vec<String> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();
    let mut plugin_ids: Vec<String> = Vec::new();

    // Structural warnings from the raw document (the typed parse ignores
    // unknown top-level keys silently — exactly what bites operators).
    match serde_yaml::from_str::<serde_yaml::Value>(content) {
        Ok(serde_yaml::Value::Mapping(map)) => {
            for (k, v) in &map {
                let Some(key) = k.as_str() else { continue };
                if !KNOWN_TOP_LEVEL.contains(&key) {
                    warnings.push(format!("unknown top-level key `{key}` is silently ignored by the daemon"));
                } else if LEGACY_SECTIONS.contains(&key) {
                    warnings.push(format!(
                        "legacy section `{key}` is validated but NOT used at runtime (runtime behaviour comes from `plugins:`)"
                    ));
                }
                if key == "plugins" {
                    if let serde_yaml::Value::Sequence(items) = v {
                        for (i, item) in items.iter().enumerate() {
                            if let serde_yaml::Value::Mapping(m) = item {
                                let id = m
                                    .get(serde_yaml::Value::String("id".into()))
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("?");
                                for (ek, _) in m {
                                    if let Some(ek) = ek.as_str() {
                                        if !PLUGIN_ENTRY_KEYS.contains(&ek) {
                                            warnings.push(format!(
                                                "plugins[{i}] (`{id}`): key `{ek}` is ignored (only id/name/config/optional are read; there is no `enabled:` — remove the entry to disable)"
                                            ));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        Ok(_) => errors.push("document root must be a mapping".into()),
        Err(e) => errors.push(format!("YAML parse error: {e}")),
    }

    if errors.is_empty() {
        match serde_yaml::from_str::<HiveGuardConfig>(content) {
            Err(e) => errors.push(format!("config parse error: {e}")),
            Ok(cfg) => {
                if let Err(e) = cfg.validate() {
                    errors.push(format!("validation: {e}"));
                }
                plugin_ids = cfg.plugins.iter().map(|p| p.id.clone()).collect();
                let has = |prefix: &str| cfg.plugins.iter().any(|p| p.id.starts_with(prefix));
                if cfg.plugins.is_empty() {
                    errors.push("no `plugins:` entries — the daemon exits without an enforcer and a scoring engine".into());
                } else {
                    if !has("enforcer.") {
                        errors.push("no `enforcer.*` plugin — the daemon refuses to start".into());
                    }
                    if !has("scoring.") {
                        errors.push("no `scoring.*` plugin — the daemon refuses to start".into());
                    }
                    if !has("source.") {
                        warnings.push("no `source.*` plugin — nothing will be detected".into());
                    }
                    if !has("detector.") {
                        warnings.push("no `detector.*` plugin — nothing will be detected".into());
                    }
                    if !has("ui.rest") {
                        warnings.push("no `ui.rest` plugin — this API will not be reachable after restart".into());
                    }
                }
                for p in &cfg.plugins {
                    if find_descriptor(&p.id).is_none() {
                        if p.optional {
                            warnings.push(format!("plugin `{}` is not linked into this binary (optional: skipped with a warning)", p.id));
                        } else {
                            errors.push(format!("plugin `{}` is not linked into this binary", p.id));
                        }
                    }
                }
                let loader = hiveguard_host::Loader::resolve_only(Arc::new(
                    hiveguard_plugin_api::secrets::SecretResolver::new(),
                ));
                if let Err(e) = loader.resolve(&crate::plugin_bridge::to_loader_config(&cfg)) {
                    errors.push(format!("plugin resolution: {e}"));
                }
            }
        }
    }

    json!({
        "valid": errors.is_empty(),
        "errors": errors,
        "warnings": warnings,
        "plugins": plugin_ids,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use hiveguard_core::models::BanSource;

    fn rec(subject: &str, src: BanSource, age_h: i64, ttl_h: Option<i64>) -> BanRecord {
        let now = Utc::now();
        BanRecord {
            subject: subject.parse().unwrap(),
            created_at: now - Duration::hours(age_h),
            expires_at: ttl_h.map(|h| now + Duration::hours(h)),
            severity: 150,
            reason: format!("test {subject}"),
            evidence_hash: [0u8; 32],
            source: src,
            geo_info: None,
        }
    }

    fn info(r: BanRecord) -> BanInfo {
        BanInfo {
            subject: r.subject.to_string(),
            severity: r.severity,
            reason: r.reason,
            expires_at: r.expires_at.map(|t| t.to_rfc3339()),
            source: match &r.source {
                BanSource::LocalDetector(d) => format!("detector:{d}"),
                BanSource::ClusterPeer(p) => format!("peer:{p}"),
                BanSource::ManualAdmin => "admin".into(),
            },
            created_at: Some(r.created_at.to_rfc3339()),
        }
    }

    fn sample() -> Vec<BanRecord> {
        vec![
            rec("11.0.0.1/32", BanSource::LocalDetector("ssh_bruteforce".into()), 0, Some(24)),
            rec("11.0.1.0/24", BanSource::LocalDetector("http_flood".into()), 2, Some(1)),
            rec("45.1.1.1/32", BanSource::ClusterPeer("node-b".into()), 30, None),
            rec("45.1.1.2/32", BanSource::ManualAdmin, 1, Some(72)),
        ]
    }

    #[test]
    fn overview_counts_sources_and_windows() {
        let v = bans_overview(&sample(), Utc::now());
        assert_eq!(v["total"], 4);
        assert_eq!(v["permanent"], 1);
        assert_eq!(v["subnets"], 1);
        assert_eq!(v["created_1h"], 1);
        assert_eq!(v["created_24h"], 3);
        assert_eq!(v["expiring_1h"], 1);
        assert_eq!(v["by_source"]["detector"], 2);
        assert_eq!(v["by_detector"]["http_flood"], 1);
    }

    #[test]
    fn filter_bans_by_source_detector_and_since() {
        let now = Utc::now();
        let v = filter_bans(sample(), &json!({"source": "detector"}), now, 5000, info).unwrap();
        assert_eq!(v["matched"], 2);
        let v = filter_bans(sample(), &json!({"detector": "http_flood"}), now, 5000, info).unwrap();
        assert_eq!(v["matched"], 1);
        assert_eq!(v["items"][0]["subject"], "11.0.1.0/24");
        let v = filter_bans(sample(), &json!({"since": "90m"}), now, 5000, info).unwrap();
        assert_eq!(v["matched"], 2);
        let v = filter_bans(sample(), &json!({"subnet_only": "true"}), now, 5000, info).unwrap();
        assert_eq!(v["matched"], 1);
        let v = filter_bans(sample(), &json!({"permanent_only": true}), now, 5000, info).unwrap();
        assert_eq!(v["items"][0]["source"], "peer:node-b");
        let v = filter_bans(sample(), &json!({"q": "45.1.1"}), now, 5000, info).unwrap();
        assert_eq!(v["matched"], 2);
    }

    #[test]
    fn filter_bans_sorts_and_paginates() {
        let now = Utc::now();
        let v = filter_bans(sample(), &json!({"sort": "created_at", "order": "asc", "limit": "2"}), now, 5000, info).unwrap();
        assert_eq!(v["items"].as_array().unwrap().len(), 2);
        assert_eq!(v["items"][0]["source"], "peer:node-b"); // oldest
        let v = filter_bans(sample(), &json!({"limit": 1, "offset": 3}), now, 5000, info).unwrap();
        assert_eq!(v["items"].as_array().unwrap().len(), 1);
        // cap by max_results
        let v = filter_bans(sample(), &json!({"limit": 999}), now, 3, info).unwrap();
        assert_eq!(v["limit"], 3);
    }

    #[test]
    fn filter_bans_rejects_bad_params() {
        let now = Utc::now();
        assert!(matches!(filter_bans(sample(), &json!({"source": "x"}), now, 10, info), Err(AgentError::BadRequest(_))));
        assert!(matches!(filter_bans(sample(), &json!({"since": "yesterday"}), now, 10, info), Err(AgentError::BadRequest(_))));
        assert!(matches!(filter_bans(sample(), &json!({"sort": "foo"}), now, 10, info), Err(AgentError::BadRequest(_))));
        assert!(matches!(filter_bans(sample(), &json!({"subnet_only": "maybe"}), now, 10, info), Err(AgentError::BadRequest(_))));
    }

    fn threat(ip: &str, det: &str, sev: u8, age_min: i64) -> ThreatInfo {
        ThreatInfo {
            ip: ip.into(),
            severity: sev,
            confidence: 80,
            detector: det.into(),
            reason: "r".into(),
            timestamp: (Utc::now() - Duration::minutes(age_min)).to_rfc3339(),
        }
    }

    #[test]
    fn threats_filter_and_top_ips() {
        let now = Utc::now();
        let t = vec![
            threat("11.0.0.1", "path_probe", 50, 1),
            threat("11.0.0.1", "path_probe", 90, 2),
            threat("11.0.0.2", "ssh_bruteforce", 120, 3),
            threat("45.0.0.9", "path_probe", 10, 600), // outside 1h default
        ];
        let v = filter_threats(&t, &json!({}), now, 5000).unwrap();
        assert_eq!(v["matched"], 3);
        assert_eq!(v["top_ips"][0]["ip"], "11.0.0.1");
        assert_eq!(v["top_ips"][0]["count"], 2);
        assert_eq!(v["top_ips"][0]["max_severity"], 90);
        assert_eq!(v["by_detector"]["path_probe"], 2);
        let v = filter_threats(&t, &json!({"since": "24h", "ip": "11.0.0.0/24"}), now, 5000).unwrap();
        assert_eq!(v["matched"], 3);
        let v = filter_threats(&t, &json!({"min_severity": "100"}), now, 5000).unwrap();
        assert_eq!(v["matched"], 1);
        let v = filter_threats(&t, &json!({"detector": "ssh_bruteforce", "limit": 1}), now, 5000).unwrap();
        assert_eq!(v["items"][0]["ip"], "11.0.0.2");
        assert!(filter_threats(&t, &json!({"ip": "nope"}), now, 10).is_err());
        let o = threats_overview(&t, now);
        assert_eq!(o["buffered"], 4);
        assert_eq!(o["last_1h"], 3);
        assert_eq!(o["last_24h"], 4);
    }

    #[test]
    fn metrics_text_is_parsed_into_counters() {
        let text = "# HELP x\n# TYPE hiveguard_events_processed counter\nhiveguard_events_processed_total{source=\"nginx\"} 1234\nhiveguard_events_processed_total{source=\"ssh\"} 5\nhiveguard_detection_signals_total{detector=\"detector.path_probe\"} 77\nhiveguard_bans_created_total{detector=\"path_probe\"} 7\nhiveguard_bans_expired_total 3\nhiveguard_active_bans 42\nhiveguard_peer_count 1\nhiveguard_memory_usage_bytes 85000000\nhiveguard_whitelisted_count 9\nhiveguard_event_processing_duration_seconds_bucket{source=\"nginx\",le=\"0.001\"} 10\n# EOF\n";
        let c = counters_from_metrics(text);
        assert_eq!(c["events_processed"]["nginx"], 1234);
        assert_eq!(c["events_processed"]["ssh"], 5);
        assert_eq!(c["detection_signals"]["detector.path_probe"], 77);
        assert_eq!(c["bans_created"]["path_probe"], 7);
        assert_eq!(c["bans_expired"], 3);
        assert_eq!(c["active_bans"], 42);
        assert_eq!(c["peer_count"], 1);
        assert_eq!(c["memory_bytes"], 85000000u64);
        assert_eq!(c["whitelisted"], 9);
        let s = parse_metrics_text("m{a=\"x\\\"y\",b=\"z\"} 1.5");
        assert_eq!(s[0].labels["a"], "x\"y");
        assert_eq!(s[0].labels["b"], "z");
        assert_eq!(s[0].value, 1.5);
    }

    #[test]
    fn schema_summary_extracts_defaults_and_required() {
        let schema = r#"{"type":"object","required":["path"],"properties":{"path":{"type":"string","description":"file"},"threshold":{"type":"integer","default":5,"minimum":1},"mode":{"enum":["a","b"]}}}"#;
        let s = schema_summary(schema);
        assert_eq!(s["path"]["required"], true);
        assert_eq!(s["threshold"]["default"], 5);
        assert_eq!(s["threshold"]["minimum"], 1);
        assert_eq!(s["mode"]["enum"][1], "b");
        assert!(schema_summary("not json").is_empty());
    }

    #[test]
    fn detectors_view_uses_entries_and_counters() {
        let entries = vec![
            PluginConfigEntry { id: "detector.ssh_bruteforce".into(), name: Some("ssh-main".into()), config: json!({"threshold": 10}), optional: false },
            PluginConfigEntry { id: "scoring.default".into(), name: None, config: json!({"ban_severity_threshold": 100}), optional: false },
            PluginConfigEntry { id: "source.file.nginx".into(), name: None, config: json!({"path": "/x"}), optional: false },
        ];
        let text = "hiveguard_detection_signals_total{detector=\"detector.ssh_bruteforce\"} 50\nhiveguard_bans_created_total{detector=\"ssh_bruteforce\"} 4\n";
        let v = detectors_view(&entries, Some(text));
        let d = &v["detectors"][0];
        assert_eq!(d["id"], "detector.ssh_bruteforce");
        assert_eq!(d["detector_name"], "ssh_bruteforce");
        assert_eq!(d["config"]["threshold"], 10);
        assert_eq!(d["signals_total"], 50);
        assert_eq!(d["bans_total"], 4);
        assert_eq!(v["scoring"]["id"], "scoring.default");
        assert_eq!(v["detectors"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn catalog_rejects_unknown_kind_and_filters() {
        assert!(matches!(catalog_view(&[], Some("bogus")), Err(AgentError::BadRequest(_))));
        // The test binary links the daemon's plugins via plugin_links.rs, so the
        // catalogue is non-empty and every entry has the requested kind.
        let v = catalog_view(&[], Some("detector")).unwrap();
        for p in v["plugins"].as_array().unwrap() {
            assert_eq!(p["kind"], "Detector");
            assert_eq!(p["enabled"], false);
        }
        let entries = vec![PluginConfigEntry { id: "detector.ssh_bruteforce".into(), name: None, config: json!({}), optional: false }];
        let v = catalog_view(&entries, None).unwrap();
        let ssh = v["plugins"].as_array().unwrap().iter().find(|p| p["id"] == "detector.ssh_bruteforce");
        if let Some(ssh) = ssh {
            assert_eq!(ssh["enabled"], true);
            assert_eq!(ssh["instances"], 1);
        }
    }

    #[test]
    fn validate_config_reports_structure_problems() {
        let v = validate_config("not: [valid");
        assert_eq!(v["valid"], false);
        assert!(v["errors"][0].as_str().unwrap().contains("YAML parse error"));

        let yaml = "node:\n  name: t\n  data_dir: /tmp/hg-validate-test\nplugins:\n  - id: enforcer.observe\n    enabled: true\n  - id: scoring.default\ndetectorss: {}\n";
        let v = validate_config(yaml);
        let warnings: Vec<String> = v["warnings"].as_array().unwrap().iter().map(|w| w.as_str().unwrap().to_string()).collect();
        assert!(warnings.iter().any(|w| w.contains("unknown top-level key `detectorss`")), "{warnings:?}");
        assert!(warnings.iter().any(|w| w.contains("`enabled` is ignored")), "{warnings:?}");
        assert_eq!(v["plugins"][0], "enforcer.observe");
    }

    #[test]
    fn ban_diff_emits_added_and_removed_after_baseline() {
        let support = AgentSupport::empty();
        let mut rx = support.events.subscribe();
        let a = info(rec("11.0.0.1/32", BanSource::ManualAdmin, 0, Some(1)));
        let b = info(rec("11.0.0.2/32", BanSource::ManualAdmin, 0, Some(1)));
        support.emit_ban_diff(&[a.clone()]); // baseline only
        assert!(rx.try_recv().is_err());
        support.emit_ban_diff(&[b.clone()]);
        let mut kinds: Vec<String> = Vec::new();
        while let Ok(ev) = rx.try_recv() {
            kinds.push(match ev {
                AgentEvent::BanAdded(x) => format!("added:{}", x.subject),
                AgentEvent::BanRemoved { subject } => format!("removed:{subject}"),
                AgentEvent::Signal(_) => "signal".into(),
            });
        }
        kinds.sort();
        assert_eq!(kinds, vec!["added:11.0.0.2/32", "removed:11.0.0.1/32"]);
    }
}
