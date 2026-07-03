//! Daemon-side implementation of [`hiveguard_plugin_api::UiApiHandle`].
//!
//! Bridges the live daemon state (ban store, enforcer, plugin registry,
//! recent threats) to UI plugins through the stable plugin API contract.
//! Each UI plugin (`ui-rest`, `ui-tui`, `ui-web`'s native side) receives an
//! `Arc<dyn UiApiHandle>` that points at one shared instance of this struct.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use ipnet::IpNet;
use serde_json::Value;
use tokio::sync::{broadcast, mpsc, Mutex, RwLock};
use tracing::{debug, info, warn};

use hiveguard_core::ban_store::BanStore;
use hiveguard_core::bot_registry::{BotPolicy, BotRegistry};
use hiveguard_core::config::{DetectorsConfig, HiveGuardConfig, KafkaTopicParser};
use hiveguard_core::models::{BanRecord, BanSource, DetectionSignal, NormalizedEvent};
use hiveguard_core::persistence::StateManager;
use hiveguard_enforce::Enforcer;
use hiveguard_plugin_api::{
    BanInfo, BanRequest, Fail2banBanInfo, Fail2banImportInfo, NodeInfo, PluginError, PluginInfo,
    PluginResult, SigmaLogSource, SigmaRuleDetail, SigmaRuleSummary, SigmaStatsInfo, StatsInfo,
    ThreatInfo, UiApiHandle, UiEvent,
};
use hiveguard_queue::deserializer::MessageRouter;
use hiveguard_sigma::{SharedSigmaRules, SharedSigmaStats, SigmaRule};

use crate::metrics::SharedMetrics;

/// Maximum number of recent threats kept in the ring buffer. Older entries
/// are evicted on insert.
const THREATS_BUFFER_CAP: usize = 500;

/// Broadcast channel buffer for [`UiEvent`]. Lagging subscribers drop frames.
const EVENT_CHANNEL_CAP: usize = 256;

/// Daemon-side state + adapter exposed to UI plugins via `Arc<dyn UiApiHandle>`.
pub struct DaemonUiApi {
    node_name: String,
    daemon_version: String,
    started_at: Instant,

    state: Arc<Mutex<StateManager>>,
    enforcer: Arc<Mutex<Box<dyn Enforcer>>>,

    /// Cached snapshot of loaded plugins. Plugins don't change at runtime, so
    /// this is built once at startup.
    plugins: Vec<PluginInfo>,

    /// Ring buffer of recent detection signals materialised into `ThreatInfo`.
    threats: RwLock<VecDeque<ThreatInfo>>,

    /// Broadcast channel for live updates. UI plugins call `subscribe()` to
    /// receive snapshot pushes.
    events: broadcast::Sender<UiEvent>,

    // --- Management surface backing state (REFACTOR 2.5) ---
    /// Path to the on-disk config file, for `get_config`/`put_config` and the
    /// detector editor. `None` disables config endpoints (503).
    config_path: Option<PathBuf>,
    /// Hot-swappable Sigma rule set. `None` → Sigma engine disabled (503).
    sigma_rules: Option<SharedSigmaRules>,
    /// Per-rule Sigma hit counters.
    sigma_stats: Option<SharedSigmaStats>,
    /// Prometheus metrics registry, for `render_metrics`. `None` → 503.
    metrics: Option<SharedMetrics>,
    /// Bot registry, for `list_bots`/`set_bot_policy`. `None` → 503.
    bot_registry: Option<Arc<Mutex<BotRegistry>>>,
    /// Pipeline ingest channel, for `ingest_logs`. `None` → 503.
    event_tx: Option<mpsc::Sender<NormalizedEvent>>,
}

impl DaemonUiApi {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        node_name: String,
        daemon_version: String,
        state: Arc<Mutex<StateManager>>,
        enforcer: Arc<Mutex<Box<dyn Enforcer>>>,
        plugins: Vec<PluginInfo>,
        config_path: Option<PathBuf>,
        sigma_rules: Option<SharedSigmaRules>,
        sigma_stats: Option<SharedSigmaStats>,
        metrics: Option<SharedMetrics>,
        bot_registry: Option<Arc<Mutex<BotRegistry>>>,
        event_tx: Option<mpsc::Sender<NormalizedEvent>>,
    ) -> Self {
        let (events, _) = broadcast::channel(EVENT_CHANNEL_CAP);
        Self {
            node_name,
            daemon_version,
            started_at: Instant::now(),
            state,
            enforcer,
            plugins,
            threats: RwLock::new(VecDeque::with_capacity(THREATS_BUFFER_CAP)),
            events,
            config_path,
            sigma_rules,
            sigma_stats,
            metrics,
            bot_registry,
            event_tx,
        }
    }

    /// Record a detection signal from the pipeline. Adds to the ring buffer
    /// (evicting the oldest entry when full) and does NOT broadcast — the
    /// pipeline calls `broadcast_threats` in batches to avoid per-signal
    /// wake-ups on every connected UI client.
    pub async fn record_signal(&self, signal: &DetectionSignal) {
        let info = signal_to_threat_info(signal);
        let mut buf = self.threats.write().await;
        if buf.len() >= THREATS_BUFFER_CAP {
            buf.pop_front();
        }
        buf.push_back(info);
    }

    /// Broadcast a fresh threats snapshot to all subscribers. Called by the
    /// pipeline after a batch of signals has been processed, or every ~1s.
    pub async fn broadcast_threats(&self) {
        let buf = self.threats.read().await;
        let snapshot: Vec<ThreatInfo> = buf.iter().rev().cloned().collect();
        drop(buf);
        let _ = self.events.send(UiEvent::ThreatsSnapshot(snapshot));
    }

    /// Broadcast a fresh bans snapshot. Called by the pipeline after each
    /// ban is added or removed.
    pub async fn broadcast_bans(&self) {
        let bans = self.list_bans_inner().await;
        let _ = self.events.send(UiEvent::BansSnapshot(bans));
    }

    /// Direct sender for tests / advanced wiring.
    pub fn event_sender(&self) -> broadcast::Sender<UiEvent> {
        self.events.clone()
    }

    async fn list_bans_inner(&self) -> Vec<BanInfo> {
        let state = self.state.lock().await;
        let store = state.ban_store();
        store
            .get_all_bans()
            .into_iter()
            .map(|r| ban_record_to_info(r.clone()))
            .collect()
    }

    /// Snapshot of per-rule Sigma hit counters (empty when stats are disabled).
    async fn sigma_hit_counts(&self) -> HashMap<String, u64> {
        match self.sigma_stats {
            Some(ref stats) => stats.lock().await.clone(),
            None => HashMap::new(),
        }
    }
}

#[async_trait]
impl UiApiHandle for DaemonUiApi {
    fn daemon_version(&self) -> String {
        self.daemon_version.clone()
    }

    fn node_name(&self) -> String {
        self.node_name.clone()
    }

    fn uptime(&self) -> Duration {
        self.started_at.elapsed()
    }

    async fn node_info(&self) -> NodeInfo {
        let total = {
            let state = self.state.lock().await;
            state.ban_store().get_all_bans().len()
        };
        NodeInfo {
            node_name: self.node_name.clone(),
            daemon_version: self.daemon_version.clone(),
            uptime_secs: self.started_at.elapsed().as_secs(),
            total_bans: total,
        }
    }

    async fn list_bans(&self) -> Vec<BanInfo> {
        self.list_bans_inner().await
    }

    async fn list_threats(&self) -> Vec<ThreatInfo> {
        let buf = self.threats.read().await;
        // Newest first.
        buf.iter().rev().cloned().collect()
    }

    async fn list_plugins(&self) -> Vec<PluginInfo> {
        self.plugins.clone()
    }

    async fn add_ban(&self, req: BanRequest) -> PluginResult<()> {
        let now = Utc::now();
        let expires_at = chrono::Duration::from_std(req.duration)
            .ok()
            .map(|d| now + d);
        let evidence_hash = [0u8; 32];
        let record = BanRecord {
            subject: req.subject,
            created_at: now,
            expires_at,
            severity: 200,
            reason: req.reason,
            evidence_hash,
            source: BanSource::ManualAdmin,
            geo_info: None,
        };

        {
            let mut state = self.state.lock().await;
            state.add_ban(record).map_err(|e| {
                hiveguard_plugin_api::PluginError::Runtime(format!(
                    "failed to persist manual ban: {e}"
                ))
            })?;
        }

        {
            let mut enf = self.enforcer.lock().await;
            if let Err(e) = enf.apply_ban(&req.subject).await {
                warn!(subject = %req.subject, error = %e, "enforcer rejected manual ban");
                // Don't undo persistence — operator intent was captured.
            }
        }

        // Broadcast new snapshot to live UIs.
        self.broadcast_bans().await;
        Ok(())
    }

    async fn remove_ban(&self, subject: IpNet) -> PluginResult<()> {
        let removed = {
            let mut state = self.state.lock().await;
            state.remove_ban(&subject).map_err(|e| {
                hiveguard_plugin_api::PluginError::Runtime(format!(
                    "failed to remove ban: {e}"
                ))
            })?
        };

        if !removed {
            return Err(hiveguard_plugin_api::PluginError::Runtime(format!(
                "ban {subject} not found"
            )));
        }

        {
            let mut enf = self.enforcer.lock().await;
            if let Err(e) = enf.remove_ban(&subject).await {
                warn!(subject = %subject, error = %e, "enforcer remove_ban failed");
            }
        }

        self.broadcast_bans().await;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Extended management surface — logic ported 1:1 from the legacy
    // `rest_api.rs` handlers (REFACTOR 2.5). Heavy lifting (config file I/O,
    // ArcSwap rule-set swaps, metrics render, MessageRouter) lives here; the
    // `ui.rest` plugin only does HTTP plumbing.
    // -----------------------------------------------------------------------

    async fn stats(&self) -> StatsInfo {
        let st = self.state.lock().await;
        StatsInfo {
            uptime_secs: self.started_at.elapsed().as_secs(),
            total_bans: st.ban_store().get_all_bans().len(),
            total_whitelisted: st.whitelist().entries().len(),
            version: self.daemon_version.clone(),
        }
    }

    async fn list_whitelist(&self) -> Vec<String> {
        let st = self.state.lock().await;
        st.whitelist().entries().iter().map(|n| n.to_string()).collect()
    }

    async fn add_whitelist(&self, cidr: IpNet) -> PluginResult<()> {
        let mut st = self.state.lock().await;
        st.add_whitelist(cidr)
            .map_err(|e| PluginError::Runtime(format!("failed to whitelist {cidr}: {e}")))?;
        info!(cidr = %cidr, "Whitelisted via ui.rest");
        Ok(())
    }

    async fn remove_whitelist(&self, cidr: IpNet) -> PluginResult<()> {
        let mut st = self.state.lock().await;
        st.remove_whitelist(&cidr)
            .map_err(|e| PluginError::Runtime(format!("failed to remove {cidr} from whitelist: {e}")))?;
        info!(cidr = %cidr, "Whitelist entry removed via ui.rest");
        Ok(())
    }

    async fn list_bots(&self) -> PluginResult<Value> {
        let Some(ref reg) = self.bot_registry else {
            return Err(PluginError::Runtime("Bot registry not enabled".to_string()));
        };
        let reg = reg.lock().await;
        Ok(serde_json::json!({ "bots": reg.all_stats() }))
    }

    async fn set_bot_policy(&self, name: String, policy: String) -> PluginResult<()> {
        let parsed = match policy.to_lowercase().as_str() {
            "allow" => BotPolicy::Allow,
            "block" => BotPolicy::Block,
            "monitor" => BotPolicy::Monitor,
            _ => {
                return Err(PluginError::ConfigValidation(
                    "Invalid policy. Use: allow, block, monitor".to_string(),
                ))
            }
        };
        let Some(ref reg) = self.bot_registry else {
            return Err(PluginError::Runtime("Bot registry not enabled".to_string()));
        };
        let mut reg = reg.lock().await;
        if reg.set_policy(&name, parsed) {
            info!(bot = %name, policy = ?parsed, "Bot policy updated via ui.rest");
            Ok(())
        } else {
            Err(PluginError::NotFound(format!("Bot '{name}' not found")))
        }
    }

    async fn get_config(&self) -> PluginResult<String> {
        let Some(ref path) = self.config_path else {
            return Err(PluginError::Runtime("Config path not available".to_string()));
        };
        std::fs::read_to_string(path).map_err(|e| PluginError::Runtime(e.to_string()))
    }

    async fn put_config(&self, content: String) -> PluginResult<()> {
        let Some(ref path) = self.config_path else {
            return Err(PluginError::Runtime("Config path not available".to_string()));
        };
        // Validate before persisting — reject malformed YAML (parity with legacy).
        serde_yaml::from_str::<HiveGuardConfig>(&content)
            .map_err(|e| PluginError::ConfigValidation(format!("YAML parse error: {e}")))?;
        std::fs::write(path, &content).map_err(|e| PluginError::Runtime(e.to_string()))?;
        Ok(())
    }

    async fn get_detectors(&self) -> PluginResult<Value> {
        let Some(ref path) = self.config_path else {
            return Err(PluginError::Runtime("Config path not available".to_string()));
        };
        let cfg = HiveGuardConfig::load(path)
            .map_err(|e| PluginError::Runtime(e.to_string()))?;
        serde_json::to_value(cfg.detectors).map_err(|e| PluginError::Runtime(e.to_string()))
    }

    async fn put_detectors(&self, detectors: Value) -> PluginResult<()> {
        let Some(ref path) = self.config_path else {
            return Err(PluginError::Runtime("Config path not available".to_string()));
        };
        // Validate the incoming block against the typed schema first.
        let new_detectors: DetectorsConfig = serde_json::from_value(detectors)
            .map_err(|e| PluginError::ConfigValidation(format!("Invalid detectors config: {e}")))?;
        // Splice the `detectors:` key into the existing YAML, preserving the rest.
        let current_yaml = std::fs::read_to_string(path)
            .map_err(|e| PluginError::Runtime(e.to_string()))?;
        let mut yaml_val: serde_yaml::Value = serde_yaml::from_str(&current_yaml)
            .map_err(|e| PluginError::Runtime(e.to_string()))?;
        let det_val = serde_yaml::to_value(&new_detectors)
            .map_err(|e| PluginError::Runtime(e.to_string()))?;
        yaml_val["detectors"] = det_val;
        let new_yaml = serde_yaml::to_string(&yaml_val)
            .map_err(|e| PluginError::Runtime(e.to_string()))?;
        std::fs::write(path, new_yaml).map_err(|e| PluginError::Runtime(e.to_string()))?;
        Ok(())
    }

    async fn list_sigma_rules(&self) -> PluginResult<Vec<SigmaRuleSummary>> {
        let Some(ref rules_arc) = self.sigma_rules else {
            return Err(PluginError::Runtime("Sigma rule engine is disabled".to_string()));
        };
        let hit_counts = self.sigma_hit_counts().await;
        let guard = rules_arc.load();
        Ok(guard.iter().map(|r| sigma_rule_summary(r, &hit_counts)).collect())
    }

    async fn get_sigma_rule(&self, id: String) -> PluginResult<Option<SigmaRuleDetail>> {
        let Some(ref rules_arc) = self.sigma_rules else {
            return Err(PluginError::Runtime("Sigma rule engine is disabled".to_string()));
        };
        let hit_counts = self.sigma_hit_counts().await;
        let guard = rules_arc.load();
        let detail = guard
            .iter()
            .find(|r| r.id.as_deref() == Some(&id) || r.title == id)
            .map(|r| sigma_rule_detail(r, &hit_counts));
        Ok(detail)
    }

    async fn sigma_stats(&self) -> PluginResult<SigmaStatsInfo> {
        let Some(ref rules_arc) = self.sigma_rules else {
            return Err(PluginError::Runtime("Sigma rule engine is disabled".to_string()));
        };
        let hit_counts = self.sigma_hit_counts().await;
        Ok(SigmaStatsInfo {
            total_rules: rules_arc.load().len(),
            hit_counts,
        })
    }

    async fn upsert_sigma_rule(&self, yaml: String) -> PluginResult<String> {
        let Some(ref rules_arc) = self.sigma_rules else {
            return Err(PluginError::Runtime("Sigma rule engine is disabled".to_string()));
        };
        let rule = SigmaRule::from_yaml(&yaml)
            .map_err(|e| PluginError::ConfigValidation(format!("Invalid Sigma rule: {e}")))?;
        let rule_id = rule.id.clone().unwrap_or_else(|| rule.title.clone());

        // Atomic swap: load → replace-by-id-or-append → store.
        let mut new_rules = rules_arc.load().as_ref().clone();
        if let Some(ref id) = rule.id {
            if let Some(i) = new_rules.iter().position(|r| r.id.as_deref() == Some(id.as_str())) {
                new_rules[i] = rule;
            } else {
                new_rules.push(rule);
            }
        } else {
            new_rules.push(rule);
        }
        rules_arc.store(Arc::new(new_rules));
        info!(rule = %rule_id, "Sigma rule upserted via ui.rest");
        Ok(rule_id)
    }

    async fn delete_sigma_rule(&self, id: String) -> PluginResult<()> {
        let Some(ref rules_arc) = self.sigma_rules else {
            return Err(PluginError::Runtime("Sigma rule engine is disabled".to_string()));
        };
        let old_rules = rules_arc.load();
        let new_rules: Vec<SigmaRule> = old_rules
            .iter()
            .filter(|r| r.id.as_deref() != Some(&id) && r.title != id)
            .cloned()
            .collect();
        if new_rules.len() == old_rules.len() {
            return Err(PluginError::NotFound(format!("Rule '{id}' not found")));
        }
        rules_arc.store(Arc::new(new_rules));
        info!(rule = %id, "Sigma rule deleted via ui.rest");
        Ok(())
    }

    async fn fail2ban_preview(
        &self,
        db: Option<String>,
        jail: Option<String>,
    ) -> PluginResult<Vec<Fail2banBanInfo>> {
        let db = db.unwrap_or_else(|| DEFAULT_F2B_DB.to_string());
        let all_bans = crate::fail2ban_import::read_active_bans(std::path::Path::new(&db))
            .map_err(PluginError::Runtime)?;
        let jail_filter = jail.as_deref();
        Ok(all_bans
            .into_iter()
            .filter(|b| jail_filter.map_or(true, |j| b.jail == j))
            .map(|b| Fail2banBanInfo {
                jail: b.jail,
                ip: b.ip,
                banned_at: b.banned_at.to_rfc3339(),
                expires_at: b.expires_at.map(|t| t.to_rfc3339()),
            })
            .collect())
    }

    async fn fail2ban_import(
        &self,
        db: Option<String>,
        jail: Option<String>,
    ) -> PluginResult<Fail2banImportInfo> {
        let db = db.unwrap_or_else(|| DEFAULT_F2B_DB.to_string());
        let all_bans = crate::fail2ban_import::read_active_bans(std::path::Path::new(&db))
            .map_err(PluginError::Runtime)?;
        let bans: Vec<_> = match jail {
            Some(ref j) => all_bans.into_iter().filter(|b| &b.jail == j).collect(),
            None => all_bans,
        };

        let mut info = Fail2banImportInfo::default();
        let mut st = self.state.lock().await;
        for ban in bans {
            let ip_addr: IpAddr = match ban.ip.parse() {
                Ok(addr) => addr,
                Err(e) => {
                    info.errors.push(format!("{}: invalid IP: {e}", ban.ip));
                    info.skipped += 1;
                    continue;
                }
            };
            if st.ban_store().is_banned(&ip_addr).is_some() {
                info.skipped += 1;
                continue;
            }
            let record = BanRecord {
                subject: IpNet::from(ip_addr),
                created_at: ban.banned_at,
                expires_at: ban.expires_at,
                severity: 200,
                reason: format!("imported from fail2ban (jail: {})", ban.jail),
                evidence_hash: [0u8; 32],
                source: BanSource::ManualAdmin,
                geo_info: None,
            };
            match st.add_ban(record) {
                Ok(()) => {
                    info!(ip = %ip_addr, jail = %ban.jail, "Imported fail2ban ban via ui.rest");
                    info.imported += 1;
                }
                Err(e) => {
                    info.errors.push(format!("{}: {e}", ban.ip));
                    info.skipped += 1;
                }
            }
        }
        Ok(info)
    }

    async fn render_metrics(&self) -> Option<String> {
        let m = self.metrics.as_ref()?;
        m.update_memory_usage();
        // Refresh gauges from live state without blocking the metrics path.
        if let Ok(st) = self.state.try_lock() {
            m.active_bans.set(st.ban_store().get_all_bans().len() as i64);
            m.whitelisted_count.set(st.whitelist().entries().len() as i64);
        }
        let _ = &m.peer_count; // set elsewhere when the cluster module is active
        Some(m.render())
    }

    async fn ingest_logs(&self, lines: Vec<String>, parser: String) -> PluginResult<(usize, usize)> {
        let Some(ref tx) = self.event_tx else {
            return Err(PluginError::Runtime("Event pipeline not available".to_string()));
        };
        // Map the wire parser name to the queue's parser enum. Unknown names
        // (and "auto") fall back to `Auto`, matching the http_push default.
        let parser = match parser.to_lowercase().as_str() {
            "ssh" => KafkaTopicParser::Ssh,
            "nginx" => KafkaTopicParser::Nginx,
            "postfix" => KafkaTopicParser::Postfix,
            _ => KafkaTopicParser::Auto,
        };
        let router = MessageRouter::new();
        let mut accepted = 0usize;
        let mut rejected = 0usize;
        for line in &lines {
            if let Some(event) = router.route_line(line, &parser, "http_push") {
                if tx.send(event).await.is_ok() {
                    accepted += 1;
                } else {
                    rejected += 1;
                }
            } else {
                rejected += 1;
            }
        }
        Ok((accepted, rejected))
    }

    fn subscribe(&self) -> broadcast::Receiver<UiEvent> {
        self.events.subscribe()
    }
}

/// Default fail2ban SQLite database path (matches legacy `rest_api.rs`).
const DEFAULT_F2B_DB: &str = "/var/lib/fail2ban/fail2ban.sqlite3";

// ---------------------------------------------------------------------------
// Conversion helpers
// ---------------------------------------------------------------------------

/// Build a [`SigmaRuleSummary`] from a parsed rule + the hit-count snapshot.
/// The hit-count key is the rule id, falling back to the title.
fn sigma_rule_summary(r: &SigmaRule, hit_counts: &HashMap<String, u64>) -> SigmaRuleSummary {
    let key = r.id.clone().unwrap_or_else(|| r.title.clone());
    SigmaRuleSummary {
        id: r.id.clone(),
        title: r.title.clone(),
        status: format!("{:?}", r.status).to_lowercase(),
        level: format!("{:?}", r.level).to_lowercase(),
        tags: r.tags.clone(),
        hit_count: hit_counts.get(&key).copied().unwrap_or(0),
    }
}

/// Build a [`SigmaRuleDetail`] from a parsed rule + the hit-count snapshot.
fn sigma_rule_detail(r: &SigmaRule, hit_counts: &HashMap<String, u64>) -> SigmaRuleDetail {
    let key = r.id.clone().unwrap_or_else(|| r.title.clone());
    SigmaRuleDetail {
        id: r.id.clone(),
        title: r.title.clone(),
        status: format!("{:?}", r.status).to_lowercase(),
        level: format!("{:?}", r.level).to_lowercase(),
        description: r.description.clone(),
        author: r.author.clone(),
        date: r.date.clone(),
        tags: r.tags.clone(),
        references: r.references.clone(),
        logsource: SigmaLogSource {
            category: r.logsource.category.clone(),
            product: r.logsource.product.clone(),
            service: r.logsource.service.clone(),
        },
        condition: r.detection.condition.clone(),
        hit_count: hit_counts.get(&key).copied().unwrap_or(0),
    }
}

fn ban_record_to_info(record: BanRecord) -> BanInfo {
    let source = match &record.source {
        BanSource::LocalDetector(name) => format!("detector:{name}"),
        BanSource::ClusterPeer(node) => format!("peer:{node}"),
        BanSource::ManualAdmin => "admin".to_string(),
    };
    BanInfo {
        subject: record.subject.to_string(),
        severity: record.severity,
        reason: record.reason,
        expires_at: record.expires_at.map(|t: DateTime<Utc>| t.to_rfc3339()),
        source,
    }
}

fn signal_to_threat_info(signal: &DetectionSignal) -> ThreatInfo {
    ThreatInfo {
        ip: signal.source_ip.addr().to_string(),
        severity: signal.severity,
        confidence: (signal.confidence.clamp(0.0, 1.0) * 100.0) as u8,
        detector: signal.detector_name.clone(),
        reason: signal.reason.clone(),
        timestamp: signal.timestamp.to_rfc3339(),
    }
}

// ---------------------------------------------------------------------------
// Sniffer hook — pipeline calls this once per signal.
// ---------------------------------------------------------------------------

/// Lightweight handle the pipeline can clone and feed signals into without
/// holding the full `DaemonUiApi` lifecycle. Built by `DaemonUiApi::sniffer`.
#[derive(Clone)]
pub struct UiSniffer {
    inner: Arc<DaemonUiApi>,
}

impl UiSniffer {
    pub fn from_arc(api: Arc<DaemonUiApi>) -> Self {
        Self { inner: api }
    }

    /// Non-blocking record (spawns a task — never blocks the hot path).
    pub fn observe(&self, signal: DetectionSignal) {
        let api = self.inner.clone();
        tokio::spawn(async move {
            api.record_signal(&signal).await;
        });
    }

    /// Trigger a snapshot broadcast (debounce in caller).
    pub fn notify_bans_changed(&self) {
        let api = self.inner.clone();
        tokio::spawn(async move {
            api.broadcast_bans().await;
        });
    }

    /// Trigger a threats snapshot broadcast.
    pub fn notify_threats_changed(&self) {
        let api = self.inner.clone();
        tokio::spawn(async move {
            api.broadcast_threats().await;
        });
    }
}

// ---------------------------------------------------------------------------
// Convert PluginDescriptor → PluginInfo at startup.
// ---------------------------------------------------------------------------

/// Build the initial plugin snapshot from the host loader output. Health
/// defaults to "Healthy" for everything that successfully loaded — a future
/// health-probe loop can update this on the side.
pub fn plugin_infos_from_loaded(
    loaded: &hiveguard_host::loader::LoadedPlugins,
) -> Vec<PluginInfo> {
    use hiveguard_plugin_api::plugin_kind_name;
    use hiveguard_plugin_api::traits::Plugin;

    let mut out = Vec::new();

    for p in &loaded.log_sources {
        let m = p.manifest();
        out.push(PluginInfo {
            id: m.id.to_string(),
            kind: plugin_kind_name(m.kind).to_string(),
            health: "Healthy".to_string(),
            version: m.version.to_string(),
        });
    }
    for p in &loaded.detectors {
        let m = p.manifest();
        out.push(PluginInfo {
            id: m.id.to_string(),
            kind: plugin_kind_name(m.kind).to_string(),
            health: "Healthy".to_string(),
            version: m.version.to_string(),
        });
    }
    for p in &loaded.enforcers {
        let m = p.manifest();
        out.push(PluginInfo {
            id: m.id.to_string(),
            kind: plugin_kind_name(m.kind).to_string(),
            health: "Healthy".to_string(),
            version: m.version.to_string(),
        });
    }
    for p in &loaded.notifiers {
        let m = p.manifest();
        out.push(PluginInfo {
            id: m.id.to_string(),
            kind: plugin_kind_name(m.kind).to_string(),
            health: "Healthy".to_string(),
            version: m.version.to_string(),
        });
    }
    for p in &loaded.cti_providers {
        let m = p.manifest();
        out.push(PluginInfo {
            id: m.id.to_string(),
            kind: plugin_kind_name(m.kind).to_string(),
            health: "Healthy".to_string(),
            version: m.version.to_string(),
        });
    }
    for p in &loaded.siem_sinks {
        let m = p.manifest();
        out.push(PluginInfo {
            id: m.id.to_string(),
            kind: plugin_kind_name(m.kind).to_string(),
            health: "Healthy".to_string(),
            version: m.version.to_string(),
        });
    }
    for p in &loaded.scoring_engines {
        let m = p.manifest();
        out.push(PluginInfo {
            id: m.id.to_string(),
            kind: plugin_kind_name(m.kind).to_string(),
            health: "Healthy".to_string(),
            version: m.version.to_string(),
        });
    }
    for p in &loaded.ui_servers {
        let m = p.manifest();
        out.push(PluginInfo {
            id: m.id.to_string(),
            kind: plugin_kind_name(m.kind).to_string(),
            health: "Healthy".to_string(),
            version: m.version.to_string(),
        });
    }
    let _ = (debug!("UI plugin snapshot built: {} entries", out.len()),);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use hiveguard_core::models::{Action, BanSource};

    fn make_signal() -> DetectionSignal {
        DetectionSignal {
            source_ip: "1.2.3.4/32".parse().unwrap(),
            severity: 150,
            confidence: 0.9,
            reason: "test".into(),
            evidence_hash: [0u8; 32],
            suggested_action: Action::Ban(Duration::from_secs(60)),
            detector_name: "ssh_bruteforce".into(),
            timestamp: Utc::now(),
        }
    }

    #[test]
    fn ban_record_conversion_handles_all_sources() {
        let local = BanRecord {
            subject: "1.2.3.4/32".parse().unwrap(),
            created_at: Utc::now(),
            expires_at: Some(Utc::now() + chrono::Duration::hours(1)),
            severity: 200,
            reason: "test".into(),
            evidence_hash: [0u8; 32],
            source: BanSource::LocalDetector("path_probe".into()),
            geo_info: None,
        };
        assert_eq!(ban_record_to_info(local).source, "detector:path_probe");

        let peer = BanRecord {
            subject: "5.6.7.8/32".parse().unwrap(),
            created_at: Utc::now(),
            expires_at: None,
            severity: 250,
            reason: "test".into(),
            evidence_hash: [0u8; 32],
            source: BanSource::ClusterPeer("node-2".into()),
            geo_info: None,
        };
        let info = ban_record_to_info(peer);
        assert_eq!(info.source, "peer:node-2");
        assert!(info.expires_at.is_none());

        let admin = BanRecord {
            subject: "9.10.11.12/32".parse().unwrap(),
            created_at: Utc::now(),
            expires_at: Some(Utc::now()),
            severity: 100,
            reason: "test".into(),
            evidence_hash: [0u8; 32],
            source: BanSource::ManualAdmin,
            geo_info: None,
        };
        assert_eq!(ban_record_to_info(admin).source, "admin");
    }

    #[test]
    fn signal_conversion_clamps_confidence() {
        let mut s = make_signal();
        s.confidence = 1.5;
        assert_eq!(signal_to_threat_info(&s).confidence, 100);

        s.confidence = -0.3;
        assert_eq!(signal_to_threat_info(&s).confidence, 0);

        s.confidence = 0.5;
        assert_eq!(signal_to_threat_info(&s).confidence, 50);
    }
}
