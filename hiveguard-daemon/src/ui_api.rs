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
use hiveguard_core::config::{HiveGuardConfig, KafkaTopicParser};
use hiveguard_core::models::{BanRecord, BanSource, DetectionSignal, NormalizedEvent};
use hiveguard_core::persistence::StateManager;
use hiveguard_enforce::Enforcer;
use hiveguard_plugin_api::{
    AgentEvent, BanInfo, BanRequest, Fail2banBanInfo, Fail2banImportInfo, NodeInfo, PluginError,
    PluginInfo, PluginResult, SigmaLogSource, SigmaRuleDetail, SigmaRuleSummary, SigmaStatsInfo,
    StatsInfo, ThreatInfo, UiApiHandle, UiEvent,
};
use hiveguard_queue::deserializer::MessageRouter;
use hiveguard_sigma::{SharedSigmaRules, SharedSigmaStats, SigmaRule};

use crate::agent_api::{self, AgentSupport};
use crate::metrics::SharedMetrics;

/// Replace configuration atomically without widening its existing permissions.
fn atomic_config_write(path: &std::path::Path, content: &str) -> PluginResult<()> {
    use std::io::Write;
    let write = || -> std::io::Result<()> {
        let target = std::fs::canonicalize(path)?;
        let metadata = std::fs::metadata(&target)?;
        // Atomic rename only needs directory write permission; explicitly respect
        // a managed read-only config file instead of bypassing its permissions.
        let _ = std::fs::OpenOptions::new().write(true).open(&target)?;
        let parent = target.parent().ok_or_else(|| std::io::Error::other("config has no parent"))?;
        let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
        temporary.as_file().set_permissions(metadata.permissions())?;
        temporary.write_all(content.as_bytes())?;
        temporary.as_file().sync_all()?;
        temporary.persist(&target).map_err(|e| e.error)?;
        std::fs::File::open(parent)?.sync_all()?;
        Ok(())
    };
    write().map_err(|e| PluginError::Runtime(format!("config not saved: {e}")))
}

/// Maximum number of recent threats kept in the ring buffer. Older entries
/// are evicted on insert.
const THREATS_BUFFER_CAP: usize = 500;

/// Broadcast channel buffer for [`UiEvent`]. Lagging subscribers drop frames.
const EVENT_CHANNEL_CAP: usize = 256;

/// Daemon-side state + adapter exposed to UI plugins via `Arc<dyn UiApiHandle>`.
pub struct DaemonUiApi {
    source_status: Option<crate::plugin_supervisor::SourceStatus>,
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

    /// Agent analysis surface (`/api/agent/*`): plugin entries, log engine,
    /// incremental event fan-out. See `agent_api.rs` / `agent_logs.rs`.
    agent: AgentSupport,
    /// Hard cap on items per agent response (`agent.max_results`).
    agent_max_results: usize,
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
            source_status: None,
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
            agent: AgentSupport::empty(),
            agent_max_results: 5000,
        }
    }

    /// Attach the agent analysis surface: the config's `plugins:` entries
    /// (effective detector configuration) and a log engine built from the
    /// same config.
    pub fn with_agent(mut self, support: AgentSupport, max_results: usize) -> Self {
        self.agent = support;
        self.agent_max_results = max_results.max(1);
        self
    }

    /// Re-diff the ban snapshot and emit `ban_added`/`ban_removed` agent
    /// events. Called after every ban change and periodically (expiry has no
    /// hook of its own).
    pub async fn sync_agent_ban_events(&self) {
        if self.agent.events.receiver_count() == 0 {
            // Still prime the baseline so the first subscriber does not get a
            // burst of historical "added" events.
            let bans = self.list_bans_inner().await;
            self.agent.emit_ban_diff(&bans);
            return;
        }
        let bans = self.list_bans_inner().await;
        self.agent.emit_ban_diff(&bans);
    }

    pub fn with_source_status(mut self, status: crate::plugin_supervisor::SourceStatus) -> Self {
        self.source_status = Some(status);
        self
    }

    /// Record a detection signal from the pipeline. Adds to the ring buffer
    /// (evicting the oldest entry when full) and does NOT broadcast — the
    /// pipeline calls `broadcast_threats` in batches to avoid per-signal
    /// wake-ups on every connected UI client.
    pub async fn record_signal(&self, signal: &DetectionSignal) {
        let info = signal_to_threat_info(signal);
        self.agent.emit_signal(&info);
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
        self.agent.emit_ban_diff(&bans);
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
        let mut plugins = self.plugins.clone();
        if let Some(status) = &self.source_status {
            if let Ok(sources) = status.read() {
                for plugin in &mut plugins {
                    let states: Vec<_> = sources.iter().filter(|(id, _)| id == &plugin.id).collect();
                    if !states.is_empty() {
                        plugin.health = states.iter().find(|(_, state)| state != "Running")
                            .unwrap_or(&states[0]).1.clone();
                    }
                }
            }
        }
        plugins
    }

    async fn add_ban(&self, mut req: BanRequest) -> PluginResult<()> {
        req.subject = req.subject.trunc();
        let now = Utc::now();
        let duration = chrono::Duration::from_std(req.duration)
            .map_err(|_| PluginError::ConfigValidation("ban duration out of range".into()))?;
        if duration <= chrono::Duration::zero() {
            return Err(PluginError::ConfigValidation("ban duration must be positive".into()));
        }
        let expires_at = Some(now.checked_add_signed(duration)
            .ok_or_else(|| PluginError::ConfigValidation("ban expiry out of range".into()))?);
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

        let mut state = self.state.lock().await;
        {
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
                return Err(PluginError::Runtime(format!("ban saved; firewall apply failed (pending retry): {e}")));
            }
        }

        drop(state);
        // Broadcast new snapshot to live UIs.
        self.broadcast_bans().await;
        Ok(())
    }

    async fn remove_ban(&self, subject: IpNet) -> PluginResult<()> {
        let subject = subject.trunc();
        let mut state = self.state.lock().await;
        {
            state.revoke_ban(&subject).map_err(|e| {
                hiveguard_plugin_api::PluginError::Runtime(format!(
                    "failed to remove ban: {e}"
                ))
            })?
        };

        {
            let mut enf = self.enforcer.lock().await;
            if let Err(e) = enf.remove_ban(&subject).await {
                warn!(subject = %subject, error = %e, "enforcer remove_ban failed");
                return Err(PluginError::Runtime(format!("unban saved; firewall removal failed (pending retry): {e}")));
            }
        }

        drop(state);
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
        let revoked = {
            st.add_whitelist(cidr)
                .map_err(|e| PluginError::Runtime(format!("failed to whitelist {cidr}: {e}")))?
        };
        // Drop the bans the new entry covers from the firewall as well; the
        // store side was handled by `add_whitelist`.
        let now = Utc::now();
        let desired: Vec<_> = st.ban_store().get_all_bans().into_iter()
            .filter(|b| !st.whitelist().overlaps(&b.subject))
            .filter(|b| b.expires_at.is_none_or(|expiry| expiry > now))
            .map(|b| b.subject).collect();
        self.enforcer.lock().await.sync_full(&desired).await
            .map_err(|e| PluginError::Runtime(format!("whitelist saved; firewall sync failed (pending retry): {e}")))?;
        info!(cidr = %cidr, revoked = revoked.len(), "Whitelisted via ui.rest");
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
        let cfg: HiveGuardConfig = serde_yaml::from_str(&content)
            .map_err(|e| PluginError::ConfigValidation(format!("YAML parse error: {e}")))?;
        cfg.validate().map_err(|e| PluginError::ConfigValidation(e.to_string()))?;
        let loader = hiveguard_host::Loader::resolve_only(Arc::new(
            hiveguard_plugin_api::secrets::SecretResolver::new()
        ));
        loader.resolve(&crate::plugin_bridge::to_loader_config(&cfg))
            .map_err(|e| PluginError::ConfigValidation(e.to_string()))?;
        atomic_config_write(path, &content)?;
        Ok(())
    }

    async fn get_detectors(&self) -> PluginResult<Value> {
        Err(PluginError::Runtime("Detectors are configured in plugins; legacy Rules editor is unavailable. Edit plugins in configuration and restart.".into()))
    }

    async fn put_detectors(&self, _detectors: Value) -> PluginResult<()> {
        Err(PluginError::Runtime("Detectors are configured in plugins; legacy Rules editor is unavailable. Edit plugins in configuration and restart.".into()))
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
            let mut record = BanRecord {
                subject: IpNet::from(ip_addr),
                created_at: ban.banned_at,
                expires_at: ban.expires_at,
                severity: 200,
                reason: format!("imported from fail2ban (jail: {})", ban.jail),
                evidence_hash: [0u8; 32],
                source: BanSource::ManualAdmin,
                geo_info: None,
            };
            // Import must not shorten an existing manual or detector ban.
            // Still apply it below so a previous firewall failure can recover.
            if let Some(existing) = st.ban_store().get_all_bans().into_iter()
                .find(|existing| existing.subject == record.subject) {
                if existing.expires_at.is_none()
                    || matches!((existing.expires_at, record.expires_at), (Some(old), Some(new)) if old >= new) {
                    record = existing.clone();
                }
            }
            match st.add_ban(record) {
                Ok(()) => {
                    match self.enforcer.lock().await.apply_ban(&IpNet::from(ip_addr)).await {
                        Ok(()) => {
                            info!(ip = %ip_addr, jail = %ban.jail, "Imported fail2ban ban via ui.rest");
                            info.imported += 1;
                        }
                        Err(e) => {
                            info.errors.push(format!("{}: ban saved; firewall failed (pending retry): {e}", ban.ip));
                            info.skipped += 1;
                        }
                    }
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

    // -----------------------------------------------------------------------
    // Agent analysis surface (docs/AGENT_API.md)
    // -----------------------------------------------------------------------

    async fn agent_overview(&self) -> PluginResult<Value> {
        let now = Utc::now();
        let (bans, whitelisted) = {
            let st = self.state.lock().await;
            let records: Vec<BanRecord> = st.ban_store().get_all_bans().into_iter().cloned().collect();
            (records, st.whitelist().entries().len())
        };
        let threats: Vec<ThreatInfo> = self.list_threats().await;
        let metrics_text = self.render_metrics().await;
        let mut counters = metrics_text
            .as_deref()
            .map(agent_api::counters_from_metrics)
            .unwrap_or_else(|| serde_json::json!({}));
        if let Value::Object(ref mut m) = counters {
            m.insert("whitelisted".into(), serde_json::json!(whitelisted));
        }
        let plugins = self.list_plugins().await;
        let unhealthy: Vec<Value> = plugins
            .iter()
            .filter(|p| p.kind == "Source" && p.health != "Running" && p.health != "Healthy")
            .map(|p| serde_json::json!({ "id": p.id, "health": p.health }))
            .collect();
        let log_sources = self
            .agent
            .log_engine
            .as_ref()
            .map(|e| e.source_names())
            .unwrap_or_default();
        Ok(serde_json::json!({
            "node": {
                "name": self.node_name,
                "version": self.daemon_version,
                "uptime_secs": self.started_at.elapsed().as_secs(),
                "now": now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            },
            "bans": agent_api::bans_overview(&bans, now),
            "threats": agent_api::threats_overview(&threats, now),
            "counters": counters,
            "plugins": plugins,
            "unhealthy_sources": unhealthy,
            "log_sources": log_sources,
        }))
    }

    async fn agent_bans(&self, params: Value) -> PluginResult<Value> {
        let records: Vec<BanRecord> = {
            let st = self.state.lock().await;
            st.ban_store().get_all_bans().into_iter().cloned().collect()
        };
        agent_api::filter_bans(records, &params, Utc::now(), self.agent_max_results, ban_record_to_info)
            .map_err(agent_api::to_plugin_error)
    }

    async fn agent_threats(&self, params: Value) -> PluginResult<Value> {
        let threats = self.list_threats().await;
        agent_api::filter_threats(&threats, &params, Utc::now(), self.agent_max_results)
            .map_err(agent_api::to_plugin_error)
    }

    async fn agent_log_sources(&self) -> PluginResult<Value> {
        let engine = self.log_engine()?;
        Ok(engine.list_sources())
    }

    async fn agent_log_query(&self, params: Value) -> PluginResult<Value> {
        let engine = self.log_engine()?;
        engine.query(params).await.map_err(agent_api::to_plugin_error)
    }

    async fn agent_log_stats(&self, params: Value) -> PluginResult<Value> {
        let engine = self.log_engine()?;
        let mut result = engine.stats(params).await.map_err(agent_api::to_plugin_error)?;
        // Enrich per-IP groups with ban/whitelist status from the live state.
        let is_ip_grouping = result
            .get("group_by")
            .and_then(Value::as_str)
            .is_some_and(|g| matches!(g, "ip" | "ip24" | "ip48"));
        if is_ip_grouping {
            if let Some(groups) = result.get_mut("groups").and_then(Value::as_array_mut) {
                let st = self.state.lock().await;
                for g in groups.iter_mut() {
                    let key = g.get("key").and_then(Value::as_str).unwrap_or("").to_string();
                    let net: Option<IpNet> = key
                        .parse::<IpNet>()
                        .ok()
                        .or_else(|| key.parse::<IpAddr>().ok().map(IpNet::from));
                    let (banned, whitelisted) = match net {
                        Some(net) => {
                            let banned = if net.prefix_len() == net.max_prefix_len() {
                                st.ban_store().is_banned(&net.addr()).is_some()
                            } else {
                                st.ban_store().get_all_bans().iter().any(|b| {
                                    b.subject.contains(&net) || net.contains(&b.subject)
                                })
                            };
                            (banned, st.whitelist().overlaps(&net))
                        }
                        None => (false, false),
                    };
                    if let Some(Value::Object(extras)) = g.get_mut("extras") {
                        extras.insert("banned".into(), Value::Bool(banned));
                        extras.insert("whitelisted".into(), Value::Bool(whitelisted));
                    } else if let Value::Object(obj) = g {
                        obj.insert(
                            "extras".into(),
                            serde_json::json!({ "banned": banned, "whitelisted": whitelisted }),
                        );
                    }
                }
            }
        }
        Ok(result)
    }

    async fn agent_ip_profile(&self, params: Value) -> PluginResult<Value> {
        let ip_str = params
            .get("ip")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| PluginError::ConfigValidation("`ip` is required".into()))?;
        let ip: IpAddr = ip_str
            .parse()
            .map_err(|_| PluginError::ConfigValidation(format!("`ip`: not an IP address: `{ip_str}`")))?;
        let since = params.get("since").and_then(Value::as_str).map(str::to_string);

        let (ban, whitelisted) = {
            let st = self.state.lock().await;
            let ban = st.ban_store().is_banned(&ip).cloned().map(ban_record_to_info);
            (ban, st.whitelist().is_whitelisted(&ip))
        };
        let threats = self.list_threats().await;
        let mine: Vec<&ThreatInfo> = threats.iter().filter(|t| t.ip == ip_str).collect();
        let mut by_det: HashMap<String, u64> = HashMap::new();
        for t in &mine {
            *by_det.entry(t.detector.clone()).or_default() += 1;
        }
        let logs = match self.agent.log_engine.as_ref() {
            Some(engine) => engine
                .ip_profile_logs(ip, since.as_deref())
                .await
                .map_err(agent_api::to_plugin_error)?,
            None => Value::Null,
        };
        Ok(serde_json::json!({
            "ip": ip_str,
            "ban": { "banned": ban.is_some(), "record": ban },
            "whitelisted": whitelisted,
            "threats": {
                "count": mine.len(),
                "by_detector": by_det,
                "last": mine.first(),
            },
            "logs": logs,
            "geo": Value::Null,
        }))
    }

    async fn agent_journal(&self, params: Value) -> PluginResult<Value> {
        let engine = self.log_engine()?;
        engine.journal(params).await.map_err(agent_api::to_plugin_error)
    }

    async fn agent_detectors(&self) -> PluginResult<Value> {
        let metrics_text = self.render_metrics().await;
        Ok(agent_api::detectors_view(&self.agent.plugin_entries, metrics_text.as_deref()))
    }

    async fn agent_catalog(&self, kind: Option<String>) -> PluginResult<Value> {
        agent_api::catalog_view(&self.agent.plugin_entries, kind.as_deref())
            .map_err(agent_api::to_plugin_error)
    }

    async fn agent_config_validate(&self, content: String) -> PluginResult<Value> {
        // Validation resolves plugin schemas and secrets; run it off the
        // async executor like the config write path does implicitly.
        tokio::task::spawn_blocking(move || agent_api::validate_config(&content))
            .await
            .map_err(|e| PluginError::Runtime(format!("validation task failed: {e}")))
    }

    fn subscribe_agent(&self) -> Option<broadcast::Receiver<AgentEvent>> {
        Some(self.agent.events.subscribe())
    }

    fn subscribe(&self) -> broadcast::Receiver<UiEvent> {
        self.events.subscribe()
    }
}

impl DaemonUiApi {
    fn log_engine(&self) -> PluginResult<&std::sync::Arc<crate::agent_logs::LogEngine>> {
        self.agent
            .log_engine
            .as_ref()
            .ok_or_else(|| PluginError::Runtime("log engine not available on this daemon".into()))
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
        created_at: Some(record.created_at.to_rfc3339()),
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
