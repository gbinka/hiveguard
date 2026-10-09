//! Shared mock `UiApiHandle` for integration tests.

use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use hiveguard_plugin_api::prelude::*;
use ipnet::IpNet;
use tokio::sync::{broadcast, Mutex};
use tokio_util::sync::CancellationToken;

use hiveguard_plugin_ui_rest::{build_router, AppState};

/// Test double that stores a configurable in-memory snapshot.
pub struct MockUiApi {
    pub bans: Mutex<Vec<BanInfo>>,
    pub threats: Mutex<Vec<ThreatInfo>>,
    pub plugins: Mutex<Vec<PluginInfo>>,
    pub whitelist: Mutex<Vec<String>>,
    pub node_name: String,
    pub daemon_version: String,
    pub started_at: Instant,
    pub events: broadcast::Sender<UiEvent>,
    /// Incremental agent events (`/api/agent/stream`). Tests push into it.
    pub agent_events: broadcast::Sender<AgentEvent>,
    /// When `true` the agent methods return `Runtime` errors (→ 503) to
    /// emulate a host without the analysis surface.
    pub agent_unsupported: bool,
}

impl MockUiApi {
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(16);
        Self {
            bans: Mutex::new(vec![sample_ban("1.2.3.4/32")]),
            threats: Mutex::new(vec![sample_threat("9.9.9.9")]),
            plugins: Mutex::new(vec![sample_plugin("detector.test")]),
            whitelist: Mutex::new(vec!["10.0.0.0/8".to_string()]),
            node_name: "test-node".to_string(),
            daemon_version: "0.0.0-test".to_string(),
            started_at: Instant::now(),
            events: tx,
            agent_events: broadcast::channel(16).0,
            agent_unsupported: false,
        }
    }

    pub fn without_agent() -> Self {
        let mut m = Self::new();
        m.agent_unsupported = true;
        m
    }

    fn agent_echo(&self, op: &str, params: serde_json::Value) -> PluginResult<serde_json::Value> {
        if self.agent_unsupported {
            return Err(PluginError::Runtime("agent surface disabled".into()));
        }
        // Emulate the daemon's error mapping so the REST layer can be tested.
        if params.get("source").and_then(|v| v.as_str()) == Some("missing") {
            return Err(PluginError::NotFound("unknown log source `missing`".into()));
        }
        if params.get("since").and_then(|v| v.as_str()) == Some("garbage") {
            return Err(PluginError::ConfigValidation("`since`: cannot parse".into()));
        }
        Ok(serde_json::json!({ "op": op, "params": params }))
    }
}

#[async_trait]
impl UiApiHandle for MockUiApi {
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
        let total = self.bans.lock().await.len();
        NodeInfo {
            node_name: self.node_name.clone(),
            daemon_version: self.daemon_version.clone(),
            uptime_secs: self.started_at.elapsed().as_secs(),
            total_bans: total,
        }
    }
    async fn list_bans(&self) -> Vec<BanInfo> {
        self.bans.lock().await.clone()
    }
    async fn list_threats(&self) -> Vec<ThreatInfo> {
        self.threats.lock().await.clone()
    }
    async fn list_plugins(&self) -> Vec<PluginInfo> {
        self.plugins.lock().await.clone()
    }
    async fn add_ban(&self, req: BanRequest) -> PluginResult<()> {
        self.bans.lock().await.push(BanInfo {
            subject: req.subject.to_string(),
            severity: 5,
            reason: req.reason,
            expires_at: None,
            source: "admin".to_string(),
            created_at: None,
        });
        Ok(())
    }
    async fn remove_ban(&self, subject: IpNet) -> PluginResult<()> {
        let target = subject.to_string();
        let mut guard = self.bans.lock().await;
        let before = guard.len();
        guard.retain(|b| b.subject != target);
        if guard.len() == before {
            return Err(PluginError::Runtime("not found".into()));
        }
        Ok(())
    }
    // --- Extended management surface overrides (REFACTOR 2.5) ---
    async fn list_whitelist(&self) -> Vec<String> {
        self.whitelist.lock().await.clone()
    }
    async fn add_whitelist(&self, cidr: IpNet) -> PluginResult<()> {
        self.whitelist.lock().await.push(cidr.to_string());
        Ok(())
    }
    async fn remove_whitelist(&self, cidr: IpNet) -> PluginResult<()> {
        let target = cidr.to_string();
        let mut guard = self.whitelist.lock().await;
        let before = guard.len();
        guard.retain(|c| c != &target);
        if guard.len() == before {
            return Err(PluginError::NotFound(format!("{target} not whitelisted")));
        }
        Ok(())
    }
    async fn put_config(&self, content: String) -> PluginResult<()> {
        // Mock "validation": reject anything containing the INVALID marker.
        if content.contains("INVALID") {
            return Err(PluginError::ConfigValidation("YAML parse error".into()));
        }
        Ok(())
    }
    async fn render_metrics(&self) -> Option<String> {
        Some("# HELP hiveguard_up 1\nhiveguard_up 1\n".to_string())
    }

    // --- Agent analysis surface ---
    async fn agent_overview(&self) -> PluginResult<serde_json::Value> {
        self.agent_echo("overview", serde_json::json!({}))
    }
    async fn agent_bans(&self, params: serde_json::Value) -> PluginResult<serde_json::Value> {
        self.agent_echo("bans", params)
    }
    async fn agent_threats(&self, params: serde_json::Value) -> PluginResult<serde_json::Value> {
        self.agent_echo("threats", params)
    }
    async fn agent_log_sources(&self) -> PluginResult<serde_json::Value> {
        self.agent_echo("log_sources", serde_json::json!({}))
    }
    async fn agent_log_query(&self, params: serde_json::Value) -> PluginResult<serde_json::Value> {
        self.agent_echo("log_query", params)
    }
    async fn agent_log_stats(&self, params: serde_json::Value) -> PluginResult<serde_json::Value> {
        self.agent_echo("log_stats", params)
    }
    async fn agent_ip_profile(&self, params: serde_json::Value) -> PluginResult<serde_json::Value> {
        self.agent_echo("ip", params)
    }
    async fn agent_journal(&self, params: serde_json::Value) -> PluginResult<serde_json::Value> {
        self.agent_echo("journal", params)
    }
    async fn agent_detectors(&self) -> PluginResult<serde_json::Value> {
        self.agent_echo("detectors", serde_json::json!({}))
    }
    async fn agent_catalog(&self, kind: Option<String>) -> PluginResult<serde_json::Value> {
        self.agent_echo("catalog", serde_json::json!({ "kind": kind }))
    }
    async fn agent_config_validate(&self, content: String) -> PluginResult<serde_json::Value> {
        if self.agent_unsupported {
            return Err(PluginError::Runtime("agent surface disabled".into()));
        }
        Ok(serde_json::json!({ "valid": !content.contains("INVALID"), "errors": [], "warnings": [], "plugins": [] }))
    }
    fn subscribe_agent(&self) -> Option<broadcast::Receiver<AgentEvent>> {
        if self.agent_unsupported {
            None
        } else {
            Some(self.agent_events.subscribe())
        }
    }

    fn subscribe(&self) -> broadcast::Receiver<UiEvent> {
        self.events.subscribe()
    }
}

fn sample_ban(cidr: &str) -> BanInfo {
    BanInfo {
        subject: cidr.to_string(),
        severity: 7,
        reason: "test".to_string(),
        expires_at: Some("2099-01-01T00:00:00Z".to_string()),
        source: "detector:test".to_string(),
        created_at: Some("2026-01-01T00:00:00Z".to_string()),
    }
}

fn sample_threat(ip: &str) -> ThreatInfo {
    ThreatInfo {
        ip: ip.to_string(),
        severity: 5,
        confidence: 80,
        detector: "test".to_string(),
        reason: "synthetic".to_string(),
        timestamp: "2099-01-01T00:00:00Z".to_string(),
    }
}

fn sample_plugin(id: &str) -> PluginInfo {
    PluginInfo {
        id: id.to_string(),
        kind: "Detector".to_string(),
        health: "Healthy".to_string(),
        version: "1.0.0".to_string(),
    }
}

/// Build a test `Router` with a mock API and a known auth token.
pub fn test_router(token: &str) -> axum::Router {
    test_router_with(token, Arc::new(MockUiApi::new()))
}

/// Build a test `Router` around a caller-provided mock (so the test keeps a
/// handle to it, e.g. to push agent events).
pub fn test_router_with(token: &str, mock: Arc<MockUiApi>) -> axum::Router {
    let api: Arc<dyn UiApiHandle> = mock;
    let state = Arc::new(AppState {
        api,
        auth_token: token.to_string(),
        started_at: Instant::now(),
        tick_interval: Duration::from_secs(30),
        shutdown: CancellationToken::new(),
        ingest: Default::default(),
    });
    build_router(state, None, &[])
}
