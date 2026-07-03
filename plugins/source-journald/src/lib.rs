//! systemd journal log source plugin.
//!
//! Spawns `journalctl --follow --output=json` as a child process and parses
//! each emitted JSON line into a [`NormalizedEvent`]. Subprocess-based
//! design avoids linking against `libsystemd`, which keeps the build
//! portable and sidesteps glibc version friction.

use std::collections::HashMap;
use std::net::IpAddr;
use std::process::Stdio;
use std::sync::Arc;

use chrono::Utc;
use regex::Regex;
use serde::Deserialize;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tracing::{debug, info, warn};

use hiveguard_core::models::{EventType, NormalizedEvent};
use hiveguard_plugin_api::prelude::*;

pub const PLUGIN_ID: &str = "source.journald";
const PLUGIN_VERSION: &str = "0.1.0";

#[derive(Debug, Clone, Deserialize)]
struct Config {
    #[serde(default)]
    units: Vec<String>,
    #[serde(default = "default_priority")]
    priority: u8,
    #[serde(default = "default_ip_field")]
    ip_field: String,
    #[serde(default)]
    ip_pattern: Option<String>,
    #[serde(default)]
    since_boot: bool,
    #[serde(default = "default_event_type")]
    event_type: String,
}

fn default_priority() -> u8 { 7 }
fn default_ip_field() -> String { "MESSAGE".to_string() }
fn default_event_type() -> String { "ConnectionEvent".to_string() }

pub struct JournaldPlugin {
    manifest: PluginManifest,
    config: Option<Config>,
}

impl JournaldPlugin {
    pub fn manifest_fn() -> PluginManifest {
        PluginManifest {
            id: PLUGIN_ID,
            version: PLUGIN_VERSION,
            description: "Tails systemd journal via journalctl -f -o json.",
            kind: PluginKind::LogSource,
            author: "HiveGuard",
            docs_url: Some(
                "https://github.com/anthropics/hiveguard/blob/main/plugins/source-journald/README.md",
            ),
        }
    }

    pub fn create(
        _ctx: PluginContext,
        cfg: serde_json::Value,
    ) -> BoxFuture<'static, PluginResult<Box<dyn LogSourcePlugin>>> {
        Box::pin(async move {
            let mut plugin = JournaldPlugin {
                manifest: Self::manifest_fn(),
                config: None,
            };
            <JournaldPlugin as Plugin>::init(&mut plugin, cfg).await?;
            Ok(Box::new(plugin) as Box<dyn LogSourcePlugin>)
        })
    }
}

#[async_trait]
impl Plugin for JournaldPlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    async fn init(&mut self, cfg: serde_json::Value) -> PluginResult<()> {
        let parsed: Config = serde_json::from_value(cfg)
            .map_err(|e| PluginError::ConfigValidation(e.to_string()))?;

        if let Some(ref pattern) = parsed.ip_pattern {
            let compiled = Regex::new(pattern).map_err(|e| {
                PluginError::ConfigValidation(format!("invalid ip_pattern regex: {e}"))
            })?;
            if !compiled.capture_names().any(|name| name == Some("ip")) {
                return Err(PluginError::ConfigValidation(
                    "ip_pattern must contain a named group 'ip' (e.g. '(?P<ip>...)')"
                        .into(),
                ));
            }
        }

        self.config = Some(parsed);
        Ok(())
    }
}

#[async_trait]
impl LogSourcePlugin for JournaldPlugin {
    async fn run(
        &mut self,
        sink: EventSink,
        shutdown: CancellationToken,
    ) -> PluginResult<()> {
        let cfg = self
            .config
            .as_ref()
            .ok_or_else(|| PluginError::Runtime("journald used before init".into()))?;

        let ip_pattern = cfg.ip_pattern.as_deref().map(|p| Arc::new(Regex::new(p).unwrap()));
        let event_type = parse_event_type(&cfg.event_type);

        let mut command = Command::new("journalctl");
        command
            .arg("--follow")
            .arg("--no-pager")
            .arg("--output=json");
        if cfg.since_boot {
            command.arg("--boot");
        }
        for unit in &cfg.units {
            command.arg(format!("--unit={unit}"));
        }
        command.arg(format!("--priority={}", cfg.priority));
        command.stdout(Stdio::piped()).stderr(Stdio::null());

        let mut child: Child = command
            .spawn()
            .map_err(|e| PluginError::Init(format!("failed to spawn journalctl: {e}")))?;

        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| PluginError::Runtime("journalctl produced no stdout".into()))?;
        let mut reader = BufReader::new(stdout).lines();

        info!(plugin = PLUGIN_ID, "journalctl follower started");

        loop {
            tokio::select! {
                _ = shutdown.cancelled() => {
                    info!(plugin = PLUGIN_ID, "shutting down journalctl");
                    let _ = child.kill().await;
                    return Ok(());
                }
                line = reader.next_line() => {
                    match line {
                        Ok(Some(line)) => {
                            if let Some(event) = parse_journal_line(
                                &line,
                                &cfg.ip_field,
                                ip_pattern.as_deref(),
                                event_type.clone(),
                            ) {
                                if sink.send(event).await.is_err() {
                                    debug!(plugin = PLUGIN_ID, "event sink closed");
                                    break;
                                }
                            }
                        }
                        Ok(None) => {
                            warn!(plugin = PLUGIN_ID, "journalctl stream ended");
                            return Err(PluginError::Runtime(
                                "journalctl exited unexpectedly".into(),
                            ));
                        }
                        Err(e) => {
                            return Err(PluginError::Runtime(format!(
                                "journalctl read error: {e}"
                            )));
                        }
                    }
                }
            }
        }

        let _ = child.kill().await;
        Ok(())
    }
}

fn parse_event_type(raw: &str) -> EventType {
    match raw {
        "AuthFailure" => EventType::AuthFailure,
        "AuthSuccess" => EventType::AuthSuccess,
        "HttpRequest" => EventType::HttpRequest,
        "Http4xx" => EventType::Http4xx,
        "Http5xx" => EventType::Http5xx,
        "SmtpAuthFailure" => EventType::SmtpAuthFailure,
        "PortAccess" => EventType::PortAccess,
        "ConnectionEvent" => EventType::ConnectionEvent,
        other => EventType::Custom(other.to_string()),
    }
}

fn parse_journal_line(
    line: &str,
    ip_field: &str,
    ip_pattern: Option<&Regex>,
    event_type: EventType,
) -> Option<NormalizedEvent> {
    let entry: serde_json::Value = serde_json::from_str(line).ok()?;
    let obj = entry.as_object()?;

    let field_value = obj.get(ip_field).and_then(|v| v.as_str()).unwrap_or("");
    if field_value.is_empty() {
        return None;
    }

    let source_ip = match ip_pattern {
        Some(re) => re
            .captures(field_value)
            .and_then(|caps| caps.name("ip"))
            .and_then(|m| m.as_str().parse::<IpAddr>().ok())?,
        None => extract_first_ip(field_value)?,
    };

    let mut metadata: HashMap<String, String> = HashMap::new();
    if let Some(unit) = obj.get("_SYSTEMD_UNIT").and_then(|v| v.as_str()) {
        metadata.insert("unit".into(), unit.to_string());
    }
    if let Some(prio) = obj.get("PRIORITY").and_then(|v| v.as_str()) {
        metadata.insert("priority".into(), prio.to_string());
    }
    if let Some(ident) = obj.get("SYSLOG_IDENTIFIER").and_then(|v| v.as_str()) {
        metadata.insert("identifier".into(), ident.to_string());
    }
    if !field_value.is_empty() {
        metadata.insert("message".into(), field_value.to_string());
    }

    Some(NormalizedEvent {
        timestamp: Utc::now(),
        source_ip,
        event_type,
        source_name: "journald".into(),
        raw_line: line.to_string(),
        metadata,
    })
}

fn extract_first_ip(s: &str) -> Option<IpAddr> {
    // Cheap scan — split on common delimiters and try parse each token.
    for token in s.split(|c: char| !c.is_ascii_alphanumeric() && c != '.' && c != ':') {
        if token.is_empty() {
            continue;
        }
        if let Ok(ip) = token.parse::<IpAddr>() {
            return Some(ip);
        }
    }
    None
}

inventory::submit! {
    PluginDescriptor {
        id: PLUGIN_ID,
        kind: PluginKind::LogSource,
        api_version: API_VERSION,
        manifest: JournaldPlugin::manifest_fn,
        config_schema: include_str!("../schema.json"),
        factory: PluginFactory::LogSource(JournaldPlugin::create),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hiveguard_plugin_api::context::parking_lot_compat::RegistryHandle;
    use hiveguard_plugin_api::secrets::SecretResolver;

    fn test_ctx() -> PluginContext {
        PluginContext::new(
            PLUGIN_ID.to_string(),
            std::env::temp_dir(),
            Arc::new(SecretResolver::new()),
            PluginMetrics {
                registry: Arc::new(RegistryHandle::default()),
                plugin_id: PLUGIN_ID.to_string(),
            },
            CancellationToken::new(),
        )
    }

    #[test]
    fn manifest_has_correct_id_and_kind() {
        let m = JournaldPlugin::manifest_fn();
        assert_eq!(m.id, PLUGIN_ID);
        assert_eq!(m.kind, PluginKind::LogSource);
    }

    #[tokio::test]
    async fn factory_accepts_defaults() {
        let plugin = JournaldPlugin::create(test_ctx(), serde_json::json!({}))
            .await
            .unwrap();
        assert_eq!(plugin.manifest().id, PLUGIN_ID);
    }

    #[tokio::test]
    async fn factory_rejects_pattern_without_ip_capture() {
        let cfg = serde_json::json!({
            "ip_pattern": "user=(?P<u>\\S+)"
        });
        match JournaldPlugin::create(test_ctx(), cfg).await {
            Err(PluginError::ConfigValidation(_)) => {}
            Err(other) => panic!("expected ConfigValidation, got {other:?}"),
            Ok(_) => panic!("expected error"),
        }
    }

    #[test]
    fn extracts_ipv4_from_message() {
        let line = r#"{"MESSAGE": "Failed password from 203.0.113.5 port 12345", "_SYSTEMD_UNIT": "ssh.service"}"#;
        let event = parse_journal_line(line, "MESSAGE", None, EventType::AuthFailure).unwrap();
        assert_eq!(event.source_ip, "203.0.113.5".parse::<IpAddr>().unwrap());
        assert_eq!(event.event_type, EventType::AuthFailure);
        assert_eq!(event.metadata.get("unit").unwrap(), "ssh.service");
    }

    #[test]
    fn extracts_ip_with_named_regex() {
        let line = r#"{"MESSAGE": "user=admin remote=10.0.0.7"}"#;
        let re = Regex::new(r"remote=(?P<ip>\S+)").unwrap();
        let event =
            parse_journal_line(line, "MESSAGE", Some(&re), EventType::ConnectionEvent).unwrap();
        assert_eq!(event.source_ip, "10.0.0.7".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn skips_lines_without_ip() {
        let line = r#"{"MESSAGE": "service restarted ok"}"#;
        assert!(parse_journal_line(line, "MESSAGE", None, EventType::ConnectionEvent).is_none());
    }

    #[test]
    fn skips_lines_with_missing_field() {
        let line = r#"{"OTHER": "1.2.3.4"}"#;
        assert!(parse_journal_line(line, "MESSAGE", None, EventType::ConnectionEvent).is_none());
    }

    #[test]
    fn skips_invalid_json() {
        assert!(parse_journal_line("not json", "MESSAGE", None, EventType::ConnectionEvent).is_none());
    }
}
