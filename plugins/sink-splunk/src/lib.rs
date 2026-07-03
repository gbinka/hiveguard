//! Splunk HTTP Event Collector (HEC) sink — POSTs HiveGuard SIEM events to
//! `{url}/services/collector/event`.
//!
//! # Auth
//!
//! Splunk HEC uses an `Authorization: Splunk <token>` header. The token is
//! resolved through the secret resolver by the host before reaching this
//! plugin.
//!
//! # TODO (production hardening)
//!
//! * Circuit breaker on repeated failure.
//! * Dead-letter queue for batches that exhaust retries.
//! * Per-event HEC response parsing for partial failures.

use std::time::Duration;

use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::sync::RwLock;
use tracing::{debug, warn};

use hiveguard_plugin_api::prelude::*;

pub const PLUGIN_ID: &str = "sink.splunk";
const PLUGIN_VERSION: &str = "0.1.0";

#[derive(Debug, Clone, Deserialize)]
struct Config {
    url: String,
    token: String,
    #[serde(default)]
    index: Option<String>,
    #[serde(default = "default_source")]
    source: String,
    #[serde(default = "default_sourcetype")]
    sourcetype: String,
    #[serde(default = "default_batch_size")]
    #[allow(dead_code)]
    batch_size: usize,
    #[serde(default = "default_flush_interval_secs")]
    #[allow(dead_code)]
    flush_interval_secs: u64,
    #[serde(default = "default_timeout_secs")]
    timeout_secs: u64,
    #[serde(default = "default_verify_tls")]
    verify_tls: bool,
}

fn default_source() -> String { "hiveguard".to_string() }
fn default_sourcetype() -> String { "_json".to_string() }
fn default_batch_size() -> usize { 100 }
fn default_flush_interval_secs() -> u64 { 10 }
fn default_timeout_secs() -> u64 { 30 }
fn default_verify_tls() -> bool { true }

struct State {
    cfg: Config,
    client: reqwest::Client,
    auth_headers: HeaderMap,
}

pub struct SplunkSinkPlugin {
    manifest: PluginManifest,
    state: RwLock<Option<State>>,
}

impl SplunkSinkPlugin {
    pub fn manifest_fn() -> PluginManifest {
        PluginManifest {
            id: PLUGIN_ID,
            version: PLUGIN_VERSION,
            description: "Splunk HEC sink for HiveGuard SIEM events.",
            kind: PluginKind::SiemSink,
            author: "HiveGuard",
            docs_url: Some(
                "https://github.com/anthropics/hiveguard/blob/main/plugins/sink-splunk/README.md",
            ),
        }
    }

    pub fn create(
        _ctx: PluginContext,
        cfg: serde_json::Value,
    ) -> BoxFuture<'static, PluginResult<Box<dyn SiemSinkPlugin>>> {
        Box::pin(async move {
            let mut plugin = SplunkSinkPlugin {
                manifest: Self::manifest_fn(),
                state: RwLock::new(None),
            };
            <SplunkSinkPlugin as Plugin>::init(&mut plugin, cfg).await?;
            Ok(Box::new(plugin) as Box<dyn SiemSinkPlugin>)
        })
    }
}

fn validate(cfg: &Config) -> PluginResult<()> {
    if cfg.token.trim().is_empty() {
        return Err(PluginError::ConfigValidation(
            "sink.splunk: `token` must not be empty".into(),
        ));
    }
    reqwest::Url::parse(&cfg.url).map_err(|e| {
        PluginError::ConfigValidation(format!("sink.splunk: invalid `url`: {e}"))
    })?;
    Ok(())
}

fn build_auth_headers(cfg: &Config) -> PluginResult<HeaderMap> {
    let mut headers = HeaderMap::new();
    let auth = format!("Splunk {}", cfg.token);
    let val = HeaderValue::from_str(&auth).map_err(|e| {
        PluginError::ConfigValidation(format!("sink.splunk: invalid token: {e}"))
    })?;
    headers.insert(AUTHORIZATION, val);
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    Ok(headers)
}

/// Build the HEC body — one JSON object per line (newline-separated).
pub fn build_hec_body(batch: &SiemBatch, cfg_index: Option<&str>, source: &str, sourcetype: &str) -> String {
    let mut buf = String::with_capacity(batch.len() * 512);
    for ev in batch {
        let mut obj = json!({
            "time": ev.timestamp.timestamp_millis() as f64 / 1000.0,
            "source": source,
            "sourcetype": sourcetype,
            "event": ev,
        });
        if let Some(idx) = cfg_index {
            obj["index"] = Value::String(idx.to_string());
        }
        buf.push_str(&obj.to_string());
        buf.push('\n');
    }
    buf
}

#[async_trait]
impl Plugin for SplunkSinkPlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    async fn init(&mut self, cfg: serde_json::Value) -> PluginResult<()> {
        let parsed: Config = serde_json::from_value(cfg)
            .map_err(|e| PluginError::ConfigValidation(format!("sink.splunk: {e}")))?;
        validate(&parsed)?;

        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(!parsed.verify_tls)
            .timeout(Duration::from_secs(parsed.timeout_secs))
            .build()
            .map_err(|e| PluginError::Init(format!("sink.splunk: HTTP client: {e}")))?;

        let auth_headers = build_auth_headers(&parsed)?;

        let mut guard = self.state.write().await;
        *guard = Some(State { cfg: parsed, client, auth_headers });
        Ok(())
    }
}

#[async_trait]
impl SiemSinkPlugin for SplunkSinkPlugin {
    async fn send(&self, batch: SiemBatch) -> PluginResult<()> {
        if batch.is_empty() {
            return Ok(());
        }
        let guard = self.state.read().await;
        let state = guard
            .as_ref()
            .ok_or_else(|| PluginError::Runtime("sink.splunk used before init".into()))?;

        let body = build_hec_body(
            &batch,
            state.cfg.index.as_deref(),
            &state.cfg.source,
            &state.cfg.sourcetype,
        );
        let url = format!(
            "{}/services/collector/event",
            state.cfg.url.trim_end_matches('/')
        );

        let mut delay = Duration::from_secs(1);
        let mut last_err: Option<String> = None;
        for attempt in 1..=3u32 {
            let res = state
                .client
                .post(&url)
                .headers(state.auth_headers.clone())
                .body(body.clone())
                .send()
                .await;

            match res {
                Ok(resp) => {
                    let status = resp.status();
                    if status.is_success() {
                        debug!(plugin = PLUGIN_ID, events = batch.len(), "splunk flush OK");
                        return Ok(());
                    }
                    let transient = status.as_u16() == 429 || status.is_server_error();
                    last_err = Some(format!("HTTP {status}"));
                    if transient && attempt < 3 {
                        warn!(plugin = PLUGIN_ID, attempt, status = %status, "transient error, retrying");
                        tokio::time::sleep(delay).await;
                        delay *= 2;
                        continue;
                    }
                    return Err(PluginError::Runtime(format!(
                        "sink.splunk: HEC failed ({status})"
                    )));
                }
                Err(e) => {
                    last_err = Some(e.to_string());
                    if attempt < 3 {
                        warn!(plugin = PLUGIN_ID, attempt, error = %e, "request error, retrying");
                        tokio::time::sleep(delay).await;
                        delay *= 2;
                        continue;
                    }
                    return Err(PluginError::Runtime(format!(
                        "sink.splunk: request failed: {e}"
                    )));
                }
            }
        }
        Err(PluginError::Runtime(format!(
            "sink.splunk: exhausted retries: {}",
            last_err.unwrap_or_default()
        )))
    }
}

inventory::submit! {
    PluginDescriptor {
        id: PLUGIN_ID,
        kind: PluginKind::SiemSink,
        api_version: API_VERSION,
        manifest: SplunkSinkPlugin::manifest_fn,
        config_schema: include_str!("../schema.json"),
        factory: PluginFactory::SiemSink(SplunkSinkPlugin::create),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;
    use chrono::Utc;
    use hiveguard_plugin_api::context::parking_lot_compat::RegistryHandle;
    use hiveguard_plugin_api::secrets::SecretResolver;
    use hiveguard_core::models::{EventType, NormalizedEvent};
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

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

    fn ev(ip: &str) -> NormalizedEvent {
        NormalizedEvent {
            timestamp: Utc::now(),
            source_ip: ip.parse::<IpAddr>().unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            event_type: EventType::AuthFailure,
            source_name: "test".into(),
            raw_line: "test line".into(),
            metadata: HashMap::new(),
        }
    }

    #[test]
    fn manifest_correct() {
        let m = SplunkSinkPlugin::manifest_fn();
        assert_eq!(m.id, PLUGIN_ID);
        assert_eq!(m.kind, PluginKind::SiemSink);
    }

    #[tokio::test]
    async fn init_with_valid_config_ok() {
        let cfg = serde_json::json!({
            "url": "https://splunk.example.com:8088",
            "token": "my-token",
        });
        let _plugin = SplunkSinkPlugin::create(test_ctx(), cfg).await.unwrap();
    }

    #[tokio::test]
    async fn init_with_empty_token_rejected() {
        let cfg = serde_json::json!({
            "url": "https://splunk.example.com:8088",
            "token": "",
        });
        match SplunkSinkPlugin::create(test_ctx(), cfg).await {
            Err(PluginError::ConfigValidation(_)) => {}
            Err(e) => panic!("expected ConfigValidation, got {e:?}"),
            Ok(_) => panic!("expected ConfigValidation, got Ok"),
        }
    }

    #[tokio::test]
    async fn init_missing_token_rejected() {
        let cfg = serde_json::json!({ "url": "https://splunk.example.com:8088" });
        match SplunkSinkPlugin::create(test_ctx(), cfg).await {
            Err(PluginError::ConfigValidation(_)) => {}
            Err(e) => panic!("expected ConfigValidation, got {e:?}"),
            Ok(_) => panic!("expected ConfigValidation, got Ok"),
        }
    }

    #[tokio::test]
    async fn ship_posts_with_hec_auth_header() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/services/collector/event"))
            .and(header("authorization", "Splunk test-token-123"))
            .and(header("content-type", "application/json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"text": "Success", "code": 0})))
            .expect(1)
            .mount(&server)
            .await;

        let cfg = serde_json::json!({
            "url": server.uri(),
            "token": "test-token-123",
            "index": "security",
            "verify_tls": false,
        });
        let plugin = SplunkSinkPlugin::create(test_ctx(), cfg).await.unwrap();
        plugin.send(vec![ev("1.2.3.4")]).await.unwrap();
    }
}
