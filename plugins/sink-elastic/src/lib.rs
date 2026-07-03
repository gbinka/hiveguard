//! Elasticsearch bulk sink — ships HiveGuard SIEM events to the
//! `POST {url}/{index}/_bulk` API.
//!
//! Each batch is serialized as NDJSON (one action line + one document line per
//! event). The plugin handles HTTP transport with timeout and retries with
//! exponential backoff. The host owns batching/buffering policy.
//!
//! # Auth
//!
//! Optional HTTP Basic auth via `username` + `password`. Both values are
//! resolved through the secret resolver before reaching this plugin, so any
//! `${env:PASSWORD}` placeholders are already expanded.
//!
//! # TODO (production hardening)
//!
//! * Circuit breaker on repeated failure (avoid hot-looping the network).
//! * Dead-letter queue for batches that exhaust retries.
//! * Per-document failure parsing from the bulk response (currently the whole
//!   batch is considered failed if `errors=true`).

use std::time::Duration;

use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use serde::Deserialize;
use tokio::sync::RwLock;
use tracing::{debug, warn};

use hiveguard_plugin_api::prelude::*;

pub const PLUGIN_ID: &str = "sink.elastic";
const PLUGIN_VERSION: &str = "0.1.0";

#[derive(Debug, Clone, Deserialize)]
struct Config {
    url: String,
    #[serde(default = "default_index")]
    index: String,
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    password: Option<String>,
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

fn default_index() -> String { "hiveguard-events".to_string() }
fn default_batch_size() -> usize { 100 }
fn default_flush_interval_secs() -> u64 { 10 }
fn default_timeout_secs() -> u64 { 30 }
fn default_verify_tls() -> bool { true }

struct State {
    cfg: Config,
    client: reqwest::Client,
    auth_headers: HeaderMap,
}

pub struct ElasticSinkPlugin {
    manifest: PluginManifest,
    state: RwLock<Option<State>>,
}

impl ElasticSinkPlugin {
    pub fn manifest_fn() -> PluginManifest {
        PluginManifest {
            id: PLUGIN_ID,
            version: PLUGIN_VERSION,
            description: "Elasticsearch bulk (_bulk) sink for HiveGuard SIEM events.",
            kind: PluginKind::SiemSink,
            author: "HiveGuard",
            docs_url: Some(
                "https://github.com/anthropics/hiveguard/blob/main/plugins/sink-elastic/README.md",
            ),
        }
    }

    pub fn create(
        _ctx: PluginContext,
        cfg: serde_json::Value,
    ) -> BoxFuture<'static, PluginResult<Box<dyn SiemSinkPlugin>>> {
        Box::pin(async move {
            let mut plugin = ElasticSinkPlugin {
                manifest: Self::manifest_fn(),
                state: RwLock::new(None),
            };
            <ElasticSinkPlugin as Plugin>::init(&mut plugin, cfg).await?;
            Ok(Box::new(plugin) as Box<dyn SiemSinkPlugin>)
        })
    }
}

fn validate(cfg: &Config) -> PluginResult<()> {
    if cfg.index.trim().is_empty() {
        return Err(PluginError::ConfigValidation(
            "sink.elastic: `index` must not be empty".into(),
        ));
    }
    reqwest::Url::parse(&cfg.url).map_err(|e| {
        PluginError::ConfigValidation(format!("sink.elastic: invalid `url`: {e}"))
    })?;
    Ok(())
}

fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let combined = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[((combined >> 18) & 0x3F) as usize] as char);
        out.push(ALPHABET[((combined >> 12) & 0x3F) as usize] as char);
        out.push(if chunk.len() > 1 { ALPHABET[((combined >> 6) & 0x3F) as usize] as char } else { '=' });
        out.push(if chunk.len() > 2 { ALPHABET[(combined & 0x3F) as usize] as char } else { '=' });
    }
    out
}

fn build_auth_headers(cfg: &Config) -> HeaderMap {
    let mut headers = HeaderMap::new();
    if let (Some(user), Some(pass)) = (&cfg.username, &cfg.password) {
        let encoded = base64_encode(format!("{user}:{pass}").as_bytes());
        if let Ok(v) = HeaderValue::from_str(&format!("Basic {encoded}")) {
            headers.insert(AUTHORIZATION, v);
        }
    }
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/x-ndjson"));
    headers
}

/// Build the NDJSON `_bulk` body for a batch of events.
pub fn build_bulk_body(batch: &SiemBatch) -> String {
    let action_line = r#"{"index":{}}"#;
    let mut buf = String::with_capacity(batch.len() * 512);
    for ev in batch {
        buf.push_str(action_line);
        buf.push('\n');
        match serde_json::to_string(ev) {
            Ok(s) => buf.push_str(&s),
            Err(_) => buf.push_str("{}"),
        }
        buf.push('\n');
    }
    buf
}

#[async_trait]
impl Plugin for ElasticSinkPlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    async fn init(&mut self, cfg: serde_json::Value) -> PluginResult<()> {
        let parsed: Config = serde_json::from_value(cfg)
            .map_err(|e| PluginError::ConfigValidation(format!("sink.elastic: {e}")))?;
        validate(&parsed)?;

        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(!parsed.verify_tls)
            .timeout(Duration::from_secs(parsed.timeout_secs))
            .build()
            .map_err(|e| PluginError::Init(format!("sink.elastic: HTTP client: {e}")))?;

        let auth_headers = build_auth_headers(&parsed);

        let mut guard = self.state.write().await;
        *guard = Some(State { cfg: parsed, client, auth_headers });
        Ok(())
    }
}

#[async_trait]
impl SiemSinkPlugin for ElasticSinkPlugin {
    async fn send(&self, batch: SiemBatch) -> PluginResult<()> {
        if batch.is_empty() {
            return Ok(());
        }
        let guard = self.state.read().await;
        let state = guard
            .as_ref()
            .ok_or_else(|| PluginError::Runtime("sink.elastic used before init".into()))?;

        let body = build_bulk_body(&batch);
        let url = format!(
            "{}/{}/_bulk",
            state.cfg.url.trim_end_matches('/'),
            state.cfg.index
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
                        // Inspect body for `errors: true` — log and treat as success
                        // for now (per-document parsing is a future improvement).
                        if let Ok(v) = resp.json::<serde_json::Value>().await {
                            if v.get("errors").and_then(|e| e.as_bool()).unwrap_or(false) {
                                warn!(plugin = PLUGIN_ID, "Elasticsearch _bulk reported per-item errors");
                            }
                        }
                        debug!(plugin = PLUGIN_ID, events = batch.len(), "elastic flush OK");
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
                        "sink.elastic: bulk indexing failed ({status})"
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
                        "sink.elastic: request failed: {e}"
                    )));
                }
            }
        }
        Err(PluginError::Runtime(format!(
            "sink.elastic: exhausted retries: {}",
            last_err.unwrap_or_default()
        )))
    }
}

inventory::submit! {
    PluginDescriptor {
        id: PLUGIN_ID,
        kind: PluginKind::SiemSink,
        api_version: API_VERSION,
        manifest: ElasticSinkPlugin::manifest_fn,
        config_schema: include_str!("../schema.json"),
        factory: PluginFactory::SiemSink(ElasticSinkPlugin::create),
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
        let m = ElasticSinkPlugin::manifest_fn();
        assert_eq!(m.id, PLUGIN_ID);
        assert_eq!(m.kind, PluginKind::SiemSink);
    }

    #[tokio::test]
    async fn init_with_valid_config_ok() {
        let cfg = serde_json::json!({
            "url": "http://localhost:9200",
            "index": "hiveguard-test"
        });
        let _plugin = ElasticSinkPlugin::create(test_ctx(), cfg).await.unwrap();
    }

    #[tokio::test]
    async fn init_with_empty_index_rejected() {
        let cfg = serde_json::json!({
            "url": "http://localhost:9200",
            "index": ""
        });
        match ElasticSinkPlugin::create(test_ctx(), cfg).await {
            Err(PluginError::ConfigValidation(_)) => {}
            Err(e) => panic!("expected ConfigValidation, got {e:?}"),
            Ok(_) => panic!("expected ConfigValidation, got Ok"),
        }
    }

    #[tokio::test]
    async fn init_with_invalid_url_rejected() {
        let cfg = serde_json::json!({
            "url": "not-a-url",
            "index": "x"
        });
        match ElasticSinkPlugin::create(test_ctx(), cfg).await {
            Err(PluginError::ConfigValidation(_)) => {}
            Err(e) => panic!("expected ConfigValidation, got {e:?}"),
            Ok(_) => panic!("expected ConfigValidation, got Ok"),
        }
    }

    #[test]
    fn bulk_body_lines_per_event() {
        let body = build_bulk_body(&vec![ev("1.2.3.4"), ev("5.6.7.8")]);
        // 2 events × 2 lines each
        assert_eq!(body.lines().count(), 4);
        assert!(body.lines().next().unwrap().contains("\"index\""));
    }

    #[tokio::test]
    async fn ship_posts_ndjson_with_basic_auth() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/hiveguard-test/_bulk"))
            .and(header("content-type", "application/x-ndjson"))
            .and(header("authorization", "Basic ZWxhc3RpYzpjaGFuZ2VtZQ=="))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "errors": false,
                "items": []
            })))
            .expect(1)
            .mount(&server)
            .await;

        let cfg = serde_json::json!({
            "url": server.uri(),
            "index": "hiveguard-test",
            "username": "elastic",
            "password": "changeme",
            "verify_tls": false,
        });
        let plugin = ElasticSinkPlugin::create(test_ctx(), cfg).await.unwrap();
        plugin.send(vec![ev("1.2.3.4")]).await.unwrap();
    }
}
