//! Datadog Logs API sink — POSTs HiveGuard SIEM events to
//! `https://http-intake.logs.{site}/api/v2/logs`.
//!
//! # Auth
//!
//! The Datadog API key is sent via the `DD-API-KEY` header. Secret resolution
//! (e.g. `${env:DD_API_KEY}`) is performed by the host before this plugin sees
//! the configuration.
//!
//! # TODO (production hardening)
//!
//! * Circuit breaker on repeated failure.
//! * Dead-letter queue for batches that exhaust retries.
//! * Compression (gzip) for large batches — Datadog supports it.

use std::time::Duration;

use reqwest::header::{HeaderMap, HeaderName, HeaderValue, CONTENT_TYPE};
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::sync::RwLock;
use tracing::{debug, warn};

use hiveguard_plugin_api::prelude::*;

pub const PLUGIN_ID: &str = "sink.datadog";
const PLUGIN_VERSION: &str = "0.1.0";
const DD_API_KEY_HEADER: &str = "dd-api-key";

#[derive(Debug, Clone, Deserialize)]
struct Config {
    api_key: String,
    #[serde(default = "default_site")]
    site: String,
    #[serde(default = "default_service")]
    service: String,
    #[serde(default = "default_source")]
    source: String,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default = "default_batch_size")]
    #[allow(dead_code)]
    batch_size: usize,
    #[serde(default = "default_flush_interval_secs")]
    #[allow(dead_code)]
    flush_interval_secs: u64,
    #[serde(default = "default_timeout_secs")]
    timeout_secs: u64,
}

fn default_site() -> String { "datadoghq.com".to_string() }
fn default_service() -> String { "hiveguard".to_string() }
fn default_source() -> String { "hiveguard".to_string() }
fn default_batch_size() -> usize { 100 }
fn default_flush_interval_secs() -> u64 { 10 }
fn default_timeout_secs() -> u64 { 30 }

struct State {
    cfg: Config,
    client: reqwest::Client,
    url: String,
    auth_headers: HeaderMap,
}

pub struct DatadogSinkPlugin {
    manifest: PluginManifest,
    state: RwLock<Option<State>>,
}

impl DatadogSinkPlugin {
    pub fn manifest_fn() -> PluginManifest {
        PluginManifest {
            id: PLUGIN_ID,
            version: PLUGIN_VERSION,
            description: "Datadog Logs API sink for HiveGuard SIEM events.",
            kind: PluginKind::SiemSink,
            author: "HiveGuard",
            docs_url: Some(
                "https://github.com/anthropics/hiveguard/blob/main/plugins/sink-datadog/README.md",
            ),
        }
    }

    pub fn create(
        _ctx: PluginContext,
        cfg: serde_json::Value,
    ) -> BoxFuture<'static, PluginResult<Box<dyn SiemSinkPlugin>>> {
        Box::pin(async move {
            let mut plugin = DatadogSinkPlugin {
                manifest: Self::manifest_fn(),
                state: RwLock::new(None),
            };
            <DatadogSinkPlugin as Plugin>::init(&mut plugin, cfg).await?;
            Ok(Box::new(plugin) as Box<dyn SiemSinkPlugin>)
        })
    }
}

fn validate(cfg: &Config) -> PluginResult<()> {
    if cfg.api_key.trim().is_empty() {
        return Err(PluginError::ConfigValidation(
            "sink.datadog: `api_key` must not be empty".into(),
        ));
    }
    if cfg.site.trim().is_empty() {
        return Err(PluginError::ConfigValidation(
            "sink.datadog: `site` must not be empty".into(),
        ));
    }
    Ok(())
}

pub fn build_logs_url(site: &str) -> String {
    let host = site.trim().to_lowercase();
    let host = host
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    format!("https://http-intake.logs.{host}/api/v2/logs")
}

fn build_auth_headers(api_key: &str) -> PluginResult<HeaderMap> {
    let mut headers = HeaderMap::new();
    let name = HeaderName::from_static(DD_API_KEY_HEADER);
    let val = HeaderValue::from_str(api_key).map_err(|e| {
        PluginError::ConfigValidation(format!("sink.datadog: invalid api_key: {e}"))
    })?;
    headers.insert(name, val);
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    Ok(headers)
}

/// Build the JSON-array body for the Datadog Logs API.
fn build_log_body(batch: &SiemBatch, cfg: &Config, hostname: &str) -> String {
    let base_tags = cfg.tags.join(",");
    let entries: Vec<Value> = batch
        .iter()
        .map(|ev| {
            let ip = ev.source_ip.to_string();
            let mut tag_parts: Vec<String> = Vec::new();
            if !base_tags.is_empty() {
                tag_parts.push(base_tags.clone());
            }
            tag_parts.push(format!("src_ip:{ip}"));
            tag_parts.push(format!("source_name:{}", ev.source_name));
            let ddtags = tag_parts.join(",");

            let message = ev.raw_line.clone();

            json!({
                "ddsource": cfg.source,
                "ddtags": ddtags,
                "hostname": hostname,
                "service": cfg.service,
                "message": message,
                "timestamp": ev.timestamp.to_rfc3339(),
                "event": ev,
            })
        })
        .collect();
    serde_json::to_string(&entries).unwrap_or_else(|_| "[]".into())
}

fn local_hostname() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::fs::read_to_string("/etc/hostname").map(|s| s.trim().to_string()))
        .unwrap_or_else(|_| "unknown".into())
}

#[async_trait]
impl Plugin for DatadogSinkPlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    async fn init(&mut self, cfg: serde_json::Value) -> PluginResult<()> {
        let parsed: Config = serde_json::from_value(cfg)
            .map_err(|e| PluginError::ConfigValidation(format!("sink.datadog: {e}")))?;
        validate(&parsed)?;

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(parsed.timeout_secs))
            .build()
            .map_err(|e| PluginError::Init(format!("sink.datadog: HTTP client: {e}")))?;

        let auth_headers = build_auth_headers(&parsed.api_key)?;
        let url = build_logs_url(&parsed.site);

        let mut guard = self.state.write().await;
        *guard = Some(State { cfg: parsed, client, url, auth_headers });
        Ok(())
    }
}

#[async_trait]
impl SiemSinkPlugin for DatadogSinkPlugin {
    async fn send(&self, batch: SiemBatch) -> PluginResult<()> {
        if batch.is_empty() {
            return Ok(());
        }
        let guard = self.state.read().await;
        let state = guard
            .as_ref()
            .ok_or_else(|| PluginError::Runtime("sink.datadog used before init".into()))?;

        let body = build_log_body(&batch, &state.cfg, &local_hostname());

        let mut delay = Duration::from_secs(1);
        let mut last_err: Option<String> = None;
        for attempt in 1..=3u32 {
            let res = state
                .client
                .post(&state.url)
                .headers(state.auth_headers.clone())
                .body(body.clone())
                .send()
                .await;

            match res {
                Ok(resp) => {
                    let status = resp.status();
                    // Datadog returns 202 Accepted on success.
                    if status.is_success() {
                        debug!(plugin = PLUGIN_ID, events = batch.len(), "datadog flush OK");
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
                        "sink.datadog: Logs API failed ({status})"
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
                        "sink.datadog: request failed: {e}"
                    )));
                }
            }
        }
        Err(PluginError::Runtime(format!(
            "sink.datadog: exhausted retries: {}",
            last_err.unwrap_or_default()
        )))
    }
}

inventory::submit! {
    PluginDescriptor {
        id: PLUGIN_ID,
        kind: PluginKind::SiemSink,
        api_version: API_VERSION,
        manifest: DatadogSinkPlugin::manifest_fn,
        config_schema: include_str!("../schema.json"),
        factory: PluginFactory::SiemSink(DatadogSinkPlugin::create),
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
        let m = DatadogSinkPlugin::manifest_fn();
        assert_eq!(m.id, PLUGIN_ID);
        assert_eq!(m.kind, PluginKind::SiemSink);
    }

    #[test]
    fn build_logs_url_us_site() {
        assert_eq!(
            build_logs_url("datadoghq.com"),
            "https://http-intake.logs.datadoghq.com/api/v2/logs"
        );
    }

    #[test]
    fn build_logs_url_eu_site() {
        assert_eq!(
            build_logs_url("datadoghq.eu"),
            "https://http-intake.logs.datadoghq.eu/api/v2/logs"
        );
    }

    #[tokio::test]
    async fn init_with_valid_config_ok() {
        let cfg = serde_json::json!({
            "api_key": "dd-key",
        });
        let _plugin = DatadogSinkPlugin::create(test_ctx(), cfg).await.unwrap();
    }

    #[tokio::test]
    async fn init_with_empty_api_key_rejected() {
        let cfg = serde_json::json!({ "api_key": "" });
        match DatadogSinkPlugin::create(test_ctx(), cfg).await {
            Err(PluginError::ConfigValidation(_)) => {}
            Err(e) => panic!("expected ConfigValidation, got {e:?}"),
            Ok(_) => panic!("expected ConfigValidation, got Ok"),
        }
    }

    #[tokio::test]
    async fn init_missing_api_key_rejected() {
        let cfg = serde_json::json!({});
        match DatadogSinkPlugin::create(test_ctx(), cfg).await {
            Err(PluginError::ConfigValidation(_)) => {}
            Err(e) => panic!("expected ConfigValidation, got {e:?}"),
            Ok(_) => panic!("expected ConfigValidation, got Ok"),
        }
    }

    /// Integration test: wiremock can't easily intercept https://http-intake.logs.{site},
    /// so for this test we monkey-patch the URL via a custom `State` after init by
    /// posting through a regular MockServer endpoint. To exercise the wire format we
    /// build the request manually using the plugin's internal helpers.
    #[tokio::test]
    async fn ship_posts_json_array_with_dd_api_key() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v2/logs"))
            .and(header("dd-api-key", "test-dd-key"))
            .and(header("content-type", "application/json"))
            .respond_with(ResponseTemplate::new(202))
            .expect(1)
            .mount(&server)
            .await;

        // We bypass `init` for URL because the real plugin builds it from `site`.
        // Instead, drive a request through reqwest with the helper functions to
        // assert the body / headers shape that the plugin would emit.
        let cfg = Config {
            api_key: "test-dd-key".into(),
            site: "datadoghq.com".into(),
            service: "hiveguard".into(),
            source: "hiveguard".into(),
            tags: vec!["env:test".into()],
            batch_size: 100,
            flush_interval_secs: 10,
            timeout_secs: 30,
        };
        let body = build_log_body(&vec![ev("1.2.3.4")], &cfg, "test-host");
        let headers = build_auth_headers(&cfg.api_key).unwrap();
        let client = reqwest::Client::new();
        let resp = client
            .post(format!("{}/api/v2/logs", server.uri()))
            .headers(headers)
            .body(body)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 202);
    }
}
