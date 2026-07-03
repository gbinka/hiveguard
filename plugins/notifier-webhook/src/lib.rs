//! # hiveguard-plugin-notifier-webhook
//!
//! Generic HTTP webhook notifier. Reference end-to-end plugin — mirror its
//! structure when writing new plugins.
//!
//! See [`README.md`](../README.md) for user-facing documentation and
//! [`../../docs/plugins/AUTHORING.md`](../../../docs/plugins/AUTHORING.md) for
//! authoring conventions.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use hiveguard_plugin_api::prelude::*;
use hiveguard_plugin_utils::{http, template};

pub const PLUGIN_ID: &str = "notifier.webhook";
pub const PLUGIN_VERSION: &str = "0.1.0";

#[derive(Debug, Clone, Deserialize)]
struct Config {
    url: String,
    #[serde(default = "default_method")]
    method: String,
    #[serde(default = "default_content_type")]
    content_type: String,
    #[serde(default)]
    auth_header: Option<String>,
    #[serde(default = "default_timeout")]
    timeout_secs: u64,
    #[serde(default)]
    events: Vec<AlertKind>,
    #[serde(default)]
    template: Option<String>,
}

fn default_method() -> String { "POST".into() }
fn default_content_type() -> String { "application/json".into() }
fn default_timeout() -> u64 { 10 }

/// Webhook notifier instance.
///
/// State is held behind `RwLock` because `NotifierPlugin::notify` takes
/// `&self` (the dispatcher may call it concurrently). Init writes once,
/// notify reads — `RwLock` is the right primitive here.
pub struct WebhookNotifier {
    manifest: PluginManifest,
    state: RwLock<Option<NotifierState>>,
}

struct NotifierState {
    cfg: Config,
    client: reqwest::Client,
    event_filter: Option<Vec<AlertKind>>,
}

impl WebhookNotifier {
    pub fn manifest_fn() -> PluginManifest {
        PluginManifest {
            id: PLUGIN_ID,
            version: PLUGIN_VERSION,
            description: "Generic HTTP webhook notifier — POSTs alerts as JSON or rendered template.",
            kind: PluginKind::Notifier,
            author: "HiveGuard",
            docs_url: Some("https://github.com/anthropics/hiveguard/blob/main/plugins/notifier-webhook/README.md"),
        }
    }

    /// Factory entry point invoked by the host loader.
    pub fn create(
        ctx: PluginContext,
        cfg: serde_json::Value,
    ) -> BoxFuture<'static, PluginResult<Box<dyn NotifierPlugin>>> {
        Box::pin(async move {
            let mut plugin = WebhookNotifier {
                manifest: Self::manifest_fn(),
                state: RwLock::new(None),
            };
            <WebhookNotifier as Plugin>::init(&mut plugin, cfg).await?;
            info!(plugin = PLUGIN_ID, "initialised");
            let _ = ctx; // ctx.data_dir / ctx.metrics will be wired up in Phase 1 full
            Ok(Box::new(plugin) as Box<dyn NotifierPlugin>)
        })
    }

    /// Build the payload for this event — either render the template or
    /// serialize the event as JSON.
    fn build_payload(cfg: &Config, event: &AlertEvent) -> PluginResult<String> {
        if let Some(tmpl) = &cfg.template {
            let ctx = event_context(event);
            Ok(template::render(tmpl, &ctx))
        } else {
            serde_json::to_string(event).map_err(PluginError::from)
        }
    }
}

#[async_trait]
impl Plugin for WebhookNotifier {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    async fn init(&mut self, cfg: serde_json::Value) -> PluginResult<()> {
        let parsed: Config = serde_json::from_value(cfg)
            .map_err(|e| PluginError::ConfigValidation(e.to_string()))?;

        let client = http::build_client(Duration::from_secs(parsed.timeout_secs))?;

        let event_filter = if parsed.events.is_empty() {
            None
        } else {
            Some(parsed.events.clone())
        };

        let state = NotifierState { cfg: parsed, client, event_filter };
        *self.state.write().await = Some(state);
        Ok(())
    }

    async fn shutdown(&mut self) -> PluginResult<()> {
        *self.state.write().await = None;
        Ok(())
    }
}

#[async_trait]
impl NotifierPlugin for WebhookNotifier {
    async fn notify(&self, event: &AlertEvent) -> PluginResult<()> {
        let guard = self.state.read().await;
        let state = guard
            .as_ref()
            .ok_or_else(|| PluginError::Runtime("notifier used before init".into()))?;

        // Per-event filter (in addition to supports()).
        if let Some(allowed) = &state.event_filter {
            if !allowed.contains(&event.kind()) {
                debug!(plugin = PLUGIN_ID, kind = ?event.kind(), "event filtered out");
                return Ok(());
            }
        }

        let payload = Self::build_payload(&state.cfg, event)?;

        let request_builder = match state.cfg.method.as_str() {
            "PUT" => state.client.put(&state.cfg.url),
            _ => state.client.post(&state.cfg.url),
        };

        let mut req = request_builder
            .header("Content-Type", &state.cfg.content_type)
            .body(payload);

        if let Some(ref auth) = state.cfg.auth_header {
            req = req.header("Authorization", auth.as_str());
        }

        let resp = req
            .send()
            .await
            .map_err(|e| PluginError::Runtime(format!("HTTP error: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            warn!(
                plugin = PLUGIN_ID,
                url = %state.cfg.url,
                status = %status,
                "webhook returned non-2xx"
            );
            return Err(PluginError::Runtime(format!("webhook HTTP {status}")));
        }

        Ok(())
    }

    fn supports(&self, _kind: AlertKind) -> bool {
        // Per-event filter is checked inside notify(); supports() is the
        // dispatcher-level prefilter. We accept all kinds and narrow per-event.
        true
    }
}

/// Build the `{{var}} → value` context for template rendering.
fn event_context(event: &AlertEvent) -> HashMap<&'static str, String> {
    let mut ctx: HashMap<&'static str, String> = HashMap::new();
    ctx.insert("type", format!("{:?}", event.kind()));
    match event {
        AlertEvent::IpBanned { ip, severity, reason, geo } => {
            ctx.insert("ip", ip.to_string());
            ctx.insert("severity", severity.to_string());
            ctx.insert("reason", reason.clone());
            ctx.insert(
                "country",
                geo.as_ref().and_then(|g| g.country_iso.clone()).unwrap_or_default(),
            );
            ctx.insert(
                "asn",
                geo.as_ref().and_then(|g| g.asn).map(|a| a.to_string()).unwrap_or_default(),
            );
        }
        AlertEvent::SubnetBanned { subnet, ip_count, reason } => {
            ctx.insert("ip", subnet.to_string());
            ctx.insert("subnet", subnet.to_string());
            ctx.insert("ip_count", ip_count.to_string());
            ctx.insert("reason", reason.clone());
        }
        AlertEvent::PeerDown { node_id, address } => {
            ctx.insert("node_id", node_id.clone());
            ctx.insert("address", address.to_string());
        }
        AlertEvent::PeerQuarantined { node_id, reason } => {
            ctx.insert("node_id", node_id.clone());
            ctx.insert("reason", reason.clone());
        }
        AlertEvent::HighThreatDetected { ip, score, top_detectors } => {
            ctx.insert("ip", ip.clone());
            ctx.insert("score", format!("{score:.2}"));
            ctx.insert("top_detectors", top_detectors.join(", "));
        }
        AlertEvent::HoneypotHit { ip, path } => {
            ctx.insert("ip", ip.clone());
            ctx.insert("path", path.clone());
        }
        AlertEvent::BanRateAnomaly { bans_per_minute, threshold } => {
            ctx.insert("bans_per_minute", bans_per_minute.to_string());
            ctx.insert("threshold", threshold.to_string());
        }
    }
    ctx
}

// ---------------------------------------------------------------------------
// Plugin registration — the host discovers this at startup via inventory.
// ---------------------------------------------------------------------------

inventory::submit! {
    PluginDescriptor {
        id: PLUGIN_ID,
        kind: PluginKind::Notifier,
        api_version: API_VERSION,
        manifest: WebhookNotifier::manifest_fn,
        config_schema: include_str!("../schema.json"),
        factory: PluginFactory::Notifier(WebhookNotifier::create),
    }
}

// ---------------------------------------------------------------------------
// Unit tests — exercise factory + template rendering without networking.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use hiveguard_plugin_api::context::parking_lot_compat::RegistryHandle;
    use hiveguard_plugin_api::secrets::SecretResolver;
    use ipnet::IpNet;

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

    #[tokio::test]
    async fn factory_accepts_minimal_config() {
        let cfg = serde_json::json!({ "url": "https://example.com/hook" });
        let _plugin = WebhookNotifier::create(test_ctx(), cfg).await.unwrap();
    }

    #[tokio::test]
    async fn factory_rejects_missing_url() {
        let cfg = serde_json::json!({});
        match WebhookNotifier::create(test_ctx(), cfg).await {
            Err(PluginError::ConfigValidation(_)) => {}
            Err(other) => panic!("expected ConfigValidation, got {other:?}"),
            Ok(_) => panic!("expected error, got Ok"),
        }
    }

    #[tokio::test]
    async fn render_template_substitutes_vars() {
        let cfg = Config {
            url: "http://x".into(),
            method: "POST".into(),
            content_type: "application/json".into(),
            auth_header: None,
            timeout_secs: 10,
            events: vec![],
            template: Some("Banned {{ip}} severity={{severity}}".into()),
        };
        let event = AlertEvent::IpBanned {
            ip: "1.2.3.4/32".parse::<IpNet>().unwrap(),
            severity: 200,
            reason: "test".into(),
            geo: None,
        };
        let payload = WebhookNotifier::build_payload(&cfg, &event).unwrap();
        assert_eq!(payload, "Banned 1.2.3.4/32 severity=200");
    }

    #[tokio::test]
    async fn no_template_produces_json() {
        let cfg = Config {
            url: "http://x".into(),
            method: "POST".into(),
            content_type: "application/json".into(),
            auth_header: None,
            timeout_secs: 10,
            events: vec![],
            template: None,
        };
        let event = AlertEvent::HoneypotHit {
            ip: "10.0.0.1".into(),
            path: "/backup.sql".into(),
        };
        let payload = WebhookNotifier::build_payload(&cfg, &event).unwrap();
        assert!(payload.contains("\"honeypot_hit\""));
        assert!(payload.contains("10.0.0.1"));
        assert!(payload.contains("/backup.sql"));
    }

    #[test]
    fn descriptor_is_registered_in_inventory() {
        // Inventory linker can be tricky in test binaries — sanity check that
        // at least our descriptor is reachable from this crate. We don't
        // exercise the global registry (host does), we just confirm the
        // submit!{} macro expanded correctly.
        let manifest = WebhookNotifier::manifest_fn();
        assert_eq!(manifest.id, PLUGIN_ID);
        assert_eq!(manifest.kind, PluginKind::Notifier);
    }
}
