//! Telegram Bot API notifier.

use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;
use tokio::sync::RwLock;
use tracing::warn;

use hiveguard_plugin_api::prelude::*;
use hiveguard_plugin_utils::http;

pub const PLUGIN_ID: &str = "notifier.telegram";
const PLUGIN_VERSION: &str = "0.1.0";

#[derive(Debug, Clone, Deserialize)]
struct Config {
    bot_token: String,
    chat_id: String,
    #[serde(default = "default_timeout")]
    timeout_secs: u64,
    #[serde(default = "default_parse_mode")]
    parse_mode: String,
}

fn default_timeout() -> u64 { 10 }
fn default_parse_mode() -> String { "Markdown".into() }

pub struct TelegramPlugin {
    manifest: PluginManifest,
    state: RwLock<Option<State>>,
}

struct State {
    cfg: Config,
    client: reqwest::Client,
}

impl TelegramPlugin {
    pub fn manifest_fn() -> PluginManifest {
        PluginManifest {
            id: PLUGIN_ID,
            version: PLUGIN_VERSION,
            description: "Telegram Bot API notifier.",
            kind: PluginKind::Notifier,
            author: "HiveGuard",
            docs_url: Some(
                "https://github.com/anthropics/hiveguard/blob/main/plugins/notifier-telegram/README.md",
            ),
        }
    }

    pub fn create(
        _ctx: PluginContext,
        cfg: serde_json::Value,
    ) -> BoxFuture<'static, PluginResult<Box<dyn NotifierPlugin>>> {
        Box::pin(async move {
            let mut plugin = TelegramPlugin {
                manifest: Self::manifest_fn(),
                state: RwLock::new(None),
            };
            <TelegramPlugin as Plugin>::init(&mut plugin, cfg).await?;
            Ok(Box::new(plugin) as Box<dyn NotifierPlugin>)
        })
    }

    fn format(event: &AlertEvent) -> String {
        match event {
            AlertEvent::IpBanned { ip, severity, reason, .. } => {
                format!("🚫 *Banned* `{ip}` (severity {severity})\n_{reason}_")
            }
            AlertEvent::SubnetBanned { subnet, ip_count, reason } => {
                format!("⛔ *Subnet ban* `{subnet}` ({ip_count} IPs)\n_{reason}_")
            }
            AlertEvent::HoneypotHit { ip, path } => {
                format!("🍯 *Honeypot triggered* `{path}` from `{ip}`")
            }
            AlertEvent::HighThreatDetected { ip, score, top_detectors } => {
                format!("⚠️ *High threat* `{ip}` (score {score:.1})\n_{}_", top_detectors.join(", "))
            }
            AlertEvent::PeerDown { node_id, address } => {
                format!("📡 *Peer down* `{node_id}` ({address})")
            }
            AlertEvent::PeerQuarantined { node_id, reason } => {
                format!("🚫 *Peer quarantined* `{node_id}`\n_{reason}_")
            }
            AlertEvent::BanRateAnomaly { bans_per_minute, threshold } => {
                format!("📈 *Ban rate anomaly* {bans_per_minute}/min (threshold {threshold})")
            }
        }
    }
}

#[async_trait]
impl Plugin for TelegramPlugin {
    fn manifest(&self) -> &PluginManifest { &self.manifest }

    async fn init(&mut self, cfg: serde_json::Value) -> PluginResult<()> {
        let parsed: Config = serde_json::from_value(cfg)
            .map_err(|e| PluginError::ConfigValidation(e.to_string()))?;
        let client = http::build_client(Duration::from_secs(parsed.timeout_secs))?;
        *self.state.write().await = Some(State { cfg: parsed, client });
        Ok(())
    }
}

#[async_trait]
impl NotifierPlugin for TelegramPlugin {
    async fn notify(&self, event: &AlertEvent) -> PluginResult<()> {
        let guard = self.state.read().await;
        let state = guard.as_ref()
            .ok_or_else(|| PluginError::Runtime("telegram notifier used before init".into()))?;

        let text = Self::format(event);
        let url = format!("https://api.telegram.org/bot{}/sendMessage", state.cfg.bot_token);
        let payload = serde_json::json!({
            "chat_id": state.cfg.chat_id,
            "text": text,
            "parse_mode": state.cfg.parse_mode,
            "disable_web_page_preview": true,
        });

        let resp = state.client.post(&url)
            .json(&payload)
            .send()
            .await
            .map_err(|e| PluginError::Runtime(format!("HTTP: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            warn!(plugin = PLUGIN_ID, status = %status, "Telegram API returned non-2xx");
            return Err(PluginError::Runtime(format!("Telegram HTTP {status}")));
        }
        Ok(())
    }
}

inventory::submit! {
    PluginDescriptor {
        id: PLUGIN_ID,
        kind: PluginKind::Notifier,
        api_version: API_VERSION,
        manifest: TelegramPlugin::manifest_fn,
        config_schema: include_str!("../schema.json"),
        factory: PluginFactory::Notifier(TelegramPlugin::create),
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
    fn manifest_correct() {
        let m = TelegramPlugin::manifest_fn();
        assert_eq!(m.id, PLUGIN_ID);
        assert_eq!(m.kind, PluginKind::Notifier);
    }

    #[tokio::test]
    async fn factory_accepts_minimal() {
        let cfg = serde_json::json!({ "bot_token": "x", "chat_id": "1" });
        let _p = TelegramPlugin::create(test_ctx(), cfg).await.unwrap();
    }

    #[tokio::test]
    async fn factory_rejects_missing() {
        match TelegramPlugin::create(test_ctx(), serde_json::json!({})).await {
            Err(PluginError::ConfigValidation(_)) => {}
            Err(other) => panic!("expected ConfigValidation, got {other:?}"),
            Ok(_) => panic!("expected error"),
        }
    }
}
