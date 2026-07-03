//! RFC 5424 syslog forwarder sink.
//!
//! Native implementation — does not depend on the legacy `siem_exporter` in
//! daemon. Connection is lazily established on first `send`; reconnects on
//! failure with a short backoff.

use std::sync::Arc;

use chrono::Utc;
use serde::Deserialize;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Mutex;
use tracing::{debug, warn};

use hiveguard_plugin_api::prelude::*;

pub const PLUGIN_ID: &str = "sink.syslog";
const PLUGIN_VERSION: &str = "0.1.0";

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Protocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Deserialize)]
struct Config {
    host: String,
    #[serde(default = "default_protocol")]
    protocol: Protocol,
    #[serde(default = "default_facility")]
    facility: u8,
    #[serde(default = "default_severity")]
    severity: u8,
    #[serde(default)]
    hostname: Option<String>,
    #[serde(default = "default_app_name")]
    app_name: String,
}

fn default_protocol() -> Protocol { Protocol::Tcp }
fn default_facility() -> u8 { 1 }
fn default_severity() -> u8 { 5 }
fn default_app_name() -> String { "hiveguard".to_string() }

enum Connection {
    Tcp(TcpStream),
    Udp(UdpSocket),
    Disconnected,
}

pub struct SyslogSinkPlugin {
    manifest: PluginManifest,
    config: Option<Config>,
    conn: Arc<Mutex<Connection>>,
}

impl SyslogSinkPlugin {
    pub fn manifest_fn() -> PluginManifest {
        PluginManifest {
            id: PLUGIN_ID,
            version: PLUGIN_VERSION,
            description: "RFC 5424 syslog forwarder (TCP/UDP).",
            kind: PluginKind::SiemSink,
            author: "HiveGuard",
            docs_url: Some(
                "https://github.com/anthropics/hiveguard/blob/main/plugins/sink-syslog/README.md",
            ),
        }
    }

    pub fn create(
        _ctx: PluginContext,
        cfg: serde_json::Value,
    ) -> BoxFuture<'static, PluginResult<Box<dyn SiemSinkPlugin>>> {
        Box::pin(async move {
            let mut plugin = SyslogSinkPlugin {
                manifest: Self::manifest_fn(),
                config: None,
                conn: Arc::new(Mutex::new(Connection::Disconnected)),
            };
            <SyslogSinkPlugin as Plugin>::init(&mut plugin, cfg).await?;
            Ok(Box::new(plugin) as Box<dyn SiemSinkPlugin>)
        })
    }

    fn build_priority(&self, cfg: &Config) -> u8 {
        cfg.facility * 8 + cfg.severity
    }

    fn hostname(cfg: &Config) -> String {
        cfg.hostname.clone().unwrap_or_else(|| {
            std::env::var("HOSTNAME").unwrap_or_else(|_| "localhost".to_string())
        })
    }
}

#[async_trait]
impl Plugin for SyslogSinkPlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    async fn init(&mut self, cfg: serde_json::Value) -> PluginResult<()> {
        let parsed: Config = serde_json::from_value(cfg)
            .map_err(|e| PluginError::ConfigValidation(e.to_string()))?;
        self.config = Some(parsed);
        Ok(())
    }

    async fn shutdown(&mut self) -> PluginResult<()> {
        let mut conn = self.conn.lock().await;
        *conn = Connection::Disconnected;
        Ok(())
    }
}

#[async_trait]
impl SiemSinkPlugin for SyslogSinkPlugin {
    async fn send(&self, batch: SiemBatch) -> PluginResult<()> {
        let cfg = self
            .config
            .as_ref()
            .ok_or_else(|| PluginError::Runtime("sink used before init".into()))?;

        let pri = self.build_priority(cfg);
        let host = Self::hostname(cfg);

        for event in &batch {
            let payload = serde_json::to_string(event).map_err(PluginError::from)?;
            let timestamp = Utc::now().to_rfc3339();
            let msg = format!(
                "<{pri}>1 {timestamp} {host} {app} - - - {payload}\n",
                pri = pri,
                app = cfg.app_name,
            );
            self.send_raw(cfg, &msg).await?;
        }
        Ok(())
    }
}

impl SyslogSinkPlugin {
    async fn send_raw(&self, cfg: &Config, msg: &str) -> PluginResult<()> {
        let mut conn = self.conn.lock().await;
        // Lazy connect / reconnect.
        if matches!(*conn, Connection::Disconnected) {
            *conn = match cfg.protocol {
                Protocol::Tcp => {
                    let stream = TcpStream::connect(&cfg.host).await.map_err(|e| {
                        PluginError::Runtime(format!("TCP connect to {}: {e}", cfg.host))
                    })?;
                    Connection::Tcp(stream)
                }
                Protocol::Udp => {
                    let sock = UdpSocket::bind("0.0.0.0:0").await.map_err(PluginError::Io)?;
                    sock.connect(&cfg.host).await.map_err(|e| {
                        PluginError::Runtime(format!("UDP connect to {}: {e}", cfg.host))
                    })?;
                    Connection::Udp(sock)
                }
            };
            debug!(plugin = PLUGIN_ID, host = %cfg.host, "syslog connected");
        }

        let send_result = match &mut *conn {
            Connection::Tcp(stream) => stream.write_all(msg.as_bytes()).await.map_err(|e| {
                PluginError::Runtime(format!("TCP write: {e}"))
            }),
            Connection::Udp(sock) => sock
                .send(msg.as_bytes())
                .await
                .map(|_| ())
                .map_err(|e| PluginError::Runtime(format!("UDP send: {e}"))),
            Connection::Disconnected => unreachable!("just connected above"),
        };

        if let Err(e) = &send_result {
            warn!(plugin = PLUGIN_ID, error = %e, "syslog write failed, will reconnect on next send");
            *conn = Connection::Disconnected;
        }
        send_result
    }
}

inventory::submit! {
    PluginDescriptor {
        id: PLUGIN_ID,
        kind: PluginKind::SiemSink,
        api_version: API_VERSION,
        manifest: SyslogSinkPlugin::manifest_fn,
        config_schema: include_str!("../schema.json"),
        factory: PluginFactory::SiemSink(SyslogSinkPlugin::create),
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
        let m = SyslogSinkPlugin::manifest_fn();
        assert_eq!(m.id, PLUGIN_ID);
        assert_eq!(m.kind, PluginKind::SiemSink);
    }

    #[tokio::test]
    async fn factory_accepts_minimal_config() {
        let cfg = serde_json::json!({ "host": "localhost:514" });
        let _plugin = SyslogSinkPlugin::create(test_ctx(), cfg).await.unwrap();
    }

    #[tokio::test]
    async fn factory_rejects_missing_host() {
        match SyslogSinkPlugin::create(test_ctx(), serde_json::json!({})).await {
            Err(PluginError::ConfigValidation(_)) => {}
            Err(other) => panic!("expected ConfigValidation, got {other:?}"),
            Ok(_) => panic!("expected error"),
        }
    }
}
