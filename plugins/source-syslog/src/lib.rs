mod netdev_parser;
mod parsers;
mod source;
mod syslog_parser;
mod syslog_router;

use std::sync::Arc;

use serde::Deserialize;

use hiveguard_core::config::{SyslogRouteConfig, SyslogTcpConfig, SyslogTlsConfig, SyslogUdpConfig};
use hiveguard_plugin_api::prelude::*;

use crate::source::{run_tcp, run_tls, run_udp};
use crate::syslog_router::SyslogRouter;

pub const UDP_PLUGIN_ID: &str = "source.syslog.udp";
pub const TCP_PLUGIN_ID: &str = "source.syslog.tcp";
pub const TLS_PLUGIN_ID: &str = "source.syslog.tls";
const PLUGIN_VERSION: &str = "0.1.0";

#[derive(Debug, Clone, Deserialize)]
struct UdpPluginConfig {
    #[serde(flatten)]
    transport: SyslogUdpConfig,
    #[serde(default)]
    routes: Vec<SyslogRouteConfig>,
}

#[derive(Debug, Clone, Deserialize)]
struct TcpPluginConfig {
    #[serde(flatten)]
    transport: SyslogTcpConfig,
    #[serde(default)]
    routes: Vec<SyslogRouteConfig>,
}

#[derive(Debug, Clone, Deserialize)]
struct TlsPluginConfig {
    #[serde(flatten)]
    transport: SyslogTlsConfig,
    #[serde(default)]
    routes: Vec<SyslogRouteConfig>,
}

enum Mode {
    Udp(SyslogUdpConfig),
    Tcp(SyslogTcpConfig),
    Tls(SyslogTlsConfig),
}

struct State {
    mode: Mode,
    router: Arc<SyslogRouter>,
}

pub struct SyslogSourcePlugin {
    manifest: PluginManifest,
    state: Option<State>,
}

impl SyslogSourcePlugin {
    fn manifest_for(id: &'static str, description: &'static str) -> PluginManifest {
        PluginManifest {
            id,
            version: PLUGIN_VERSION,
            description,
            kind: PluginKind::LogSource,
            author: "HiveGuard",
            docs_url: Some("https://github.com/anthropics/hiveguard/blob/main/plugins/source-syslog/README.md"),
        }
    }

    fn create_with_manifest(cfg: serde_json::Value, manifest: PluginManifest) -> BoxFuture<'static, PluginResult<Box<dyn LogSourcePlugin>>> {
        Box::pin(async move {
            let mut plugin = SyslogSourcePlugin { manifest, state: None };
            <SyslogSourcePlugin as Plugin>::init(&mut plugin, cfg).await?;
            Ok(Box::new(plugin) as Box<dyn LogSourcePlugin>)
        })
    }

    pub fn create_udp(_ctx: PluginContext, cfg: serde_json::Value) -> BoxFuture<'static, PluginResult<Box<dyn LogSourcePlugin>>> {
        Self::create_with_manifest(cfg, Self::manifest_for(UDP_PLUGIN_ID, "Network syslog source over UDP (RFC 5426)."))
    }

    pub fn create_tcp(_ctx: PluginContext, cfg: serde_json::Value) -> BoxFuture<'static, PluginResult<Box<dyn LogSourcePlugin>>> {
        Self::create_with_manifest(cfg, Self::manifest_for(TCP_PLUGIN_ID, "Network syslog source over TCP (RFC 6587)."))
    }

    pub fn create_tls(_ctx: PluginContext, cfg: serde_json::Value) -> BoxFuture<'static, PluginResult<Box<dyn LogSourcePlugin>>> {
        Self::create_with_manifest(cfg, Self::manifest_for(TLS_PLUGIN_ID, "Network syslog source over TLS (RFC 5425)."))
    }

    fn build_state(plugin_id: &str, cfg: serde_json::Value) -> PluginResult<State> {
        match plugin_id {
            UDP_PLUGIN_ID => {
                let cfg: UdpPluginConfig = serde_json::from_value(cfg).map_err(|e| PluginError::ConfigValidation(e.to_string()))?;
                Ok(State { mode: Mode::Udp(cfg.transport), router: Arc::new(SyslogRouter::from_config(&cfg.routes)?) })
            }
            TCP_PLUGIN_ID => {
                let cfg: TcpPluginConfig = serde_json::from_value(cfg).map_err(|e| PluginError::ConfigValidation(e.to_string()))?;
                Ok(State { mode: Mode::Tcp(cfg.transport), router: Arc::new(SyslogRouter::from_config(&cfg.routes)?) })
            }
            TLS_PLUGIN_ID => {
                let cfg: TlsPluginConfig = serde_json::from_value(cfg).map_err(|e| PluginError::ConfigValidation(e.to_string()))?;
                Ok(State { mode: Mode::Tls(cfg.transport), router: Arc::new(SyslogRouter::from_config(&cfg.routes)?) })
            }
            other => Err(PluginError::Runtime(format!("unsupported plugin id: {other}"))),
        }
    }
}

#[async_trait]
impl Plugin for SyslogSourcePlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    async fn init(&mut self, cfg: serde_json::Value) -> PluginResult<()> {
        self.state = Some(Self::build_state(self.manifest.id, cfg)?);
        Ok(())
    }

    async fn shutdown(&mut self) -> PluginResult<()> {
        self.state = None;
        Ok(())
    }
}

#[async_trait]
impl LogSourcePlugin for SyslogSourcePlugin {
    async fn run(&mut self, sink: EventSink, shutdown: CancellationToken) -> PluginResult<()> {
        let state = self.state.as_ref().ok_or_else(|| PluginError::Runtime("log source used before init".into()))?;
        match &state.mode {
            Mode::Udp(config) => run_udp(config.clone(), state.router.clone(), self.manifest.id.to_string(), sink, shutdown).await,
            Mode::Tcp(config) => run_tcp(config.clone(), state.router.clone(), self.manifest.id.to_string(), sink, shutdown).await,
            Mode::Tls(config) => run_tls(config.clone(), state.router.clone(), self.manifest.id.to_string(), sink, shutdown).await,
        }
    }
}

inventory::submit! {
    PluginDescriptor {
        id: UDP_PLUGIN_ID,
        kind: PluginKind::LogSource,
        api_version: API_VERSION,
        manifest: || SyslogSourcePlugin::manifest_for(UDP_PLUGIN_ID, "Network syslog source over UDP (RFC 5426)."),
        config_schema: include_str!("../schema-udp.json"),
        factory: PluginFactory::LogSource(SyslogSourcePlugin::create_udp),
    }
}

inventory::submit! {
    PluginDescriptor {
        id: TCP_PLUGIN_ID,
        kind: PluginKind::LogSource,
        api_version: API_VERSION,
        manifest: || SyslogSourcePlugin::manifest_for(TCP_PLUGIN_ID, "Network syslog source over TCP (RFC 6587)."),
        config_schema: include_str!("../schema-tcp.json"),
        factory: PluginFactory::LogSource(SyslogSourcePlugin::create_tcp),
    }
}

inventory::submit! {
    PluginDescriptor {
        id: TLS_PLUGIN_ID,
        kind: PluginKind::LogSource,
        api_version: API_VERSION,
        manifest: || SyslogSourcePlugin::manifest_for(TLS_PLUGIN_ID, "Network syslog source over TLS (RFC 5425)."),
        config_schema: include_str!("../schema-tls.json"),
        factory: PluginFactory::LogSource(SyslogSourcePlugin::create_tls),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use hiveguard_plugin_api::context::parking_lot_compat::RegistryHandle;
    use hiveguard_plugin_api::secrets::SecretResolver;

    use super::*;

    fn test_context(plugin_id: &str) -> PluginContext {
        PluginContext::new(
            plugin_id.to_string(),
            std::env::temp_dir().join("hg-source-syslog-tests"),
            Arc::new(SecretResolver::new()),
            PluginMetrics {
                registry: Arc::new(RegistryHandle::default()),
                plugin_id: plugin_id.to_string(),
            },
            CancellationToken::new(),
        )
    }

    #[tokio::test]
    async fn init_accepts_udp_config() {
        let plugin = SyslogSourcePlugin::create_udp(
            test_context(UDP_PLUGIN_ID),
            serde_json::json!({
                "listen": "127.0.0.1:5514",
                "routes": [
                    {
                        "match": { "app_name": "kernel" },
                        "parser": "iptables"
                    }
                ]
            }),
        )
        .await
        .unwrap();
        assert_eq!(plugin.manifest().id, UDP_PLUGIN_ID);
    }

    #[test]
    fn invalid_custom_route_rejected() {
        let result = SyslogSourcePlugin::build_state(
            UDP_PLUGIN_ID,
            serde_json::json!({
                "listen": "127.0.0.1:5514",
                "routes": [
                    {
                        "match": { "app_name": "myapp" },
                        "parser": "custom",
                        "pattern": "[broken"
                    }
                ]
            }),
        );
        assert!(matches!(result, Err(PluginError::Other(_)) | Err(PluginError::ConfigValidation(_))));
    }
}