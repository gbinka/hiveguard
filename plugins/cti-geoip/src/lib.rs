use std::collections::HashSet;
use std::net::IpAddr;
use std::path::PathBuf;

use serde::Deserialize;

use hiveguard_cti::GeoIpDb;
use hiveguard_plugin_api::prelude::*;

const PLUGIN_ID: &str = "cti.geoip";
const PLUGIN_VERSION: &str = "0.1.0";

#[derive(Debug, Deserialize)]
struct Config {
    #[serde(default, alias = "database_path")]
    data_dir: Option<PathBuf>,
    #[serde(default)]
    trusted_asns: Vec<u32>,
    #[serde(default = "default_confidence")]
    datacenter_confidence: u8,
    #[serde(default, alias = "recommend_ban_datacenter")]
    ban_on_first_hit: bool,
}

fn default_confidence() -> u8 { 30 }

pub struct GeoIpPlugin {
    manifest: PluginManifest,
    db: Option<GeoIpDb>,
    default_data_dir: PathBuf,
    trusted_asns: HashSet<u32>,
    datacenter_confidence: u8,
    ban_on_first_hit: bool,
}

impl GeoIpPlugin {
    pub fn manifest_fn() -> PluginManifest {
        PluginManifest {
            id: PLUGIN_ID,
            version: PLUGIN_VERSION,
            description: "GeoIP/ASN intelligence provider.",
            kind: PluginKind::CtiProvider,
            author: "HiveGuard",
            docs_url: Some("https://github.com/anthropics/hiveguard/blob/main/plugins/cti-geoip/README.md"),
        }
    }

    pub fn create(
        ctx: PluginContext,
        cfg: serde_json::Value,
    ) -> BoxFuture<'static, PluginResult<Box<dyn CtiProviderPlugin>>> {
        Box::pin(async move {
            let mut plugin = GeoIpPlugin {
                manifest: Self::manifest_fn(),
                db: None,
                default_data_dir: ctx.data_dir,
                trusted_asns: HashSet::new(),
                datacenter_confidence: default_confidence(),
                ban_on_first_hit: false,
            };
            <GeoIpPlugin as Plugin>::init(&mut plugin, cfg).await?;
            Ok(Box::new(plugin) as Box<dyn CtiProviderPlugin>)
        })
    }
}

#[async_trait]
impl Plugin for GeoIpPlugin {
    fn manifest(&self) -> &PluginManifest { &self.manifest }

    async fn init(&mut self, cfg: serde_json::Value) -> PluginResult<()> {
        let parsed: Config = serde_json::from_value(cfg)
            .map_err(|e| PluginError::ConfigValidation(e.to_string()))?;

        let data_dir = parsed.data_dir.unwrap_or_else(|| self.default_data_dir.clone());
        self.db = GeoIpDb::try_load(&data_dir);
        self.trusted_asns = parsed.trusted_asns.into_iter().collect();
        self.datacenter_confidence = parsed.datacenter_confidence;
        self.ban_on_first_hit = parsed.ban_on_first_hit;
        Ok(())
    }

    fn health(&self) -> HealthState {
        if self.db.is_some() {
            HealthState::Healthy
        } else {
            HealthState::Degraded("GeoIP databases not loaded".to_string())
        }
    }
}

#[async_trait]
impl CtiProviderPlugin for GeoIpPlugin {
    async fn lookup(&self, ip: IpAddr) -> PluginResult<Option<CtiVerdict>> {
        let db = match self.db.as_ref() {
            Some(db) => db,
            None => return Ok(None),
        };

        let info = db.lookup(ip);
        if let Some(asn) = info.asn {
            if self.trusted_asns.contains(&asn) {
                return Ok(None);
            }
        }

        if info.is_datacenter {
            return Ok(Some(CtiVerdict {
                provider: "geoip".to_string(),
                confidence: Some(self.datacenter_confidence),
                reason: Some(format!(
                    "Datacenter ASN detected: {:?} ({:?})",
                    info.asn, info.asn_org
                )),
                recommend_ban: self.ban_on_first_hit && self.datacenter_confidence >= 90,
            }));
        }

        Ok(None)
    }
}

inventory::submit! {
    PluginDescriptor {
        id: PLUGIN_ID,
        kind: PluginKind::CtiProvider,
        api_version: API_VERSION,
        manifest: GeoIpPlugin::manifest_fn,
        config_schema: include_str!("../schema.json"),
        factory: PluginFactory::CtiProvider(GeoIpPlugin::create),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

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
        let manifest = GeoIpPlugin::manifest_fn();
        assert_eq!(manifest.id, PLUGIN_ID);
        assert_eq!(manifest.kind, PluginKind::CtiProvider);
    }

    #[tokio::test]
    async fn factory_accepts_valid_config_with_missing_database_path() {
        let cfg = serde_json::json!({
            "database_path": "/path/that/does/not/exist",
            "datacenter_confidence": 30
        });
        let _plugin = GeoIpPlugin::create(test_ctx(), cfg).await.unwrap();
    }

    #[tokio::test]
    async fn factory_rejects_invalid_config() {
        let bad_cfg = serde_json::json!({ "trusted_asns": "not-a-list" });
        match GeoIpPlugin::create(test_ctx(), bad_cfg).await {
            Err(PluginError::ConfigValidation(_)) => {}
            Err(other) => panic!("expected ConfigValidation, got {other:?}"),
            Ok(_) => panic!("expected error"),
        }
    }
}
