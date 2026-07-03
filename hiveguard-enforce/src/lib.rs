pub mod cloudflare;
pub mod enforcer;
pub mod nftables;
pub mod observe_only;

pub use cloudflare::CloudflareEnforcer;
pub use enforcer::Enforcer;
pub use nftables::NftablesEnforcer;
pub use observe_only::ObserveOnlyEnforcer;

use hiveguard_core::config::EnforcementConfig;

/// Factory: create the appropriate enforcer based on config.
pub fn create_enforcer(config: &EnforcementConfig) -> Box<dyn Enforcer> {
    match config.backend.as_str() {
        "nftables" => {
            let batch_interval = config
                .batch_interval
                .as_duration()
                .unwrap_or(std::time::Duration::from_secs(1));
            Box::new(NftablesEnforcer::new(
                config.nftables_table.clone(),
                config.nftables_set_name.clone(),
                batch_interval,
            ))
        }
        "cloudflare" => {
            if let Some(cf_config) = config.cloudflare.clone() {
                Box::new(CloudflareEnforcer::new(cf_config))
            } else {
                tracing::warn!(
                    "backend 'cloudflare' selected but no [enforcement.cloudflare] \
                     section found — falling back to observe_only"
                );
                Box::new(ObserveOnlyEnforcer::new())
            }
        }
        "observe_only" => Box::new(ObserveOnlyEnforcer::new()),
        other => {
            tracing::warn!(
                "unknown enforcement backend '{}', falling back to observe_only",
                other
            );
            Box::new(ObserveOnlyEnforcer::new())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn factory_creates_observe_only() {
        let config = EnforcementConfig {
            backend: "observe_only".to_string(),
            ..Default::default()
        };
        let mut enforcer = create_enforcer(&config);
        let net: ipnet::IpNet = "10.0.0.1/32".parse().unwrap();
        enforcer.apply_ban(&net).await.unwrap();
        let bans = enforcer.get_current_bans().await.unwrap();
        assert_eq!(bans.len(), 1);
    }

    #[tokio::test]
    async fn factory_creates_nftables() {
        let config = EnforcementConfig {
            backend: "nftables".to_string(),
            nftables_table: "test_table".to_string(),
            nftables_set_name: "test_set".to_string(),
            ..Default::default()
        };
        // Just verify it creates without panic — actual nft calls need root
        let _enforcer = create_enforcer(&config);
    }

    #[tokio::test]
    async fn factory_unknown_backend_falls_back() {
        let config = EnforcementConfig {
            backend: "unknown_thing".to_string(),
            ..Default::default()
        };
        let mut enforcer = create_enforcer(&config);
        // Should behave like observe_only
        let net: ipnet::IpNet = "10.0.0.1/32".parse().unwrap();
        enforcer.apply_ban(&net).await.unwrap();
        let bans = enforcer.get_current_bans().await.unwrap();
        assert_eq!(bans.len(), 1);
    }
}
