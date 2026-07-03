use async_trait::async_trait;
use ipnet::IpNet;
use tracing::info;

use crate::enforcer::Enforcer;
use hiveguard_core::errors::HiveGuardError;

type Result<T> = std::result::Result<T, HiveGuardError>;

/// A no-op enforcer that logs actions without executing them.
/// Useful for dry-run / observe-only mode.
pub struct ObserveOnlyEnforcer {
    bans: Vec<IpNet>,
}

impl ObserveOnlyEnforcer {
    pub fn new() -> Self {
        Self { bans: Vec::new() }
    }
}

impl Default for ObserveOnlyEnforcer {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Enforcer for ObserveOnlyEnforcer {
    async fn apply_ban(&mut self, subject: &IpNet) -> Result<()> {
        info!("[observe-only] would ban {}", subject);
        if !self.bans.contains(subject) {
            self.bans.push(*subject);
        }
        Ok(())
    }

    async fn remove_ban(&mut self, subject: &IpNet) -> Result<()> {
        info!("[observe-only] would unban {}", subject);
        self.bans.retain(|b| b != subject);
        Ok(())
    }

    async fn sync_full(&mut self, banned: &[IpNet]) -> Result<()> {
        info!(
            "[observe-only] would sync {} ban(s): {:?}",
            banned.len(),
            banned
        );
        self.bans = banned.to_vec();
        Ok(())
    }

    async fn get_current_bans(&self) -> Result<Vec<IpNet>> {
        Ok(self.bans.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn apply_ban_logs_and_tracks() {
        let mut enforcer = ObserveOnlyEnforcer::new();
        let net: IpNet = "192.168.1.0/24".parse().unwrap();

        enforcer.apply_ban(&net).await.unwrap();
        let bans = enforcer.get_current_bans().await.unwrap();
        assert_eq!(bans.len(), 1);
        assert_eq!(bans[0], net);
    }

    #[tokio::test]
    async fn apply_ban_deduplicates() {
        let mut enforcer = ObserveOnlyEnforcer::new();
        let net: IpNet = "10.0.0.1/32".parse().unwrap();

        enforcer.apply_ban(&net).await.unwrap();
        enforcer.apply_ban(&net).await.unwrap();
        let bans = enforcer.get_current_bans().await.unwrap();
        assert_eq!(bans.len(), 1);
    }

    #[tokio::test]
    async fn remove_ban_logs_and_removes() {
        let mut enforcer = ObserveOnlyEnforcer::new();
        let net: IpNet = "10.0.0.5/32".parse().unwrap();

        enforcer.apply_ban(&net).await.unwrap();
        assert_eq!(enforcer.get_current_bans().await.unwrap().len(), 1);

        enforcer.remove_ban(&net).await.unwrap();
        assert!(enforcer.get_current_bans().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn remove_nonexistent_ban_ok() {
        let mut enforcer = ObserveOnlyEnforcer::new();
        let net: IpNet = "10.0.0.5/32".parse().unwrap();
        // Should not error
        enforcer.remove_ban(&net).await.unwrap();
    }

    #[tokio::test]
    async fn sync_full_replaces_all() {
        let mut enforcer = ObserveOnlyEnforcer::new();
        let a: IpNet = "10.0.0.1/32".parse().unwrap();
        let b: IpNet = "10.0.0.2/32".parse().unwrap();
        let c: IpNet = "192.168.0.0/16".parse().unwrap();

        enforcer.apply_ban(&a).await.unwrap();
        enforcer.apply_ban(&b).await.unwrap();
        assert_eq!(enforcer.get_current_bans().await.unwrap().len(), 2);

        enforcer.sync_full(&[c]).await.unwrap();
        let bans = enforcer.get_current_bans().await.unwrap();
        assert_eq!(bans.len(), 1);
        assert_eq!(bans[0], c);
    }

    #[tokio::test]
    async fn empty_initial_state() {
        let enforcer = ObserveOnlyEnforcer::new();
        assert!(enforcer.get_current_bans().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn ipv6_support() {
        let mut enforcer = ObserveOnlyEnforcer::new();
        let net: IpNet = "2001:db8::/32".parse().unwrap();

        enforcer.apply_ban(&net).await.unwrap();
        let bans = enforcer.get_current_bans().await.unwrap();
        assert_eq!(bans.len(), 1);
        assert_eq!(bans[0], net);
    }
}
