use hiveguard_core::errors::HiveGuardError;
use ipnet::IpNet;

type Result<T> = std::result::Result<T, HiveGuardError>;

/// Trait for firewall enforcement backends (nftables, iptables, etc.).
#[async_trait::async_trait]
pub trait Enforcer: Send + Sync {
    /// One-time setup (create tables, sets, chains). Default is no-op.
    async fn setup(&mut self) -> Result<()> {
        Ok(())
    }
    async fn apply_ban(&mut self, subject: &IpNet) -> Result<()>;
    async fn remove_ban(&mut self, subject: &IpNet) -> Result<()>;
    async fn sync_full(&mut self, banned: &[IpNet]) -> Result<()>;
    async fn get_current_bans(&self) -> Result<Vec<IpNet>>;
}
