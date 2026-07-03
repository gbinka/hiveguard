use async_trait::async_trait;
use ipnet::IpNet;

use crate::error::PluginResult;
use crate::traits::Plugin;

/// Firewall enforcement backend.
///
/// Replaces the previous `hiveguard-enforce::Enforcer` trait. Plugins of this
/// kind translate ban records into kernel-level rules (nftables, ipset,
/// Cloudflare API, observe-only, …).
#[async_trait]
pub trait EnforcerPlugin: Plugin {
    /// One-time setup — create tables, sets, chains. Called once after `init`.
    /// Default impl is a no-op.
    async fn setup(&mut self) -> PluginResult<()> {
        Ok(())
    }

    /// Block traffic from `subject`.
    async fn apply_ban(&mut self, subject: &IpNet) -> PluginResult<()>;

    /// Remove a previously applied ban.
    async fn remove_ban(&mut self, subject: &IpNet) -> PluginResult<()>;

    /// Replace the active set with `banned`. Used after WAL replay / cluster
    /// sync when the in-memory state diverges from the kernel state.
    async fn sync_full(&mut self, banned: &[IpNet]) -> PluginResult<()>;

    /// Read back what the kernel actually has. Used for drift detection.
    async fn get_current_bans(&self) -> PluginResult<Vec<IpNet>>;
}
