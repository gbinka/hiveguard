//! Whitelist ⇄ ban-store reconciliation.
//!
//! The whitelist is only consulted on the *new signal* path, so a ban that is
//! already in the store survives any whitelist entry added afterwards — it is
//! re-pushed to the firewall by the enforcer sync on every restart, until it
//! expires. These helpers close that gap: whenever the whitelist grows, the
//! bans it now covers are revoked from the store (and from the firewall, if a
//! live enforcer is supplied).
//!
//! Ordering matters at startup: the config whitelist must be in the state
//! *before* `sync_full`, otherwise covered bans reach nftables regardless.

use std::sync::Arc;

use ipnet::IpNet;
use tokio::sync::Mutex;
use tracing::{info, warn};

use hiveguard_core::ban_store::BanStore;
use hiveguard_core::persistence::StateManager;
use hiveguard_enforce::Enforcer;

/// Load the config whitelist into the state and revoke the bans it covers.
///
/// Returns the revoked ban subjects. Call this **before** syncing the ban
/// store to the enforcer.
pub async fn apply_config_whitelist(
    state: &Arc<Mutex<StateManager>>,
    nets: impl IntoIterator<Item = IpNet>,
) -> Result<Vec<IpNet>, hiveguard_core::errors::HiveGuardError> {
    let mut st = state.lock().await;
    for net in nets {
        if !st.whitelist().covers(&net) {
            st.add_whitelist(net)?;
        }
    }
    st.revoke_bans_covered_by_whitelist()
}

/// Load the config whitelist, revoke the bans it covers, and only then push
/// what remains to the enforcer.
///
/// The two steps live in one function because their order is the fix for the
/// startup half of the bug: the snapshot carries the *previous* whitelist, so
/// syncing first hands the firewall bans the current config forbids.
pub async fn init_whitelist_and_sync(
    state: &Arc<Mutex<StateManager>>,
    nets: impl IntoIterator<Item = IpNet>,
    enforcer: &mut dyn Enforcer,
) -> Result<(), hiveguard_core::errors::HiveGuardError> {
    apply_config_whitelist(state, nets).await?;

    let st = state.lock().await;
    let current_bans: Vec<IpNet> = st
        .ban_store()
        .get_all_bans()
        .iter()
        .filter(|b| b.expires_at.is_none_or(|exp| exp > chrono::Utc::now()))
        .map(|b| b.subject)
        .collect();
    info!(
        count = current_bans.len(),
        "Syncing existing bans to enforcer"
    );
    enforcer.sync_full(&current_bans).await
}

/// Drop revoked subjects from a live enforcer. Used on the runtime path
/// (`whitelist add` via socket or REST); at startup the subsequent `sync_full`
/// already rewrites the whole set, so there is nothing to remove.
pub async fn drop_from_enforcer(
    enforcer: &Arc<Mutex<Box<dyn Enforcer>>>,
    revoked: &[IpNet],
) -> Result<(), hiveguard_core::errors::HiveGuardError> {
    if revoked.is_empty() {
        return Ok(());
    }
    let mut enf = enforcer.lock().await;
    let mut failure = None;
    for subject in revoked {
        if let Err(e) = enf.remove_ban(subject).await {
            warn!(subject = %subject, "whitelist revoke: enforcer remove failed: {}", e);
            failure = Some(e);
        }
    }
    match failure {
        Some(e) => Err(e),
        None => Ok(()),
    }
}
