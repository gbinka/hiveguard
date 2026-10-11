use std::collections::BTreeSet;
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

use async_trait::async_trait;
use ipnet::IpNet;
use tokio::process::Command;
use tracing::{debug, info, warn};

use crate::enforcer::Enforcer;
use hiveguard_core::errors::HiveGuardError;

type Result<T> = std::result::Result<T, HiveGuardError>;

/// Name of the optional HiveGuard-owned chain on the `prerouting` hook.
pub const PREROUTING_CHAIN: &str = "prerouting";

/// Priority of the optional `prerouting` drop chain.
///
/// `-300` is the `raw` slot: it runs before defragmentation-dependent
/// conntrack (`-200`), mangle (`-150`) and destination NAT (`-100`, where
/// Docker rewrites published ports). A banned source is therefore dropped
/// before Docker's DNAT can route it to a container through `forward`, and
/// before it can create a conntrack entry. Locally generated traffic never
/// traverses prerouting, and loopback/local sources are always whitelisted.
pub const PREROUTING_PRIORITY: i32 = -300;

/// Observed state of the optional prerouting chain before setup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PreroutingState {
    Absent,
    /// Exists with exactly the hook/type/priority/policy this build creates.
    Matching,
    /// Exists with a different definition (e.g. another priority); it must be
    /// replaced, because `add chain` cannot change a base chain's priority.
    Mismatched,
}

/// Enforcer that manages bans via the `nft` command-line tool.
///
/// Creates an inet table with IPv4 and IPv6 sets, and filter rules
/// that drop traffic from addresses in those sets. The `input` chain is
/// always present; an optional `prerouting` chain carries the same drop rules
/// so that traffic DNAT-ed to containers (Docker published ports, which go
/// prerouting → forward and never reach `input`) is blocked as well.
pub struct NftablesEnforcer {
    table_name: String,
    set_name_v4: String,
    set_name_v6: String,
    sync_set_name_v4: String,
    sync_set_name_v6: String,
    sync_next_set_name_v4: String,
    sync_next_set_name_v6: String,
    batch_interval: Duration,
    // Preserve exact logical bans, including hosts hidden by broader intervals.
    // Their lifetimes belong to the persistent daemon state; sync_full is the
    // authoritative replacement used at startup and for periodic reconciliation.
    desired_bans: BTreeSet<IpNet>,
    nft_binary: PathBuf,
    command_timeout: Duration,
    initialized: bool,
    /// Also install the drop rules on a `prerouting` hook chain.
    prerouting_hook: bool,
}

impl NftablesEnforcer {
    pub fn new(table_name: String, set_name: String, batch_interval: Duration) -> Self {
        let set_name_v6 = format!("{}_v6", set_name);
        let sync_set_name_v4 = format!("{}_sync", set_name);
        let sync_set_name_v6 = format!("{}_sync", set_name_v6);
        let sync_next_set_name_v4 = format!("{}_sync_next", set_name);
        let sync_next_set_name_v6 = format!("{}_sync_next", set_name_v6);
        Self {
            table_name,
            set_name_v4: set_name,
            set_name_v6,
            sync_set_name_v4,
            sync_set_name_v6,
            sync_next_set_name_v4,
            sync_next_set_name_v6,
            batch_interval,
            desired_bans: BTreeSet::new(),
            nft_binary: PathBuf::from("nft"),
            command_timeout: Duration::from_secs(10),
            initialized: false,
            prerouting_hook: false,
        }
    }

    /// Enable/disable the additional `prerouting` drop chain (default: off).
    ///
    /// When disabled, `setup` removes a chain left behind by an earlier run
    /// that had it enabled, so the kernel layout always follows the config.
    pub fn with_prerouting_hook(mut self, enabled: bool) -> Self {
        self.prerouting_hook = enabled;
        self
    }

    pub fn prerouting_hook(&self) -> bool {
        self.prerouting_hook
    }

    /// Create with default config values.
    pub fn with_defaults() -> Self {
        Self::new(
            "hiveguard".to_string(),
            "hiveguard_blocklist".to_string(),
            Duration::from_secs(1),
        )
    }

    pub fn batch_interval(&self) -> Duration {
        self.batch_interval
    }

    pub fn table_name(&self) -> &str {
        &self.table_name
    }

    pub fn set_name_v4(&self) -> &str {
        &self.set_name_v4
    }

    pub fn set_name_v6(&self) -> &str {
        &self.set_name_v6
    }

    pub fn sync_set_name_v4(&self) -> &str {
        &self.sync_set_name_v4
    }

    pub fn sync_set_name_v6(&self) -> &str {
        &self.sync_set_name_v6
    }

    pub fn sync_next_set_name_v4(&self) -> &str {
        &self.sync_next_set_name_v4
    }

    pub fn sync_next_set_name_v6(&self) -> &str {
        &self.sync_next_set_name_v6
    }

    /// Determine which set name to use based on the IP version.
    #[cfg(test)]
    fn set_for(&self, net: &IpNet) -> &str {
        match net {
            IpNet::V4(_) => &self.set_name_v4,
            IpNet::V6(_) => &self.set_name_v6,
        }
    }

    /// Determine which shadow set name to use based on the IP version.
    #[cfg(test)]
    fn sync_set_for(&self, net: &IpNet) -> &str {
        match net {
            IpNet::V4(_) => &self.sync_set_name_v4,
            IpNet::V6(_) => &self.sync_set_name_v6,
        }
    }

    /// Determine which second shadow set name to use based on the IP version.
    #[cfg(test)]
    fn sync_next_set_for(&self, net: &IpNet) -> &str {
        match net {
            IpNet::V4(_) => &self.sync_next_set_name_v4,
            IpNet::V6(_) => &self.sync_next_set_name_v6,
        }
    }

    /// Reapply the complete desired state in one transaction.
    pub async fn flush_batch(&mut self) -> Result<()> {
        let banned: Vec<_> = self.desired_bans.iter().copied().collect();
        self.sync_full(&banned).await
    }

    async fn execute(&self, args: &[&str], input: Option<&str>) -> Result<String> {
        execute_nft(&self.nft_binary, args, input, self.command_timeout).await
    }

    /// Inspect the current kernel chains of the managed table (read-only).
    async fn prerouting_state(&self) -> Result<PreroutingState> {
        let output = self
            .execute(&["-j", "list", "chains", "inet"], None)
            .await?;
        Ok(parse_prerouting_state(&output, &self.table_name))
    }

    fn drop_rules(&self, chain: &str, batch: &mut String) {
        let table = &self.table_name;
        for (family, sets) in [
            (
                "ip",
                [
                    &self.set_name_v4,
                    &self.sync_set_name_v4,
                    &self.sync_next_set_name_v4,
                ],
            ),
            (
                "ip6",
                [
                    &self.set_name_v6,
                    &self.sync_set_name_v6,
                    &self.sync_next_set_name_v6,
                ],
            ),
        ] {
            for set in sets {
                batch.push_str(&format!(
                    "add rule inet {table} {chain} {family} saddr @{set} drop\n"
                ));
            }
        }
    }

    fn build_setup_batch(&self, prerouting: PreroutingState) -> String {
        let table = &self.table_name;
        let mut batch = format!("add table inet {table}\n");
        for set in [
            &self.set_name_v4,
            &self.sync_set_name_v4,
            &self.sync_next_set_name_v4,
        ] {
            batch.push_str(&format!(
                "add set inet {table} {set} {{ type ipv4_addr; flags interval; }}\n"
            ));
        }
        for set in [
            &self.set_name_v6,
            &self.sync_set_name_v6,
            &self.sync_next_set_name_v6,
        ] {
            batch.push_str(&format!(
                "add set inet {table} {set} {{ type ipv6_addr; flags interval; }}\n"
            ));
        }
        batch.push_str(&format!("add chain inet {table} input {{ type filter hook input priority -10; policy accept; }}\n"));
        // This chain is owned by HiveGuard. Replacing its rules in the same nft
        // transaction removes duplicates without flushing bans or opening a gap.
        batch.push_str(&format!("flush chain inet {table} input\n"));
        self.drop_rules("input", &mut batch);

        // Optional prerouting chain, managed in the same atomic transaction:
        // packets see either the old or the new complete layout.
        let chain = PREROUTING_CHAIN;
        let remove_existing = match prerouting {
            PreroutingState::Absent => false,
            PreroutingState::Matching => !self.prerouting_hook,
            PreroutingState::Mismatched => true,
        };
        if remove_existing {
            batch.push_str(&format!("flush chain inet {table} {chain}\n"));
            batch.push_str(&format!("delete chain inet {table} {chain}\n"));
        }
        if self.prerouting_hook {
            batch.push_str(&format!(
                "add chain inet {table} {chain} {{ type filter hook prerouting priority {PREROUTING_PRIORITY}; policy accept; }}\n"
            ));
            batch.push_str(&format!("flush chain inet {table} {chain}\n"));
            self.drop_rules(chain, &mut batch);
        }
        batch
    }

    /// Build nft batch commands for a full sync.
    ///
    /// nft applies the entire batch atomically. On any error the previously
    /// applied sets remain in place; the caller must retain state for retry.
    pub fn build_sync_batch(&self, banned: &[IpNet]) -> String {
        let table = &self.table_name;
        let mut batch = String::new();

        // Remove overlapping entries (e.g. 45.8.17.5 inside 45.8.17.0/24)
        // nftables interval sets reject conflicting ranges.
        let deduped = dedup_overlapping(banned);

        let v4: Vec<&IpNet> = deduped
            .iter()
            .filter(|n| matches!(n, IpNet::V4(_)))
            .collect();
        let v6: Vec<&IpNet> = deduped
            .iter()
            .filter(|n| matches!(n, IpNet::V6(_)))
            .collect();

        append_replace_set_batch(&mut batch, table, &self.sync_set_name_v4, &v4);
        append_replace_set_batch(&mut batch, table, &self.sync_set_name_v6, &v6);
        append_replace_set_batch(&mut batch, table, &self.sync_next_set_name_v4, &v4);
        append_replace_set_batch(&mut batch, table, &self.sync_next_set_name_v6, &v6);
        append_replace_set_batch(&mut batch, table, &self.set_name_v4, &v4);
        append_replace_set_batch(&mut batch, table, &self.set_name_v6, &v6);

        // Clear legacy shadow sets in the same atomic replacement transaction.
        batch.push_str(&format!(
            "flush set inet {table} {}\n",
            self.sync_set_name_v4
        ));
        batch.push_str(&format!(
            "flush set inet {table} {}\n",
            self.sync_set_name_v6
        ));
        batch.push_str(&format!(
            "flush set inet {table} {}\n",
            self.sync_next_set_name_v4
        ));
        batch.push_str(&format!(
            "flush set inet {table} {}\n",
            self.sync_next_set_name_v6
        ));

        batch
    }

    fn all_set_names(&self) -> [&str; 6] {
        [
            &self.set_name_v4,
            &self.set_name_v6,
            &self.sync_set_name_v4,
            &self.sync_set_name_v6,
            &self.sync_next_set_name_v4,
            &self.sync_next_set_name_v6,
        ]
    }
}

fn append_replace_set_batch(batch: &mut String, table: &str, set: &str, nets: &[&IpNet]) {
    batch.push_str(&format!("flush set inet {table} {set}\n"));

    if !nets.is_empty() {
        let elems: Vec<String> = nets.iter().map(|n| format_net(n)).collect();
        batch.push_str(&format!(
            "add element inet {table} {set} {{ {} }}\n",
            elems.join(", ")
        ));
    }
}

#[async_trait]
impl Enforcer for NftablesEnforcer {
    async fn setup(&mut self) -> Result<()> {
        // Identifiers enter nft's language, not a shell: reject syntax injection.
        for name in std::iter::once(self.table_name.as_str()).chain(self.all_set_names()) {
            if name.is_empty()
                || !name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_')
                || name.as_bytes()[0].is_ascii_digit()
            {
                return Err(HiveGuardError::Enforcement(
                    "invalid nft table/set identifier".into(),
                ));
            }
        }
        let prerouting = match self.prerouting_state().await {
            Ok(state) => state,
            Err(e) => {
                // Enabled: `add chain` is idempotent for an identical chain and
                // a differing one fails the transaction loudly. Disabled: a
                // stale chain (still a correct drop chain) may remain.
                warn!(error = %e, "nftables: could not list chains; assuming no prerouting chain");
                PreroutingState::Absent
            }
        };
        self.execute(&["-f", "-"], Some(&self.build_setup_batch(prerouting)))
            .await?;
        if prerouting != PreroutingState::Absent && !self.prerouting_hook {
            info!(table = %self.table_name, "nftables: removed prerouting chain (prerouting_hook disabled)");
        }
        if !self.initialized {
            // Preserve existing kernel bans until startup's authoritative sync.
            self.desired_bans = self.get_current_bans().await?.into_iter().collect();
        }
        self.initialized = true;
        info!(
            table = %self.table_name,
            prerouting_hook = self.prerouting_hook,
            "nftables setup complete"
        );
        Ok(())
    }

    async fn apply_ban(&mut self, subject: &IpNet) -> Result<()> {
        let mut next = self.desired_bans.clone();
        next.insert(subject.trunc());
        self.sync_full(&next.into_iter().collect::<Vec<_>>()).await
    }

    async fn remove_ban(&mut self, subject: &IpNet) -> Result<()> {
        let mut next = self.desired_bans.clone();
        next.remove(&subject.trunc());
        // Restores any still-active narrower bans previously hidden by subject.
        self.sync_full(&next.into_iter().collect::<Vec<_>>()).await
    }

    async fn sync_full(&mut self, banned: &[IpNet]) -> Result<()> {
        let desired: BTreeSet<_> = banned.iter().map(IpNet::trunc).collect();
        let batch = self.build_sync_batch(&desired.iter().copied().collect::<Vec<_>>());
        self.execute(&["-f", "-"], Some(&batch)).await?;
        // Only advance the applied cache after the atomic kernel update succeeds.
        self.desired_bans = desired;
        Ok(())
    }

    async fn get_current_bans(&self) -> Result<Vec<IpNet>> {
        let table = &self.table_name;
        let mut result = Vec::new();

        for set in self.all_set_names() {
            let output = self
                .execute(&["-j", "list", "set", "inet", table, set], None)
                .await?;
            parse_nft_set_elements(&output, &mut result);
        }
        result.sort();
        result.dedup();

        Ok(result)
    }
}

// ---------------------------------------------------------------------------
// Helper: deduplicate overlapping IpNets for nftables interval sets
// ---------------------------------------------------------------------------

/// Remove IpNets that are contained within broader CIDRs in the list.
/// nftables interval sets reject overlapping ranges (e.g. 45.8.17.5 inside 45.8.17.0/24).
fn dedup_overlapping(nets: &[IpNet]) -> Vec<IpNet> {
    if nets.is_empty() {
        return Vec::new();
    }
    let mut sorted: Vec<IpNet> = nets.iter().map(IpNet::trunc).collect();
    sorted.sort();
    let mut result: Vec<IpNet> = vec![sorted[0]];
    for &net in &sorted[1..] {
        let last = result.last().unwrap();
        if !last.contains(&net) {
            result.push(net);
        }
    }
    if result.len() < nets.len() {
        info!(
            "nftables: deduped {} overlapping entries ({} -> {})",
            nets.len() - result.len(),
            nets.len(),
            result.len()
        );
    }
    result
}

// ---------------------------------------------------------------------------
// Helper: format IpNet for nft commands
// ---------------------------------------------------------------------------

/// Format an IpNet for use in nft commands.
/// Single-host addresses (/32 for IPv4, /128 for IPv6) are output without prefix.
fn format_net(net: &IpNet) -> String {
    let max_prefix = match net {
        IpNet::V4(_) => 32,
        IpNet::V6(_) => 128,
    };
    if net.prefix_len() == max_prefix {
        net.addr().to_string()
    } else {
        net.to_string()
    }
}

// ---------------------------------------------------------------------------
// Helper: run nft commands
// ---------------------------------------------------------------------------

/// Bound both pipe writes and process completion. Dropping a timed-out child
/// kills it, preventing a stuck nft process from holding the enforcer forever.
async fn execute_nft(
    binary: &std::path::Path,
    args: &[&str],
    input: Option<&str>,
    deadline: Duration,
) -> Result<String> {
    let operation = async {
        let mut child = Command::new(binary)
            .args(args)
            .kill_on_drop(true)
            .stdin(if input.is_some() {
                std::process::Stdio::piped()
            } else {
                std::process::Stdio::null()
            })
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| HiveGuardError::Enforcement(format!("failed to spawn nft: {e}")))?;
        if let (Some(mut stdin), Some(input)) = (child.stdin.take(), input) {
            use tokio::io::AsyncWriteExt;
            stdin.write_all(input.as_bytes()).await.map_err(|e| {
                HiveGuardError::Enforcement(format!("failed to write nft stdin: {e}"))
            })?;
        }
        let output = child
            .wait_with_output()
            .await
            .map_err(|e| HiveGuardError::Enforcement(format!("failed to wait for nft: {e}")))?;
        if !output.status.success() {
            // No stderr substring may turn a failed transaction into success:
            // nft rolls back every command, including supposedly idempotent ones.
            return Err(HiveGuardError::Enforcement(format!(
                "nft command failed (exit {}): {}",
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        String::from_utf8(output.stdout)
            .map_err(|e| HiveGuardError::Enforcement(format!("invalid UTF-8 from nft: {e}")))
    };
    debug!(?args, "running nft");
    tokio::time::timeout(deadline, operation)
        .await
        .map_err(|_| {
            HiveGuardError::Enforcement(format!(
                "nft command timed out after {}s",
                deadline.as_secs()
            ))
        })?
}

#[cfg(test)]
async fn run_nft(args: &str) -> Result<()> {
    execute_nft(
        std::path::Path::new("nft"),
        &["-f", "-"],
        Some(&format!("{args}\n")),
        Duration::from_secs(10),
    )
    .await
    .map(|_| ())
}

// ---------------------------------------------------------------------------
// Helper: parse nft JSON set elements
// ---------------------------------------------------------------------------

/// Classify the `prerouting` chain of `table` in `nft -j list chains` output.
fn parse_prerouting_state(json_str: &str, table: &str) -> PreroutingState {
    let Ok(json) = serde_json::from_str::<serde_json::Value>(json_str) else {
        warn!("failed to parse nft JSON chain list");
        return PreroutingState::Absent;
    };
    let Some(items) = json.get("nftables").and_then(|v| v.as_array()) else {
        return PreroutingState::Absent;
    };
    for item in items {
        let Some(chain) = item.get("chain") else {
            continue;
        };
        if chain.get("family").and_then(|v| v.as_str()) != Some("inet")
            || chain.get("table").and_then(|v| v.as_str()) != Some(table)
            || chain.get("name").and_then(|v| v.as_str()) != Some(PREROUTING_CHAIN)
        {
            continue;
        }
        let matching = chain.get("type").and_then(|v| v.as_str()) == Some("filter")
            && chain.get("hook").and_then(|v| v.as_str()) == Some("prerouting")
            && chain.get("prio").and_then(|v| v.as_i64()) == Some(PREROUTING_PRIORITY as i64)
            && chain.get("policy").and_then(|v| v.as_str()) == Some("accept");
        return if matching {
            PreroutingState::Matching
        } else {
            PreroutingState::Mismatched
        };
    }
    PreroutingState::Absent
}

/// Parse nft JSON output to extract set elements as IpNet.
fn parse_nft_set_elements(json_str: &str, out: &mut Vec<IpNet>) {
    let Ok(json) = serde_json::from_str::<serde_json::Value>(json_str) else {
        warn!("failed to parse nft JSON output");
        return;
    };

    // nft -j list set produces: {"nftables": [{...}, {"set": {..., "elem": [...]}}]}
    let Some(nftables) = json.get("nftables").and_then(|v| v.as_array()) else {
        return;
    };

    for item in nftables {
        let Some(set) = item.get("set") else {
            continue;
        };
        let Some(elem) = set.get("elem").and_then(|v| v.as_array()) else {
            continue;
        };
        for e in elem {
            if let Some(parsed) = parse_nft_element(e) {
                out.push(parsed);
            }
        }
    }
}

/// Parse a single nft JSON set element into an IpNet.
/// Elements can be:
/// - Simple string: "1.2.3.4"
/// - Prefix object: {"prefix": {"addr": "10.0.0.0", "len": 24}}
fn parse_nft_element(value: &serde_json::Value) -> Option<IpNet> {
    // Simple address string
    if let Some(s) = value.as_str() {
        if let Ok(addr) = s.parse::<IpAddr>() {
            return Some(host_net(addr));
        }
        if let Ok(net) = s.parse::<IpNet>() {
            return Some(net);
        }
        return None;
    }

    // Prefix object
    if let Some(prefix) = value.get("prefix") {
        let addr_str = prefix.get("addr")?.as_str()?;
        let len = prefix.get("len")?.as_u64()? as u8;
        let addr: IpAddr = addr_str.parse().ok()?;
        let net_str = format!("{}/{}", addr, len);
        return net_str.parse::<IpNet>().ok();
    }

    None
}

/// Convert single IP address to a host IpNet (/32 or /128).
fn host_net(addr: IpAddr) -> IpNet {
    match addr {
        IpAddr::V4(v4) => IpNet::V4(ipnet::Ipv4Net::from(v4)),
        IpAddr::V6(v6) => IpNet::V6(ipnet::Ipv6Net::from(v6)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_net_single_ipv4() {
        let net: IpNet = "10.0.0.1/32".parse().unwrap();
        assert_eq!(format_net(&net), "10.0.0.1");
    }

    #[test]
    fn format_net_cidr_ipv4() {
        let net: IpNet = "10.0.0.0/24".parse().unwrap();
        assert_eq!(format_net(&net), "10.0.0.0/24");
    }

    #[test]
    fn format_net_single_ipv6() {
        let net: IpNet = "2001:db8::1/128".parse().unwrap();
        assert_eq!(format_net(&net), "2001:db8::1");
    }

    #[test]
    fn format_net_cidr_ipv6() {
        let net: IpNet = "2001:db8::/32".parse().unwrap();
        assert_eq!(format_net(&net), "2001:db8::/32");
    }

    #[test]
    fn set_for_ipv4_returns_v4_set() {
        let e = NftablesEnforcer::with_defaults();
        let net: IpNet = "10.0.0.1/32".parse().unwrap();
        assert_eq!(e.set_for(&net), "hiveguard_blocklist");
    }

    #[test]
    fn set_for_ipv6_returns_v6_set() {
        let e = NftablesEnforcer::with_defaults();
        let net: IpNet = "2001:db8::/32".parse().unwrap();
        assert_eq!(e.set_for(&net), "hiveguard_blocklist_v6");
    }

    #[test]
    fn sync_set_for_returns_shadow_set() {
        let e = NftablesEnforcer::with_defaults();
        let v4: IpNet = "10.0.0.1/32".parse().unwrap();
        let v6: IpNet = "2001:db8::/32".parse().unwrap();
        assert_eq!(e.sync_set_for(&v4), "hiveguard_blocklist_sync");
        assert_eq!(e.sync_set_for(&v6), "hiveguard_blocklist_v6_sync");
        assert_eq!(e.sync_next_set_for(&v4), "hiveguard_blocklist_sync_next");
        assert_eq!(e.sync_next_set_for(&v6), "hiveguard_blocklist_v6_sync_next");
    }

    #[test]
    fn build_sync_batch_empty() {
        let e = NftablesEnforcer::with_defaults();
        let batch = e.build_sync_batch(&[]);
        assert!(batch.contains("flush set inet hiveguard hiveguard_blocklist_sync\n"));
        assert!(batch.contains("flush set inet hiveguard hiveguard_blocklist_v6_sync\n"));
        assert!(batch.contains("flush set inet hiveguard hiveguard_blocklist_sync_next\n"));
        assert!(batch.contains("flush set inet hiveguard hiveguard_blocklist_v6_sync_next\n"));
        assert!(batch.contains("flush set inet hiveguard hiveguard_blocklist\n"));
        assert!(batch.contains("flush set inet hiveguard hiveguard_blocklist_v6\n"));
        assert!(!batch.contains("add element"));
    }

    #[test]
    fn build_sync_batch_ipv4_only() {
        let e = NftablesEnforcer::with_defaults();
        let nets: Vec<IpNet> = vec![
            "10.0.0.1/32".parse().unwrap(),
            "192.168.0.0/24".parse().unwrap(),
        ];
        let batch = e.build_sync_batch(&nets);
        assert!(batch.contains("flush set inet hiveguard hiveguard_blocklist_sync\n"));
        assert!(batch.contains(
            "add element inet hiveguard hiveguard_blocklist_sync { 10.0.0.1, 192.168.0.0/24 }"
        ));
        assert!(batch.contains(
            "add element inet hiveguard hiveguard_blocklist_sync_next { 10.0.0.1, 192.168.0.0/24 }"
        ));
        assert!(batch.contains("flush set inet hiveguard hiveguard_blocklist\n"));
        assert!(batch.contains(
            "add element inet hiveguard hiveguard_blocklist { 10.0.0.1, 192.168.0.0/24 }"
        ));
        assert!(!batch.contains("add element inet hiveguard hiveguard_blocklist_v6"));
    }

    #[test]
    fn build_sync_batch_mixed_v4_v6() {
        let e = NftablesEnforcer::with_defaults();
        let nets: Vec<IpNet> = vec![
            "10.0.0.1/32".parse().unwrap(),
            "2001:db8::1/128".parse().unwrap(),
        ];
        let batch = e.build_sync_batch(&nets);
        assert!(batch.contains("add element inet hiveguard hiveguard_blocklist_sync { 10.0.0.1 }"));
        assert!(batch
            .contains("add element inet hiveguard hiveguard_blocklist_v6_sync { 2001:db8::1 }"));
        assert!(
            batch.contains("add element inet hiveguard hiveguard_blocklist_sync_next { 10.0.0.1 }")
        );
        assert!(batch.contains(
            "add element inet hiveguard hiveguard_blocklist_v6_sync_next { 2001:db8::1 }"
        ));
        assert!(batch.contains("add element inet hiveguard hiveguard_blocklist { 10.0.0.1 }"));
        assert!(batch.contains("add element inet hiveguard hiveguard_blocklist_v6 { 2001:db8::1 }"));
    }

    #[test]
    fn build_sync_batch_populates_shadow_before_flushing_active() {
        let e = NftablesEnforcer::with_defaults();
        let nets: Vec<IpNet> = vec!["10.0.0.1/32".parse().unwrap()];
        let batch = e.build_sync_batch(&nets);

        let shadow_add = batch
            .find("add element inet hiveguard hiveguard_blocklist_sync { 10.0.0.1 }")
            .unwrap();
        let second_shadow_add = batch
            .find("add element inet hiveguard hiveguard_blocklist_sync_next { 10.0.0.1 }")
            .unwrap();
        let active_flush = batch
            .find("flush set inet hiveguard hiveguard_blocklist\n")
            .unwrap();

        assert!(shadow_add < active_flush);
        assert!(second_shadow_add < active_flush);
    }

    #[test]
    fn build_sync_batch_custom_table() {
        let e = NftablesEnforcer::new(
            "mytable".to_string(),
            "myblacklist".to_string(),
            Duration::from_secs(2),
        );
        let nets: Vec<IpNet> = vec!["10.0.0.1/32".parse().unwrap()];
        let batch = e.build_sync_batch(&nets);
        assert!(batch.contains("flush set inet mytable myblacklist_sync\n"));
        assert!(batch.contains("flush set inet mytable myblacklist_v6_sync\n"));
        assert!(batch.contains("flush set inet mytable myblacklist_sync_next\n"));
        assert!(batch.contains("flush set inet mytable myblacklist_v6_sync_next\n"));
        assert!(batch.contains("flush set inet mytable myblacklist\n"));
        assert!(batch.contains("flush set inet mytable myblacklist_v6\n"));
        assert!(batch.contains("add element inet mytable myblacklist_sync { 10.0.0.1 }"));
        assert!(batch.contains("add element inet mytable myblacklist_sync_next { 10.0.0.1 }"));
        assert!(batch.contains("add element inet mytable myblacklist { 10.0.0.1 }"));
    }

    #[test]
    fn parse_nft_element_simple_ip() {
        let val = serde_json::json!("10.0.0.1");
        let net = parse_nft_element(&val).unwrap();
        assert_eq!(net, "10.0.0.1/32".parse::<IpNet>().unwrap());
    }

    #[test]
    fn parse_nft_element_prefix() {
        let val = serde_json::json!({"prefix": {"addr": "192.168.0.0", "len": 24}});
        let net = parse_nft_element(&val).unwrap();
        assert_eq!(net, "192.168.0.0/24".parse::<IpNet>().unwrap());
    }

    #[test]
    fn parse_nft_element_ipv6() {
        let val = serde_json::json!("2001:db8::1");
        let net = parse_nft_element(&val).unwrap();
        assert_eq!(net, "2001:db8::1/128".parse::<IpNet>().unwrap());
    }

    #[test]
    fn parse_nft_element_ipv6_prefix() {
        let val = serde_json::json!({"prefix": {"addr": "2001:db8::", "len": 32}});
        let net = parse_nft_element(&val).unwrap();
        assert_eq!(net, "2001:db8::/32".parse::<IpNet>().unwrap());
    }

    #[test]
    fn parse_nft_element_invalid_returns_none() {
        let val = serde_json::json!(42);
        assert!(parse_nft_element(&val).is_none());
    }

    #[test]
    fn parse_nft_set_elements_full_json() {
        let json = r#"{"nftables": [{"metainfo": {}}, {"set": {"family": "inet", "name": "test", "table": "hiveguard", "type": "ipv4_addr", "elem": ["10.0.0.1", {"prefix": {"addr": "192.168.0.0", "len": 24}}]}}]}"#;
        let mut result = Vec::new();
        parse_nft_set_elements(json, &mut result);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0], "10.0.0.1/32".parse::<IpNet>().unwrap());
        assert_eq!(result[1], "192.168.0.0/24".parse::<IpNet>().unwrap());
    }

    #[test]
    fn parse_nft_set_elements_empty_set() {
        let json = r#"{"nftables": [{"metainfo": {}}, {"set": {"family": "inet", "name": "test", "table": "hiveguard", "type": "ipv4_addr"}}]}"#;
        let mut result = Vec::new();
        parse_nft_set_elements(json, &mut result);
        assert!(result.is_empty());
    }

    #[test]
    fn parse_nft_set_elements_invalid_json() {
        let mut result = Vec::new();
        parse_nft_set_elements("not json", &mut result);
        assert!(result.is_empty());
    }

    #[test]
    fn default_constructor() {
        let e = NftablesEnforcer::with_defaults();
        assert_eq!(e.table_name(), "hiveguard");
        assert_eq!(e.set_name_v4(), "hiveguard_blocklist");
        assert_eq!(e.set_name_v6(), "hiveguard_blocklist_v6");
        assert_eq!(e.sync_set_name_v4(), "hiveguard_blocklist_sync");
        assert_eq!(e.sync_set_name_v6(), "hiveguard_blocklist_v6_sync");
        assert_eq!(e.sync_next_set_name_v4(), "hiveguard_blocklist_sync_next");
        assert_eq!(
            e.sync_next_set_name_v6(),
            "hiveguard_blocklist_v6_sync_next"
        );
        assert_eq!(e.batch_interval(), Duration::from_secs(1));
        assert!(!e.initialized);
    }

    #[tokio::test]
    async fn command_deadline_covers_wait_and_pipe_write() {
        // exec replaces the shell, so kill_on_drop kills the actual sleeper.
        for input in [None, Some("x".repeat(1024 * 1024))] {
            let start = std::time::Instant::now();
            let result = execute_nft(
                std::path::Path::new("/bin/sh"),
                &["-c", "exec sleep 30"],
                input.as_deref(),
                Duration::from_millis(50),
            )
            .await;
            assert!(result.unwrap_err().to_string().contains("timed out"));
            assert!(start.elapsed() < Duration::from_secs(2));
        }
    }

    #[tokio::test]
    async fn error_text_never_turns_a_failed_transaction_into_success() {
        for message in [
            "File exists",
            "interval overlaps with an existing one",
            "does not exist",
        ] {
            let result = execute_nft(
                std::path::Path::new("/bin/sh"),
                &["-c", "printf '%s' \"$1\" >&2; exit 1", "sh", message],
                None,
                Duration::from_secs(2),
            )
            .await;
            assert!(result.is_err());
        }
    }

    #[test]
    fn normalization_handles_noncanonical_network_addresses() {
        let nets = [
            "11.22.33.9/24".parse().unwrap(),
            "11.22.33.1/32".parse().unwrap(),
        ];
        assert_eq!(
            dedup_overlapping(&nets),
            vec!["11.22.33.0/24".parse::<IpNet>().unwrap()]
        );
    }

    fn rule_lines<'a>(batch: &'a str, chain: &str) -> Vec<&'a str> {
        let prefix = format!("add rule inet hiveguard {chain} ");
        batch.lines().filter(|l| l.starts_with(&prefix)).collect()
    }

    #[test]
    fn setup_batch_default_has_only_input_chain() {
        let e = NftablesEnforcer::with_defaults();
        assert!(!e.prerouting_hook());
        let batch = e.build_setup_batch(PreroutingState::Absent);
        assert!(batch.contains(
            "add chain inet hiveguard input { type filter hook input priority -10; policy accept; }\n"
        ));
        assert_eq!(rule_lines(&batch, "input").len(), 6);
        assert!(!batch.contains("prerouting"));
    }

    #[test]
    fn setup_batch_with_prerouting_hook_mirrors_the_six_drop_rules() {
        let e = NftablesEnforcer::with_defaults().with_prerouting_hook(true);
        for state in [PreroutingState::Absent, PreroutingState::Matching] {
            let batch = e.build_setup_batch(state);
            assert!(batch.contains(
                "add chain inet hiveguard prerouting { type filter hook prerouting priority -300; policy accept; }\n"
            ));
            assert!(batch.contains("flush chain inet hiveguard prerouting\n"));
            assert!(!batch.contains("delete chain"));
            let input: Vec<_> = rule_lines(&batch, "input")
                .iter()
                .map(|l| l.replacen(" input ", " X ", 1))
                .collect();
            let pre: Vec<_> = rule_lines(&batch, "prerouting")
                .iter()
                .map(|l| l.replacen(" prerouting ", " X ", 1))
                .collect();
            assert_eq!(input.len(), 6);
            assert_eq!(input, pre);
            // Input chain is set up first; prerouting flush precedes its rules.
            let flush = batch.find("flush chain inet hiveguard prerouting").unwrap();
            let first_rule = batch.find("add rule inet hiveguard prerouting").unwrap();
            assert!(batch.find("add chain inet hiveguard input").unwrap() < flush);
            assert!(flush < first_rule);
        }
    }

    #[test]
    fn setup_batch_replaces_mismatched_prerouting_chain_atomically() {
        let e = NftablesEnforcer::with_defaults().with_prerouting_hook(true);
        let batch = e.build_setup_batch(PreroutingState::Mismatched);
        let delete = batch
            .find("delete chain inet hiveguard prerouting\n")
            .unwrap();
        let add = batch.find("add chain inet hiveguard prerouting").unwrap();
        assert!(delete < add);
        assert_eq!(rule_lines(&batch, "prerouting").len(), 6);
    }

    #[test]
    fn setup_batch_disabled_removes_a_leftover_prerouting_chain() {
        let e = NftablesEnforcer::with_defaults();
        for state in [PreroutingState::Matching, PreroutingState::Mismatched] {
            let batch = e.build_setup_batch(state);
            let flush = batch.find("flush chain inet hiveguard prerouting\n").unwrap();
            let delete = batch.find("delete chain inet hiveguard prerouting\n").unwrap();
            assert!(flush < delete);
            assert!(!batch.contains("add chain inet hiveguard prerouting"));
            assert!(rule_lines(&batch, "prerouting").is_empty());
            assert_eq!(rule_lines(&batch, "input").len(), 6);
        }
    }

    #[test]
    fn prerouting_state_is_parsed_from_chain_list() {
        let chains = |name: &str, table: &str, prio: i64| {
            format!(
                r#"{{"nftables": [{{"metainfo": {{}}}}, {{"chain": {{"family": "inet", "table": "{table}", "name": "input", "type": "filter", "hook": "input", "prio": -10, "policy": "accept"}}}}, {{"chain": {{"family": "inet", "table": "{table}", "name": "{name}", "type": "filter", "hook": "prerouting", "prio": {prio}, "policy": "accept"}}}}]}}"#
            )
        };
        assert_eq!(
            parse_prerouting_state(&chains("prerouting", "hiveguard", -300), "hiveguard"),
            PreroutingState::Matching
        );
        assert_eq!(
            parse_prerouting_state(&chains("prerouting", "hiveguard", -150), "hiveguard"),
            PreroutingState::Mismatched
        );
        assert_eq!(
            parse_prerouting_state(&chains("prerouting", "other", -300), "hiveguard"),
            PreroutingState::Absent
        );
        assert_eq!(
            parse_prerouting_state(&chains("raw_pre", "hiveguard", -300), "hiveguard"),
            PreroutingState::Absent
        );
        assert_eq!(
            parse_prerouting_state(r#"{"nftables": [{"metainfo": {}}]}"#, "hiveguard"),
            PreroutingState::Absent
        );
    }

    // Run ONLY inside an isolated network namespace (see plugin README).
    #[tokio::test]
    #[ignore]
    async fn integration_prerouting_hook_toggle_and_replacement() {
        async fn chain_rules(e: &NftablesEnforcer, chain: &str) -> Option<(i64, usize)> {
            let out = e.execute(&["-j", "list", "table", "inet", "hiveguard"], None).await.ok()?;
            let doc: serde_json::Value = serde_json::from_str(&out).unwrap();
            let items = doc["nftables"].as_array().unwrap();
            let prio = items
                .iter()
                .filter_map(|v| v.get("chain"))
                .find(|c| c["name"] == chain)?["prio"]
                .as_i64()
                .unwrap();
            let rules = items
                .iter()
                .filter_map(|v| v.get("rule"))
                .filter(|r| r["chain"] == chain)
                .count();
            Some((prio, rules))
        }

        let _ = run_nft("delete table inet hiveguard").await;
        let host: IpNet = "11.22.33.5/32".parse().unwrap();
        let mut enforcer = NftablesEnforcer::with_defaults().with_prerouting_hook(true);
        enforcer.setup().await.unwrap();
        enforcer.sync_full(&[host]).await.unwrap();
        assert_eq!(chain_rules(&enforcer, "input").await, Some((-10, 6)));
        assert_eq!(chain_rules(&enforcer, "prerouting").await, Some((-300, 6)));

        // Restart with the hook still enabled: idempotent, bans kept.
        let mut again = NftablesEnforcer::with_defaults().with_prerouting_hook(true);
        again.setup().await.unwrap();
        assert_eq!(chain_rules(&again, "prerouting").await, Some((-300, 6)));
        assert_eq!(again.get_current_bans().await.unwrap(), vec![host]);

        // Restart with the hook disabled: chain removed, input + sets intact.
        let mut off = NftablesEnforcer::with_defaults();
        off.setup().await.unwrap();
        assert_eq!(chain_rules(&off, "prerouting").await, None);
        assert_eq!(chain_rules(&off, "input").await, Some((-10, 6)));
        assert_eq!(off.get_current_bans().await.unwrap(), vec![host]);
        off.setup().await.unwrap(); // absent + disabled is a no-op

        // A differently defined chain (e.g. other priority) is replaced.
        run_nft("add chain inet hiveguard prerouting { type filter hook prerouting priority -150; policy accept; }")
            .await
            .unwrap();
        let mut on = NftablesEnforcer::with_defaults().with_prerouting_hook(true);
        on.setup().await.unwrap();
        assert_eq!(chain_rules(&on, "prerouting").await, Some((-300, 6)));
        assert_eq!(on.get_current_bans().await.unwrap(), vec![host]);
        run_nft("delete table inet hiveguard").await.unwrap();
    }

    // Run ONLY inside an isolated network namespace (see plugin README).
    #[tokio::test]
    #[ignore]
    async fn integration_overlap_expiry_atomic_rollback_and_restart() {
        let mut enforcer = NftablesEnforcer::with_defaults();
        enforcer.setup().await.unwrap();
        enforcer.setup().await.unwrap();
        let rules = enforcer
            .execute(&["-j", "list", "chain", "inet", "hiveguard", "input"], None)
            .await
            .unwrap();
        let rules: serde_json::Value = serde_json::from_str(&rules).unwrap();
        assert_eq!(
            rules["nftables"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|v| v.get("rule").is_some())
                .count(),
            6
        );

        for (host, subnet) in [
            ("11.22.33.5/32", "11.22.33.0/24"),
            ("2001:db8:1::5/128", "2001:db8:1::/48"),
        ] {
            let host: IpNet = host.parse().unwrap();
            let subnet: IpNet = subnet.parse().unwrap();
            for host_first in [true, false] {
                enforcer.sync_full(&[]).await.unwrap();
                for net in if host_first {
                    [host, subnet]
                } else {
                    [subnet, host]
                } {
                    enforcer.apply_ban(&net).await.unwrap();
                }
                assert_eq!(enforcer.get_current_bans().await.unwrap(), vec![subnet]);
                assert_eq!(enforcer.desired_bans.len(), 2);
                // Setup again must preserve logical hosts hidden by intervals.
                enforcer.setup().await.unwrap();
                enforcer.remove_ban(&subnet).await.unwrap();
                assert_eq!(enforcer.get_current_bans().await.unwrap(), vec![host]);
                enforcer.remove_ban(&host).await.unwrap();
                assert!(enforcer.get_current_bans().await.unwrap().is_empty());
            }
        }

        let host: IpNet = "11.22.33.5/32".parse().unwrap();
        enforcer.sync_full(&[host]).await.unwrap();
        // A failing final command must roll back earlier shadow flush/adds too.
        let original_set = enforcer.set_name_v6.clone();
        enforcer.set_name_v6 = "missing_set".into();
        assert!(enforcer.sync_full(&[]).await.is_err());
        assert_eq!(enforcer.desired_bans, [host].into_iter().collect());
        enforcer.set_name_v6 = original_set;
        assert_eq!(enforcer.get_current_bans().await.unwrap(), vec![host]);

        // A fresh process restores exact logical records from durable state.
        let subnet: IpNet = "11.22.33.0/24".parse().unwrap();
        enforcer.sync_full(&[host, subnet]).await.unwrap();
        let mut restarted = NftablesEnforcer::with_defaults();
        restarted.setup().await.unwrap();
        restarted.sync_full(&[host, subnet]).await.unwrap();
        restarted.remove_ban(&subnet).await.unwrap();
        assert_eq!(restarted.get_current_bans().await.unwrap(), vec![host]);
        restarted.sync_full(&[]).await.unwrap();
        assert!(restarted.get_current_bans().await.unwrap().is_empty());
        run_nft("delete table inet hiveguard").await.unwrap();
    }

    // Integration test requiring root/CAP_NET_ADMIN — run manually
    #[tokio::test]
    #[ignore]
    async fn integration_setup_ban_unban() {
        let mut enforcer = NftablesEnforcer::with_defaults();
        enforcer.setup().await.unwrap();

        let ip: IpNet = "198.51.100.1/32".parse().unwrap();
        enforcer.apply_ban(&ip).await.unwrap();

        let bans = enforcer.get_current_bans().await.unwrap();
        assert!(bans.contains(&ip));

        enforcer.remove_ban(&ip).await.unwrap();
        let bans = enforcer.get_current_bans().await.unwrap();
        assert!(!bans.contains(&ip));

        // Cleanup
        let _ = run_nft("delete table inet hiveguard").await;
    }

    #[tokio::test]
    #[ignore]
    async fn integration_sync_full() {
        let mut enforcer = NftablesEnforcer::with_defaults();
        enforcer.setup().await.unwrap();

        let nets: Vec<IpNet> = vec![
            "10.0.0.1/32".parse().unwrap(),
            "192.168.0.0/24".parse().unwrap(),
            "2001:db8::1/128".parse().unwrap(),
        ];
        enforcer.sync_full(&nets).await.unwrap();

        let bans = enforcer.get_current_bans().await.unwrap();
        assert_eq!(bans.len(), 3);

        // Cleanup
        let _ = run_nft("delete table inet hiveguard").await;
    }
}
