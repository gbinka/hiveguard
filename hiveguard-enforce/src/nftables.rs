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

/// Enforcer that manages bans via the `nft` command-line tool.
///
/// Creates an inet table with IPv4 and IPv6 sets, and filter rules
/// that drop traffic from addresses in those sets.
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
        }
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

    fn build_setup_batch(&self) -> String {
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
                    "add rule inet {table} input {family} saddr @{set} drop\n"
                ));
            }
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
        self.execute(&["-f", "-"], Some(&self.build_setup_batch()))
            .await?;
        if !self.initialized {
            // Preserve existing kernel bans until startup's authoritative sync.
            self.desired_bans = self.get_current_bans().await?.into_iter().collect();
        }
        self.initialized = true;
        info!(table = %self.table_name, "nftables setup complete");
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
