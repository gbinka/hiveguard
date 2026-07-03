use std::net::IpAddr;
use std::time::Duration;

use async_trait::async_trait;
use ipnet::IpNet;
use tokio::process::Command;
use tracing::{debug, error, info, warn};

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
    pending_adds: Vec<IpNet>,
    pending_removes: Vec<IpNet>,
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
            pending_adds: Vec::new(),
            pending_removes: Vec::new(),
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
    fn set_for(&self, net: &IpNet) -> &str {
        match net {
            IpNet::V4(_) => &self.set_name_v4,
            IpNet::V6(_) => &self.set_name_v6,
        }
    }

    /// Determine which shadow set name to use based on the IP version.
    fn sync_set_for(&self, net: &IpNet) -> &str {
        match net {
            IpNet::V4(_) => &self.sync_set_name_v4,
            IpNet::V6(_) => &self.sync_set_name_v6,
        }
    }

    /// Determine which second shadow set name to use based on the IP version.
    fn sync_next_set_for(&self, net: &IpNet) -> &str {
        match net {
            IpNet::V4(_) => &self.sync_next_set_name_v4,
            IpNet::V6(_) => &self.sync_next_set_name_v6,
        }
    }

    /// Flush pending batch operations — execute queued adds/removes in a single nft batch.
    pub async fn flush_batch(&mut self) -> Result<()> {
        if self.pending_adds.is_empty() && self.pending_removes.is_empty() {
            return Ok(());
        }

        let mut batch = String::new();
        let table = &self.table_name;

        let removes: Vec<IpNet> = self.pending_removes.drain(..).collect();
        for net in &removes {
            let set = self.set_for(net);
            batch.push_str(&format!(
                "delete element inet {table} {set} {{ {} }}\n",
                format_net(net)
            ));
        }

        let adds: Vec<IpNet> = self.pending_adds.drain(..).collect();
        for net in &adds {
            let set = self.set_for(net);
            batch.push_str(&format!(
                "add element inet {table} {set} {{ {} }}\n",
                format_net(net)
            ));
        }

        debug!("flushing nft batch:\n{}", batch);
        run_nft_stdin(&batch).await
    }

    /// Build nft batch commands for a full sync.
    ///
    /// Shadow sets are populated before active sets are flushed. If execution
    /// fails after an active flush, the shadow drop rules still enforce the
    /// desired ban list until the next successful sync.
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

        // Cleanup is intentionally last: if active replacement fails after a
        // flush, populated shadow sets are left in place as fail-closed
        // protection rather than leaving the firewall open.
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
        let table = &self.table_name;

        // Create table (idempotent via `add`)
        run_nft(&format!("add table inet {table}")).await?;

        // Create active and shadow sets with interval flag for CIDR support.
        for set in [
            &self.set_name_v4,
            &self.sync_set_name_v4,
            &self.sync_next_set_name_v4,
        ] {
            run_nft(&format!(
                "add set inet {table} {set} {{ type ipv4_addr; flags interval; }}"
            ))
            .await?;
        }

        for set in [
            &self.set_name_v6,
            &self.sync_set_name_v6,
            &self.sync_next_set_name_v6,
        ] {
            run_nft(&format!(
                "add set inet {table} {set} {{ type ipv6_addr; flags interval; }}"
            ))
            .await?;
        }

        // Create input chain with filter hook at priority -10
        run_nft(&format!(
            "add chain inet {table} input {{ type filter hook input priority -10; policy accept; }}"
        ))
        .await?;

        // Add drop rules referencing both active and shadow sets.
        for set in [
            &self.set_name_v4,
            &self.sync_set_name_v4,
            &self.sync_next_set_name_v4,
        ] {
            run_nft(&format!("add rule inet {table} input ip saddr @{set} drop")).await?;
        }

        for set in [
            &self.set_name_v6,
            &self.sync_set_name_v6,
            &self.sync_next_set_name_v6,
        ] {
            run_nft(&format!(
                "add rule inet {table} input ip6 saddr @{set} drop"
            ))
            .await?;
        }

        self.initialized = true;
        info!(
            "nftables setup complete: table={}, sets={}/{}, shadow_sets={}/{}/{}/{}",
            table,
            self.set_name_v4,
            self.set_name_v6,
            self.sync_set_name_v4,
            self.sync_set_name_v6,
            self.sync_next_set_name_v4,
            self.sync_next_set_name_v6
        );
        Ok(())
    }

    async fn apply_ban(&mut self, subject: &IpNet) -> Result<()> {
        let table = &self.table_name;
        let set = self.set_for(subject).to_string();
        let elem = format_net(subject);

        info!("nftables: banning {} in set {}", subject, set);

        let max_prefix = match subject {
            IpNet::V4(_) => 32,
            IpNet::V6(_) => 128,
        };
        // Banning a subnet (e.g. a /24 from the distributed-slow detector) into
        // an interval set fails with "interval overlaps with an existing one"
        // if a narrower entry it contains (e.g. an already-banned /32 host) is
        // present. Purge those contained entries first, otherwise the broader
        // ban is rejected and the rest of the subnet keeps leaking traffic.
        if subject.prefix_len() < max_prefix {
            let existing = self.get_current_bans().await.unwrap_or_default();
            for net in existing
                .into_iter()
                .filter(|n| n != subject && subject.contains(n))
            {
                let contained = format_net(&net);
                run_nft_idempotent_delete(&format!(
                    "delete element inet {table} {set} {{ {contained} }}"
                ))
                .await?;
            }
        }

        // Tolerate a residual overlap: if the target is still contained in a
        // broader existing interval it is already blocked, so treat that as
        // success rather than failing the ban.
        run_nft_idempotent_add(&format!("add element inet {table} {set} {{ {elem} }}")).await
    }

    async fn remove_ban(&mut self, subject: &IpNet) -> Result<()> {
        let table = &self.table_name;
        let set = self.set_for(subject).to_string();
        let sync_set = self.sync_set_for(subject).to_string();
        let sync_next_set = self.sync_next_set_for(subject).to_string();
        let elem = format_net(subject);

        info!(
            "nftables: unbanning {} from sets {}/{}/{}",
            subject, set, sync_set, sync_next_set
        );
        run_nft_idempotent_delete(&format!("delete element inet {table} {set} {{ {elem} }}"))
            .await?;
        run_nft_idempotent_delete(&format!(
            "delete element inet {table} {sync_set} {{ {elem} }}"
        ))
        .await?;
        run_nft_idempotent_delete(&format!(
            "delete element inet {table} {sync_next_set} {{ {elem} }}"
        ))
        .await
    }

    async fn sync_full(&mut self, banned: &[IpNet]) -> Result<()> {
        info!("nftables: full sync with {} ban(s)", banned.len());
        let batch = self.build_sync_batch(banned);
        run_nft_stdin(&batch).await
    }

    async fn get_current_bans(&self) -> Result<Vec<IpNet>> {
        let table = &self.table_name;
        let mut result = Vec::new();

        for set in self.all_set_names() {
            let output = run_nft_output(&format!("-j list set inet {table} {set}")).await?;
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
    let mut sorted: Vec<IpNet> = nets.to_vec();
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

async fn run_nft(args: &str) -> Result<()> {
    debug!("nft {}", args);
    // Feed the command via stdin (`nft -f -`) rather than splitting it into argv.
    // Whitespace-splitting breaks expressions such as `priority -10;`: the bare
    // `-10;` token starts with `-`, so nft's option parser treats it as a CLI
    // flag and aborts with "invalid option -- '1'" on older nft (e.g. 0.9.3 on
    // Ubuntu 20.04). Reading from stdin sidesteps option parsing entirely.
    let mut child = Command::new("nft")
        .arg("-f")
        .arg("-")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| HiveGuardError::Enforcement(format!("failed to run nft: {e}")))?;

    if let Some(mut stdin) = child.stdin.take() {
        use tokio::io::AsyncWriteExt;
        stdin
            .write_all(format!("{args}\n").as_bytes())
            .await
            .map_err(|e| HiveGuardError::Enforcement(format!("failed to write nft stdin: {e}")))?;
    }

    let output = child
        .wait_with_output()
        .await
        .map_err(|e| HiveGuardError::Enforcement(format!("failed to run nft: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // "File exists" is okay for idempotent adds
        if stderr.contains("File exists") {
            warn!("nft: already exists (idempotent): {}", args);
            return Ok(());
        }
        error!("nft command failed: {}", stderr);
        return Err(HiveGuardError::Enforcement(format!(
            "nft command failed (exit {}): {}",
            output.status,
            stderr.trim()
        )));
    }

    Ok(())
}

/// Run nft with batch input on stdin (`nft -f -`).
async fn run_nft_stdin(batch: &str) -> Result<()> {
    debug!("nft -f - (batch):\n{}", batch);
    let mut child = Command::new("nft")
        .arg("-f")
        .arg("-")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| HiveGuardError::Enforcement(format!("failed to spawn nft: {e}")))?;

    if let Some(mut stdin) = child.stdin.take() {
        use tokio::io::AsyncWriteExt;
        stdin
            .write_all(batch.as_bytes())
            .await
            .map_err(|e| HiveGuardError::Enforcement(format!("failed to write nft stdin: {e}")))?;
        // Drop to close stdin
    }

    let output = child
        .wait_with_output()
        .await
        .map_err(|e| HiveGuardError::Enforcement(format!("failed to wait for nft: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        error!("nft batch failed: {}", stderr);
        return Err(HiveGuardError::Enforcement(format!(
            "nft batch failed (exit {}): {}",
            output.status,
            stderr.trim()
        )));
    }

    Ok(())
}

async fn run_nft_idempotent_delete(args: &str) -> Result<()> {
    match run_nft(args).await {
        Ok(()) => Ok(()),
        Err(HiveGuardError::Enforcement(msg))
            if msg.contains("No such file or directory") || msg.contains("does not exist") =>
        {
            warn!("nft: already absent (idempotent delete): {}", args);
            Ok(())
        }
        Err(err) => Err(err),
    }
}

/// Run an `add element` that tolerates the target already being covered by an
/// existing interval ("interval overlaps with an existing one"). That error
/// means a broader ban already blocks the address, so the add is a no-op rather
/// than a failure. Exact duplicates ("File exists") are handled inside `run_nft`.
async fn run_nft_idempotent_add(args: &str) -> Result<()> {
    match run_nft(args).await {
        Ok(()) => Ok(()),
        Err(HiveGuardError::Enforcement(msg)) if msg.contains("overlaps with an existing one") => {
            warn!("nft: already covered by broader interval (idempotent add): {}", args);
            Ok(())
        }
        Err(err) => Err(err),
    }
}

/// Run nft command and capture stdout.
async fn run_nft_output(args: &str) -> Result<String> {
    debug!("nft {}", args);
    let output = Command::new("nft")
        .args(args.split_whitespace())
        .output()
        .await
        .map_err(|e| HiveGuardError::Enforcement(format!("failed to run nft: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(HiveGuardError::Enforcement(format!(
            "nft command failed (exit {}): {}",
            output.status,
            stderr.trim()
        )));
    }

    String::from_utf8(output.stdout)
        .map_err(|e| HiveGuardError::Enforcement(format!("invalid UTF-8 from nft: {e}")))
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
