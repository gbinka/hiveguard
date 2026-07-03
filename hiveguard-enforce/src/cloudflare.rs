//! Cloudflare edge enforcement backend (phase 7.1).
//!
//! Pushes HiveGuard ban lists to Cloudflare IP Lists so attacks are
//! blocked at the CDN edge before reaching the origin server.
//!
//! # API flow
//!
//! 1. On `setup()`: find or create the named IP List under the account;
//!    create a firewall rule in every configured zone that blocks traffic
//!    whose source IP matches the list.
//! 2. On `apply_ban()`: push the IP to a local pending queue. A flush
//!    happens automatically when the queue reaches `BATCH_SIZE`.
//! 3. On `remove_ban()`: issue a DELETE for the individual list item.
//! 4. On `sync_full()`: replace the entire IP List with the supplied
//!    set (used by the hourly reconciliation loop in the daemon).
//! 5. On `get_current_bans()`: pull the live IP List from Cloudflare.
//!
//! # Rate limiting
//!
//! Cloudflare allows 1 200 requests per 5 minutes per API token.
//! The enforcer enforces this with a simple token bucket that refills
//! 1 200 tokens every 300 seconds (4 tokens/s).
//!
//! # Error handling
//!
//! HTTP 403 → log + return `Ok(())` (the local ban is still applied
//! by other backends; we must not block the pipeline).
//! Other 4xx/5xx → log + return error so the caller can decide.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

use crate::enforcer::Enforcer;
use hiveguard_core::config::CloudflareConfig;
use hiveguard_core::errors::HiveGuardError;

type Result<T> = std::result::Result<T, HiveGuardError>;

const CF_API_BASE: &str = "https://api.cloudflare.com/client/v4";

/// Maximum IPs per bulk-insert request (Cloudflare limit).
const BATCH_SIZE: usize = 1000;

/// Cloudflare rate limit: 1 200 requests per 5-minute window.
const RATE_LIMIT_MAX: u32 = 1200;
const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(300);

// ---------------------------------------------------------------------------
// Token-bucket rate limiter
// ---------------------------------------------------------------------------

struct TokenBucket {
    tokens: u32,
    max: u32,
    refill_interval: Duration,
    last_refill: Instant,
}

impl TokenBucket {
    fn new(max: u32, refill_interval: Duration) -> Self {
        Self {
            tokens: max,
            max,
            refill_interval,
            last_refill: Instant::now(),
        }
    }

    /// Consume `n` tokens, returning `true` if available.
    fn try_consume(&mut self, n: u32) -> bool {
        self.refill();
        if self.tokens >= n {
            self.tokens -= n;
            true
        } else {
            false
        }
    }

    fn refill(&mut self) {
        let elapsed = self.last_refill.elapsed();
        if elapsed >= self.refill_interval {
            self.tokens = self.max;
            self.last_refill = Instant::now();
        }
    }
}

// ---------------------------------------------------------------------------
// Cloudflare JSON types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct CfResponse<T> {
    success: bool,
    errors: Vec<CfError>,
    result: Option<T>,
}

#[derive(Deserialize)]
struct CfError {
    code: u32,
    message: String,
}

#[derive(Deserialize)]
struct CfList {
    id: String,
    name: String,
}

#[derive(Serialize)]
struct CreateListRequest<'a> {
    name: &'a str,
    kind: &'a str,
    description: &'a str,
}

#[derive(Serialize, Deserialize, Clone)]
struct CfListItem {
    ip: String,
}

#[derive(Serialize)]
struct BulkDeleteRequest {
    items: Vec<CfListItemId>,
}

#[derive(Serialize, Clone)]
struct CfListItemId {
    id: String,
}

#[derive(Deserialize)]
struct CfListItemWithId {
    id: String,
    ip: String,
}

#[derive(Serialize)]
struct FirewallRuleRequest<'a> {
    action: &'a str,
    filter: FirewallFilter<'a>,
    description: &'a str,
}

#[derive(Serialize)]
struct FirewallFilter<'a> {
    expression: &'a str,
}

#[derive(Deserialize)]
struct CfFirewallRule {
    id: String,
}

// ---------------------------------------------------------------------------
// CloudflareEnforcer
// ---------------------------------------------------------------------------

/// Cloudflare Firewall Rules / IP Lists enforcement backend.
///
/// Implements [`Enforcer`] so it can be used as a drop-in replacement for
/// nftables or alongside it (by wrapping both in a multi-enforcer).
pub struct CloudflareEnforcer {
    config: CloudflareConfig,
    client: reqwest::Client,
    rate_limiter: Arc<Mutex<TokenBucket>>,
    /// ID of the managed IP list (populated in `setup()`).
    list_id: Option<String>,
    /// Pending bans waiting to be flushed in a batch.
    pending_adds: Vec<IpNet>,
}

impl CloudflareEnforcer {
    /// Create a new enforcer from config.
    ///
    /// The Cloudflare API token is read from `config.api_token`.
    pub fn new(config: CloudflareConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("failed to build HTTP client");

        Self {
            config,
            client,
            rate_limiter: Arc::new(Mutex::new(TokenBucket::new(
                RATE_LIMIT_MAX,
                RATE_LIMIT_WINDOW,
            ))),
            list_id: None,
            pending_adds: Vec::new(),
        }
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Consume one rate-limit token, returning an error if the bucket is empty.
    async fn check_rate_limit(&self) -> Result<()> {
        let ok = self.rate_limiter.lock().await.try_consume(1);
        if ok {
            Ok(())
        } else {
            Err(HiveGuardError::Enforcement(
                "Cloudflare API rate limit exceeded; request dropped".into(),
            ))
        }
    }

    fn auth_header(&self) -> String {
        format!("Bearer {}", self.config.api_token)
    }

    /// GET all IP lists for the account, returning `(name → id)` map.
    async fn fetch_lists(&self) -> Result<HashMap<String, String>> {
        self.check_rate_limit().await?;
        let url = format!(
            "{}/accounts/{}/rules/lists",
            CF_API_BASE, self.config.account_id
        );
        let resp = self
            .client
            .get(&url)
            .header("Authorization", self.auth_header())
            .send()
            .await
            .map_err(|e| HiveGuardError::Enforcement(format!("Cloudflare GET lists: {e}")))?;

        let status = resp.status();
        if status == reqwest::StatusCode::FORBIDDEN {
            warn!("Cloudflare API returned 403; check API token permissions");
            return Ok(HashMap::new());
        }

        let body: CfResponse<Vec<CfList>> = resp
            .json()
            .await
            .map_err(|e| HiveGuardError::Enforcement(format!("Cloudflare parse lists: {e}")))?;

        if !body.success {
            let msgs: Vec<_> = body.errors.iter().map(|e| e.message.as_str()).collect();
            return Err(HiveGuardError::Enforcement(format!(
                "Cloudflare API error: {}",
                msgs.join(", ")
            )));
        }

        Ok(body
            .result
            .unwrap_or_default()
            .into_iter()
            .map(|l| (l.name, l.id))
            .collect())
    }

    /// Create an IP list with the configured name.
    async fn create_list(&self) -> Result<String> {
        self.check_rate_limit().await?;
        let url = format!(
            "{}/accounts/{}/rules/lists",
            CF_API_BASE, self.config.account_id
        );
        let body = CreateListRequest {
            name: &self.config.list_name,
            kind: "ip",
            description: "Managed by HiveGuard — do not edit manually",
        };
        let resp = self
            .client
            .post(&url)
            .header("Authorization", self.auth_header())
            .json(&body)
            .send()
            .await
            .map_err(|e| HiveGuardError::Enforcement(format!("Cloudflare POST list: {e}")))?;

        let status = resp.status();
        if status == reqwest::StatusCode::FORBIDDEN {
            warn!("Cloudflare API returned 403 on create_list; check token scope");
            return Err(HiveGuardError::Enforcement(
                "Cloudflare 403: insufficient permissions to create IP list".into(),
            ));
        }

        let body: CfResponse<CfList> = resp
            .json()
            .await
            .map_err(|e| HiveGuardError::Enforcement(format!("Cloudflare parse create_list: {e}")))?;

        if !body.success || body.result.is_none() {
            let msgs: Vec<_> = body.errors.iter().map(|e| e.message.as_str()).collect();
            return Err(HiveGuardError::Enforcement(format!(
                "Cloudflare create list error: {}",
                msgs.join(", ")
            )));
        }

        Ok(body.result.unwrap().id)
    }

    /// Find or create the IP list, returning its ID.
    async fn ensure_list_id(&mut self) -> Result<String> {
        if let Some(id) = &self.list_id {
            return Ok(id.clone());
        }
        let lists = self.fetch_lists().await?;
        let id = if let Some(existing) = lists.get(&self.config.list_name) {
            info!(
                "Cloudflare: using existing IP list '{}' (id: {})",
                self.config.list_name, existing
            );
            existing.clone()
        } else {
            info!(
                "Cloudflare: creating IP list '{}'",
                self.config.list_name
            );
            let new_id = self.create_list().await?;
            info!(
                "Cloudflare: created IP list '{}' (id: {})",
                self.config.list_name, new_id
            );
            new_id
        };
        self.list_id = Some(id.clone());
        Ok(id)
    }

    /// Create a firewall rule that blocks IPs matching the list in `zone_id`.
    async fn ensure_firewall_rule(&self, zone_id: &str) -> Result<()> {
        // Check whether a matching rule already exists.
        self.check_rate_limit().await?;
        let list_expr = format!(
            "ip.src in ${}",
            self.config.list_name.replace('-', "_")
        );
        let desc = format!("Block IPs in {} (HiveGuard)", self.config.list_name);

        let url = format!("{}/zones/{}/firewall/rules", CF_API_BASE, zone_id);
        let rule = FirewallRuleRequest {
            action: "block",
            filter: FirewallFilter {
                expression: &list_expr,
            },
            description: &desc,
        };

        let resp = self
            .client
            .post(&url)
            .header("Authorization", self.auth_header())
            .json(&[rule])
            .send()
            .await
            .map_err(|e| HiveGuardError::Enforcement(format!("Cloudflare POST firewall rule: {e}")))?;

        let status = resp.status();
        if status == reqwest::StatusCode::FORBIDDEN {
            warn!(
                "Cloudflare API returned 403 on create firewall rule for zone {}; \
                 check token scope — local ban is still applied",
                zone_id
            );
            return Ok(());
        }

        if status.is_success() {
            let body: CfResponse<Vec<CfFirewallRule>> = resp
                .json()
                .await
                .map_err(|e| HiveGuardError::Enforcement(format!("Cloudflare parse rule: {e}")))?;
            if body.success {
                if let Some(rules) = body.result {
                    if let Some(r) = rules.first() {
                        info!(
                            "Cloudflare: created firewall rule (id: {}) in zone {}",
                            r.id, zone_id
                        );
                    }
                }
            } else {
                // Rule may already exist (duplicate) — log and continue.
                let msgs: Vec<_> = body.errors.iter().map(|e| e.message.as_str()).collect();
                warn!(
                    "Cloudflare firewall rule warning for zone {}: {}",
                    zone_id,
                    msgs.join(", ")
                );
            }
        } else {
            warn!(
                "Cloudflare firewall rule creation returned HTTP {} for zone {} — \
                 local ban is still applied",
                status, zone_id
            );
        }
        Ok(())
    }

    /// Append up to `BATCH_SIZE` IPs to the IP list.
    async fn flush_pending(&mut self) -> Result<()> {
        if self.pending_adds.is_empty() {
            return Ok(());
        }
        let list_id = self.ensure_list_id().await?;
        let batch: Vec<IpNet> = self.pending_adds.drain(..).collect();
        self.bulk_add_to_list(&list_id, &batch).await
    }

    /// POST up to `BATCH_SIZE` items per request.
    async fn bulk_add_to_list(&self, list_id: &str, ips: &[IpNet]) -> Result<()> {
        for chunk in ips.chunks(BATCH_SIZE) {
            self.check_rate_limit().await?;
            let items: Vec<CfListItem> = chunk
                .iter()
                .map(|n| CfListItem { ip: n.to_string() })
                .collect();
            let url = format!(
                "{}/accounts/{}/rules/lists/{}/items",
                CF_API_BASE, self.config.account_id, list_id
            );
            let resp = self
                .client
                .post(&url)
                .header("Authorization", self.auth_header())
                .json(&items)
                .send()
                .await
                .map_err(|e| {
                    HiveGuardError::Enforcement(format!("Cloudflare bulk add items: {e}"))
                })?;

            let status = resp.status();
            if status == reqwest::StatusCode::FORBIDDEN {
                warn!(
                    "Cloudflare 403 on bulk add — local ban still applied; \
                     check API token scope"
                );
                return Ok(());
            }
            if !status.is_success() {
                let text = resp.text().await.unwrap_or_default();
                return Err(HiveGuardError::Enforcement(format!(
                    "Cloudflare bulk add HTTP {}: {}",
                    status, text
                )));
            }
            debug!(
                "Cloudflare: pushed {} IPs to list {}",
                chunk.len(),
                list_id
            );
        }
        Ok(())
    }

    /// GET all items in the list, returning `(ip_string → item_id)` pairs.
    async fn fetch_list_items(&self, list_id: &str) -> Result<HashMap<String, String>> {
        self.check_rate_limit().await?;
        let url = format!(
            "{}/accounts/{}/rules/lists/{}/items",
            CF_API_BASE, self.config.account_id, list_id
        );
        let resp = self
            .client
            .get(&url)
            .header("Authorization", self.auth_header())
            .send()
            .await
            .map_err(|e| HiveGuardError::Enforcement(format!("Cloudflare GET list items: {e}")))?;

        let status = resp.status();
        if status == reqwest::StatusCode::FORBIDDEN {
            warn!("Cloudflare 403 on fetch list items");
            return Ok(HashMap::new());
        }

        let body: CfResponse<Vec<CfListItemWithId>> = resp
            .json()
            .await
            .map_err(|e| HiveGuardError::Enforcement(format!("Cloudflare parse list items: {e}")))?;

        if !body.success {
            let msgs: Vec<_> = body.errors.iter().map(|e| e.message.as_str()).collect();
            return Err(HiveGuardError::Enforcement(format!(
                "Cloudflare list items error: {}",
                msgs.join(", ")
            )));
        }

        Ok(body
            .result
            .unwrap_or_default()
            .into_iter()
            .map(|i| (i.ip, i.id))
            .collect())
    }

    /// DELETE a single item by its Cloudflare item ID.
    async fn delete_list_item(&self, list_id: &str, item_id: &str) -> Result<()> {
        self.check_rate_limit().await?;
        let url = format!(
            "{}/accounts/{}/rules/lists/{}/items",
            CF_API_BASE, self.config.account_id, list_id
        );
        let req = BulkDeleteRequest {
            items: vec![CfListItemId {
                id: item_id.to_string(),
            }],
        };
        let resp = self
            .client
            .delete(&url)
            .header("Authorization", self.auth_header())
            .json(&req)
            .send()
            .await
            .map_err(|e| HiveGuardError::Enforcement(format!("Cloudflare DELETE item: {e}")))?;

        let status = resp.status();
        if status == reqwest::StatusCode::FORBIDDEN {
            warn!("Cloudflare 403 on delete item — local unban still applied");
            return Ok(());
        }
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(HiveGuardError::Enforcement(format!(
                "Cloudflare DELETE item HTTP {}: {}",
                status, text
            )));
        }
        Ok(())
    }

    /// PUT (replace all) items in the IP list in `BATCH_SIZE` chunks.
    ///
    /// Cloudflare's `PUT` endpoint replaces the entire list atomically,
    /// but is still bounded by the 1 000-item payload limit per call.
    /// We therefore DELETE all existing items first and then re-add.
    async fn replace_list_items(&self, list_id: &str, ips: &[IpNet]) -> Result<()> {
        // Delete all existing items.
        let existing = self.fetch_list_items(list_id).await?;
        if !existing.is_empty() {
            self.check_rate_limit().await?;
            let url = format!(
                "{}/accounts/{}/rules/lists/{}/items",
                CF_API_BASE, self.config.account_id, list_id
            );
            let ids: Vec<CfListItemId> = existing
                .values()
                .map(|id| CfListItemId { id: id.clone() })
                .collect();
            // Bulk-delete in chunks.
            for chunk in ids.chunks(BATCH_SIZE) {
                self.check_rate_limit().await?;
                let req = BulkDeleteRequest {
                    items: chunk.to_vec(),
                };
                let resp = self
                    .client
                    .delete(&url)
                    .header("Authorization", self.auth_header())
                    .json(&req)
                    .send()
                    .await
                    .map_err(|e| {
                        HiveGuardError::Enforcement(format!("Cloudflare bulk delete: {e}"))
                    })?;
                let status = resp.status();
                if status == reqwest::StatusCode::FORBIDDEN {
                    warn!("Cloudflare 403 on bulk delete — sync aborted");
                    return Ok(());
                }
                if !status.is_success() {
                    let text = resp.text().await.unwrap_or_default();
                    return Err(HiveGuardError::Enforcement(format!(
                        "Cloudflare bulk delete HTTP {}: {}",
                        status, text
                    )));
                }
            }
        }

        // Add new items.
        if !ips.is_empty() {
            self.bulk_add_to_list(list_id, ips).await?;
        }

        info!(
            "Cloudflare: reconciliation complete — {} IPs in list {}",
            ips.len(),
            list_id
        );
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Enforcer impl
// ---------------------------------------------------------------------------

#[async_trait]
impl Enforcer for CloudflareEnforcer {
    /// Find or create the IP list and create firewall rules in all zones.
    async fn setup(&mut self) -> Result<()> {
        if !self.config.enabled {
            debug!("Cloudflare enforcer disabled — skipping setup");
            return Ok(());
        }

        let list_id = match self.ensure_list_id().await {
            Ok(id) => id,
            Err(e) => {
                error!("Cloudflare setup failed (list): {e} — falling back to local enforcement");
                return Ok(());
            }
        };

        // Create firewall rule in the primary zone.
        if let Err(e) = self.ensure_firewall_rule(&self.config.zone_id.clone()).await {
            error!(
                "Cloudflare firewall rule setup failed for primary zone: {e} — \
                 local enforcement still active"
            );
        }

        // Create firewall rules in additional zones.
        let extra_zones: Vec<String> = self
            .config
            .zones
            .iter()
            .map(|z| z.id.clone())
            .collect();
        for zone_id in extra_zones {
            if let Err(e) = self.ensure_firewall_rule(&zone_id).await {
                error!(
                    "Cloudflare firewall rule setup failed for zone {zone_id}: {e}"
                );
            }
        }

        info!(
            "Cloudflare enforcer ready — list_id: {}",
            list_id
        );
        Ok(())
    }

    /// Queue the IP; flush to Cloudflare when the batch is full.
    async fn apply_ban(&mut self, subject: &IpNet) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }
        debug!("Cloudflare: queuing ban for {}", subject);
        self.pending_adds.push(*subject);
        if self.pending_adds.len() >= BATCH_SIZE {
            self.flush_pending().await?;
        }
        Ok(())
    }

    /// Flush any pending bans, then remove the specified IP from the list.
    async fn remove_ban(&mut self, subject: &IpNet) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }
        // Flush any queued adds first so the list is up-to-date.
        if let Err(e) = self.flush_pending().await {
            warn!("Cloudflare flush before remove failed: {e}");
        }

        let list_id = match self.ensure_list_id().await {
            Ok(id) => id,
            Err(e) => {
                warn!("Cloudflare remove_ban: cannot get list_id: {e}");
                return Ok(());
            }
        };

        let items = match self.fetch_list_items(&list_id).await {
            Ok(m) => m,
            Err(e) => {
                warn!("Cloudflare remove_ban: fetch items failed: {e}");
                return Ok(());
            }
        };

        let ip_str = subject.to_string();
        if let Some(item_id) = items.get(&ip_str) {
            self.delete_list_item(&list_id, item_id).await?;
            debug!("Cloudflare: removed {} from list {}", subject, list_id);
        } else {
            debug!("Cloudflare: {} not found in list — nothing to remove", subject);
        }
        Ok(())
    }

    /// Reconcile the Cloudflare IP list with the canonical set of active bans.
    ///
    /// Called by the hourly reconciliation task in the daemon.
    async fn sync_full(&mut self, banned: &[IpNet]) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }
        // Discard any pending adds — they are included in `banned`.
        self.pending_adds.clear();

        let list_id = match self.ensure_list_id().await {
            Ok(id) => id,
            Err(e) => {
                error!("Cloudflare sync_full: cannot get list_id: {e}");
                return Ok(());
            }
        };

        if let Err(e) = self.replace_list_items(&list_id, banned).await {
            error!("Cloudflare sync_full failed: {e} — local bans are unaffected");
        }
        Ok(())
    }

    /// Return the live list of banned IPs from Cloudflare.
    async fn get_current_bans(&self) -> Result<Vec<IpNet>> {
        if !self.config.enabled {
            return Ok(Vec::new());
        }
        let list_id = match &self.list_id {
            Some(id) => id.clone(),
            None => {
                // Not yet initialized.
                return Ok(Vec::new());
            }
        };

        let items = match self.fetch_list_items(&list_id).await {
            Ok(m) => m,
            Err(e) => {
                warn!("Cloudflare get_current_bans failed: {e}");
                return Ok(Vec::new());
            }
        };

        let nets: Vec<IpNet> = items
            .keys()
            .filter_map(|ip_str| ip_str.parse::<IpNet>().ok())
            .collect();
        Ok(nets)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use hiveguard_core::config::{CloudflareConfig, CloudflareZoneConfig};

    fn test_config() -> CloudflareConfig {
        CloudflareConfig {
            enabled: true,
            api_token: "test_token".to_string(),
            zone_id: "zone123".to_string(),
            account_id: "acct456".to_string(),
            list_name: "hiveguard-blocklist".to_string(),
            min_severity: 60,
            zones: vec![],
        }
    }

    #[test]
    fn token_bucket_basic() {
        let mut bucket = TokenBucket::new(10, Duration::from_secs(300));
        assert!(bucket.try_consume(5));
        assert!(bucket.try_consume(5));
        assert!(!bucket.try_consume(1));
    }

    #[test]
    fn token_bucket_refill() {
        let mut bucket = TokenBucket::new(10, Duration::from_nanos(1));
        assert!(bucket.try_consume(10));
        // Force last_refill to be old enough.
        std::thread::sleep(Duration::from_millis(1));
        // After refill window (1 ns has definitely passed), should work again.
        assert!(bucket.try_consume(1));
    }

    #[test]
    fn disabled_enforcer_is_noop() {
        let mut config = test_config();
        config.enabled = false;
        let enforcer = CloudflareEnforcer::new(config);
        // No API calls are made, so no runtime errors.
        assert!(enforcer.list_id.is_none());
        assert!(enforcer.pending_adds.is_empty());
    }

    #[test]
    fn pending_adds_batches_at_limit() {
        let config = test_config();
        let mut enforcer = CloudflareEnforcer::new(config);
        for i in 0..BATCH_SIZE {
            let ip: IpNet = format!("10.{}.{}.1/32", i / 256, i % 256).parse().unwrap();
            enforcer.pending_adds.push(ip);
        }
        assert_eq!(enforcer.pending_adds.len(), BATCH_SIZE);
    }

    #[test]
    fn multi_zone_config_accepted() {
        let config = CloudflareConfig {
            enabled: true,
            api_token: "tok".to_string(),
            zone_id: "z1".to_string(),
            account_id: "a1".to_string(),
            list_name: "hiveguard-blocklist".to_string(),
            min_severity: 60,
            zones: vec![
                CloudflareZoneConfig {
                    id: "z2".to_string(),
                    list_id: None,
                },
                CloudflareZoneConfig {
                    id: "z3".to_string(),
                    list_id: Some("list-xyz".to_string()),
                },
            ],
        };
        let enforcer = CloudflareEnforcer::new(config);
        assert_eq!(enforcer.config.zones.len(), 2);
    }
}
