use std::collections::HashMap;

use hiveguard_core::anti_poison::{check_quarantine, median, RateLimiter};
use hiveguard_core::trust::TrustManager;
use hiveguard_core::BanRecord;
use rand::seq::IndexedRandom;
use tracing::{debug, info, warn};

use crate::peer::PeerManager;
use crate::signed_record::SignedBanRecord;

/// Configuration for the gossip engine.
#[derive(Debug, Clone)]
pub struct GossipConfig {
    /// Number of peers to gossip new bans to.
    pub fanout: usize,
    /// Leading zero bits required in the PoW stamp attached to each outgoing ban record.
    /// Must be >= `PowStamp::MIN_DIFFICULTY` (16). Higher values increase mining cost.
    pub pow_difficulty: u8,
}

impl Default for GossipConfig {
    fn default() -> Self {
        Self {
            fanout: 3,
            pow_difficulty: 16,
        }
    }
}

/// Result of gossip operations — actions the caller should execute.
#[derive(Debug, Clone)]
pub enum GossipAction {
    /// Send a ban sync message to these peers.
    SendBanSync {
        target_ids: Vec<String>,
        records: Vec<SignedBanRecord>,
    },
    /// Send a digest exchange to a peer.
    SendDigestExchange {
        target_id: String,
        digest: Vec<u8>,
    },
    /// Send a diff request to a peer.
    SendDiffRequest {
        target_id: String,
        missing_keys: Vec<String>,
    },
    /// Apply these received ban records locally (already verified).
    ApplyBans {
        records: Vec<BanRecord>,
    },
}

/// Gossip engine for propagating ban records across the cluster.
pub struct GossipEngine {
    config: GossipConfig,
    local_node_id: String,
}

impl GossipEngine {
    /// Create a new gossip engine.
    pub fn new(local_node_id: String, config: GossipConfig) -> Self {
        Self {
            config,
            local_node_id,
        }
    }

    /// Compute a simple digest of the local ban store.
    /// Returns a blake3 hash of all ban subjects sorted alphabetically.
    pub fn compute_digest(bans: &[BanRecord]) -> Vec<u8> {
        let mut keys: Vec<String> = bans.iter().map(|b| b.subject.to_string()).collect();
        keys.sort();
        let combined = keys.join(",");
        let hash = blake3::hash(combined.as_bytes());
        hash.as_bytes().to_vec()
    }

    /// Determine which peers to gossip a new ban to.
    pub fn select_gossip_targets(&self, peer_manager: &PeerManager) -> Vec<String> {
        let alive = peer_manager.get_alive_peers();
        if alive.is_empty() {
            return Vec::new();
        }

        let mut rng = rand::rng();
        let k = self.config.fanout.min(alive.len());
        alive
            .choose_multiple(&mut rng, k)
            .map(|p| p.node_id.clone())
            .collect()
    }

    /// Create a gossip action for propagating new (signed) bans.
    pub fn propagate_bans(
        &self,
        records: Vec<SignedBanRecord>,
        peer_manager: &PeerManager,
    ) -> Option<GossipAction> {
        if records.is_empty() {
            return None;
        }

        let targets = self.select_gossip_targets(peer_manager);
        if targets.is_empty() {
            return None;
        }

        info!(
            count = records.len(),
            targets = targets.len(),
            "Propagating bans via gossip"
        );

        Some(GossipAction::SendBanSync {
            target_ids: targets,
            records,
        })
    }

    /// Process a received digest and determine if a diff is needed.
    pub fn handle_digest_exchange(
        &self,
        remote_digest: &[u8],
        local_bans: &[BanRecord],
        sender_id: &str,
    ) -> Option<GossipAction> {
        let local_digest = Self::compute_digest(local_bans);

        if local_digest == remote_digest {
            debug!(peer = sender_id, "Digest match — no sync needed");
            return None;
        }

        info!(peer = sender_id, "Digest mismatch — requesting diff");

        // For simple implementation, request all keys (the peer will send what we're missing)
        let local_keys: Vec<String> = local_bans.iter().map(|b| b.subject.to_string()).collect();
        Some(GossipAction::SendDiffRequest {
            target_id: sender_id.to_string(),
            missing_keys: local_keys,
        })
    }

    /// Process a diff request — return records the peer is missing.
    pub fn handle_diff_request(
        &self,
        peer_keys: &[String],
        local_bans: &[BanRecord],
    ) -> Vec<BanRecord> {
        let peer_set: std::collections::HashSet<&str> =
            peer_keys.iter().map(|s| s.as_str()).collect();

        local_bans
            .iter()
            .filter(|b| !peer_set.contains(b.subject.to_string().as_str()))
            .cloned()
            .collect()
    }

    /// Process received ban records from a peer (unfiltered).
    ///
    /// **WARNING:** This method bypasses trust scoring, rate limiting, quarantine,
    /// and signature checks. It must NOT be used for records received from the network.
    /// Use `handle_ban_sync_filtered()` instead. Retained only for local/internal use.
    pub(crate) fn handle_ban_sync(&self, records: Vec<SignedBanRecord>) -> Option<GossipAction> {
        if records.is_empty() {
            return None;
        }

        info!(count = records.len(), "Received ban sync from peer");
        Some(GossipAction::ApplyBans {
            records: records.into_iter().map(|s| s.record).collect(),
        })
    }

    /// Process received signed ban records from a peer with full security filtering.
    ///
    /// Each record is checked against:
    /// 1. Quarantine — reject all if sender's ban volume is anomalous
    /// 2. Rate limiter — reject if sender exceeds max bans per minute
    /// 3. Signature verification — reject if Ed25519 signature is invalid
    /// 4. Trust scoring — reject if reporters' combined trust < threshold
    ///
    /// `peer_public_keys`: map of node_id → raw Ed25519 public key bytes,
    /// populated from `PeerInfo::public_key_bytes` after TLS handshake.
    ///
    /// Returns only the `BanRecord`s that pass all filters.
    pub fn handle_ban_sync_filtered(
        &self,
        records: Vec<SignedBanRecord>,
        sender_id: &str,
        trust_manager: &TrustManager,
        rate_limiter: &mut RateLimiter,
        ban_counts: &HashMap<String, usize>,
        peer_public_keys: &HashMap<String, Vec<u8>>,
    ) -> Option<GossipAction> {
        if records.is_empty() {
            return None;
        }

        // 1. Quarantine check
        let counts: Vec<usize> = ban_counts
            .iter()
            .filter(|(k, _)| k.as_str() != sender_id)
            .map(|(_, v)| *v)
            .collect();
        let med = median(&counts);
        let sender_count = ban_counts.get(sender_id).copied().unwrap_or(0);

        if !counts.is_empty() && check_quarantine(sender_count + records.len(), med) {
            warn!(
                sender = sender_id,
                ban_count = sender_count + records.len(),
                median = med,
                "Node quarantined — rejecting all ban records"
            );
            return None;
        }

        let mut accepted = Vec::new();

        for signed in records {
            // 2. Rate limit check
            if !rate_limiter.check_and_record(sender_id) {
                warn!(
                    sender = sender_id,
                    subject = %signed.record.subject,
                    "Rate limit exceeded — dropping ban record"
                );
                continue;
            }

            // 3. Signature verification — use signer's public key if known
            if let Some(pub_key) = peer_public_keys.get(&signed.signer_id) {
                if let Err(e) = signed.verify(pub_key) {
                    warn!(
                        sender = sender_id,
                        signer = %signed.signer_id,
                        subject = %signed.record.subject,
                        error = %e,
                        "Signature verification failed — dropping ban record"
                    );
                    continue;
                }
            } else {
                // Unknown signer: no public key to verify against — drop record
                warn!(
                    sender = sender_id,
                    signer = %signed.signer_id,
                    subject = %signed.record.subject,
                    "Unknown signer (no public key) — dropping ban record"
                );
                continue;
            }

            // 4. Trust check: signer + relay endorsement
            let mut reporters = vec![sender_id.to_string()];
            if signed.signer_id != sender_id {
                reporters.push(signed.signer_id.clone());
            }

            if !trust_manager.should_enforce(&reporters) {
                debug!(
                    sender = sender_id,
                    signer = %signed.signer_id,
                    subject = %signed.record.subject,
                    "Insufficient trust — dropping ban record"
                );
                continue;
            }

            accepted.push(signed.record);
        }

        if accepted.is_empty() {
            info!(sender = sender_id, "All ban records filtered out");
            return None;
        }

        info!(
            sender = sender_id,
            accepted = accepted.len(),
            "Accepted filtered ban records from peer"
        );
        Some(GossipAction::ApplyBans { records: accepted })
    }

    /// Get the gossip config.
    pub fn config(&self) -> &GossipConfig {
        &self.config
    }

    /// Get the local node ID.
    pub fn local_node_id(&self) -> &str {
        &self.local_node_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use hiveguard_core::BanSource;
    use ipnet::IpNet;
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    /// Test difficulty — must be >= 16 (hiveguard-core is compiled as a lib dep,
    /// not in #[cfg(test)] mode, so MIN_DIFFICULTY=16 applies during verification).
    const TEST_POW: u8 = 16;

    /// Generate a fresh Ed25519 keypair. Returns (pkcs8_bytes, pub_key_bytes).
    fn gen_key() -> (Vec<u8>, Vec<u8>) {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let kp = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let pub_key = kp.public_key().as_ref().to_vec();
        (pkcs8.as_ref().to_vec(), pub_key)
    }

    /// Make a SignedBanRecord for `ip` signed by "test-node".
    /// Returns (record, signer_id, pub_key_bytes).
    fn make_signed_ban(ip: &str) -> (SignedBanRecord, String, Vec<u8>) {
        let (priv_key, pub_key) = gen_key();
        let record = hiveguard_core::models::BanRecord {
            subject: ip.parse::<IpNet>().unwrap(),
            created_at: Utc::now(),
            expires_at: Some(Utc::now() + chrono::Duration::hours(24)),
            severity: 150,
            reason: "test".into(),
            evidence_hash: [0u8; 32],
            source: BanSource::LocalDetector("test".into()),
            geo_info: None,
        };
        let signed = SignedBanRecord::sign(record, "test-node", &priv_key, TEST_POW).unwrap();
        (signed, "test-node".to_string(), pub_key)
    }

    /// Make a SignedBanRecord for `ip` signed by `signer_id` with ClusterPeer source.
    fn make_signed_ban_from_peer(ip: &str, signer_id: &str) -> (SignedBanRecord, String, Vec<u8>) {
        let (priv_key, pub_key) = gen_key();
        let record = hiveguard_core::models::BanRecord {
            subject: ip.parse::<IpNet>().unwrap(),
            created_at: Utc::now(),
            expires_at: Some(Utc::now() + chrono::Duration::hours(24)),
            severity: 150,
            reason: "test".into(),
            evidence_hash: [0u8; 32],
            source: BanSource::ClusterPeer(signer_id.to_string()),
            geo_info: None,
        };
        let signed = SignedBanRecord::sign(record, signer_id, &priv_key, TEST_POW).unwrap();
        (signed, signer_id.to_string(), pub_key)
    }

    /// Build a peer_public_keys map from a list of (signer_id, pub_key).
    fn peer_keys(items: &[(&str, Vec<u8>)]) -> HashMap<String, Vec<u8>> {
        items.iter().map(|(id, k)| (id.to_string(), k.clone())).collect()
    }

    /// Simpler helper that creates a single signed ban and returns the signed record.
    /// Sets signer_id to the sender_id provided so the peer_keys match.
    fn make_ban(ip: &str) -> SignedBanRecord {
        make_signed_ban(ip).0
    }

    fn make_ban_from_peer(ip: &str, peer_id: &str) -> SignedBanRecord {
        make_signed_ban_from_peer(ip, peer_id).0
    }

    fn make_peer_info(id: &str) -> crate::peer::PeerInfo {
        crate::peer::PeerInfo::new(
            id.into(),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 9000),
            format!("fp_{id}"),
        )
    }

    fn make_trusted_manager(node_ids: &[&str]) -> TrustManager {
        make_trusted_manager_with_threshold(node_ids, 2.0)
    }

    fn make_trusted_manager_with_threshold(node_ids: &[&str], threshold: f64) -> TrustManager {
        let mut tm = TrustManager::new(threshold);
        let old_time = Utc::now() - chrono::Duration::days(8);
        for id in node_ids {
            tm.register_node_with_time(id.to_string(), old_time);
            for _ in 0..100 {
                tm.record_true_positive(id);
            }
        }
        tm
    }

    #[test]
    fn compute_digest_same_bans_same_digest() {
        let bans = vec![make_ban("10.0.0.1/32").record, make_ban("10.0.0.2/32").record];
        let d1 = GossipEngine::compute_digest(&bans);
        let d2 = GossipEngine::compute_digest(&bans);
        assert_eq!(d1, d2);
    }

    #[test]
    fn compute_digest_different_bans_different_digest() {
        let bans1 = vec![make_ban("10.0.0.1/32").record];
        let bans2 = vec![make_ban("10.0.0.2/32").record];
        let d1 = GossipEngine::compute_digest(&bans1);
        let d2 = GossipEngine::compute_digest(&bans2);
        assert_ne!(d1, d2);
    }

    #[test]
    fn compute_digest_order_independent() {
        let bans1 = vec![make_ban("10.0.0.1/32").record, make_ban("10.0.0.2/32").record];
        let bans2 = vec![make_ban("10.0.0.2/32").record, make_ban("10.0.0.1/32").record];
        let d1 = GossipEngine::compute_digest(&bans1);
        let d2 = GossipEngine::compute_digest(&bans2);
        assert_eq!(d1, d2); // sorted internally
    }

    #[test]
    fn compute_digest_empty() {
        let d = GossipEngine::compute_digest(&[]);
        assert!(!d.is_empty());
    }

    #[test]
    fn select_gossip_targets_no_peers() {
        let engine = GossipEngine::new("local".into(), GossipConfig::default());
        let pm = PeerManager::new();
        let targets = engine.select_gossip_targets(&pm);
        assert!(targets.is_empty());
    }

    #[test]
    fn select_gossip_targets_with_peers() {
        let engine = GossipEngine::new("local".into(), GossipConfig { fanout: 2, ..Default::default() });
        let mut pm = PeerManager::new();
        pm.add_peer(make_peer_info("n1"));
        pm.add_peer(make_peer_info("n2"));
        pm.add_peer(make_peer_info("n3"));

        let targets = engine.select_gossip_targets(&pm);
        assert_eq!(targets.len(), 2);
    }

    #[test]
    fn select_gossip_targets_fanout_exceeds_peers() {
        let engine = GossipEngine::new("local".into(), GossipConfig { fanout: 10, ..Default::default() });
        let mut pm = PeerManager::new();
        pm.add_peer(make_peer_info("n1"));
        pm.add_peer(make_peer_info("n2"));

        let targets = engine.select_gossip_targets(&pm);
        assert_eq!(targets.len(), 2); // Only 2 peers available
    }

    #[test]
    fn propagate_bans_no_peers_returns_none() {
        let engine = GossipEngine::new("local".into(), GossipConfig::default());
        let pm = PeerManager::new();
        let result = engine.propagate_bans(vec![make_ban("10.0.0.1/32")], &pm);
        assert!(result.is_none());
    }

    #[test]
    fn propagate_bans_empty_records_returns_none() {
        let engine = GossipEngine::new("local".into(), GossipConfig::default());
        let mut pm = PeerManager::new();
        pm.add_peer(make_peer_info("n1"));
        let result = engine.propagate_bans(vec![], &pm);
        assert!(result.is_none());
    }

    #[test]
    fn propagate_bans_with_peers_returns_action() {
        let engine = GossipEngine::new("local".into(), GossipConfig { fanout: 2, ..Default::default() });
        let mut pm = PeerManager::new();
        pm.add_peer(make_peer_info("n1"));
        pm.add_peer(make_peer_info("n2"));

        let bans = vec![make_ban("10.0.0.1/32")];
        let result = engine.propagate_bans(bans, &pm);
        assert!(result.is_some());
        match result.unwrap() {
            GossipAction::SendBanSync { target_ids, records } => {
                assert_eq!(target_ids.len(), 2);
                assert_eq!(records.len(), 1);
            }
            _ => panic!("Expected SendBanSync"),
        }
    }

    #[test]
    fn handle_digest_exchange_matching_digest() {
        let engine = GossipEngine::new("local".into(), GossipConfig::default());
        let bans = vec![make_ban("10.0.0.1/32").record];
        let digest = GossipEngine::compute_digest(&bans);

        let result = engine.handle_digest_exchange(&digest, &bans, "peer1");
        assert!(result.is_none()); // Digests match
    }

    #[test]
    fn handle_digest_exchange_mismatching_digest() {
        let engine = GossipEngine::new("local".into(), GossipConfig::default());
        let local_bans = vec![make_ban("10.0.0.1/32").record];
        let remote_digest = vec![0u8; 32]; // Different from local

        let result = engine.handle_digest_exchange(&remote_digest, &local_bans, "peer1");
        assert!(result.is_some());
        match result.unwrap() {
            GossipAction::SendDiffRequest { target_id, missing_keys } => {
                assert_eq!(target_id, "peer1");
                assert_eq!(missing_keys.len(), 1);
            }
            _ => panic!("Expected SendDiffRequest"),
        }
    }

    #[test]
    fn handle_diff_request_returns_missing_records() {
        let engine = GossipEngine::new("local".into(), GossipConfig::default());
        let local_bans = vec![
            make_ban("10.0.0.1/32").record,
            make_ban("10.0.0.2/32").record,
            make_ban("10.0.0.3/32").record,
        ];

        // Peer already has 10.0.0.1/32
        let peer_keys = vec!["10.0.0.1/32".to_string()];
        let missing = engine.handle_diff_request(&peer_keys, &local_bans);
        assert_eq!(missing.len(), 2); // 10.0.0.2 and 10.0.0.3
    }

    #[test]
    fn handle_diff_request_peer_has_all() {
        let engine = GossipEngine::new("local".into(), GossipConfig::default());
        let local_bans = vec![make_ban("10.0.0.1/32").record];
        let peer_keys = vec!["10.0.0.1/32".to_string()];
        let missing = engine.handle_diff_request(&peer_keys, &local_bans);
        assert!(missing.is_empty());
    }

    #[test]
    fn handle_ban_sync_empty_returns_none() {
        let engine = GossipEngine::new("local".into(), GossipConfig::default());
        let result = engine.handle_ban_sync(vec![]);
        assert!(result.is_none());
    }

    #[test]
    fn handle_ban_sync_with_records_returns_apply() {
        let engine = GossipEngine::new("local".into(), GossipConfig::default());
        let bans = vec![make_ban("10.0.0.1/32")];
        let result = engine.handle_ban_sync(bans);
        match result.unwrap() {
            GossipAction::ApplyBans { records } => {
                assert_eq!(records.len(), 1);
            }
            _ => panic!("Expected ApplyBans"),
        }
    }

    #[test]
    fn gossip_config_default() {
        let config = GossipConfig::default();
        assert_eq!(config.fanout, 3);
    }

    // --- Phase 18: trust + rate limit + quarantine integration tests ---
    //
    // These tests use shared static keypairs (OnceLock) to avoid per-call key
    // generation and ensure the signer_id embedded in SignedBanRecord matches
    // the pub_key stored in the peer_public_keys map.

    use std::sync::OnceLock;

    static SENDER_1: OnceLock<(Vec<u8>, Vec<u8>)> = OnceLock::new();
    static ORIGIN_1: OnceLock<(Vec<u8>, Vec<u8>)> = OnceLock::new();
    static PEER_X: OnceLock<(Vec<u8>, Vec<u8>)> = OnceLock::new();
    static SENDER_LOW: OnceLock<(Vec<u8>, Vec<u8>)> = OnceLock::new();

    fn kp(cell: &'static OnceLock<(Vec<u8>, Vec<u8>)>) -> &'static (Vec<u8>, Vec<u8>) {
        cell.get_or_init(|| gen_key())
    }

    fn signed_ban(ip: &str, signer: &str, cell: &'static OnceLock<(Vec<u8>, Vec<u8>)>) -> SignedBanRecord {
        let (priv_key, _) = kp(cell);
        let record = hiveguard_core::models::BanRecord {
            subject: ip.parse::<IpNet>().unwrap(),
            created_at: Utc::now(),
            expires_at: Some(Utc::now() + chrono::Duration::hours(24)),
            severity: 150,
            reason: "test".into(),
            evidence_hash: [0u8; 32],
            source: BanSource::LocalDetector("test".into()),
            geo_info: None,
        };
        SignedBanRecord::sign(record, signer, priv_key, TEST_POW).unwrap()
    }

    fn signed_ban_from_peer(ip: &str, signer: &str, cell: &'static OnceLock<(Vec<u8>, Vec<u8>)>) -> SignedBanRecord {
        let (priv_key, _) = kp(cell);
        let record = hiveguard_core::models::BanRecord {
            subject: ip.parse::<IpNet>().unwrap(),
            created_at: Utc::now(),
            expires_at: Some(Utc::now() + chrono::Duration::hours(24)),
            severity: 150,
            reason: "test".into(),
            evidence_hash: [0u8; 32],
            source: BanSource::ClusterPeer(signer.to_string()),
            geo_info: None,
        };
        SignedBanRecord::sign(record, signer, priv_key, TEST_POW).unwrap()
    }

    fn pkeys(pairs: &[(&str, &'static OnceLock<(Vec<u8>, Vec<u8>)>)]) -> HashMap<String, Vec<u8>> {
        pairs.iter()
            .map(|(id, cell)| (id.to_string(), kp(cell).1.clone()))
            .collect()
    }

    #[test]
    fn filtered_sync_two_reporters_accepted() {
        let engine = GossipEngine::new("local".into(), GossipConfig::default());
        let tm = make_trusted_manager(&["sender-1", "origin-1"]);
        let mut rl = RateLimiter::new(100, chrono::Duration::minutes(1));
        let ban_counts: HashMap<String, usize> = HashMap::new();

        let bans = vec![signed_ban_from_peer("1.2.3.0/32", "origin-1", &ORIGIN_1)];
        let pk = pkeys(&[("origin-1", &ORIGIN_1)]);

        let result = engine.handle_ban_sync_filtered(bans, "sender-1", &tm, &mut rl, &ban_counts, &pk);
        assert!(result.is_some());
        match result.unwrap() {
            GossipAction::ApplyBans { records } => assert_eq!(records.len(), 1),
            _ => panic!("Expected ApplyBans"),
        }
    }

    #[test]
    fn filtered_sync_single_sender_local_detector_below_threshold() {
        let engine = GossipEngine::new("local".into(), GossipConfig::default());
        let tm = make_trusted_manager(&["sender-1"]);
        let mut rl = RateLimiter::new(100, chrono::Duration::minutes(1));
        let ban_counts: HashMap<String, usize> = HashMap::new();

        let bans = vec![signed_ban("1.2.3.1/32", "sender-1", &SENDER_1)];
        let pk = pkeys(&[("sender-1", &SENDER_1)]);
        let result = engine.handle_ban_sync_filtered(bans, "sender-1", &tm, &mut rl, &ban_counts, &pk);
        assert!(result.is_none()); // Single reporter ~1.0 < threshold 2.0
    }

    #[test]
    fn filtered_sync_single_sender_low_threshold_accepted() {
        let engine = GossipEngine::new("local".into(), GossipConfig::default());
        let tm = make_trusted_manager_with_threshold(&["sender-1"], 0.8);
        let mut rl = RateLimiter::new(100, chrono::Duration::minutes(1));
        let ban_counts: HashMap<String, usize> = HashMap::new();

        let bans = vec![signed_ban("1.2.3.2/32", "sender-1", &SENDER_1)];
        let pk = pkeys(&[("sender-1", &SENDER_1)]);
        let result = engine.handle_ban_sync_filtered(bans, "sender-1", &tm, &mut rl, &ban_counts, &pk);
        assert!(result.is_some());
    }

    #[test]
    fn filtered_sync_untrusted_sender_rejected() {
        let engine = GossipEngine::new("local".into(), GossipConfig::default());
        let mut tm = TrustManager::new(2.0);
        tm.register_node("sender-low".into());
        let mut rl = RateLimiter::new(100, chrono::Duration::minutes(1));
        let ban_counts: HashMap<String, usize> = HashMap::new();

        let bans = vec![signed_ban("1.2.3.3/32", "sender-low", &SENDER_LOW)];
        let pk = pkeys(&[("sender-low", &SENDER_LOW)]);
        let result = engine.handle_ban_sync_filtered(bans, "sender-low", &tm, &mut rl, &ban_counts, &pk);
        assert!(result.is_none()); // Trust too low
    }

    #[test]
    fn filtered_sync_rate_limited() {
        let engine = GossipEngine::new("local".into(), GossipConfig::default());
        let tm = make_trusted_manager_with_threshold(&["sender-1"], 0.8);
        let mut rl = RateLimiter::new(5, chrono::Duration::minutes(1));
        let ban_counts: HashMap<String, usize> = HashMap::new();

        for _ in 0..5 {
            rl.check_and_record("sender-1");
        }

        let bans = vec![signed_ban("1.2.3.4/32", "sender-1", &SENDER_1)];
        let pk = pkeys(&[("sender-1", &SENDER_1)]);
        let result = engine.handle_ban_sync_filtered(bans, "sender-1", &tm, &mut rl, &ban_counts, &pk);
        assert!(result.is_none()); // Rate limited
    }

    #[test]
    fn filtered_sync_partial_rate_limit() {
        let engine = GossipEngine::new("local".into(), GossipConfig::default());
        let tm = make_trusted_manager_with_threshold(&["sender-1"], 0.8);
        let mut rl = RateLimiter::new(3, chrono::Duration::minutes(1));
        let ban_counts: HashMap<String, usize> = HashMap::new();

        rl.check_and_record("sender-1");
        rl.check_and_record("sender-1");

        let bans = vec![
            signed_ban("1.2.4.1/32", "sender-1", &SENDER_1),
            signed_ban("1.2.4.2/32", "sender-1", &SENDER_1),
            signed_ban("1.2.4.3/32", "sender-1", &SENDER_1),
        ];
        let pk = pkeys(&[("sender-1", &SENDER_1)]);
        let result = engine.handle_ban_sync_filtered(bans, "sender-1", &tm, &mut rl, &ban_counts, &pk);
        assert!(result.is_some());
        match result.unwrap() {
            GossipAction::ApplyBans { records } => assert_eq!(records.len(), 1),
            _ => panic!("Expected ApplyBans"),
        }
    }

    #[test]
    fn filtered_sync_quarantined_sender_all_rejected() {
        let engine = GossipEngine::new("local".into(), GossipConfig::default());
        let tm = make_trusted_manager_with_threshold(&["sender-1"], 0.8);
        let mut rl = RateLimiter::new(1000, chrono::Duration::minutes(1));

        let mut ban_counts: HashMap<String, usize> = HashMap::new();
        ban_counts.insert("sender-1".into(), 600);
        ban_counts.insert("sender-2".into(), 5);
        ban_counts.insert("sender-3".into(), 4);

        let bans = vec![signed_ban("1.2.5.1/32", "sender-1", &SENDER_1)];
        let pk = pkeys(&[("sender-1", &SENDER_1)]);
        let result = engine.handle_ban_sync_filtered(bans, "sender-1", &tm, &mut rl, &ban_counts, &pk);
        assert!(result.is_none()); // Quarantined
    }

    #[test]
    fn filtered_sync_empty_records_returns_none() {
        let engine = GossipEngine::new("local".into(), GossipConfig::default());
        let tm = make_trusted_manager(&["sender-1"]);
        let mut rl = RateLimiter::new(100, chrono::Duration::minutes(1));
        let ban_counts: HashMap<String, usize> = HashMap::new();

        let result = engine.handle_ban_sync_filtered(
            vec![], "sender-1", &tm, &mut rl, &ban_counts, &HashMap::new(),
        );
        assert!(result.is_none());
    }

    #[test]
    fn filtered_sync_cluster_peer_both_trusted() {
        let engine = GossipEngine::new("local".into(), GossipConfig::default());
        let tm = make_trusted_manager(&["sender-1", "peer-x"]);
        let mut rl = RateLimiter::new(100, chrono::Duration::minutes(1));
        let ban_counts: HashMap<String, usize> = HashMap::new();

        let bans = vec![signed_ban_from_peer("1.2.6.1/32", "peer-x", &PEER_X)];
        let pk = pkeys(&[("peer-x", &PEER_X)]);
        let result = engine.handle_ban_sync_filtered(bans, "sender-1", &tm, &mut rl, &ban_counts, &pk);
        assert!(result.is_some()); // Both reporters trusted → sum ≥ 2.0
    }

    #[test]
    fn filtered_sync_cluster_peer_source_untrusted_originator() {
        // peer-y is not trusted → only sender-1's score (~1.0) < threshold 2.0
        // But: we don't have PEER_Y in pkeys → signer unknown → record dropped
        let engine = GossipEngine::new("local".into(), GossipConfig::default());
        let tm = make_trusted_manager(&["sender-1"]);
        let mut rl = RateLimiter::new(100, chrono::Duration::minutes(1));
        let ban_counts: HashMap<String, usize> = HashMap::new();

        // Sign as "peer-x" but use a freshly generated (unknown) key
        let (priv_key, _) = gen_key();
        let record = hiveguard_core::models::BanRecord {
            subject: "1.2.7.1/32".parse::<IpNet>().unwrap(),
            created_at: Utc::now(),
            expires_at: None,
            severity: 100,
            reason: "test".into(),
            evidence_hash: [0u8; 32],
            source: BanSource::ClusterPeer("peer-y".to_string()),
            geo_info: None,
        };
        let signed = SignedBanRecord::sign(record, "peer-y", &priv_key, TEST_POW).unwrap();
        let result = engine.handle_ban_sync_filtered(
            vec![signed], "sender-1", &tm, &mut rl, &ban_counts,
            &HashMap::new(), // peer-y not in peer_keys → unknown signer → dropped
        );
        assert!(result.is_none());
    }

    #[test]
    fn filtered_sync_100_bans_within_rate_limit() {
        let engine = GossipEngine::new("local".into(), GossipConfig::default());
        let tm = make_trusted_manager_with_threshold(&["sender-1"], 0.8);
        let mut rl = RateLimiter::new(100, chrono::Duration::minutes(1));
        let ban_counts: HashMap<String, usize> = HashMap::new();

        let (priv_key, pub_key) = gen_key();
        let bans: Vec<SignedBanRecord> = (1u32..=100)
            .map(|i| {
                let ip = format!("2.0.{}.{}/32", i / 256, i % 256);
                let r = hiveguard_core::models::BanRecord {
                    subject: ip.parse::<IpNet>().unwrap(),
                    created_at: Utc::now(),
                    expires_at: None,
                    severity: 100,
                    reason: "test".into(),
                    evidence_hash: [0u8; 32],
                    source: BanSource::LocalDetector("test".into()),
                    geo_info: None,
                };
                SignedBanRecord::sign(r, "sender-1", &priv_key, TEST_POW).unwrap()
            })
            .collect();
        let pk: HashMap<String, Vec<u8>> = [("sender-1".to_string(), pub_key)].into_iter().collect();
        let result = engine.handle_ban_sync_filtered(bans, "sender-1", &tm, &mut rl, &ban_counts, &pk);
        assert!(result.is_some());
        match result.unwrap() {
            GossipAction::ApplyBans { records } => assert_eq!(records.len(), 100),
            _ => panic!("Expected ApplyBans"),
        }
    }

    #[test]
    fn filtered_sync_101st_ban_rejected() {
        let engine = GossipEngine::new("local".into(), GossipConfig::default());
        let tm = make_trusted_manager_with_threshold(&["sender-1"], 0.8);
        let mut rl = RateLimiter::new(100, chrono::Duration::minutes(1));
        let ban_counts: HashMap<String, usize> = HashMap::new();

        let (priv_key, pub_key) = gen_key();
        let bans: Vec<SignedBanRecord> = (1u32..=101)
            .map(|i| {
                let ip = format!("3.0.{}.{}/32", i / 256, i % 256);
                let r = hiveguard_core::models::BanRecord {
                    subject: ip.parse::<IpNet>().unwrap(),
                    created_at: Utc::now(),
                    expires_at: None,
                    severity: 100,
                    reason: "test".into(),
                    evidence_hash: [0u8; 32],
                    source: BanSource::LocalDetector("test".into()),
                    geo_info: None,
                };
                SignedBanRecord::sign(r, "sender-1", &priv_key, TEST_POW).unwrap()
            })
            .collect();
        let pk: HashMap<String, Vec<u8>> = [("sender-1".to_string(), pub_key)].into_iter().collect();
        let result = engine.handle_ban_sync_filtered(bans, "sender-1", &tm, &mut rl, &ban_counts, &pk);
        assert!(result.is_some());
        match result.unwrap() {
            GossipAction::ApplyBans { records } => assert_eq!(records.len(), 100),
            _ => panic!("Expected ApplyBans"),
        }
    }

    #[test]
    fn filtered_sync_quarantine_at_exact_boundary() {
        let engine = GossipEngine::new("local".into(), GossipConfig::default());
        let tm = make_trusted_manager_with_threshold(&["sender-1"], 0.8);
        let mut rl = RateLimiter::new(1000, chrono::Duration::minutes(1));

        let mut ban_counts: HashMap<String, usize> = HashMap::new();
        ban_counts.insert("sender-1".into(), 49);
        ban_counts.insert("other".into(), 5);

        let bans = vec![signed_ban("1.2.8.1/32", "sender-1", &SENDER_1)];
        let pk = pkeys(&[("sender-1", &SENDER_1)]);
        let result = engine.handle_ban_sync_filtered(bans, "sender-1", &tm, &mut rl, &ban_counts, &pk);
        assert!(result.is_some()); // 50 <= 50, not quarantined
    }

    #[test]
    fn filtered_sync_quarantine_just_above_boundary() {
        let engine = GossipEngine::new("local".into(), GossipConfig::default());
        let tm = make_trusted_manager_with_threshold(&["sender-1"], 0.8);
        let mut rl = RateLimiter::new(1000, chrono::Duration::minutes(1));

        let mut ban_counts: HashMap<String, usize> = HashMap::new();
        ban_counts.insert("sender-1".into(), 50);
        ban_counts.insert("other".into(), 5);

        let bans = vec![signed_ban("1.2.9.1/32", "sender-1", &SENDER_1)];
        let pk = pkeys(&[("sender-1", &SENDER_1)]);
        let result = engine.handle_ban_sync_filtered(bans, "sender-1", &tm, &mut rl, &ban_counts, &pk);
        assert!(result.is_none()); // 51 > 50, quarantined
    }

    #[test]
    fn filtered_sync_grace_period_new_node_needs_higher_trust() {
        let mut tm = TrustManager::new(2.0);
        tm.register_node("new-node".into());
        assert!(tm.is_in_grace_period("new-node"));
        assert!((tm.effective_threshold("new-node") - 4.0).abs() < f64::EPSILON);
    }

    #[test]
    fn filtered_sync_multiple_reporters_sum_trust() {
        let tm = make_trusted_manager(&["n1", "n2"]);
        assert!(tm.should_enforce(&["n1".into(), "n2".into()]));
        assert!(!tm.should_enforce(&["n1".into()]));
    }

    #[test]
    fn filtered_sync_same_sender_as_originator_deduplicated() {
        let engine = GossipEngine::new("local".into(), GossipConfig::default());
        let tm = make_trusted_manager(&["sender-1"]);
        let mut rl = RateLimiter::new(100, chrono::Duration::minutes(1));
        let ban_counts: HashMap<String, usize> = HashMap::new();

        // ClusterPeer source with same ID as sender → only 1 reporter
        let bans = vec![signed_ban_from_peer("1.2.10.1/32", "sender-1", &SENDER_1)];
        let pk = pkeys(&[("sender-1", &SENDER_1)]);
        let result = engine.handle_ban_sync_filtered(bans, "sender-1", &tm, &mut rl, &ban_counts, &pk);
        assert!(result.is_none()); // Single reporter ~1.0 < 2.0
    }
}
