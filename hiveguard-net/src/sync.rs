use crate::gossip::{GossipAction, GossipConfig, GossipEngine};
use crate::membership::{SwimAction, SwimConfig, SwimMembership};
use crate::peer::PeerManager;
use crate::signed_record::SignedBanRecord;

/// Orchestrates SWIM membership protocol and gossip-based ban synchronization.
pub struct SyncCoordinator {
    swim: SwimMembership,
    gossip: GossipEngine,
    peer_manager: PeerManager,
}

impl SyncCoordinator {
    /// Create a new sync coordinator.
    pub fn new(
        local_node_id: String,
        swim_config: SwimConfig,
        gossip_config: GossipConfig,
    ) -> Self {
        let swim = SwimMembership::new(local_node_id.clone(), swim_config);
        let gossip = GossipEngine::new(local_node_id, gossip_config);
        Self {
            swim,
            gossip,
            peer_manager: PeerManager::new(),
        }
    }

    /// Access the peer manager.
    pub fn peer_manager(&self) -> &PeerManager {
        &self.peer_manager
    }

    /// Access the peer manager mutably.
    pub fn peer_manager_mut(&mut self) -> &mut PeerManager {
        &mut self.peer_manager
    }

    /// Access the SWIM membership.
    pub fn swim(&self) -> &SwimMembership {
        &self.swim
    }

    /// Access the gossip engine.
    pub fn gossip(&self) -> &GossipEngine {
        &self.gossip
    }

    /// Run one SWIM probe cycle.
    ///
    /// Returns the SWIM actions the caller should execute (send messages).
    pub fn run_probe_cycle(&mut self, local_digest: Vec<u8>) -> Vec<SwimAction> {
        let mut actions = Vec::new();

        // Select a target to probe
        let probe_action = self.swim.select_probe_target(&self.peer_manager, local_digest);
        if !matches!(probe_action, SwimAction::None) {
            actions.push(probe_action);
        }

        // Check for timeouts
        let timeout_actions = self.swim.check_timeouts(&mut self.peer_manager);
        actions.extend(timeout_actions);

        actions
    }

    /// Handle an incoming Pong message.
    pub fn handle_pong(&mut self, sender_id: &str) {
        self.swim.handle_pong(sender_id, &mut self.peer_manager);
    }

    /// Handle an incoming Ping message. Returns a Pong action.
    pub fn handle_ping(
        &mut self,
        sender_id: &str,
        _remote_digest: &[u8],
    ) -> SwimAction {
        // Update sender state to alive
        self.peer_manager.update_peer_state(sender_id, crate::peer::PeerState::Alive);

        // We don't produce a SwimAction::SendPong — the caller
        // should assemble a Pong ClusterMessage and send it directly.
        SwimAction::None
    }

    /// Propagate signed bans via gossip.
    pub fn propagate_bans(
        &self,
        records: Vec<SignedBanRecord>,
    ) -> Option<GossipAction> {
        self.gossip.propagate_bans(records, &self.peer_manager)
    }

    /// Handle a received ban sync from a peer (unfiltered, internal only).
    ///
    /// **WARNING:** Bypasses trust, rate limiting, quarantine, and signature checks.
    /// Must NOT be used for network-received data. Use `handle_ban_sync_filtered()` instead.
    pub(crate) fn handle_ban_sync(
        &self,
        records: Vec<SignedBanRecord>,
    ) -> Option<GossipAction> {
        self.gossip.handle_ban_sync(records)
    }

    /// Handle a received ban sync from a peer with full security filtering.
    pub fn handle_ban_sync_filtered(
        &self,
        records: Vec<SignedBanRecord>,
        sender_id: &str,
        trust_manager: &hiveguard_core::trust::TrustManager,
        rate_limiter: &mut hiveguard_core::anti_poison::RateLimiter,
        ban_counts: &std::collections::HashMap<String, usize>,
        peer_public_keys: &std::collections::HashMap<String, Vec<u8>>,
    ) -> Option<GossipAction> {
        self.gossip.handle_ban_sync_filtered(
            records,
            sender_id,
            trust_manager,
            rate_limiter,
            ban_counts,
            peer_public_keys,
        )
    }

    /// Handle a digest exchange from a peer.
    pub fn handle_digest_exchange(
        &self,
        remote_digest: &[u8],
        local_bans: &[hiveguard_core::BanRecord],
        sender_id: &str,
    ) -> Option<GossipAction> {
        self.gossip
            .handle_digest_exchange(remote_digest, local_bans, sender_id)
    }

    /// Handle a diff request from a peer.
    pub fn handle_diff_request(
        &self,
        peer_keys: &[String],
        local_bans: &[hiveguard_core::BanRecord],
    ) -> Vec<hiveguard_core::BanRecord> {
        self.gossip.handle_diff_request(peer_keys, local_bans)
    }

    /// Get the number of alive peers.
    pub fn alive_peer_count(&self) -> usize {
        self.peer_manager.get_alive_peers().len()
    }

    /// Get total peer count.
    pub fn total_peer_count(&self) -> usize {
        self.peer_manager.peer_count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer::PeerInfo;
    use crate::signed_record::SignedBanRecord;
    use chrono::Utc;
    use hiveguard_core::{BanRecord, BanSource};
    use ipnet::IpNet;
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn make_peer(id: &str, port: u16) -> PeerInfo {
        PeerInfo::new(
            id.to_string(),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), port),
            format!("fp_{id}"),
        )
    }

    /// Returns (SignedBanRecord, pkcs8_bytes, raw_pub_key_bytes) for use in tests.
    fn make_signed_ban_with_key(ip: &str) -> (SignedBanRecord, Vec<u8>, Vec<u8>) {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let pub_key = key_pair.public_key().as_ref().to_vec();
        let record = BanRecord {
            subject: ip.parse::<IpNet>().unwrap(),
            created_at: Utc::now(),
            expires_at: Some(Utc::now() + chrono::Duration::hours(24)),
            severity: 150,
            reason: "test ban".into(),
            evidence_hash: [0u8; 32],
            source: BanSource::LocalDetector("test".into()),
            geo_info: None,
        };
        let signed = SignedBanRecord::sign(record, "sender-1", pkcs8.as_ref(), 16).unwrap();
        (signed, pkcs8.as_ref().to_vec(), pub_key)
    }

    fn make_ban(ip: &str) -> SignedBanRecord {
        make_signed_ban_with_key(ip).0
    }

    /// Returns (SignedBanRecord, HashMap<signer_id, pub_key>)
    fn make_ban_with_keys(ip: &str, signer_id: &str) -> (SignedBanRecord, HashMap<String, Vec<u8>>) {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let pub_key = key_pair.public_key().as_ref().to_vec();
        let record = BanRecord {
            subject: ip.parse::<IpNet>().unwrap(),
            created_at: Utc::now(),
            expires_at: Some(Utc::now() + chrono::Duration::hours(24)),
            severity: 150,
            reason: "test ban".into(),
            evidence_hash: [0u8; 32],
            source: BanSource::LocalDetector("test".into()),
            geo_info: None,
        };
        let signed = SignedBanRecord::sign(record, signer_id, pkcs8.as_ref(), 16).unwrap();
        let mut peer_keys = HashMap::new();
        peer_keys.insert(signer_id.to_string(), pub_key);
        (signed, peer_keys)
    }

    #[test]
    fn coordinator_creation() {
        let coord = SyncCoordinator::new(
            "node1".into(),
            SwimConfig::default(),
            GossipConfig::default(),
        );
        assert_eq!(coord.swim().local_node_id(), "node1");
        assert_eq!(coord.gossip().local_node_id(), "node1");
        assert_eq!(coord.total_peer_count(), 0);
        assert_eq!(coord.alive_peer_count(), 0);
    }

    #[test]
    fn add_peers_and_probe() {
        let mut coord = SyncCoordinator::new(
            "local".into(),
            SwimConfig::default(),
            GossipConfig::default(),
        );
        coord.peer_manager_mut().add_peer(make_peer("n1", 9001));
        coord.peer_manager_mut().add_peer(make_peer("n2", 9002));

        assert_eq!(coord.total_peer_count(), 2);
        assert_eq!(coord.alive_peer_count(), 2);

        let actions = coord.run_probe_cycle(vec![1, 2, 3]);
        assert!(!actions.is_empty());
    }

    #[test]
    fn handle_pong_updates_state() {
        let mut coord = SyncCoordinator::new(
            "local".into(),
            SwimConfig::default(),
            GossipConfig::default(),
        );
        coord.peer_manager_mut().add_peer(make_peer("n1", 9001));

        coord.handle_pong("n1");
        assert_eq!(
            coord.peer_manager().get_peer("n1").unwrap().state,
            crate::peer::PeerState::Alive
        );
    }

    #[test]
    fn propagate_bans_no_peers() {
        let coord = SyncCoordinator::new(
            "local".into(),
            SwimConfig::default(),
            GossipConfig::default(),
        );
        let result = coord.propagate_bans(vec![make_ban("10.0.0.1/32")]);
        assert!(result.is_none());
    }

    #[test]
    fn propagate_bans_with_peers() {
        let mut coord = SyncCoordinator::new(
            "local".into(),
            SwimConfig::default(),
            GossipConfig::default(),
        );
        coord.peer_manager_mut().add_peer(make_peer("n1", 9001));

        let result = coord.propagate_bans(vec![make_ban("10.0.0.1/32")]);
        assert!(result.is_some());
    }

    #[test]
    fn handle_ban_sync_returns_apply() {
        let coord = SyncCoordinator::new(
            "local".into(),
            SwimConfig::default(),
            GossipConfig::default(),
        );

        let result = coord.handle_ban_sync(vec![make_ban("10.0.0.1/32")]);
        assert!(result.is_some());
        match result.unwrap() {
            GossipAction::ApplyBans { records } => assert_eq!(records.len(), 1),
            _ => panic!("Expected ApplyBans"),
        }
    }

    #[test]
    fn handle_ban_sync_filtered_trusted_accepted() {
        let coord = SyncCoordinator::new(
            "local".into(),
            SwimConfig::default(),
            GossipConfig::default(),
        );
        // Use threshold 0.8 so a single trusted sender (score ~1.0) suffices
        let mut tm = hiveguard_core::trust::TrustManager::new(0.8);
        let old_time = Utc::now() - chrono::Duration::days(8);
        tm.register_node_with_time("sender-1".into(), old_time);
        for _ in 0..100 {
            tm.record_true_positive("sender-1");
        }
        let mut rl = hiveguard_core::anti_poison::RateLimiter::new(
            100, chrono::Duration::minutes(1),
        );
        let ban_counts = std::collections::HashMap::new();
        let (signed, peer_keys) = make_ban_with_keys("1.2.3.4/32", "sender-1");

        let result = coord.handle_ban_sync_filtered(
            vec![signed],
            "sender-1",
            &tm,
            &mut rl,
            &ban_counts,
            &peer_keys,
        );
        assert!(result.is_some());
        match result.unwrap() {
            GossipAction::ApplyBans { records } => assert_eq!(records.len(), 1),
            _ => panic!("Expected ApplyBans"),
        }
    }

    #[test]
    fn handle_ban_sync_filtered_untrusted_rejected() {
        let coord = SyncCoordinator::new(
            "local".into(),
            SwimConfig::default(),
            GossipConfig::default(),
        );
        let mut tm = hiveguard_core::trust::TrustManager::new(2.0);
        tm.register_node("sender-low".into()); // default 0.5 score < 2.0
        let mut rl = hiveguard_core::anti_poison::RateLimiter::new(
            100, chrono::Duration::minutes(1),
        );
        let ban_counts = std::collections::HashMap::new();
        let (signed, peer_keys) = make_ban_with_keys("1.2.3.5/32", "sender-low");

        let result = coord.handle_ban_sync_filtered(
            vec![signed],
            "sender-low",
            &tm,
            &mut rl,
            &ban_counts,
            &peer_keys,
        );
        assert!(result.is_none());
    }

    #[test]
    fn handle_digest_exchange_matching() {
        let coord = SyncCoordinator::new(
            "local".into(),
            SwimConfig::default(),
            GossipConfig::default(),
        );
        let ban = BanRecord {
            subject: "1.2.3.4/32".parse::<IpNet>().unwrap(),
            created_at: Utc::now(),
            expires_at: None,
            severity: 100,
            reason: "test".into(),
            evidence_hash: [0u8; 32],
            source: BanSource::LocalDetector("test".into()),
            geo_info: None,
        };
        let bans = vec![ban];
        let digest = GossipEngine::compute_digest(&bans);

        let result = coord.handle_digest_exchange(&digest, &bans, "peer1");
        assert!(result.is_none()); // Digests match
    }

    #[test]
    fn handle_digest_exchange_mismatching() {
        let coord = SyncCoordinator::new(
            "local".into(),
            SwimConfig::default(),
            GossipConfig::default(),
        );
        let ban = BanRecord {
            subject: "1.2.3.4/32".parse::<IpNet>().unwrap(),
            created_at: Utc::now(),
            expires_at: None,
            severity: 100,
            reason: "test".into(),
            evidence_hash: [0u8; 32],
            source: BanSource::LocalDetector("test".into()),
            geo_info: None,
        };
        let bans = vec![ban];

        let result = coord.handle_digest_exchange(&[0u8; 32], &bans, "peer1");
        assert!(result.is_some()); // Digests differ
    }

    #[test]
    fn handle_diff_request_returns_missing() {
        let coord = SyncCoordinator::new(
            "local".into(),
            SwimConfig::default(),
            GossipConfig::default(),
        );
        let ban1 = BanRecord {
            subject: "1.2.3.4/32".parse::<IpNet>().unwrap(),
            created_at: Utc::now(),
            expires_at: None,
            severity: 100,
            reason: "test".into(),
            evidence_hash: [0u8; 32],
            source: BanSource::LocalDetector("test".into()),
            geo_info: None,
        };
        let ban2 = BanRecord {
            subject: "1.2.3.5/32".parse::<IpNet>().unwrap(),
            created_at: Utc::now(),
            expires_at: None,
            severity: 100,
            reason: "test".into(),
            evidence_hash: [0u8; 32],
            source: BanSource::LocalDetector("test".into()),
            geo_info: None,
        };
        let bans = vec![ban1, ban2];
        let peer_keys = vec!["1.2.3.4/32".to_string()];

        let missing = coord.handle_diff_request(&peer_keys, &bans);
        assert_eq!(missing.len(), 1);
        assert_eq!(missing[0].subject.to_string(), "1.2.3.5/32");
    }

    #[test]
    fn handle_ping_updates_peer_state() {
        let mut coord = SyncCoordinator::new(
            "local".into(),
            SwimConfig::default(),
            GossipConfig::default(),
        );
        let mut peer = make_peer("n1", 9001);
        peer.state = crate::peer::PeerState::Suspect;
        coord.peer_manager_mut().add_peer(peer);

        coord.handle_ping("n1", &[]);
        assert_eq!(
            coord.peer_manager().get_peer("n1").unwrap().state,
            crate::peer::PeerState::Alive
        );
    }

    #[test]
    fn probe_cycle_with_no_peers_returns_empty() {
        let mut coord = SyncCoordinator::new(
            "local".into(),
            SwimConfig::default(),
            GossipConfig::default(),
        );
        let actions = coord.run_probe_cycle(vec![]);
        assert!(actions.is_empty());
    }
}
