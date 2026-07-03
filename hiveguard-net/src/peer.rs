use std::collections::HashMap;
use std::net::SocketAddr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use hiveguard_core::HiveGuardError;

/// State of a cluster peer in the SWIM failure detector.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PeerState {
    Alive,
    Suspect,
    Dead,
}

/// Information about a cluster peer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PeerInfo {
    pub node_id: String,
    pub address: SocketAddr,
    pub fingerprint: String,
    pub trust_score: f64,
    pub state: PeerState,
    pub last_seen: DateTime<Utc>,
    /// Raw Ed25519 public key bytes — used to verify `SignedBanRecord` signatures.
    /// Empty when the peer was added from static config (before first TLS handshake).
    pub public_key_bytes: Vec<u8>,
}

impl PeerInfo {
    pub fn new(node_id: String, address: SocketAddr, fingerprint: String) -> Self {
        Self {
            node_id,
            address,
            fingerprint,
            trust_score: 0.5,
            state: PeerState::Alive,
            last_seen: Utc::now(),
            public_key_bytes: Vec::new(),
        }
    }
}

/// Manages known cluster peers.
pub struct PeerManager {
    known_peers: HashMap<String, PeerInfo>,
    /// When true, unknown peers are automatically accepted and registered.
    auto_accept: bool,
}

impl PeerManager {
    pub fn new() -> Self {
        Self {
            known_peers: HashMap::new(),
            auto_accept: false,
        }
    }

    /// Create a PeerManager in auto-accept mode (development / bootstrap).
    pub fn new_auto_accept() -> Self {
        Self {
            known_peers: HashMap::new(),
            auto_accept: true,
        }
    }

    /// Whether auto-accept mode is enabled.
    pub fn auto_accept_enabled(&self) -> bool {
        self.auto_accept
    }

    pub fn add_peer(&mut self, peer: PeerInfo) {
        self.known_peers.insert(peer.node_id.clone(), peer);
    }

    pub fn remove_peer(&mut self, node_id: &str) -> Option<PeerInfo> {
        self.known_peers.remove(node_id)
    }

    pub fn update_peer_state(&mut self, node_id: &str, state: PeerState) -> bool {
        if let Some(peer) = self.known_peers.get_mut(node_id) {
            peer.state = state;
            peer.last_seen = Utc::now();
            true
        } else {
            false
        }
    }

    pub fn get_alive_peers(&self) -> Vec<&PeerInfo> {
        self.known_peers
            .values()
            .filter(|p| p.state == PeerState::Alive)
            .collect()
    }

    pub fn get_peer(&self, node_id: &str) -> Option<&PeerInfo> {
        self.known_peers.get(node_id)
    }

    pub fn all_peers(&self) -> Vec<&PeerInfo> {
        self.known_peers.values().collect()
    }

    pub fn peer_count(&self) -> usize {
        self.known_peers.len()
    }

    /// Validate a peer connection by checking the TLS fingerprint against known peers.
    /// Also extracts and stores the peer's Ed25519 public key for message verification.
    ///
    /// In strict mode (auto_accept = false):
    /// - Known peer: fingerprint must match the registered value
    /// - Unknown peer: connection is rejected
    ///
    /// In auto-accept mode:
    /// - Known peer: fingerprint must match
    /// - Unknown peer: automatically registered with the presented fingerprint
    pub fn validate_peer_connection(
        &mut self,
        conn: &quinn::Connection,
        claimed_node_id: &str,
    ) -> Result<(), HiveGuardError> {
        let (fp, pub_key_bytes) = crate::transport::extract_peer_fingerprint_and_key(conn)
            .ok_or_else(|| HiveGuardError::Protocol("no peer certificate".to_string()))?;

        match self.known_peers.get_mut(claimed_node_id) {
            Some(known) if known.fingerprint == fp => {
                // Update public key bytes on every successful handshake
                known.public_key_bytes = pub_key_bytes;
                Ok(())
            }
            Some(known) => {
                warn!(
                    node_id = claimed_node_id,
                    expected = %known.fingerprint,
                    got = %fp,
                    "Fingerprint mismatch — rejecting connection"
                );
                Err(HiveGuardError::Protocol(format!(
                    "fingerprint mismatch for {}: expected {}, got {}",
                    claimed_node_id, known.fingerprint, fp
                )))
            }
            None if self.auto_accept => {
                info!(
                    node_id = claimed_node_id,
                    fingerprint = %fp,
                    addr = %conn.remote_address(),
                    "Auto-accepting new peer"
                );
                let mut peer = PeerInfo::new(
                    claimed_node_id.to_string(),
                    conn.remote_address(),
                    fp,
                );
                peer.public_key_bytes = pub_key_bytes;
                self.add_peer(peer);
                Ok(())
            }
            None => {
                warn!(
                    node_id = claimed_node_id,
                    fingerprint = %fp,
                    "Unknown peer rejected (auto-accept disabled)"
                );
                Err(HiveGuardError::Protocol(
                    "unknown peer, auto-accept disabled".to_string(),
                ))
            }
        }
    }

    /// Verify that a claimed sender_id matches the fingerprint registered for that peer.
    /// Returns true if the sender is valid (fingerprint matches or no fingerprint known yet).
    pub fn verify_sender(&self, claimed_id: &str, peer_fingerprint: &str) -> bool {
        match self.known_peers.get(claimed_id) {
            Some(peer) => peer.fingerprint == peer_fingerprint,
            None => false,
        }
    }
}

impl Default for PeerManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_peer(id: &str) -> PeerInfo {
        PeerInfo::new(
            id.to_string(),
            "127.0.0.1:7946".parse().unwrap(),
            format!("fp_{id}"),
        )
    }

    #[test]
    fn add_and_get_peer() {
        let mut mgr = PeerManager::new();
        mgr.add_peer(make_peer("node-1"));

        assert_eq!(mgr.peer_count(), 1);
        let peer = mgr.get_peer("node-1").unwrap();
        assert_eq!(peer.node_id, "node-1");
        assert_eq!(peer.fingerprint, "fp_node-1");
        assert_eq!(peer.state, PeerState::Alive);
        assert!((peer.trust_score - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn remove_peer() {
        let mut mgr = PeerManager::new();
        mgr.add_peer(make_peer("node-1"));
        mgr.add_peer(make_peer("node-2"));

        let removed = mgr.remove_peer("node-1");
        assert!(removed.is_some());
        assert_eq!(mgr.peer_count(), 1);
        assert!(mgr.get_peer("node-1").is_none());
    }

    #[test]
    fn remove_nonexistent_returns_none() {
        let mut mgr = PeerManager::new();
        assert!(mgr.remove_peer("ghost").is_none());
    }

    #[test]
    fn update_peer_state() {
        let mut mgr = PeerManager::new();
        mgr.add_peer(make_peer("node-1"));

        assert!(mgr.update_peer_state("node-1", PeerState::Suspect));
        assert_eq!(mgr.get_peer("node-1").unwrap().state, PeerState::Suspect);

        assert!(mgr.update_peer_state("node-1", PeerState::Dead));
        assert_eq!(mgr.get_peer("node-1").unwrap().state, PeerState::Dead);
    }

    #[test]
    fn update_nonexistent_returns_false() {
        let mut mgr = PeerManager::new();
        assert!(!mgr.update_peer_state("ghost", PeerState::Dead));
    }

    #[test]
    fn get_alive_peers() {
        let mut mgr = PeerManager::new();
        mgr.add_peer(make_peer("alive-1"));
        mgr.add_peer(make_peer("alive-2"));
        mgr.add_peer(make_peer("dead-1"));
        mgr.update_peer_state("dead-1", PeerState::Dead);

        let alive = mgr.get_alive_peers();
        assert_eq!(alive.len(), 2);
        assert!(alive.iter().all(|p| p.state == PeerState::Alive));
    }

    #[test]
    fn all_peers_includes_all_states() {
        let mut mgr = PeerManager::new();
        mgr.add_peer(make_peer("a"));
        mgr.add_peer(make_peer("b"));
        mgr.update_peer_state("b", PeerState::Suspect);

        assert_eq!(mgr.all_peers().len(), 2);
    }

    #[test]
    fn add_peer_overwrites_existing() {
        let mut mgr = PeerManager::new();
        let mut peer = make_peer("node-1");
        peer.trust_score = 0.8;
        mgr.add_peer(peer);

        let mut updated = make_peer("node-1");
        updated.trust_score = 0.3;
        mgr.add_peer(updated);

        assert_eq!(mgr.peer_count(), 1);
        assert!((mgr.get_peer("node-1").unwrap().trust_score - 0.3).abs() < f64::EPSILON);
    }

    #[test]
    fn default_constructor() {
        let mgr = PeerManager::default();
        assert_eq!(mgr.peer_count(), 0);
    }

    #[test]
    fn peer_info_default_values() {
        let peer = PeerInfo::new(
            "n1".into(),
            "192.168.1.1:7946".parse().unwrap(),
            "abc123".into(),
        );
        assert_eq!(peer.state, PeerState::Alive);
        assert!((peer.trust_score - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn peer_info_ipv6() {
        let peer = PeerInfo::new(
            "n1".into(),
            "[::1]:7946".parse().unwrap(),
            "fp".into(),
        );
        assert_eq!(peer.address, "[::1]:7946".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn verify_sender_known_peer_correct_fingerprint() {
        let mut mgr = PeerManager::new();
        mgr.add_peer(make_peer("node-1"));
        assert!(mgr.verify_sender("node-1", "fp_node-1"));
    }

    #[test]
    fn verify_sender_known_peer_wrong_fingerprint() {
        let mut mgr = PeerManager::new();
        mgr.add_peer(make_peer("node-1"));
        assert!(!mgr.verify_sender("node-1", "wrong_fingerprint"));
    }

    #[test]
    fn verify_sender_unknown_peer() {
        let mgr = PeerManager::new();
        assert!(!mgr.verify_sender("ghost", "any_fp"));
    }

    #[test]
    fn auto_accept_mode() {
        let mgr = PeerManager::new_auto_accept();
        assert!(mgr.auto_accept_enabled());
        assert!(!PeerManager::new().auto_accept_enabled());
    }
}
