use std::time::Duration;

use chrono::Utc;
use rand::seq::IndexedRandom;
use tracing::debug;

use crate::peer::{PeerInfo, PeerManager, PeerState};

/// Configuration for the SWIM membership protocol.
#[derive(Debug, Clone)]
pub struct SwimConfig {
    /// Interval between probe rounds.
    pub ping_interval: Duration,
    /// Timeout waiting for a Pong reply.
    pub ping_timeout: Duration,
    /// Number of peers to use for indirect probing.
    pub ping_req_fanout: usize,
    /// Time in Suspect state before marking Dead.
    pub suspect_timeout: Duration,
    /// Time in Dead state before removal.
    pub dead_timeout: Duration,
}

impl Default for SwimConfig {
    fn default() -> Self {
        Self {
            ping_interval: Duration::from_secs(1),
            ping_timeout: Duration::from_millis(500),
            ping_req_fanout: 3,
            suspect_timeout: Duration::from_secs(5),
            dead_timeout: Duration::from_secs(30),
        }
    }
}

/// Result of a SWIM probe action.
#[derive(Debug, Clone)]
pub enum SwimAction {
    /// Send a Ping to the given peer.
    SendPing {
        target_id: String,
        digest: Vec<u8>,
    },
    /// Send a PingReq through intermediary peers.
    SendPingReq {
        target_id: String,
        via_peers: Vec<String>,
    },
    /// Mark a peer as Suspect.
    MarkSuspect {
        node_id: String,
    },
    /// Mark a peer as Dead.
    MarkDead {
        node_id: String,
    },
    /// Remove a dead peer.
    RemovePeer {
        node_id: String,
    },
    /// No action needed (no peers or nothing to do).
    None,
}

/// SWIM membership protocol implementation.
///
/// This implements the failure detection logic. The actual network I/O
/// is handled by the sync coordinator which calls into this module.
pub struct SwimMembership {
    config: SwimConfig,
    local_node_id: String,
    /// Tracks which peers have been pinged and are awaiting Pong.
    pending_pings: Vec<PendingPing>,
}

#[derive(Debug, Clone)]
struct PendingPing {
    target_id: String,
    sent_at: chrono::DateTime<Utc>,
    indirect_sent: bool,
}

impl SwimMembership {
    /// Create a new SWIM membership handler.
    pub fn new(local_node_id: String, config: SwimConfig) -> Self {
        Self {
            config,
            local_node_id,
            pending_pings: Vec::new(),
        }
    }

    /// Select a random alive peer to probe and return the action.
    pub fn select_probe_target(&mut self, peer_manager: &PeerManager, digest: Vec<u8>) -> SwimAction {
        let alive = peer_manager.get_alive_peers();
        if alive.is_empty() {
            return SwimAction::None;
        }

        let mut rng = rand::rng();
        let target = alive.choose(&mut rng).unwrap();
        let target_id = target.node_id.clone();

        self.pending_pings.push(PendingPing {
            target_id: target_id.clone(),
            sent_at: Utc::now(),
            indirect_sent: false,
        });

        SwimAction::SendPing {
            target_id,
            digest,
        }
    }

    /// Handle a received Pong — remove from pending pings.
    pub fn handle_pong(&mut self, sender_id: &str, peer_manager: &mut PeerManager) {
        self.pending_pings.retain(|p| p.target_id != sender_id);
        peer_manager.update_peer_state(sender_id, PeerState::Alive);
        debug!(from = sender_id, "Received Pong");
    }

    /// Check for timed-out pings and return necessary actions.
    pub fn check_timeouts(&mut self, peer_manager: &mut PeerManager) -> Vec<SwimAction> {
        let now = Utc::now();
        let mut actions = Vec::new();

        // Collect indices of expired pings
        let mut to_remove = Vec::new();

        for (idx, pending) in self.pending_pings.iter_mut().enumerate() {
            let elapsed = now
                .signed_duration_since(pending.sent_at)
                .to_std()
                .unwrap_or(Duration::ZERO);

            if !pending.indirect_sent && elapsed >= self.config.ping_timeout {
                // Direct ping timed out — try indirect via random peers
                pending.indirect_sent = true;

                let alive: Vec<String> = peer_manager
                    .get_alive_peers()
                    .iter()
                    .filter(|p| p.node_id != pending.target_id && p.node_id != self.local_node_id)
                    .map(|p| p.node_id.clone())
                    .collect();

                let mut rng = rand::rng();
                let k = self.config.ping_req_fanout.min(alive.len());
                let via: Vec<String> = if k > 0 {
                    alive.choose_multiple(&mut rng, k).cloned().collect()
                } else {
                    Vec::new()
                };

                if via.is_empty() {
                    // No intermediaries available — mark suspect immediately
                    actions.push(SwimAction::MarkSuspect {
                        node_id: pending.target_id.clone(),
                    });
                    peer_manager.update_peer_state(&pending.target_id, PeerState::Suspect);
                    to_remove.push(idx);
                } else {
                    actions.push(SwimAction::SendPingReq {
                        target_id: pending.target_id.clone(),
                        via_peers: via,
                    });
                }
            } else if pending.indirect_sent {
                let total_elapsed = now
                    .signed_duration_since(pending.sent_at)
                    .to_std()
                    .unwrap_or(Duration::ZERO);

                // If indirect probe also timed out (2x ping_timeout)
                if total_elapsed >= self.config.ping_timeout * 2 {
                    actions.push(SwimAction::MarkSuspect {
                        node_id: pending.target_id.clone(),
                    });
                    peer_manager.update_peer_state(&pending.target_id, PeerState::Suspect);
                    to_remove.push(idx);
                }
            }
        }

        // Remove processed pings (reverse order to keep indices valid)
        for idx in to_remove.into_iter().rev() {
            self.pending_pings.remove(idx);
        }

        // Check suspects for timeout → Dead
        let suspect_peers: Vec<PeerInfo> = peer_manager
            .all_peers()
            .iter()
            .filter(|p| p.state == PeerState::Suspect)
            .cloned()
            .cloned()
            .collect();

        for peer in &suspect_peers {
            let elapsed = now
                .signed_duration_since(peer.last_seen)
                .to_std()
                .unwrap_or(Duration::ZERO);

            if elapsed >= self.config.suspect_timeout {
                actions.push(SwimAction::MarkDead {
                    node_id: peer.node_id.clone(),
                });
                peer_manager.update_peer_state(&peer.node_id, PeerState::Dead);
            }
        }

        // Check dead peers for removal
        let dead_peers: Vec<PeerInfo> = peer_manager
            .all_peers()
            .iter()
            .filter(|p| p.state == PeerState::Dead)
            .cloned()
            .cloned()
            .collect();

        for peer in &dead_peers {
            let elapsed = now
                .signed_duration_since(peer.last_seen)
                .to_std()
                .unwrap_or(Duration::ZERO);

            if elapsed >= self.config.dead_timeout {
                actions.push(SwimAction::RemovePeer {
                    node_id: peer.node_id.clone(),
                });
                peer_manager.remove_peer(&peer.node_id);
            }
        }

        actions
    }

    /// Get the local node ID.
    pub fn local_node_id(&self) -> &str {
        &self.local_node_id
    }

    /// Get the SWIM config.
    pub fn config(&self) -> &SwimConfig {
        &self.config
    }

    /// Number of pending (unacknowledged) pings.
    pub fn pending_count(&self) -> usize {
        self.pending_pings.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer::PeerInfo;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn make_peer(id: &str) -> PeerInfo {
        PeerInfo::new(
            id.to_string(),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 9000),
            format!("fp_{id}"),
        )
    }

    #[test]
    fn select_probe_target_with_no_peers() {
        let mut swim = SwimMembership::new("local".into(), SwimConfig::default());
        let pm = PeerManager::new();
        let action = swim.select_probe_target(&pm, vec![]);
        assert!(matches!(action, SwimAction::None));
    }

    #[test]
    fn select_probe_target_with_peers() {
        let mut swim = SwimMembership::new("local".into(), SwimConfig::default());
        let mut pm = PeerManager::new();
        pm.add_peer(make_peer("node1"));
        pm.add_peer(make_peer("node2"));

        let action = swim.select_probe_target(&pm, vec![1, 2, 3]);
        match action {
            SwimAction::SendPing { target_id, digest } => {
                assert!(target_id == "node1" || target_id == "node2");
                assert_eq!(digest, vec![1, 2, 3]);
            }
            _ => panic!("Expected SendPing"),
        }
        assert_eq!(swim.pending_count(), 1);
    }

    #[test]
    fn handle_pong_clears_pending() {
        let mut swim = SwimMembership::new("local".into(), SwimConfig::default());
        let mut pm = PeerManager::new();
        pm.add_peer(make_peer("node1"));

        swim.select_probe_target(&pm, vec![]);
        assert_eq!(swim.pending_count(), 1);

        swim.handle_pong("node1", &mut pm);
        assert_eq!(swim.pending_count(), 0);
        assert_eq!(pm.get_peer("node1").unwrap().state, PeerState::Alive);
    }

    #[test]
    fn check_timeouts_no_pending() {
        let mut swim = SwimMembership::new("local".into(), SwimConfig::default());
        let mut pm = PeerManager::new();
        let actions = swim.check_timeouts(&mut pm);
        assert!(actions.is_empty());
    }

    #[test]
    fn check_timeouts_marks_suspect_when_no_intermediaries() {
        let config = SwimConfig {
            ping_timeout: Duration::from_millis(1), // Very short timeout
            ..SwimConfig::default()
        };
        let mut swim = SwimMembership::new("local".into(), config);
        let mut pm = PeerManager::new();
        pm.add_peer(make_peer("node1"));

        swim.select_probe_target(&pm, vec![]);

        // Wait for timeout
        std::thread::sleep(Duration::from_millis(5));

        let actions = swim.check_timeouts(&mut pm);
        assert!(!actions.is_empty());

        // With only one peer (the target), no intermediaries exist
        // So it should be marked suspect
        let has_suspect = actions.iter().any(|a| matches!(a, SwimAction::MarkSuspect { node_id } if node_id == "node1"));
        assert!(has_suspect, "Expected MarkSuspect for node1, got: {:?}", actions);
        assert_eq!(pm.get_peer("node1").unwrap().state, PeerState::Suspect);
    }

    #[test]
    fn check_timeouts_sends_ping_req_with_intermediaries() {
        let config = SwimConfig {
            ping_timeout: Duration::from_millis(1),
            ..SwimConfig::default()
        };
        let mut swim = SwimMembership::new("local".into(), config);
        let mut pm = PeerManager::new();
        pm.add_peer(make_peer("target"));
        pm.add_peer(make_peer("helper1"));
        pm.add_peer(make_peer("helper2"));

        // Manually push a pending ping for "target"
        swim.pending_pings.push(PendingPing {
            target_id: "target".into(),
            sent_at: Utc::now() - chrono::Duration::seconds(1),
            indirect_sent: false,
        });

        let actions = swim.check_timeouts(&mut pm);

        let has_ping_req = actions.iter().any(|a| matches!(a, SwimAction::SendPingReq { target_id, .. } if target_id == "target"));
        assert!(has_ping_req, "Expected SendPingReq, got: {:?}", actions);
    }

    #[test]
    fn local_node_id_accessor() {
        let swim = SwimMembership::new("my_node".into(), SwimConfig::default());
        assert_eq!(swim.local_node_id(), "my_node");
    }

    #[test]
    fn config_accessor() {
        let config = SwimConfig {
            ping_interval: Duration::from_secs(5),
            ..SwimConfig::default()
        };
        let swim = SwimMembership::new("local".into(), config.clone());
        assert_eq!(swim.config().ping_interval, Duration::from_secs(5));
    }

    #[test]
    fn default_swim_config() {
        let config = SwimConfig::default();
        assert_eq!(config.ping_interval, Duration::from_secs(1));
        assert_eq!(config.ping_timeout, Duration::from_millis(500));
        assert_eq!(config.ping_req_fanout, 3);
        assert_eq!(config.suspect_timeout, Duration::from_secs(5));
        assert_eq!(config.dead_timeout, Duration::from_secs(30));
    }
}
