use hiveguard_core::models::BanRecord;
use serde::{Deserialize, Serialize};

use crate::peer::PeerInfo;
use crate::signed_record::SignedBanRecord;

/// Wire-format messages exchanged between cluster nodes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ClusterMessage {
    /// SWIM protocol ping with state digest.
    Ping {
        sender_id: String,
        digest: Vec<u8>,
    },
    /// SWIM protocol pong in response to Ping.
    Pong {
        sender_id: String,
        digest: Vec<u8>,
    },
    /// Indirect ping request: ask sender to ping target on our behalf.
    PingReq {
        sender_id: String,
        target_id: String,
    },
    /// Push signed ban records to a peer (gossip propagation).
    /// Each record carries an Ed25519 signature from the original author,
    /// providing end-to-end authentication across relay hops.
    BanSync {
        sender_id: String,
        records: Vec<SignedBanRecord>,
    },
    /// Exchange Merkle root for anti-entropy reconciliation.
    DigestExchange {
        merkle_root: Vec<u8>,
    },
    /// Request specific ban records by key.
    DiffRequest {
        missing_keys: Vec<String>,
    },
    /// Response with requested ban records (signed).
    DiffResponse {
        records: Vec<SignedBanRecord>,
    },
    /// Membership update: share known peers.
    MembershipUpdate {
        peers: Vec<PeerInfo>,
    },
}

impl ClusterMessage {
    /// Extract the sender_id from messages that carry one.
    pub fn sender_id(&self) -> Option<&str> {
        match self {
            ClusterMessage::Ping { sender_id, .. } => Some(sender_id),
            ClusterMessage::Pong { sender_id, .. } => Some(sender_id),
            ClusterMessage::PingReq { sender_id, .. } => Some(sender_id),
            ClusterMessage::BanSync { sender_id, .. } => Some(sender_id),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use hiveguard_core::models::BanSource;
    use ipnet::IpNet;

    fn make_ban_record() -> BanRecord {
        BanRecord {
            subject: "192.168.1.1/32".parse::<IpNet>().unwrap(),
            created_at: Utc::now(),
            expires_at: Some(Utc::now()),
            severity: 150,
            reason: "test ban".into(),
            evidence_hash: [0u8; 32],
            source: BanSource::LocalDetector("test".into()),
            geo_info: None,
        }
    }

    fn make_signed_record() -> SignedBanRecord {
        use ring::rand::SystemRandom;
        use ring::signature::Ed25519KeyPair;
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        SignedBanRecord::sign(make_ban_record(), "node-1", pkcs8.as_ref(), 16).unwrap()
    }

    fn roundtrip(msg: &ClusterMessage) -> ClusterMessage {
        let bytes = bincode::serialize(msg).unwrap();
        bincode::deserialize(&bytes).unwrap()
    }

    #[test]
    fn ping_roundtrip() {
        let msg = ClusterMessage::Ping {
            sender_id: "node-1".into(),
            digest: vec![1, 2, 3, 4],
        };
        assert_eq!(msg, roundtrip(&msg));
    }

    #[test]
    fn pong_roundtrip() {
        let msg = ClusterMessage::Pong {
            sender_id: "node-2".into(),
            digest: vec![5, 6, 7],
        };
        assert_eq!(msg, roundtrip(&msg));
    }

    #[test]
    fn ping_req_roundtrip() {
        let msg = ClusterMessage::PingReq {
            sender_id: "node-1".into(),
            target_id: "node-3".into(),
        };
        assert_eq!(msg, roundtrip(&msg));
    }

    #[test]
    fn ban_sync_roundtrip() {
        let msg = ClusterMessage::BanSync {
            sender_id: "node-1".into(),
            records: vec![make_signed_record()],
        };
        assert_eq!(msg, roundtrip(&msg));
    }

    #[test]
    fn digest_exchange_roundtrip() {
        let msg = ClusterMessage::DigestExchange {
            merkle_root: vec![0xAA, 0xBB, 0xCC],
        };
        assert_eq!(msg, roundtrip(&msg));
    }

    #[test]
    fn diff_request_roundtrip() {
        let msg = ClusterMessage::DiffRequest {
            missing_keys: vec!["k1".into(), "k2".into()],
        };
        assert_eq!(msg, roundtrip(&msg));
    }

    #[test]
    fn diff_response_roundtrip() {
        let msg = ClusterMessage::DiffResponse {
            records: vec![make_signed_record()],
        };
        assert_eq!(msg, roundtrip(&msg));
    }

    #[test]
    fn membership_update_roundtrip() {
        let peer = PeerInfo::new(
            "node-5".into(),
            "10.0.0.5:7946".parse().unwrap(),
            "fp123".into(),
        );
        let msg = ClusterMessage::MembershipUpdate {
            peers: vec![peer],
        };
        assert_eq!(msg, roundtrip(&msg));
    }

    #[test]
    fn ban_sync_empty_records() {
        let msg = ClusterMessage::BanSync { sender_id: "node-1".into(), records: vec![] };
        assert_eq!(msg, roundtrip(&msg));
    }

    #[test]
    fn membership_update_empty_peers() {
        let msg = ClusterMessage::MembershipUpdate { peers: vec![] };
        assert_eq!(msg, roundtrip(&msg));
    }
}

