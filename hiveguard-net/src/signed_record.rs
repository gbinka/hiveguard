use hiveguard_core::{BanRecord, HiveGuardError, PowStamp};
use ring::signature::{Ed25519KeyPair, UnparsedPublicKey, ED25519};
use serde::{Deserialize, Serialize};

/// A `BanRecord` with an Ed25519 signature and a Proof-of-Work stamp.
///
/// **Signature** covers the bincode-serialized `BanRecord`, binding the record
/// to its content and author.  End-to-end authentication across relay hops.
///
/// **PoW stamp** proves the originating node spent CPU to produce this record,
/// making mass fake-ban flooding costly (default: 16-bit PoW ≈ 65 µs/record).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SignedBanRecord {
    pub record: BanRecord,
    /// node_id (blake3 fingerprint of Ed25519 public key) of the originating node.
    pub signer_id: String,
    /// Ed25519 signature over `bincode::serialize(&record)`.
    pub signature: Vec<u8>,
    /// Proof-of-Work stamp mined over `bincode::serialize(&record)`.
    pub pow: PowStamp,
}

impl SignedBanRecord {
    /// Sign a `BanRecord` and attach a PoW stamp.
    ///
    /// `difficulty` is the number of leading zero bits required (min 16).
    /// `local_node_id` should be `NodeIdentity::node_id()`.
    pub fn sign(
        record: BanRecord,
        local_node_id: &str,
        pkcs8_key_bytes: &[u8],
        difficulty: u8,
    ) -> Result<Self, HiveGuardError> {
        let canonical = bincode::serialize(&record)
            .map_err(|e| HiveGuardError::Protocol(format!("sign: serialize error: {e}")))?;

        let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8_key_bytes).map_err(|_| {
            HiveGuardError::Protocol("sign: invalid Ed25519 PKCS#8 key".to_string())
        })?;

        let signature = key_pair.sign(&canonical).as_ref().to_vec();

        let pow = PowStamp::mine(&canonical, difficulty, u64::MAX).ok_or_else(|| {
            HiveGuardError::Protocol("PoW mining exhausted nonce space".to_string())
        })?;

        Ok(Self {
            record,
            signer_id: local_node_id.to_string(),
            signature,
            pow,
        })
    }

    /// Verify both the Ed25519 signature and the PoW stamp.
    ///
    /// `public_key_raw` must be the raw 32-byte Ed25519 public key stored
    /// in `PeerInfo::public_key_bytes` after TLS handshake.
    pub fn verify(&self, public_key_raw: &[u8]) -> Result<(), HiveGuardError> {
        let canonical = bincode::serialize(&self.record)
            .map_err(|e| HiveGuardError::Protocol(format!("verify: serialize error: {e}")))?;

        // 1. Verify Ed25519 signature
        let peer_public_key = UnparsedPublicKey::new(&ED25519, public_key_raw);
        peer_public_key
            .verify(&canonical, &self.signature)
            .map_err(|_| {
                HiveGuardError::Protocol(format!(
                    "invalid signature from signer {}",
                    self.signer_id
                ))
            })?;

        // 2. Verify Proof-of-Work
        self.pow
            .verify(&canonical)
            .map_err(|e| HiveGuardError::Protocol(format!("PoW verification failed: {e}")))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use hiveguard_core::{BanSource, models::BanRecord};
    use ipnet::IpNet;
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use ring::rand::SystemRandom;

    fn make_record() -> BanRecord {
        BanRecord {
            subject: "1.2.3.4/32".parse::<IpNet>().unwrap(),
            created_at: Utc::now(),
            expires_at: None,
            severity: 200,
            reason: "test".into(),
            evidence_hash: [0u8; 32],
            source: BanSource::LocalDetector("ssh_bruteforce".into()),
            geo_info: None,
        }
    }

    fn gen_key() -> (Vec<u8>, Vec<u8>) {
        let rng = SystemRandom::new();
        let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).unwrap();
        let pub_key = key_pair.public_key().as_ref().to_vec();
        (pkcs8_bytes.as_ref().to_vec(), pub_key)
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let (priv_key, pub_key) = gen_key();
        let record = make_record();
        let signed = SignedBanRecord::sign(record.clone(), "node-abc", &priv_key, 16).unwrap();

        assert_eq!(signed.signer_id, "node-abc");
        assert_eq!(signed.record, record);
        signed.verify(&pub_key).expect("signature should be valid");
    }

    #[test]
    fn tampered_record_fails_verification() {
        let (priv_key, pub_key) = gen_key();
        let record = make_record();
        let mut signed = SignedBanRecord::sign(record, "node-abc", &priv_key, 16).unwrap();

        // Tamper with the severity
        signed.record.severity = 10;

        signed
            .verify(&pub_key)
            .expect_err("tampered record must fail verification");
    }

    #[test]
    fn wrong_key_fails_verification() {
        let (priv_key, _) = gen_key();
        let (_, other_pub_key) = gen_key();
        let record = make_record();
        let signed = SignedBanRecord::sign(record, "node-abc", &priv_key, 16).unwrap();

        signed
            .verify(&other_pub_key)
            .expect_err("wrong public key must fail verification");
    }

    #[test]
    fn tampered_pow_fails_verification() {
        let (priv_key, pub_key) = gen_key();
        let record = make_record();
        let mut signed = SignedBanRecord::sign(record, "node-abc", &priv_key, 16).unwrap();

        signed.pow.nonce ^= 0xDEAD_BEEF_u64;

        signed
            .verify(&pub_key)
            .expect_err("tampered PoW must fail verification");
    }

    /// CRITICAL compatibility check: the rcgen-generated NodeIdentity key must be
    /// usable by ring's `Ed25519KeyPair::from_pkcs8` (used inside `sign`), and the
    /// resulting signature must verify against the identity's raw public key (the
    /// same key parsed out of the TLS cert by peers).
    #[test]
    fn node_identity_key_signs_and_verifies() {
        use crate::identity::NodeIdentity;
        use tempfile::TempDir;

        let dir = TempDir::new().unwrap();
        let id = NodeIdentity::generate(dir.path()).unwrap();
        let pkcs8 = id.private_key_der();

        let signed = SignedBanRecord::sign(make_record(), id.node_id(), &pkcs8, 16)
            .expect("ring must accept rcgen PKCS#8 key");

        let raw_pub = id.keypair().public_key_raw();
        signed
            .verify(raw_pub)
            .expect("signature from identity key must verify against its raw pubkey");
    }
}
