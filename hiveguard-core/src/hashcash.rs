use serde::{Deserialize, Serialize};

/// Proof-of-Work stamp attached to ban records sent via cluster gossip.
///
/// Uses a Hashcash-style scheme: the blake3 hash of
/// `[nonce || canonical_bytes]` must have at least `difficulty` leading
/// zero bits.  Default difficulty = 16 (≈ 65 µs on a modern CPU),
/// making flooding 1 000 000 fake bans cost ~65 seconds of CPU.
///
/// The `canonical_bytes` should be `bincode::serialize(&BanRecord)`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PowStamp {
    pub nonce: u64,
    pub difficulty: u8,
}

impl PowStamp {
    /// Minimum accepted difficulty during verification (prevents trivially-weak stamps).
    /// In tests this is lowered to 1 to make mining instant.
    #[cfg(not(test))]
    pub const MIN_DIFFICULTY: u8 = 16;
    #[cfg(test)]
    pub const MIN_DIFFICULTY: u8 = 1;

    /// Mine a PoW stamp for `canonical_bytes` requiring `difficulty` leading zero bits.
    ///
    /// Unlike `verify()`, this method does NOT enforce `MIN_DIFFICULTY` — the caller
    /// is responsible for choosing a sensible difficulty.  Use at least `MIN_DIFFICULTY`
    /// for production code; tests may use lower values.
    ///
    /// Returns `None` after `max_attempts` without a solution.
    pub fn mine(canonical_bytes: &[u8], difficulty: u8, max_attempts: u64) -> Option<Self> {
        let (full_bytes, remainder) = (
            difficulty as usize / 8,
            difficulty as usize % 8,
        );

        for nonce in 0..max_attempts {
            let hash = Self::compute_hash(nonce, canonical_bytes);
            if Self::has_leading_zeros(&hash, full_bytes, remainder) {
                return Some(Self {
                    nonce,
                    difficulty,
                });
            }
        }
        None
    }

    /// Verify that this stamp is valid for `canonical_bytes`.
    ///
    /// Returns `Ok(())` on success or `Err` with a description of the failure.
    pub fn verify(&self, canonical_bytes: &[u8]) -> Result<(), String> {
        if self.difficulty < Self::MIN_DIFFICULTY {
            return Err(format!(
                "PoW difficulty {} below minimum {}",
                self.difficulty,
                Self::MIN_DIFFICULTY
            ));
        }
        let hash = Self::compute_hash(self.nonce, canonical_bytes);
        let full_bytes = self.difficulty as usize / 8;
        let remainder = self.difficulty as usize % 8;
        if Self::has_leading_zeros(&hash, full_bytes, remainder) {
            Ok(())
        } else {
            Err(format!(
                "PoW verification failed (difficulty={}, nonce={})",
                self.difficulty, self.nonce
            ))
        }
    }

    fn compute_hash(nonce: u64, data: &[u8]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&nonce.to_le_bytes());
        hasher.update(data);
        *hasher.finalize().as_bytes()
    }

    fn has_leading_zeros(hash: &[u8; 32], full_bytes: usize, remainder: usize) -> bool {
        for b in hash.iter().take(full_bytes) {
            if *b != 0 {
                return false;
            }
        }
        if remainder > 0 {
            let mask = 0xFF_u8 << (8 - remainder as u32);
            return hash[full_bytes] & mask == 0;
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DATA: &[u8] = b"192.0.2.1/32:ssh_bruteforce:severity=200";

    #[test]
    fn mine_and_verify() {
        let stamp = PowStamp::mine(DATA, 16, u64::MAX).expect("should find a solution");
        assert!(stamp.difficulty >= PowStamp::MIN_DIFFICULTY);
        stamp.verify(DATA).expect("valid stamp should verify");
    }

    #[test]
    fn verify_wrong_data_fails() {
        let stamp = PowStamp::mine(DATA, 16, u64::MAX).unwrap();
        let result = stamp.verify(b"other data");
        assert!(result.is_err(), "wrong data must fail verification");
    }

    #[test]
    fn below_min_difficulty_rejected() {
        // Manually craft a stamp with low difficulty
        let stamp = PowStamp { nonce: 0, difficulty: 8 };
        let result = stamp.verify(DATA);
        assert!(result.is_err(), "difficulty < MIN must be rejected");
    }

    #[test]
    fn tampered_nonce_fails() {
        let mut stamp = PowStamp::mine(DATA, 16, u64::MAX).unwrap();
        stamp.nonce ^= 0xDEAD_BEEF; // flip bits
        let result = stamp.verify(DATA);
        assert!(result.is_err(), "tampered nonce must fail");
    }

    #[test]
    fn leading_zeros_check_full_bytes() {
        let hash = [0u8; 32];
        assert!(PowStamp::has_leading_zeros(&hash, 4, 0));
    }

    #[test]
    fn leading_zeros_check_partial_byte() {
        let mut hash = [0u8; 32];
        hash[2] = 0b0000_0100; // 5 leading zeros in byte 2
        // full_bytes=2, remainder=3 → mask = 0b1110_0000
        // hash[2] & mask = 0 → passes
        assert!(PowStamp::has_leading_zeros(&hash, 2, 3));
        // remainder=4 → mask = 0b1111_0000
        // hash[2] & mask = 0 → passes
        assert!(PowStamp::has_leading_zeros(&hash, 2, 4));
        // remainder=5 → mask = 0b1111_1000
        // hash[2] & mask = 0 → passes
        assert!(PowStamp::has_leading_zeros(&hash, 2, 5));
        // remainder=6 → mask = 0b1111_1100
        // hash[2] & mask = 0b0000_0100 & 0b1111_1100 = 0b0000_0100 ≠ 0 → fails
        assert!(!PowStamp::has_leading_zeros(&hash, 2, 6));
    }
}
