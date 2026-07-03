use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Merkle digest tree for efficient delta synchronization.
///
/// Uses blake3 hash of sorted ban subjects to detect differences
/// between two nodes' ban stores. Supports splitting subjects into
/// buckets for efficient diff computation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MerkleDigest {
    /// Root hash of the entire tree.
    pub root_hash: [u8; 32],
    /// Bucket hashes for diff computation.
    /// Key: bucket index (first byte of subject hash), Value: hash of entries in that bucket.
    pub buckets: BTreeMap<u8, [u8; 32]>,
    /// Total number of entries.
    pub entry_count: usize,
}

impl MerkleDigest {
    /// Build a Merkle digest from a list of subjects.
    pub fn build(subjects: &[String]) -> Self {
        let mut buckets: BTreeMap<u8, Vec<String>> = BTreeMap::new();

        for subject in subjects {
            let hash = blake3::hash(subject.as_bytes());
            let bucket_key = hash.as_bytes()[0];
            buckets.entry(bucket_key).or_default().push(subject.clone());
        }

        let mut bucket_hashes: BTreeMap<u8, [u8; 32]> = BTreeMap::new();
        let mut root_hasher = blake3::Hasher::new();

        // Sort bucket keys for deterministic ordering
        for (key, entries) in &mut buckets {
            entries.sort();
            let combined = entries.join(",");
            let hash = blake3::hash(combined.as_bytes());
            bucket_hashes.insert(*key, *hash.as_bytes());
            root_hasher.update(hash.as_bytes());
        }

        let root_hash = *root_hasher.finalize().as_bytes();

        Self {
            root_hash,
            buckets: bucket_hashes,
            entry_count: subjects.len(),
        }
    }

    /// Check if two digests are equal (no differences).
    pub fn matches(&self, other: &MerkleDigest) -> bool {
        self.root_hash == other.root_hash
    }

    /// Find differing buckets between two digests.
    /// Returns bucket keys where the hashes differ.
    pub fn diff_buckets(&self, other: &MerkleDigest) -> Vec<u8> {
        let mut diff = Vec::new();

        // Buckets in self but not in other, or different
        for (key, hash) in &self.buckets {
            match other.buckets.get(key) {
                Some(other_hash) if other_hash == hash => {} // Same
                _ => diff.push(*key),
            }
        }

        // Buckets in other but not in self
        for key in other.buckets.keys() {
            if !self.buckets.contains_key(key) {
                diff.push(*key);
            }
        }

        diff.sort();
        diff.dedup();
        diff
    }

    /// Determine which subjects from local are missing in the remote digest,
    /// given the set of differing buckets.
    pub fn subjects_in_buckets(subjects: &[String], buckets: &[u8]) -> Vec<String> {
        let bucket_set: std::collections::HashSet<u8> = buckets.iter().cloned().collect();

        subjects
            .iter()
            .filter(|s| {
                let hash = blake3::hash(s.as_bytes());
                bucket_set.contains(&hash.as_bytes()[0])
            })
            .cloned()
            .collect()
    }

    /// Build a simple root hash from subjects (no buckets — for lightweight comparison).
    pub fn root_hash_only(subjects: &[String]) -> [u8; 32] {
        let mut sorted = subjects.to_vec();
        sorted.sort();
        let combined = sorted.join(",");
        *blake3::hash(combined.as_bytes()).as_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_empty() {
        let digest = MerkleDigest::build(&[]);
        assert_eq!(digest.entry_count, 0);
        assert!(digest.buckets.is_empty());
    }

    #[test]
    fn build_single_entry() {
        let digest = MerkleDigest::build(&["10.0.0.1/32".to_string()]);
        assert_eq!(digest.entry_count, 1);
        assert!(!digest.buckets.is_empty());
    }

    #[test]
    fn build_deterministic() {
        let subjects = vec!["10.0.0.1/32".to_string(), "10.0.0.2/32".to_string()];
        let d1 = MerkleDigest::build(&subjects);
        let d2 = MerkleDigest::build(&subjects);
        assert_eq!(d1.root_hash, d2.root_hash);
        assert_eq!(d1.buckets, d2.buckets);
    }

    #[test]
    fn build_order_independent() {
        let d1 = MerkleDigest::build(&["a".to_string(), "b".to_string()]);
        let d2 = MerkleDigest::build(&["b".to_string(), "a".to_string()]);
        assert_eq!(d1.root_hash, d2.root_hash);
    }

    #[test]
    fn matches_identical() {
        let subjects = vec!["10.0.0.1/32".to_string()];
        let d1 = MerkleDigest::build(&subjects);
        let d2 = MerkleDigest::build(&subjects);
        assert!(d1.matches(&d2));
    }

    #[test]
    fn matches_different() {
        let d1 = MerkleDigest::build(&["10.0.0.1/32".to_string()]);
        let d2 = MerkleDigest::build(&["10.0.0.2/32".to_string()]);
        assert!(!d1.matches(&d2));
    }

    #[test]
    fn diff_buckets_identical() {
        let subjects = vec!["10.0.0.1/32".to_string(), "10.0.0.2/32".to_string()];
        let d1 = MerkleDigest::build(&subjects);
        let d2 = MerkleDigest::build(&subjects);
        assert!(d1.diff_buckets(&d2).is_empty());
    }

    #[test]
    fn diff_buckets_different() {
        let d1 = MerkleDigest::build(&["10.0.0.1/32".to_string()]);
        let d2 = MerkleDigest::build(&["10.0.0.1/32".to_string(), "10.0.0.2/32".to_string()]);
        let diff = d1.diff_buckets(&d2);
        assert!(!diff.is_empty());
    }

    #[test]
    fn diff_buckets_superset() {
        let d1 = MerkleDigest::build(&[
            "a".to_string(),
            "b".to_string(),
            "c".to_string(),
        ]);
        let d2 = MerkleDigest::build(&["a".to_string(), "b".to_string()]);
        let diff = d1.diff_buckets(&d2);
        // Should have at least one differing bucket (the one containing "c")
        assert!(!diff.is_empty());
    }

    #[test]
    fn subjects_in_buckets_filters() {
        let subjects = vec![
            "10.0.0.1/32".to_string(),
            "10.0.0.2/32".to_string(),
            "10.0.0.3/32".to_string(),
        ];
        let d1 = MerkleDigest::build(&subjects);

        // Use all buckets — should return all subjects
        let all_buckets: Vec<u8> = d1.buckets.keys().cloned().collect();
        let filtered = MerkleDigest::subjects_in_buckets(&subjects, &all_buckets);
        assert_eq!(filtered.len(), subjects.len());

        // Empty buckets — no subjects
        let none = MerkleDigest::subjects_in_buckets(&subjects, &[]);
        assert!(none.is_empty());
    }

    #[test]
    fn root_hash_only_deterministic() {
        let subjects = vec!["a".to_string(), "b".to_string()];
        let h1 = MerkleDigest::root_hash_only(&subjects);
        let h2 = MerkleDigest::root_hash_only(&subjects);
        assert_eq!(h1, h2);
    }

    #[test]
    fn root_hash_only_order_independent() {
        let h1 = MerkleDigest::root_hash_only(&["a".to_string(), "b".to_string()]);
        let h2 = MerkleDigest::root_hash_only(&["b".to_string(), "a".to_string()]);
        assert_eq!(h1, h2);
    }

    #[test]
    fn root_hash_only_different_sets() {
        let h1 = MerkleDigest::root_hash_only(&["a".to_string()]);
        let h2 = MerkleDigest::root_hash_only(&["b".to_string()]);
        assert_ne!(h1, h2);
    }

    #[test]
    fn serialization_roundtrip() {
        let digest = MerkleDigest::build(&["10.0.0.1/32".to_string(), "10.0.0.2/32".to_string()]);
        let bytes = bincode::serialize(&digest).unwrap();
        let parsed: MerkleDigest = bincode::deserialize(&bytes).unwrap();
        assert_eq!(digest, parsed);
    }

    #[test]
    fn many_entries() {
        let subjects: Vec<String> = (0..1000).map(|i| format!("10.0.{}.{}/32", i / 256, i % 256)).collect();
        let digest = MerkleDigest::build(&subjects);
        assert_eq!(digest.entry_count, 1000);
        assert!(!digest.root_hash.iter().all(|&b| b == 0));
    }
}
