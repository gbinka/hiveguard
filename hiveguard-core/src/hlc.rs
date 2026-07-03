use std::cmp::Ordering;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// Hybrid Logical Clock timestamp.
///
/// Provides causal ordering across distributed nodes with bounded clock skew.
/// Ordering: wall_time_ms first, then counter, then node_id_hash for total ordering.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct HlcTimestamp {
    /// Physical wall clock time in milliseconds since epoch.
    pub wall_time_ms: u64,
    /// Logical counter for events at the same wall time.
    pub counter: u32,
    /// Hash of the originating node ID (for tiebreaking).
    pub node_id_hash: u32,
}

impl HlcTimestamp {
    /// Create a new HLC timestamp from current wall clock.
    pub fn now(node_id_hash: u32) -> Self {
        let wall_time_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        Self {
            wall_time_ms,
            counter: 0,
            node_id_hash,
        }
    }

    /// Create an HLC timestamp with specific values.
    pub fn new(wall_time_ms: u64, counter: u32, node_id_hash: u32) -> Self {
        Self {
            wall_time_ms,
            counter,
            node_id_hash,
        }
    }

    /// Compute a node ID hash from a string identifier.
    pub fn hash_node_id(node_id: &str) -> u32 {
        let hash = blake3::hash(node_id.as_bytes());
        let bytes = hash.as_bytes();
        u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
    }

    /// Generate the next local event timestamp, advancing the HLC.
    pub fn tick(&mut self) -> HlcTimestamp {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        if now_ms > self.wall_time_ms {
            self.wall_time_ms = now_ms;
            self.counter = 0;
        } else {
            self.counter += 1;
        }

        self.clone()
    }

    /// Update based on a received remote timestamp (receive event).
    ///
    /// If the remote timestamp exceeds the max skew bound, it is clamped
    /// to prevent a malicious node from advancing the local clock.
    pub fn update(&mut self, remote: &HlcTimestamp) -> HlcTimestamp {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        // Clamp remote wall_time_ms to prevent clock manipulation attacks
        let remote_wall = if remote.wall_time_ms > now_ms + Self::MAX_SKEW_MS {
            now_ms + Self::MAX_SKEW_MS
        } else {
            remote.wall_time_ms
        };

        if now_ms > self.wall_time_ms && now_ms > remote_wall {
            self.wall_time_ms = now_ms;
            self.counter = 0;
        } else if self.wall_time_ms == remote_wall {
            self.counter = self.counter.max(remote.counter) + 1;
        } else if remote_wall > self.wall_time_ms {
            self.wall_time_ms = remote_wall;
            self.counter = remote.counter + 1;
        } else {
            // self.wall_time_ms > remote_wall
            self.counter += 1;
        }

        self.clone()
    }

    /// Maximum allowed clock skew in milliseconds (5 minutes).
    pub const MAX_SKEW_MS: u64 = 5 * 60 * 1000;

    /// Check if the timestamp is within acceptable skew bounds.
    pub fn is_within_skew(&self) -> bool {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let diff = if self.wall_time_ms > now_ms {
            self.wall_time_ms - now_ms
        } else {
            now_ms - self.wall_time_ms
        };

        diff <= Self::MAX_SKEW_MS
    }
}

impl Ord for HlcTimestamp {
    fn cmp(&self, other: &Self) -> Ordering {
        self.wall_time_ms
            .cmp(&other.wall_time_ms)
            .then_with(|| self.counter.cmp(&other.counter))
            .then_with(|| self.node_id_hash.cmp(&other.node_id_hash))
    }
}

impl PartialOrd for HlcTimestamp {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hlc_now_creates_timestamp() {
        let ts = HlcTimestamp::now(42);
        assert!(ts.wall_time_ms > 0);
        assert_eq!(ts.counter, 0);
        assert_eq!(ts.node_id_hash, 42);
    }

    #[test]
    fn hlc_new_creates_with_values() {
        let ts = HlcTimestamp::new(1000, 5, 99);
        assert_eq!(ts.wall_time_ms, 1000);
        assert_eq!(ts.counter, 5);
        assert_eq!(ts.node_id_hash, 99);
    }

    #[test]
    fn hlc_ordering_by_wall_time() {
        let a = HlcTimestamp::new(100, 0, 0);
        let b = HlcTimestamp::new(200, 0, 0);
        assert!(a < b);
    }

    #[test]
    fn hlc_ordering_by_counter() {
        let a = HlcTimestamp::new(100, 1, 0);
        let b = HlcTimestamp::new(100, 2, 0);
        assert!(a < b);
    }

    #[test]
    fn hlc_ordering_by_node_id_hash() {
        let a = HlcTimestamp::new(100, 1, 10);
        let b = HlcTimestamp::new(100, 1, 20);
        assert!(a < b);
    }

    #[test]
    fn hlc_equality() {
        let a = HlcTimestamp::new(100, 1, 42);
        let b = HlcTimestamp::new(100, 1, 42);
        assert_eq!(a, b);
    }

    #[test]
    fn hlc_tick_advances() {
        let mut ts = HlcTimestamp::new(0, 0, 42);
        let t1 = ts.tick();
        assert!(t1.wall_time_ms > 0); // Jumped to current time
        assert_eq!(t1.counter, 0);

        // Tick again immediately — same wall time, counter increments
        let t2 = ts.tick();
        assert!(t2 >= t1);
    }

    #[test]
    fn hlc_update_with_remote() {
        let mut local = HlcTimestamp::new(100, 0, 1);
        let remote = HlcTimestamp::new(200, 5, 2);

        let updated = local.update(&remote);
        // Remote has higher wall time than local's old value,
        // but current time is much higher than 200ms
        assert!(updated.wall_time_ms >= 200);
    }

    #[test]
    fn hlc_update_same_wall_time() {
        // Both timestamps far in the future to ensure wall_time stays
        let future_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
            + 100_000;

        let mut local = HlcTimestamp::new(future_ms, 3, 1);
        let remote = HlcTimestamp::new(future_ms, 5, 2);

        let updated = local.update(&remote);
        assert_eq!(updated.wall_time_ms, future_ms);
        assert_eq!(updated.counter, 6); // max(3,5) + 1
    }

    #[test]
    fn hash_node_id_deterministic() {
        let h1 = HlcTimestamp::hash_node_id("node-1");
        let h2 = HlcTimestamp::hash_node_id("node-1");
        assert_eq!(h1, h2);
    }

    #[test]
    fn hash_node_id_different_nodes() {
        let h1 = HlcTimestamp::hash_node_id("node-1");
        let h2 = HlcTimestamp::hash_node_id("node-2");
        assert_ne!(h1, h2);
    }

    #[test]
    fn is_within_skew_current() {
        let ts = HlcTimestamp::now(42);
        assert!(ts.is_within_skew());
    }

    #[test]
    fn is_within_skew_far_future() {
        let ts = HlcTimestamp::new(u64::MAX / 2, 0, 42);
        assert!(!ts.is_within_skew());
    }

    #[test]
    fn total_ordering_is_consistent() {
        let timestamps = vec![
            HlcTimestamp::new(100, 0, 0),
            HlcTimestamp::new(100, 1, 0),
            HlcTimestamp::new(100, 1, 1),
            HlcTimestamp::new(200, 0, 0),
        ];

        for i in 0..timestamps.len() - 1 {
            assert!(timestamps[i] < timestamps[i + 1]);
        }
    }

    #[test]
    fn serialization_roundtrip() {
        let ts = HlcTimestamp::new(12345, 7, 99);
        let json = serde_json::to_string(&ts).unwrap();
        let parsed: HlcTimestamp = serde_json::from_str(&json).unwrap();
        assert_eq!(ts, parsed);
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn ordering_is_total(
            w1 in any::<u64>(), c1 in any::<u32>(), n1 in any::<u32>(),
            w2 in any::<u64>(), c2 in any::<u32>(), n2 in any::<u32>(),
        ) {
            let a = HlcTimestamp::new(w1, c1, n1);
            let b = HlcTimestamp::new(w2, c2, n2);
            // Total ordering: exactly one of <, =, > must hold
            let lt = a < b;
            let eq = a == b;
            let gt = a > b;
            prop_assert!(lt as u8 + eq as u8 + gt as u8 == 1);
        }

        #[test]
        fn ordering_is_transitive(
            w1 in 0u64..1000, c1 in 0u32..100, n1 in 0u32..100,
            w2 in 0u64..1000, c2 in 0u32..100, n2 in 0u32..100,
            w3 in 0u64..1000, c3 in 0u32..100, n3 in 0u32..100,
        ) {
            let a = HlcTimestamp::new(w1, c1, n1);
            let b = HlcTimestamp::new(w2, c2, n2);
            let c = HlcTimestamp::new(w3, c3, n3);
            if a <= b && b <= c {
                prop_assert!(a <= c);
            }
        }

        #[test]
        fn update_never_goes_backward(
            local_wall in 0u64..u64::MAX/2,
            local_counter in any::<u32>(),
            remote_wall in 0u64..u64::MAX/2,
            remote_counter in any::<u32>(),
        ) {
            let mut local = HlcTimestamp::new(local_wall, local_counter, 1);
            let old_local = local.clone();
            let remote = HlcTimestamp::new(remote_wall, remote_counter, 2);

            let result = local.update(&remote);
            // HLC must be monotonically non-decreasing
            prop_assert!(result >= old_local);
        }

        #[test]
        fn update_clamps_extreme_future(
            remote_wall in (u64::MAX/2)..u64::MAX,
            remote_counter in any::<u32>(),
        ) {
            let mut local = HlcTimestamp::now(1);
            let remote = HlcTimestamp::new(remote_wall, remote_counter, 2);
            let result = local.update(&remote);
            // The result's wall_time should never exceed now + MAX_SKEW
            let now_ms = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;
            prop_assert!(result.wall_time_ms <= now_ms + HlcTimestamp::MAX_SKEW_MS + 1000);
        }
    }
}
