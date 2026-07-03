use std::collections::HashMap;

use chrono::{DateTime, Utc};
use tracing::warn;

/// Sliding window rate limiter per key.
pub struct RateLimiter {
    /// Maximum entries allowed per window.
    max_per_window: usize,
    /// Window duration.
    window: chrono::Duration,
    /// Timestamps of recent entries per key.
    entries: HashMap<String, Vec<DateTime<Utc>>>,
    /// Maximum number of distinct keys to track (prevents OOM from peer flood).
    max_keys: usize,
}

/// Default maximum number of distinct keys in the rate limiter.
const DEFAULT_MAX_KEYS: usize = 10_000;

impl RateLimiter {
    /// Create a new rate limiter.
    pub fn new(max_per_window: usize, window: chrono::Duration) -> Self {
        Self {
            max_per_window,
            window,
            entries: HashMap::new(),
            max_keys: DEFAULT_MAX_KEYS,
        }
    }

    /// Check if an entry is allowed and record it if so.
    /// Returns true if the entry is within limits.
    pub fn check_and_record(&mut self, key: &str) -> bool {
        let now = Utc::now();
        let cutoff = now - self.window;

        // If key is new and we're at capacity, run cleanup first
        if !self.entries.contains_key(key) && self.entries.len() >= self.max_keys {
            self.cleanup();
            // If still at capacity after cleanup, reject new keys
            if self.entries.len() >= self.max_keys {
                warn!(
                    key = key,
                    max_keys = self.max_keys,
                    "Rate limiter at capacity — rejecting new key"
                );
                return false;
            }
        }

        let timestamps = self.entries.entry(key.to_string()).or_default();

        // Remove expired entries
        timestamps.retain(|t| *t > cutoff);

        if timestamps.len() >= self.max_per_window {
            warn!(key = key, limit = self.max_per_window, "Rate limit exceeded");
            return false;
        }

        timestamps.push(now);
        true
    }

    /// Check rate without recording.
    pub fn would_allow(&self, key: &str) -> bool {
        let now = Utc::now();
        let cutoff = now - self.window;

        match self.entries.get(key) {
            Some(timestamps) => {
                let active = timestamps.iter().filter(|t| **t > cutoff).count();
                active < self.max_per_window
            }
            None => true,
        }
    }

    /// Get current count for a key.
    pub fn current_count(&self, key: &str) -> usize {
        let now = Utc::now();
        let cutoff = now - self.window;

        self.entries
            .get(key)
            .map(|ts| ts.iter().filter(|t| **t > cutoff).count())
            .unwrap_or(0)
    }

    /// Clean up expired entries for all keys.
    pub fn cleanup(&mut self) {
        let now = Utc::now();
        let cutoff = now - self.window;

        self.entries.retain(|_, timestamps| {
            timestamps.retain(|t| *t > cutoff);
            !timestamps.is_empty()
        });
    }
}

/// Check if a node should be quarantined based on anomalous ban volume.
///
/// Quarantine if node_ban_count > 10 * median_ban_count.
pub fn check_quarantine(node_ban_count: usize, median_ban_count: usize) -> bool {
    let threshold = if median_ban_count == 0 {
        10 // Minimum threshold when median is 0
    } else {
        median_ban_count * 10
    };

    node_ban_count > threshold
}

/// Compute the median of a slice of values.
pub fn median(values: &[usize]) -> usize {
    if values.is_empty() {
        return 0;
    }

    let mut sorted = values.to_vec();
    sorted.sort();

    let mid = sorted.len() / 2;
    if sorted.len() % 2 == 0 {
        (sorted[mid - 1] + sorted[mid]) / 2
    } else {
        sorted[mid]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limiter_allows_under_limit() {
        let mut rl = RateLimiter::new(100, chrono::Duration::minutes(1));
        for _ in 0..100 {
            assert!(rl.check_and_record("node-1"));
        }
    }

    #[test]
    fn rate_limiter_rejects_over_limit() {
        let mut rl = RateLimiter::new(100, chrono::Duration::minutes(1));
        for _ in 0..100 {
            rl.check_and_record("node-1");
        }
        assert!(!rl.check_and_record("node-1")); // 101st is rejected
    }

    #[test]
    fn rate_limiter_separate_keys() {
        let mut rl = RateLimiter::new(2, chrono::Duration::minutes(1));
        assert!(rl.check_and_record("a"));
        assert!(rl.check_and_record("a"));
        assert!(!rl.check_and_record("a"));
        // Different key still has quota
        assert!(rl.check_and_record("b"));
    }

    #[test]
    fn would_allow_without_recording() {
        let mut rl = RateLimiter::new(1, chrono::Duration::minutes(1));
        assert!(rl.would_allow("node-1"));
        rl.check_and_record("node-1");
        assert!(!rl.would_allow("node-1"));
    }

    #[test]
    fn current_count() {
        let mut rl = RateLimiter::new(10, chrono::Duration::minutes(1));
        assert_eq!(rl.current_count("node-1"), 0);
        rl.check_and_record("node-1");
        rl.check_and_record("node-1");
        assert_eq!(rl.current_count("node-1"), 2);
    }

    #[test]
    fn cleanup_removes_empty() {
        let mut rl = RateLimiter::new(10, chrono::Duration::minutes(1));
        rl.check_and_record("node-1");
        rl.cleanup();
        // Still within window, should not be cleaned
        assert_eq!(rl.current_count("node-1"), 1);
    }

    #[test]
    fn quarantine_normal_node() {
        assert!(!check_quarantine(5, 5)); // 5 <= 50
    }

    #[test]
    fn quarantine_anomalous_node() {
        assert!(check_quarantine(51, 5)); // 51 > 50
    }

    #[test]
    fn quarantine_ten_times_exact() {
        assert!(!check_quarantine(50, 5)); // 50 == 50, not >
    }

    #[test]
    fn quarantine_zero_median() {
        assert!(!check_quarantine(10, 0)); // 10 == 10 threshold
        assert!(check_quarantine(11, 0)); // 11 > 10 threshold
    }

    #[test]
    fn median_empty() {
        assert_eq!(median(&[]), 0);
    }

    #[test]
    fn median_single() {
        assert_eq!(median(&[5]), 5);
    }

    #[test]
    fn median_odd_count() {
        assert_eq!(median(&[3, 1, 2]), 2);
    }

    #[test]
    fn median_even_count() {
        assert_eq!(median(&[1, 2, 3, 4]), 2); // (2+3)/2 = 2 (integer division)
    }

    #[test]
    fn median_already_sorted() {
        assert_eq!(median(&[1, 2, 3, 4, 5]), 3);
    }
}
