use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Trust score for a cluster peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustScore {
    /// Current trust score in [0.0, 1.0] range.
    pub score: f64,
    /// Number of bans confirmed as true positives.
    pub true_positives: u64,
    /// Number of bans confirmed as false positives.
    pub false_positives: u64,
    /// When the node joined the cluster.
    pub joined_at: DateTime<Utc>,
    /// How many times the node was penalized for minority reports.
    pub minority_penalties: u32,
}

impl TrustScore {
    /// Create a new trust score for a freshly joined node.
    pub fn new() -> Self {
        Self {
            score: 0.5,
            true_positives: 0,
            false_positives: 0,
            joined_at: Utc::now(),
            minority_penalties: 0,
        }
    }

    /// Create a trust score for a founder node — starts with maximum trust (1.0).
    ///
    /// Founders are seeded with 100 synthetic true positives and a join time
    /// 30 days in the past so that `calculate_score` keeps them at or near 1.0
    /// even after a handful of false positives.  They are declared in the
    /// cluster config via `node.founder_nodes`.
    pub fn founder() -> Self {
        Self {
            score: 1.0,
            true_positives: 100,
            false_positives: 0,
            joined_at: Utc::now() - chrono::Duration::days(30),
            minority_penalties: 0,
        }
    }

    /// Create with specific join time (for testing).
    pub fn with_join_time(joined_at: DateTime<Utc>) -> Self {
        Self {
            score: 0.5,
            true_positives: 0,
            false_positives: 0,
            joined_at,
            minority_penalties: 0,
        }
    }
}

impl Default for TrustScore {
    fn default() -> Self {
        Self::new()
    }
}

/// A single ban report from one cluster node about a target IP.
#[derive(Debug, Clone)]
pub struct BanReport {
    /// Reporting node ID.
    pub reporter_id: String,
    /// Event weight (e.g. 1.0 for port scan, 5.0 for exploit attempt).
    pub event_weight: f64,
}

/// Manages trust scores for cluster peers.
pub struct TrustManager {
    trust_scores: HashMap<String, TrustScore>,
    /// Sum of trust scores required to enforce a ban (default: 2.0).
    pub ban_threshold: f64,
    /// Accumulated ban reports per target IP: IP → Vec<BanReport>.
    /// Used to compute weighted suspicion score (Σ w_i × v_i).
    ip_reports: HashMap<String, Vec<BanReport>>,
}

impl TrustManager {
    /// Create a new trust manager.
    pub fn new(ban_threshold: f64) -> Self {
        Self {
            trust_scores: HashMap::new(),
            ban_threshold,
            ip_reports: HashMap::new(),
        }
    }

    /// Register a new node with default trust.
    pub fn register_node(&mut self, node_id: String) {
        self.trust_scores
            .entry(node_id)
            .or_default();
    }

    /// Register a node as a founder with maximum initial trust score (1.0).
    ///
    /// Founder nodes are declared in `node.founder_nodes` in the cluster config.
    /// If the node was already registered, its existing score is preserved.
    pub fn register_founder_node(&mut self, node_id: String) {
        self.trust_scores
            .entry(node_id)
            .or_insert_with(TrustScore::founder);
    }

    /// Register a node with a specific join time.
    pub fn register_node_with_time(&mut self, node_id: String, joined_at: DateTime<Utc>) {
        self.trust_scores
            .entry(node_id)
            .or_insert_with(|| TrustScore::with_join_time(joined_at));
    }

    /// Record a true positive for a node.
    pub fn record_true_positive(&mut self, node_id: &str) {
        if let Some(ts) = self.trust_scores.get_mut(node_id) {
            ts.true_positives += 1;
            ts.score = Self::calculate_score(ts.true_positives, ts.false_positives, ts.joined_at);
        }
    }

    /// Record a false positive for a node.
    pub fn record_false_positive(&mut self, node_id: &str) {
        if let Some(ts) = self.trust_scores.get_mut(node_id) {
            ts.false_positives += 1;
            ts.score = Self::calculate_score(ts.true_positives, ts.false_positives, ts.joined_at);
        }
    }

    /// Penalize a node for being a statistical minority reporter (its ban reports
    /// persistently disagree with the rest of the cluster).
    ///
    /// Applies a multiplicative penalty of 0.9 per call (floor: 0.1).
    /// The penalty is logged as `minority_penalties` for diagnostics.
    pub fn penalize_minority_reporter(&mut self, node_id: &str) {
        if let Some(ts) = self.trust_scores.get_mut(node_id) {
            ts.minority_penalties = ts.minority_penalties.saturating_add(1);
            ts.score = (ts.score * 0.9).max(0.1);
        }
    }

    /// Calculate trust score from TP/FP counts and seniority.
    ///
    /// Base: `tp / (tp + fp + 1)` bounded to [0, 1]
    /// Seniority bonus: +0.1 after 24h, +0.2 after 7d (capped at 0.2)
    pub fn calculate_score(tp: u64, fp: u64, joined_at: DateTime<Utc>) -> f64 {
        let base = tp as f64 / (tp as f64 + fp as f64 + 1.0);

        let elapsed = Utc::now().signed_duration_since(joined_at);
        let seniority_bonus = if elapsed >= chrono::Duration::days(7) {
            0.2
        } else if elapsed >= chrono::Duration::days(1) {
            0.1
        } else {
            0.0
        };

        (base + seniority_bonus).min(1.0)
    }

    /// Check if a ban should be enforced based on reporter trust scores.
    ///
    /// Returns true if the sum of reporters' trust scores >= ban_threshold.
    pub fn should_enforce(&self, reporters: &[String]) -> bool {
        let total: f64 = reporters
            .iter()
            .filter_map(|r| self.trust_scores.get(r))
            .map(|ts| ts.score)
            .sum();

        total >= self.ban_threshold
    }

    /// Record a ban report for `target_ip` from `reporter_id` with `event_weight`.
    ///
    /// `event_weight` should reflect severity of the triggering event, e.g.:
    /// - 1.0 for port scan / SSH brute-force single attempt
    /// - 5.0 for honeypot hit / exploit attempt
    ///
    /// Multiple calls accumulate reports; call `weighted_suspicion_score()` to
    /// check whether the threshold has been reached.
    pub fn record_ban_report(&mut self, target_ip: &str, reporter_id: &str, event_weight: f64) {
        self.ip_reports
            .entry(target_ip.to_string())
            .or_default()
            .push(BanReport {
                reporter_id: reporter_id.to_string(),
                event_weight,
            });
    }

    /// Compute the weighted suspicion score for `target_ip`:
    ///
    /// $$S_{IP} = \sum_{i} w_i \cdot v_i$$
    ///
    /// where `w_i` is the reporter's current `trust_score` and `v_i` is the
    /// recorded `event_weight`.  Deduplicated by reporter — only the highest
    /// event weight per reporter is counted to prevent self-amplification.
    pub fn weighted_suspicion_score(&self, target_ip: &str) -> f64 {
        let reports = match self.ip_reports.get(target_ip) {
            Some(r) => r,
            None => return 0.0,
        };

        // Deduplicate: keep max event_weight per reporter
        let mut max_weight_per_reporter: HashMap<&str, f64> = HashMap::new();
        for report in reports {
            let entry = max_weight_per_reporter
                .entry(report.reporter_id.as_str())
                .or_insert(0.0);
            if report.event_weight > *entry {
                *entry = report.event_weight;
            }
        }

        max_weight_per_reporter
            .into_iter()
            .map(|(reporter_id, v)| {
                let w = self
                    .trust_scores
                    .get(reporter_id)
                    .map(|ts| ts.score)
                    .unwrap_or(0.0);
                w * v
            })
            .sum()
    }

    /// Whether `target_ip` has exceeded the suspicion threshold for a global ban.
    ///
    /// Uses the same `ban_threshold` as `should_enforce`.
    pub fn should_global_ban(&self, target_ip: &str) -> bool {
        self.weighted_suspicion_score(target_ip) >= self.ban_threshold
    }

    /// Remove all accumulated reports for `target_ip` (call after applying the ban).
    pub fn clear_reports(&mut self, target_ip: &str) {
        self.ip_reports.remove(target_ip);
    }

    /// Scan all pending reports and penalize nodes that are "isolated reporters":
    /// nodes that reported an IP **solo** (without corroboration from at least
    /// `min_corroboration` distinct other nodes) AND whose report did not
    /// reach the ban threshold on its own.
    ///
    /// Intended to be called periodically (e.g., every 5 minutes) to detect
    /// nodes that persistently report IPs nobody else sees.
    ///
    /// **Returns** the list of node IDs that were penalized (for logging).
    ///
    /// Reports for IPs that triggered a penalty are cleared; reports for IPs
    /// that *did* reach the threshold (corroborated bans) are left untouched
    /// so they can still be acted on.
    pub fn drain_isolated_reports(&mut self, min_corroboration: usize) -> Vec<String> {
        let mut penalized: Vec<String> = Vec::new();

        // Collect IPs whose reporters should be penalized.
        let to_penalize: Vec<String> = self
            .ip_reports
            .iter()
            .filter_map(|(ip, reports)| {
                // Already above threshold → corroborated, leave it alone.
                if self.weighted_suspicion_score(ip) >= self.ban_threshold {
                    return None;
                }
                // Count distinct reporters for this IP.
                let mut distinct: Vec<&str> = reports.iter().map(|r| r.reporter_id.as_str()).collect();
                distinct.sort_unstable();
                distinct.dedup();
                if distinct.len() < min_corroboration {
                    Some(ip.clone())
                } else {
                    None
                }
            })
            .collect();

        for ip in &to_penalize {
            if let Some(reports) = self.ip_reports.remove(ip) {
                let mut distinct: Vec<String> = reports.iter().map(|r| r.reporter_id.clone()).collect();
                distinct.sort_unstable();
                distinct.dedup();
                for reporter in distinct {
                    self.penalize_minority_reporter(&reporter);
                    penalized.push(reporter);
                }
            }
        }

        penalized
    }

    /// Get a node's trust score.
    pub fn get_score(&self, node_id: &str) -> Option<&TrustScore> {
        self.trust_scores.get(node_id)
    }

    /// Get all trust scores.
    pub fn all_scores(&self) -> &HashMap<String, TrustScore> {
        &self.trust_scores
    }

    /// Check if a node is within the grace period (< 24h).
    pub fn is_in_grace_period(&self, node_id: &str) -> bool {
        self.trust_scores
            .get(node_id)
            .map(|ts| {
                let elapsed = Utc::now().signed_duration_since(ts.joined_at);
                elapsed < chrono::Duration::days(1)
            })
            .unwrap_or(true) // Unknown nodes are treated as in grace period
    }

    /// Get the effective threshold for a node (doubled during grace period).
    pub fn effective_threshold(&self, node_id: &str) -> f64 {
        if self.is_in_grace_period(node_id) {
            self.ban_threshold * 2.0
        } else {
            self.ban_threshold
        }
    }

    /// Number of registered nodes.
    pub fn node_count(&self) -> usize {
        self.trust_scores.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_trust_score_defaults() {
        let ts = TrustScore::new();
        assert!((ts.score - 0.5).abs() < f64::EPSILON);
        assert_eq!(ts.true_positives, 0);
        assert_eq!(ts.false_positives, 0);
    }

    #[test]
    fn register_node() {
        let mut tm = TrustManager::new(2.0);
        tm.register_node("node-1".into());
        assert_eq!(tm.node_count(), 1);
        assert!(tm.get_score("node-1").is_some());
    }

    #[test]
    fn register_node_idempotent() {
        let mut tm = TrustManager::new(2.0);
        tm.register_node("node-1".into());
        tm.register_node("node-1".into());
        assert_eq!(tm.node_count(), 1);
    }

    #[test]
    fn high_tp_high_score() {
        let mut tm = TrustManager::new(2.0);
        let old_time = Utc::now() - chrono::Duration::days(8);
        tm.register_node_with_time("node-1".into(), old_time);

        for _ in 0..90 {
            tm.record_true_positive("node-1");
        }
        for _ in 0..10 {
            tm.record_false_positive("node-1");
        }

        let score = tm.get_score("node-1").unwrap().score;
        assert!(score > 0.8, "Expected high score, got {score}");
    }

    #[test]
    fn high_fp_low_score() {
        let mut tm = TrustManager::new(2.0);
        tm.register_node("node-1".into());

        for _ in 0..50 {
            tm.record_false_positive("node-1");
        }

        let score = tm.get_score("node-1").unwrap().score;
        assert!(score < 0.1, "Expected low score, got {score}");
    }

    #[test]
    fn seniority_bonus_none_for_new_node() {
        let score = TrustManager::calculate_score(10, 0, Utc::now());
        // base = 10/11 ≈ 0.909, no seniority bonus
        assert!(score < 0.95);
    }

    #[test]
    fn seniority_bonus_after_24h() {
        let joined = Utc::now() - chrono::Duration::days(2);
        let score = TrustManager::calculate_score(10, 0, joined);
        // base = 10/11 ≈ 0.909, +0.1 seniority = 1.0 (capped)
        assert!(score >= 0.99);
    }

    #[test]
    fn seniority_bonus_after_7d() {
        let joined = Utc::now() - chrono::Duration::days(8);
        let score = TrustManager::calculate_score(5, 5, joined);
        // base = 5/11 ≈ 0.454, +0.2 seniority = 0.654
        assert!(score > 0.6 && score < 0.7, "Score: {score}");
    }

    #[test]
    fn should_enforce_above_threshold() {
        let mut tm = TrustManager::new(2.0);
        let old_time = Utc::now() - chrono::Duration::days(8);
        tm.register_node_with_time("n1".into(), old_time);
        tm.register_node_with_time("n2".into(), old_time);
        tm.register_node_with_time("n3".into(), old_time);

        // Give each node high TP count
        for _ in 0..100 {
            tm.record_true_positive("n1");
            tm.record_true_positive("n2");
            tm.record_true_positive("n3");
        }

        let reporters = vec!["n1".into(), "n2".into(), "n3".into()];
        assert!(tm.should_enforce(&reporters));
    }

    #[test]
    fn should_enforce_below_threshold() {
        let mut tm = TrustManager::new(2.0);
        tm.register_node("n1".into());

        // Single new node with default 0.5 score < 2.0 threshold
        let reporters = vec!["n1".into()];
        assert!(!tm.should_enforce(&reporters));
    }

    #[test]
    fn should_enforce_unknown_reporters_ignored() {
        let tm = TrustManager::new(2.0);
        let reporters = vec!["unknown1".into(), "unknown2".into()];
        assert!(!tm.should_enforce(&reporters));
    }

    #[test]
    fn grace_period_new_node() {
        let mut tm = TrustManager::new(2.0);
        tm.register_node("node-new".into());
        assert!(tm.is_in_grace_period("node-new"));
    }

    #[test]
    fn grace_period_old_node() {
        let mut tm = TrustManager::new(2.0);
        let old_time = Utc::now() - chrono::Duration::days(2);
        tm.register_node_with_time("node-old".into(), old_time);
        assert!(!tm.is_in_grace_period("node-old"));
    }

    #[test]
    fn effective_threshold_doubled_during_grace() {
        let mut tm = TrustManager::new(2.0);
        tm.register_node("node-new".into());
        assert!((tm.effective_threshold("node-new") - 4.0).abs() < f64::EPSILON);
    }

    #[test]
    fn effective_threshold_normal_after_grace() {
        let mut tm = TrustManager::new(2.0);
        let old_time = Utc::now() - chrono::Duration::days(2);
        tm.register_node_with_time("node-old".into(), old_time);
        assert!((tm.effective_threshold("node-old") - 2.0).abs() < f64::EPSILON);
    }

    // ----- Weighted suspicion score tests -----

    #[test]
    fn suspicion_score_single_reporter() {
        let mut tm = TrustManager::new(2.0);
        let old_time = Utc::now() - chrono::Duration::days(8);
        tm.register_node_with_time("n1".into(), old_time);
        for _ in 0..100 {
            tm.record_true_positive("n1");
        }
        // trust_score of n1 is near 1.0
        let score_n1 = tm.get_score("n1").unwrap().score;
        tm.record_ban_report("1.2.3.4", "n1", 1.0);
        let suspicion = tm.weighted_suspicion_score("1.2.3.4");
        let expected = score_n1 * 1.0;
        assert!((suspicion - expected).abs() < 1e-9);
    }

    #[test]
    fn suspicion_score_two_reporters_exceeds_threshold() {
        let mut tm = TrustManager::new(2.0);
        let old_time = Utc::now() - chrono::Duration::days(8);
        tm.register_node_with_time("n1".into(), old_time);
        tm.register_node_with_time("n2".into(), old_time);
        for _ in 0..100 {
            tm.record_true_positive("n1");
            tm.record_true_positive("n2");
        }
        tm.record_ban_report("5.5.5.5", "n1", 1.0);
        tm.record_ban_report("5.5.5.5", "n2", 1.0);
        assert!(tm.should_global_ban("5.5.5.5"));
    }

    #[test]
    fn suspicion_score_deduplicates_reporter() {
        let mut tm = TrustManager::new(2.0);
        tm.register_node("n1".into());
        // n1 reports same IP three times with weight 1.0
        tm.record_ban_report("2.2.2.2", "n1", 1.0);
        tm.record_ban_report("2.2.2.2", "n1", 1.0);
        tm.record_ban_report("2.2.2.2", "n1", 1.0);
        // Only one report counted (deduplication by reporter)
        let score_n1 = tm.get_score("n1").unwrap().score; // 0.5
        let suspicion = tm.weighted_suspicion_score("2.2.2.2");
        assert!((suspicion - score_n1 * 1.0).abs() < 1e-9);
    }

    #[test]
    fn suspicion_score_uses_max_weight_per_reporter() {
        let mut tm = TrustManager::new(2.0);
        tm.register_node("n1".into());
        tm.record_ban_report("3.3.3.3", "n1", 1.0);
        tm.record_ban_report("3.3.3.3", "n1", 5.0); // higher weight
        let score_n1 = tm.get_score("n1").unwrap().score;
        let suspicion = tm.weighted_suspicion_score("3.3.3.3");
        // Should use 5.0, not 1.0
        assert!((suspicion - score_n1 * 5.0).abs() < 1e-9);
    }

    #[test]
    fn clear_reports_resets_suspicion() {
        let mut tm = TrustManager::new(2.0);
        tm.register_node("n1".into());
        tm.record_ban_report("9.9.9.9", "n1", 5.0);
        assert!(tm.weighted_suspicion_score("9.9.9.9") > 0.0);
        tm.clear_reports("9.9.9.9");
        assert_eq!(tm.weighted_suspicion_score("9.9.9.9"), 0.0);
    }

    // ----- Dynamic trust penalization tests -----

    #[test]
    fn minority_penalty_reduces_score() {
        let mut tm = TrustManager::new(2.0);
        let old_time = Utc::now() - chrono::Duration::days(8);
        tm.register_node_with_time("n1".into(), old_time);
        for _ in 0..100 {
            tm.record_true_positive("n1");
        }
        let score_before = tm.get_score("n1").unwrap().score;
        tm.penalize_minority_reporter("n1");
        let score_after = tm.get_score("n1").unwrap().score;
        assert!(score_after < score_before);
    }

    #[test]
    fn minority_penalty_floor_at_0_1() {
        let mut tm = TrustManager::new(2.0);
        tm.register_node("n1".into());
        // Apply 50 penalties — should not go below 0.1
        for _ in 0..50 {
            tm.penalize_minority_reporter("n1");
        }
        let score = tm.get_score("n1").unwrap().score;
        assert!(score >= 0.1 - 1e-9);
    }

    #[test]
    fn penalty_count_increments() {
        let mut tm = TrustManager::new(2.0);
        tm.register_node("n1".into());
        tm.penalize_minority_reporter("n1");
        tm.penalize_minority_reporter("n1");
        assert_eq!(tm.get_score("n1").unwrap().minority_penalties, 2);
    }

    // ----- drain_isolated_reports tests -----

    #[test]
    fn drain_isolated_penalizes_sole_reporter() {
        let mut tm = TrustManager::new(2.0);
        tm.register_node("n1".into());
        // n1 is the ONLY reporter for 5.5.5.5 — score 0.5 < threshold 2.0
        tm.record_ban_report("5.5.5.5", "n1", 1.0);

        let penalized = tm.drain_isolated_reports(2);
        assert!(penalized.contains(&"n1".to_string()), "n1 should be penalized");
        // Report should be cleared
        assert_eq!(tm.weighted_suspicion_score("5.5.5.5"), 0.0);
    }

    #[test]
    fn drain_isolated_skips_corroborated_ip() {
        let mut tm = TrustManager::new(1.0);
        let old_time = Utc::now() - chrono::Duration::days(8);
        tm.register_node_with_time("n1".into(), old_time);
        tm.register_node_with_time("n2".into(), old_time);
        for _ in 0..100 {
            tm.record_true_positive("n1");
            tm.record_true_positive("n2");
        }
        // Both n1 and n2 reported — corroborated, should reach threshold
        tm.record_ban_report("7.7.7.7", "n1", 1.0);
        tm.record_ban_report("7.7.7.7", "n2", 1.0);
        assert!(tm.should_global_ban("7.7.7.7"));

        let penalized = tm.drain_isolated_reports(2);
        // Corroborated IP should not be drained or penalized
        assert!(penalized.is_empty(), "corroborated reporters must not be penalized");
        // Reports still present (not cleared by drain)
        assert!(tm.weighted_suspicion_score("7.7.7.7") > 0.0);
    }

    #[test]
    fn drain_isolated_two_reporters_not_penalized() {
        let mut tm = TrustManager::new(10.0); // high threshold — won't trigger ban
        tm.register_node("n1".into());
        tm.register_node("n2".into());
        tm.record_ban_report("8.8.8.8", "n1", 1.0);
        tm.record_ban_report("8.8.8.8", "n2", 1.0);

        // Two distinct reporters → meets min_corroboration=2 → should NOT penalize
        let penalized = tm.drain_isolated_reports(2);
        assert!(penalized.is_empty(), "2 reporters should not be penalized with min_corroboration=2");
    }

    #[test]
    fn drain_isolated_returns_penalized_list() {
        let mut tm = TrustManager::new(2.0);
        tm.register_node("sole-node".into());
        tm.record_ban_report("9.9.9.9", "sole-node", 1.0);

        let penalized = tm.drain_isolated_reports(2);
        assert_eq!(penalized, vec!["sole-node".to_string()]);
    }
}
