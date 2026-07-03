//! SigmaDetector — implements the `Detector` trait for Sigma rule evaluation.
//!
//! # Hot-reload
//!
//! The active rule set is stored behind an `Arc<ArcSwap<Vec<SigmaRule>>>`.
//! Call `SigmaDetector::rules_handle()` to get a reference to this shared
//! handle and pass it to the hot-reload watcher (`crate::loader`).

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use chrono::Utc;
use ipnet::IpNet;
use tokio::sync::Mutex;
use tracing::debug;

use hiveguard_core::detector::Detector;
use hiveguard_core::models::{Action, DetectionSignal, NormalizedEvent};

use crate::fieldmap::FieldMapper;
use crate::rule::SigmaRule;

// ---------------------------------------------------------------------------
// Shared types
// ---------------------------------------------------------------------------

/// Hot-swappable shared rule set.
pub type SharedSigmaRules = Arc<ArcSwap<Vec<SigmaRule>>>;

/// Per-rule hit counter, keyed by rule ID (or title when ID is absent).
pub type SharedSigmaStats = Arc<Mutex<HashMap<String, u64>>>;

// ---------------------------------------------------------------------------
// SigmaDetector
// ---------------------------------------------------------------------------

/// Detector that evaluates a set of Sigma rules against each event.
///
/// Returns the *highest-severity* matching signal. All rules are checked;
/// multiple matches within a single event are silently accumulated and the
/// most severe one is returned.
pub struct SigmaDetector {
    /// Shared, hot-swappable rule set.
    rules: SharedSigmaRules,
    /// Field mapper for translating Sigma field names to event fields.
    mapper: FieldMapper,
    /// Detector name reported to the scoring engine.
    name: String,
    /// Optional hit counters exposed via REST API.
    stats: Option<SharedSigmaStats>,
}

impl SigmaDetector {
    /// Create a new `SigmaDetector` with the given rules and mapper.
    pub fn new(rules: Vec<SigmaRule>, mapper: FieldMapper) -> Self {
        Self {
            rules: Arc::new(ArcSwap::from_pointee(rules)),
            mapper,
            name: "sigma".to_string(),
            stats: None,
        }
    }

    /// Create an empty detector (no rules loaded yet).
    pub fn empty(mapper: FieldMapper) -> Self {
        Self::new(vec![], mapper)
    }

    /// Attach shared stats counters (used by REST API to expose hit counts).
    pub fn with_stats(mut self, stats: SharedSigmaStats) -> Self {
        self.stats = Some(stats);
        self
    }

    /// Return a handle to the shared rule set for atomic hot-reload.
    pub fn rules_handle(&self) -> SharedSigmaRules {
        self.rules.clone()
    }

    /// Return a handle to the shared stats, creating it if not yet set.
    pub fn stats_handle(&self) -> Option<SharedSigmaStats> {
        self.stats.clone()
    }

    /// Replace the active rule set atomically (no locking required by callers).
    pub fn reload(&self, new_rules: Vec<SigmaRule>) {
        self.rules.store(Arc::new(new_rules));
    }
}

// ---------------------------------------------------------------------------
// Detector trait
// ---------------------------------------------------------------------------

impl Detector for SigmaDetector {
    fn name(&self) -> &str {
        &self.name
    }

    fn process(&self, event: &NormalizedEvent) -> Option<DetectionSignal> {
        let guard = self.rules.load();
        let rules = guard.as_slice();

        let mut best: Option<DetectionSignal> = None;

        for rule in rules {
            if !rule.matches(event, &self.mapper) {
                continue;
            }

            let severity = rule.severity();
            let rule_key = rule
                .id
                .as_deref()
                .map(|s| s.to_string())
                .unwrap_or_else(|| rule.title.clone());

            // Increment hit counter if stats are attached.
            if let Some(ref stats) = self.stats {
                if let Ok(mut map) = stats.try_lock() {
                    *map.entry(rule_key.clone()).or_insert(0) += 1;
                }
            }

            let evidence_hash = compute_evidence_hash(&rule_key, &event.source_ip);

            let signal = DetectionSignal {
                source_ip: ip_to_net(event.source_ip),
                severity,
                confidence: 0.85,
                reason: format!(
                    "[Sigma] {} ({})",
                    rule.title,
                    rule.id.as_deref().unwrap_or("no-id")
                ),
                evidence_hash,
                suggested_action: Action::Ban(Duration::from_secs(86400)),
                detector_name: format!("sigma:{}", rule_key),
                timestamp: event.timestamp,
            };

            debug!(
                rule = %rule.title,
                severity = severity,
                ip = %event.source_ip,
                "Sigma rule matched"
            );

            match &best {
                None => best = Some(signal),
                Some(prev) if signal.severity > prev.severity => best = Some(signal),
                _ => {}
            }
        }

        best
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn ip_to_net(ip: IpAddr) -> IpNet {
    match ip {
        IpAddr::V4(v4) => IpNet::V4(ipnet::Ipv4Net::new(v4, 32).unwrap()),
        IpAddr::V6(v6) => IpNet::V6(ipnet::Ipv6Net::new(v6, 128).unwrap()),
    }
}

fn compute_evidence_hash(rule_key: &str, ip: &IpAddr) -> [u8; 32] {
    let ts = Utc::now().timestamp_millis();
    let input = format!("sigma:{rule_key}:{ip}:{ts}");
    *blake3::hash(input.as_bytes()).as_bytes()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use hiveguard_core::models::{EventType, NormalizedEvent};
    use std::collections::HashMap;

    fn make_event(raw: &str, meta: &[(&str, &str)]) -> NormalizedEvent {
        NormalizedEvent {
            timestamp: Utc::now(),
            source_ip: "10.0.0.1".parse().unwrap(),
            event_type: EventType::HttpRequest,
            source_name: "test".to_string(),
            raw_line: raw.to_string(),
            metadata: meta
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        }
    }

    const SSH_RULE: &str = r#"
title: SSH Auth Failure
id: test-001
status: experimental
logsource:
  service: ssh
detection:
  selection:
    CommandLine|contains: 'Failed password'
  condition: selection
level: medium
"#;

    #[test]
    fn sigma_detector_matches() {
        let rule = SigmaRule::from_yaml(SSH_RULE).unwrap();
        let mapper = FieldMapper::new();
        let mut det = SigmaDetector::new(vec![rule], mapper);

        let event = make_event("Failed password for root", &[("command", "Failed password for root")]);
        let signal = det.process(&event);
        assert!(signal.is_some());
        let s = signal.unwrap();
        assert!(s.reason.contains("[Sigma]"));
        assert_eq!(s.severity, 60); // medium
    }

    #[test]
    fn sigma_detector_no_match() {
        let rule = SigmaRule::from_yaml(SSH_RULE).unwrap();
        let mapper = FieldMapper::new();
        let mut det = SigmaDetector::new(vec![rule], mapper);

        let event = make_event("Accepted publickey for admin", &[("command", "Accepted publickey")]);
        let signal = det.process(&event);
        assert!(signal.is_none());
    }

    #[test]
    fn sigma_detector_empty_rules() {
        let mut det = SigmaDetector::empty(FieldMapper::new());
        let event = make_event("anything", &[]);
        assert!(det.process(&event).is_none());
    }

    #[test]
    fn sigma_detector_returns_highest_severity() {
        let rule_medium = SigmaRule::from_yaml(SSH_RULE).unwrap();
        let rule_critical = SigmaRule::from_yaml(
            r#"
title: SSH Failure Critical
status: experimental
logsource:
  service: ssh
detection:
  selection:
    CommandLine|contains: 'Failed'
  condition: selection
level: critical
"#,
        )
        .unwrap();

        let mapper = FieldMapper::new();
        let mut det = SigmaDetector::new(vec![rule_medium, rule_critical], mapper);

        let event = make_event("Failed password", &[("command", "Failed password for root")]);
        let signal = det.process(&event).unwrap();
        assert_eq!(signal.severity, 120); // critical wins
    }

    #[test]
    fn sigma_detector_hot_reload() {
        let mapper = FieldMapper::new();
        let mut det = SigmaDetector::empty(mapper);

        let event = make_event("Failed password", &[("command", "Failed password for root")]);
        assert!(det.process(&event).is_none()); // no rules yet

        // Hot-reload a rule
        let rule = SigmaRule::from_yaml(SSH_RULE).unwrap();
        det.reload(vec![rule]);
        assert!(det.process(&event).is_some()); // now matches
    }
}
