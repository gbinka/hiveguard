//! Process-wide "under attack" states published by non-banning detectors
//! (e.g. `distributed_crawl`).
//!
//! Detector plugins cannot reach the daemon's Prometheus registry (metrics
//! registered on `PluginContext.metrics` go to a throw-away registry), so a
//! detector publishes its state here and the daemon copies it into the
//! `hiveguard_under_attack{detector}` / `hiveguard_under_attack_fresh_ips`
//! gauges when `/metrics` is rendered.

use std::collections::BTreeMap;
use std::sync::{Mutex, OnceLock};

use chrono::{DateTime, Utc};

/// One published state.
#[derive(Debug, Clone, PartialEq)]
pub struct AttackState {
    /// `true` while the detector considers the site under attack.
    pub on: bool,
    /// Last measured value (e.g. fresh IPs in the window).
    pub value: u64,
    /// When the current state was entered.
    pub since: DateTime<Utc>,
}

fn registry() -> &'static Mutex<BTreeMap<String, AttackState>> {
    static REG: OnceLock<Mutex<BTreeMap<String, AttackState>>> = OnceLock::new();
    REG.get_or_init(|| Mutex::new(BTreeMap::new()))
}

/// Publish (insert or replace) the state of `detector`.
pub fn publish(detector: &str, state: AttackState) {
    if let Ok(mut reg) = registry().lock() {
        reg.insert(detector.to_string(), state);
    }
}

/// Update only the measured value of `detector` (no-op if never published).
pub fn update_value(detector: &str, value: u64) {
    if let Ok(mut reg) = registry().lock() {
        if let Some(s) = reg.get_mut(detector) {
            s.value = value;
        }
    }
}

/// Remove `detector` (e.g. on plugin shutdown).
pub fn clear(detector: &str) {
    if let Ok(mut reg) = registry().lock() {
        reg.remove(detector);
    }
}

/// Copy of all published states, sorted by detector name.
pub fn snapshot() -> Vec<(String, AttackState)> {
    registry()
        .lock()
        .map(|reg| reg.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn publish_update_clear_roundtrip() {
        let name = "unit_test_attack_state";
        publish(name, AttackState { on: true, value: 3, since: Utc::now() });
        update_value(name, 7);
        let snap = snapshot();
        let (_, s) = snap.iter().find(|(k, _)| k == name).expect("published");
        assert!(s.on);
        assert_eq!(s.value, 7);
        clear(name);
        assert!(snapshot().iter().all(|(k, _)| k != name));
    }
}
