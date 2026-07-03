use std::time::Duration;

/// Policy for restarting a plugin that returns `Err` from its driver loop or
/// reports `HealthState::Failed`.
#[derive(Debug, Clone)]
pub struct RestartPolicy {
    /// Initial back-off delay. Doubled on each consecutive failure.
    pub initial_backoff: Duration,

    /// Cap on back-off delay.
    pub max_backoff: Duration,

    /// Maximum restart attempts. `None` = retry forever.
    pub max_attempts: Option<u32>,
}

impl Default for RestartPolicy {
    fn default() -> Self {
        Self {
            initial_backoff: Duration::from_secs(2),
            max_backoff: Duration::from_secs(60),
            max_attempts: None,
        }
    }
}

/// Supervisor state machine for one plugin instance. Phase 0 ships the type
/// and policy; the actual supervision loop lands in Phase 1 once we have a
/// real plugin to test against.
pub struct Lifecycle {
    pub policy: RestartPolicy,
}

impl Lifecycle {
    pub fn new(policy: RestartPolicy) -> Self {
        Self { policy }
    }
}
