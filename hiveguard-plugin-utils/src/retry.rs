use std::future::Future;
use std::time::Duration;

use rand::Rng;
use tracing::warn;

/// Configuration for exponential backoff with jitter.
///
/// Standard usage: `RetryPolicy::default()` for short-running ops,
/// `RetryPolicy::for_alerts()` matching the legacy alert manager retry
/// timings (5 s → 30 s → 2 min → 10 min, 4 attempts).
#[derive(Debug, Clone)]
pub struct RetryPolicy {
    pub max_attempts: u32,
    pub initial_delay: Duration,
    pub max_delay: Duration,
    pub multiplier: f64,
    /// Add up to `±jitter * delay` randomness to each delay.
    pub jitter: f64,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            initial_delay: Duration::from_millis(500),
            max_delay: Duration::from_secs(30),
            multiplier: 2.0,
            jitter: 0.2,
        }
    }
}

impl RetryPolicy {
    /// Matches the legacy `alert_manager::RETRY_DELAYS` (5 s, 30 s, 2 min, 10 min).
    pub fn for_alerts() -> Self {
        Self {
            max_attempts: 4,
            initial_delay: Duration::from_secs(5),
            max_delay: Duration::from_secs(600),
            multiplier: 6.0, // 5 → 30 → 180 → 1080 (clamped to 600)
            jitter: 0.1,
        }
    }

    fn delay_for(&self, attempt: u32) -> Duration {
        let base = self.initial_delay.as_secs_f64() * self.multiplier.powi(attempt as i32);
        let clamped = base.min(self.max_delay.as_secs_f64());
        let jitter_range = clamped * self.jitter;
        let jitter = rand::thread_rng().gen_range(-jitter_range..=jitter_range);
        Duration::from_secs_f64((clamped + jitter).max(0.0))
    }
}

/// Run `op` with retries according to `policy`. Returns the last error if
/// all attempts fail.
///
/// `op` is called with the current attempt number (0-indexed). It returns
/// `Ok(value)` on success, `Err(e)` to trigger a retry.
///
/// Cooperative cancellation: if the surrounding task is dropped, the sleep
/// is cancelled too.
pub async fn with_retry<T, E, F, Fut>(policy: &RetryPolicy, mut op: F) -> Result<T, E>
where
    E: std::fmt::Display,
    F: FnMut(u32) -> Fut,
    Fut: Future<Output = Result<T, E>>,
{
    let mut last_err: Option<E> = None;
    for attempt in 0..policy.max_attempts {
        match op(attempt).await {
            Ok(v) => return Ok(v),
            Err(e) => {
                let is_last = attempt + 1 >= policy.max_attempts;
                let delay = policy.delay_for(attempt);
                if !is_last {
                    warn!(
                        attempt = attempt + 1,
                        max = policy.max_attempts,
                        retry_in_secs = delay.as_secs_f64(),
                        error = %e,
                        "retrying after failure"
                    );
                    tokio::time::sleep(delay).await;
                }
                last_err = Some(e);
            }
        }
    }
    Err(last_err.expect("loop body always assigns on error"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    #[tokio::test]
    async fn succeeds_on_first_try() {
        let r: Result<i32, &str> = with_retry(&RetryPolicy::default(), |_| async { Ok(42) }).await;
        assert_eq!(r.unwrap(), 42);
    }

    #[tokio::test(start_paused = true)]
    async fn retries_then_succeeds() {
        let counter = AtomicU32::new(0);
        let policy = RetryPolicy {
            max_attempts: 3,
            initial_delay: Duration::from_millis(1),
            max_delay: Duration::from_millis(2),
            multiplier: 1.0,
            jitter: 0.0,
        };
        let r: Result<i32, &str> = with_retry(&policy, |attempt| {
            let n = counter.fetch_add(1, Ordering::SeqCst);
            async move {
                if n < 2 { Err("transient") } else { Ok(attempt as i32) }
            }
        }).await;
        assert_eq!(r.unwrap(), 2);
        assert_eq!(counter.load(Ordering::SeqCst), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn gives_up_after_max_attempts() {
        let counter = AtomicU32::new(0);
        let policy = RetryPolicy {
            max_attempts: 3,
            initial_delay: Duration::from_millis(1),
            max_delay: Duration::from_millis(2),
            multiplier: 1.0,
            jitter: 0.0,
        };
        let r: Result<i32, &str> = with_retry(&policy, |_| {
            counter.fetch_add(1, Ordering::SeqCst);
            async { Err("always") }
        }).await;
        assert!(r.is_err());
        assert_eq!(counter.load(Ordering::SeqCst), 3);
    }
}
