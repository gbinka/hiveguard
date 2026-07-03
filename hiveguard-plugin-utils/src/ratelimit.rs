use std::sync::Mutex;
use std::time::Instant;

/// Simple token bucket for self-throttling plugin operations
/// (CTI quota, webhook rate limits, etc.).
///
/// Not designed for sub-millisecond precision — the use case is "stay under
/// 1000 API calls/hour", not "10k rps". For tight per-request limits use a
/// dedicated crate like `governor`.
pub struct TokenBucket {
    capacity: f64,
    refill_per_sec: f64,
    state: Mutex<State>,
}

struct State {
    tokens: f64,
    last_refill: Instant,
}

impl TokenBucket {
    /// Create a bucket with `capacity` tokens that refills at `refill_per_sec`.
    ///
    /// Example: `TokenBucket::new(100.0, 100.0 / 3600.0)` — 100 calls per
    /// hour, smoothed.
    pub fn new(capacity: f64, refill_per_sec: f64) -> Self {
        Self {
            capacity,
            refill_per_sec,
            state: Mutex::new(State {
                tokens: capacity,
                last_refill: Instant::now(),
            }),
        }
    }

    /// Try to consume one token. Returns `true` if a token was available.
    pub fn try_acquire(&self) -> bool {
        self.try_acquire_n(1.0)
    }

    /// Try to consume `n` tokens. Returns `true` if available.
    pub fn try_acquire_n(&self, n: f64) -> bool {
        let mut s = self.state.lock().expect("token bucket poisoned");
        let now = Instant::now();
        let elapsed = now.duration_since(s.last_refill).as_secs_f64();
        s.tokens = (s.tokens + elapsed * self.refill_per_sec).min(self.capacity);
        s.last_refill = now;

        if s.tokens >= n {
            s.tokens -= n;
            true
        } else {
            false
        }
    }

    /// Return the number of tokens currently available (approximately).
    pub fn available(&self) -> f64 {
        let s = self.state.lock().expect("token bucket poisoned");
        let elapsed = s.last_refill.elapsed().as_secs_f64();
        (s.tokens + elapsed * self.refill_per_sec).min(self.capacity)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn starts_full() {
        let b = TokenBucket::new(5.0, 1.0);
        for _ in 0..5 {
            assert!(b.try_acquire(), "should have a token");
        }
        assert!(!b.try_acquire(), "should be empty");
    }

    #[test]
    fn refills_over_time() {
        let b = TokenBucket::new(2.0, 100.0); // 100 tokens/sec
        assert!(b.try_acquire());
        assert!(b.try_acquire());
        assert!(!b.try_acquire());
        std::thread::sleep(Duration::from_millis(50)); // should get ~5 tokens
        assert!(b.try_acquire());
    }

    #[test]
    fn caps_at_capacity() {
        let b = TokenBucket::new(2.0, 1000.0);
        std::thread::sleep(Duration::from_millis(50)); // would refill 50 tokens
        assert!(b.try_acquire());
        assert!(b.try_acquire());
        assert!(!b.try_acquire(), "capacity caps the refill");
    }
}
