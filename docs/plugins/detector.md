# Detector plugin

Inspect normalized events and emit detection signals. Reference impls (after
Fala A3): `plugins/detector-ssh-bruteforce`, `plugins/detector-honeypot`,
`plugins/detector-sigma`.

> Before reading this: finish [AUTHORING.md](./AUTHORING.md).

## Trait

```rust
pub trait DetectorPlugin: Plugin {
    fn process(&self, event: &NormalizedEvent) -> Option<DetectionSignal>;
}
```

**Note the `&self`.** This is a deliberate departure from the legacy
`hiveguard_core::Detector` trait, which used `&mut self`. The new trait
lets the pipeline run detectors concurrently across events.

## What the host guarantees

- `process` is called from many tasks in parallel. It **must** be safe to
  invoke concurrently — use `DashMap`, `RwLock`, or atomics for any state.
- Every event is dispatched to every enabled detector in the order they
  appear in the `plugins:` config.
- Return `None` for the common case (event doesn't match). Return
  `Some(DetectionSignal)` when your detector fires.
- A `DetectionSignal` does **not** cause a ban by itself — it feeds the
  scoring engine, which accumulates severity × confidence over a window.
  The scoring engine decides when the threshold is crossed.

## What you implement

### 1. State with interior mutability

Sliding-window detectors (most of them) track per-IP state. Use `DashMap`:

```rust
use dashmap::DashMap;
use std::collections::VecDeque;
use std::net::IpAddr;
use chrono::{DateTime, Utc};

pub struct BruteforceDetector {
    threshold: u32,
    window: Duration,
    failures: DashMap<IpAddr, VecDeque<DateTime<Utc>>>,
}

impl DetectorPlugin for BruteforceDetector {
    fn process(&self, event: &NormalizedEvent) -> Option<DetectionSignal> {
        if event.event_type != EventType::AuthFailure {
            return None;
        }
        let mut entry = self.failures.entry(event.source_ip).or_default();
        Self::prune(&mut entry, self.window, event.timestamp);
        entry.push_back(event.timestamp);
        if entry.len() as u32 >= self.threshold {
            let signal = self.build_signal(event, &entry);
            entry.clear();
            return Some(signal);
        }
        None
    }
}
```

`DashMap::entry()` returns a write-locked `RefMut`. Hold it only for the
duration of the operation; never await across it.

### 2. Severity and confidence

`DetectionSignal` carries:
- `severity: u8` (0–255) — how bad this finding is on its own.
- `confidence: f32` (0.0–1.0) — how sure you are.

The scoring engine accumulates `severity × confidence`. Calibration
guidelines:

| Detector type | Severity | Confidence |
|---------------|----------|------------|
| Honeypot hit | 250 | 1.0 |
| Scanner UA match | 90 | 0.95 |
| Path probe (`/.env`, `/wp-login.php`) | 80 | 0.9 |
| Brute-force (5 failures in 5 min) | 60 | 0.85 |
| HTTP 4xx flood | 50 | 0.8 |
| Entropy anomaly | 30–80 | 0.5–0.9 |

If you're uncertain about calibration, **err on the side of low
confidence** — a noisy detector that always fires at confidence 0.5 is
recoverable; one that fires at 1.0 bans legitimate users.

### 3. Suggested action

`DetectionSignal::suggested_action` is a hint to the scoring engine:

- `Action::Ban(duration)` — please ban for at least this long. Used by
  high-severity detectors (honeypot, hard scanner signatures).
- `Action::Observe` — record but don't escalate. Used by experimental
  detectors during validation.
- `Action::Escalate` — flag for human review (currently treated as
  `Observe` by the default scoring engine, but reserved for future
  workflows).

### 4. Evidence hash

Compute a stable hash over the inputs that triggered the signal:

```rust
fn evidence_hash(ip: &IpAddr, reason: &str) -> [u8; 32] {
    *blake3::hash(format!("{ip}:{reason}").as_bytes()).as_bytes()
}
```

The pipeline uses this for deduplication across cluster nodes (CRDT). Same
input must produce the same hash.

## Config

Detector-specific. Common fields:

| Field | Type | Purpose |
|-------|------|---------|
| `enabled` | bool | Master switch (alternative to omitting from `plugins:`) |
| `threshold` | int | Trigger threshold |
| `window` | duration string | Sliding window |
| `ban_duration` | duration string | Suggested ban length |
| `severity` | int 0–255 | Override default severity |
| `confidence` | float 0.0–1.0 | Override default confidence |

## Metrics

```
hiveguard_plugin_detector_<name>_signals_total
hiveguard_plugin_detector_<name>_evaluations_total      # every event seen
hiveguard_plugin_detector_<name>_state_size              # gauge of tracked IPs
hiveguard_plugin_detector_<name>_evaluation_duration_seconds  # histogram
```

## Common pitfalls

- **`Mutex<HashMap>` instead of `DashMap`** — the pipeline runs hot, and
  global locks serialize all detectors. `DashMap` shards internally.
- **No state pruning** — `HashMap<IpAddr, _>` grows unbounded if you don't
  remove cold entries. Either prune in `process` (entries with empty
  deques after window slide), or spawn a janitor task in `init`.
- **Mutating shared state across `.await`** — `process` is sync (no `async`),
  so this can't happen by mistake. But if you spawn helpers, watch for it.
- **Reading metadata that might not exist** — `event.metadata.get("user")`
  is `Option<&String>`. Don't unwrap.
- **Time-window detectors using `Utc::now()`** instead of `event.timestamp`
  — replay / lag breaks the detector when the difference grows.

## Detector vs CTI vs Scoring

| If you want to … | Use |
|------------------|-----|
| Count failures over a window | Detector |
| Check an external reputation list | CTI provider |
| Combine multiple signals into a ban decision | Scoring engine |

If you find yourself doing two of these in one plugin, split it.
