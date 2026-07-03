# Scoring engine plugin

Decide when to issue a ban based on accumulated detection signals.
Reference impl (after Fala A3): `plugins/scoring-default` — the weighted
sliding-window accumulator that was previously hard-coded in
`hiveguard-core::scoring`.

> Before reading this: finish [AUTHORING.md](./AUTHORING.md).

This is the **most consequential** plugin category. Exactly one scoring
engine is active per daemon — its decisions become bans, which become
firewall rules, which determine what traffic reaches the protected
services. Take calibration seriously.

## Trait

```rust
#[async_trait]
pub trait ScoringEnginePlugin: Plugin {
    fn record(&self, signal: DetectionSignal);
    fn evaluate(&self, ip: IpAddr) -> Option<BanDecision>;
    fn decay(&self);
    fn snapshot(&self) -> serde_json::Value;
    fn restore(&self, state: serde_json::Value) -> PluginResult<()>;
}

pub struct BanDecision {
    pub subject: IpNet,
    pub duration: Duration,
    pub reason: String,
    pub severity: u8,
    pub evidence_hash: [u8; 32],
}
```

## What the host guarantees

- The pipeline calls `record(signal)` for every `DetectionSignal` produced
  by any detector. `record` is hot — keep it fast (< 100 µs).
- After each `record`, the pipeline calls `evaluate(ip)` on the source IP.
  Return `Some(BanDecision)` to issue a ban.
- `decay()` is called periodically (~ every 30 s) for housekeeping (pruning
  expired entries from the sliding window). It must not block the pipeline.
- `snapshot()` is called during WAL+snapshot save (default every 5 min) and
  during graceful shutdown. The returned `Value` is persisted alongside the
  ban store; on restart, `restore(state)` rebuilds your internal state.

## What you implement

### 1. The accumulation model

The default implementation:
- Maintains a sliding window (default 30 min) per IP.
- Accumulates `severity × confidence` for every signal in the window.
- When `sum ≥ ban_severity_threshold` (default 100), emits a `BanDecision`.
- Ban duration = max of all `Action::Ban(duration)` suggestions in the window.

A custom scoring engine can:
- Replace the linear accumulator with something non-linear (e.g.
  exponential decay).
- Use Bayesian inference over detector outputs.
- Train an ML model offline and run inference here.
- Integrate CTI verdicts as additional features.
- Apply business rules (e.g. "never ban during 9–17 weekday office hours").

What matters: the contract is "given a stream of signals, emit ban
decisions". Everything inside the plugin is at your discretion.

### 2. Snapshot / restore

The pipeline doesn't know about your internal data structures. Persist them
yourself via `snapshot()` → `serde_json::Value` → `restore(value)`. Restore
must reconstruct state such that subsequent `record`/`evaluate` calls
behave identically to having received the original signals.

Tests for `snapshot ∘ restore = identity` are mandatory.

```rust
fn snapshot(&self) -> serde_json::Value {
    let state = self.state.read();
    serde_json::to_value(&*state).unwrap_or_default()
}
fn restore(&self, value: serde_json::Value) -> PluginResult<()> {
    let parsed: PersistedState = serde_json::from_value(value)
        .map_err(|e| PluginError::Runtime(e.to_string()))?;
    *self.state.write() = parsed.into();
    Ok(())
}
```

### 3. Interior mutability everywhere

`record` and `evaluate` both take `&self`. Use `RwLock` (read-heavy
evaluate) or per-IP sharding (`DashMap`) to avoid global contention.

### 4. Calibration knobs

Expose every meaningful tuning parameter via config — never hard-code
thresholds. A scoring engine that can't be tuned without a recompile is a
broken scoring engine.

## Config

Default scoring engine:

| Field | Type | Purpose |
|-------|------|---------|
| `accumulation_window` | duration string | Sliding window length |
| `ban_severity_threshold` | int | Sum threshold for ban |
| `default_ban_duration` | duration string | When no detector suggests one |
| `per_detector_weights` | map name→float | Multipliers for specific detectors |
| `whitelist_country_codes` | array | Skip evaluation for these |
| `decay_factor` | float | Exponential decay vs linear window |

ML-based scoring engine (hypothetical):

| Field | Type | Purpose |
|-------|------|---------|
| `model_path` | string | Path to serialised model file |
| `threshold` | float 0.0–1.0 | Classifier decision threshold |
| `feature_window` | duration string | How much history to use |
| `update_interval_secs` | int | Hot-reload of model file |

## Metrics

```
hiveguard_plugin_scoring_<name>_signals_recorded_total
hiveguard_plugin_scoring_<name>_evaluations_total
hiveguard_plugin_scoring_<name>_bans_issued_total
hiveguard_plugin_scoring_<name>_tracked_ips             # gauge
hiveguard_plugin_scoring_<name>_record_duration_seconds # histogram (hot path)
hiveguard_plugin_scoring_<name>_evaluate_duration_seconds
hiveguard_plugin_scoring_<name>_snapshot_size_bytes     # gauge
```

## Calibration discipline

This isn't just a coding concern — it's the difference between "useful
security tool" and "DoS against your users".

Before shipping any scoring engine:

1. **Run in `enforcer-observe` mode for at least a week.** Watch what
   would-be bans look like. Look for cases where a legitimate user (CDN,
   load balancer, your own monitoring tools) accumulates enough signals
   to be banned. Whitelist them.
2. **Test the snapshot/restore round-trip** with realistic state sizes
   (10k+ tracked IPs).
3. **Measure `record_duration_seconds` p99** under load. Should be
   < 1 ms; if not, your data structures need rethinking before you ship.
4. **Adversarial testing:** can an attacker craft a stream of events that
   makes your engine ban a third party? (CIDR-level bans are especially
   dangerous here — see `DistributedSlowDetector` in legacy code.)
5. **Sanity check against the default scoring engine.** If yours is more
   aggressive, document why. If less aggressive, document why.

## Common pitfalls

- **Unbounded memory** — tracked-IP set must have an upper bound. Evict
  cold entries.
- **Floating-point drift in accumulator state** — use `f64`, not `f32`;
  consider integer fixed-point for the hot path.
- **Snapshot too large to persist atomically** — if your state is > 10 MB,
  use streaming serialization (`serde_bincode`) and write to a temp file +
  rename.
- **Calling out to ML inference synchronously** — if model inference is
  slow (> 1 ms), the pipeline backs up. Use a separate task with a bounded
  channel; record signals into a queue, evaluate asynchronously, emit ban
  decisions back through a callback. (Plugin API will grow a `ScoringSink`
  type for this when the first ML-based engine is implemented; until then,
  keep `record`/`evaluate` synchronous-bounded.)
- **Ignoring `Action::Ban(duration)` from signals** — at minimum, honour
  the longest suggested duration. Detectors know their domain.
