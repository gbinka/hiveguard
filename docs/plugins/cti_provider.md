# CTI provider plugin

Look up reputation / context for an IP address. Reference impls (after Fala
A2): `plugins/cti-abuseipdb`, `plugins/cti-geoip`, `plugins/cti-tor`.

> Before reading this: finish [AUTHORING.md](./AUTHORING.md).

## Trait

```rust
#[async_trait]
pub trait CtiProviderPlugin: Plugin {
    async fn lookup(&self, ip: IpAddr) -> PluginResult<Option<CtiVerdict>>;
}

pub struct CtiVerdict {
    pub provider: String,
    pub confidence: Option<u8>,     // 0..=100
    pub reason: Option<String>,
    pub recommend_ban: bool,
}
```

## What the host guarantees

- `lookup` may be called concurrently from multiple pipeline workers. `&self`
  + interior mutability.
- The pipeline calls `lookup` for every event that doesn't have a recent
  cached verdict. **You implement the cache** — the host does not.
- `Ok(None)` means "no opinion" — different from `Err`. Use `Err` only for
  service failures (rate limit hit, network error). The host treats `Err` as
  "skip this provider for this event"; it does NOT abort the pipeline.
- A single verdict with `recommend_ban: true` is enough for the scoring engine
  to issue a ban without waiting for accumulation. Use it sparingly — high
  confidence sources only.

## What you implement

### 1. Caching

CTI calls are slow and rate-limited. Cache locally in `ctx.data_dir`:

```
<data_dir>/cache.bincode    # IpAddr → (Verdict, expires_at)
```

TTL is config-driven; sensible defaults:
- Reputation (AbuseIPDB, OTX): 6–24 h
- Tor exit list: 1 h (full refresh)
- GeoIP: 7 d (rarely changes)
- DNSBL: 30 min

Bound cache size; LRU eviction at the configured `max_cache_entries`.

### 2. Rate limiting

Most providers have a free-tier quota. Track your usage in a token bucket;
return `Ok(None)` when bucket is empty (do not error — the cache will still
serve fresh entries).

Use `hiveguard_plugin_utils::ratelimit::TokenBucket`.

### 3. Confidence ↔ ban recommendation

Map provider-specific scores to the standard 0–100 confidence range:

| Provider | Mapping |
|----------|---------|
| AbuseIPDB | Their score 0–100 → use directly |
| Spamhaus | Listed = 95, not listed = `None` |
| Tor | Exit node = 60 (configurable threshold) |
| OTX | min_pulse_count threshold → 50–90 |
| GeoIP | `is_datacenter` adds penalty via scoring config, not a verdict |

Set `recommend_ban: true` only when **both**:
- Confidence ≥ 90, AND
- Provider config has `ban_on_first_hit: true` (explicit opt-in).

### 4. Refresh tasks (for full-list providers)

Some providers (Tor exit list, GeoIP DB) ship full datasets you download
periodically rather than per-IP API calls. Spawn a refresh task in `init`,
tie it to `ctx.shutdown`:

```rust
let shutdown = ctx.shutdown.clone();
tokio::spawn(async move {
    let mut tick = tokio::time::interval(refresh_interval);
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            _ = tick.tick() => { let _ = refresh_dataset().await; }
        }
    }
});
```

## Config

| Field | Type | Purpose |
|-------|------|---------|
| `api_key` | string `${env:…}` | Provider API key |
| `confidence_threshold` | int 0-100 | Minimum to surface |
| `ban_on_first_hit` | bool | Skip score accumulation |
| `cache_ttl_secs` | int | Per-entry TTL |
| `max_cache_entries` | int | LRU cap |
| `refresh_interval_secs` | int | For full-list providers |
| `timeout_secs` | int | HTTP timeout |

## Metrics

```
hiveguard_plugin_cti_<name>_lookups_total{result="hit"|"miss"|"error"}
hiveguard_plugin_cti_<name>_cache_size
hiveguard_plugin_cti_<name>_quota_remaining       # if observable
hiveguard_plugin_cti_<name>_refresh_duration_seconds
```

## Common pitfalls

- **Synchronous DNS lookups** in DNSBL providers — use `hickory-resolver`
  or `trust-dns-resolver`, not `std::net::ToSocketAddrs`.
- **Cache poisoning** — never cache `Err` results; only cache `Ok(verdict)`.
- **Treating "not listed" as `Err`** — it's `Ok(None)`. Important
  distinction.
- **Burning API quota on cache misses** — implement negative caching too
  (cache `Ok(None)` for a shorter TTL, e.g. 1 h).
- **PII exposure** — provider URLs sometimes include the IP in the path
  (e.g. AbuseIPDB). Don't log full URLs at `info!` or above.

## CTI provider vs Detector

A CTI provider returns a **reputation**. A detector observes **behaviour**.
If you find yourself counting events in a CTI provider, you wanted a
detector. If you find yourself fetching external data in a detector, you
wanted a CTI provider.
