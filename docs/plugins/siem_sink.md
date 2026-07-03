# SIEM sink plugin

Ship pipeline events to external log storage / SIEM platforms. Reference impls
(after Fala B2): `plugins/sink-elastic`, `plugins/sink-splunk`,
`plugins/sink-datadog`, `plugins/sink-syslog`.

> Before reading this: finish [AUTHORING.md](./AUTHORING.md).

## Trait

```rust
#[async_trait]
pub trait SiemSinkPlugin: Plugin {
    async fn send(&self, batch: SiemBatch) -> PluginResult<()>;
    fn max_in_flight(&self) -> usize { 1 }
    async fn flush(&self) -> PluginResult<()> { Ok(()) }
}

pub type SiemBatch = Vec<NormalizedEvent>;
```

## What the host guarantees

- Events are **batched** by the host before reaching `send`. Batch size and
  flush interval are global config (`siem.batch_size`, `siem.flush_secs`),
  not per-plugin.
- `send` may be called concurrently up to `max_in_flight()` times.
- `flush` is called once during graceful shutdown. Drain any in-memory or
  on-disk buffer before returning.

## What you implement

### 1. Wire-format mapping

Convert `NormalizedEvent` to the destination's format. Each platform has its
preferred shape:

| Platform | Format |
|----------|--------|
| Elasticsearch | NDJSON, one `{ "index": {} }` line + one document line, per the [bulk API](https://www.elastic.co/guide/en/elasticsearch/reference/current/docs-bulk.html) |
| Splunk HEC | JSON `{ "event": <NormalizedEvent>, "sourcetype": "...", "time": ... }` lines |
| Datadog Logs | JSON `{ "ddsource": "hiveguard", "service": "...", "message": "..." }` array |
| Syslog | RFC 5424 framing over TCP/UDP/TLS |

Provide a `wire.rs` (or equivalent) module that exposes a pure function
`event_to_wire(event: &NormalizedEvent) -> Bytes`. This makes wire-format
unit-testable without networking.

### 2. Buffering with disk spillover

Network sinks fail. Your plugin owns the buffer. Recommended layout:

```
<data_dir>/buffer/
├── current.ndjson         # active append-only file
└── pending/
    ├── batch-001.ndjson   # rotated when full or on flush interval
    └── batch-002.ndjson
```

- Append every event to `current.ndjson` before attempting upload.
- On successful upload of a `pending/batch-*.ndjson`, delete the file.
- On startup, scan `pending/` and reattempt upload.
- Cap total spillover (`buffer.max_size_mb`). When full, drop oldest with a
  `warn!` and metric.

Reuse `hiveguard_plugin_utils::buffer::DiskBuffer` once it's available.

### 3. Retry policy

Inside `send`:

- 2xx → success.
- 4xx (non-rate-limit) → return `Err` permanently. The host will not retry
  the same batch — it's poison.
- 429 / 503 / network error → return `Err` with `PluginError::Runtime(...)`.
  The host will requeue.

For 429, honour `Retry-After` header if present.

### 4. ECS / CEF normalisation (Elasticsearch / SIEM-classic)

If you're shipping to a platform with strong schema expectations, map fields
to that schema:

- Elastic Common Schema: `source.ip`, `event.action`, `event.severity`,
  `user.name`, `url.path`.
- ArcSight CEF: standard prefix + key=value extension fields.

Don't fabricate fields you don't have. `metadata` keys vary by log source —
pass them through under `hiveguard.metadata.<key>`.

## Config

| Field | Type | Purpose |
|-------|------|---------|
| `url` | string | Destination endpoint |
| `index_prefix` | string | E.g. `hiveguard-events-` (date-suffixed) |
| `sourcetype` | string | Splunk-specific |
| `service` | string | Datadog-specific |
| `token` | string `${env:…}` | Auth |
| `tls.ca_cert` | string | Path to CA cert |
| `batch_size` | int | Override host default |
| `buffer_max_size_mb` | int | Disk spill cap |
| `install_template` | bool | Push ILM / index template on startup |

## Metrics

```
hiveguard_plugin_sink_<name>_events_sent_total
hiveguard_plugin_sink_<name>_events_failed_total
hiveguard_plugin_sink_<name>_batches_total
hiveguard_plugin_sink_<name>_buffer_size_bytes
hiveguard_plugin_sink_<name>_last_success_timestamp_seconds
hiveguard_plugin_sink_<name>_send_duration_seconds (histogram)
```

## Common pitfalls

- **No buffer = data loss** under any network blip. Disk-spillover is not
  optional for SIEM sinks.
- **Synchronous compression** in the hot path (gzipping a 4 MB batch per
  call). Pre-compress as you buffer.
- **Token in logs** — `tracing` will happily print whatever you pass it.
  Wrap secrets in a `Display`-less newtype.
- **Index name with date** — make sure your `chrono::Utc::now()` calls don't
  cross midnight inside a batch (you'd get two indices in one bulk request).
- **HTTPS verification disabled** — never. Use proper CA cert configuration.
