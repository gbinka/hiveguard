# Log source plugin

Read events from somewhere and feed them into the pipeline as
[`NormalizedEvent`s](../../hiveguard-core/src/models.rs). Reference impls
(after Fala A1): `plugins/source-file`, `plugins/source-syslog`.

> Before reading this: finish [AUTHORING.md](./AUTHORING.md).

## Trait

```rust
#[async_trait]
pub trait LogSourcePlugin: Plugin {
    async fn run(&mut self, sink: EventSink, shutdown: CancellationToken)
        -> PluginResult<()>;
}
```

Where `EventSink = tokio::sync::mpsc::Sender<NormalizedEvent>`.

## What the host guarantees

- `run` is called exactly once, after `init`. Loop until `shutdown` fires.
- The `sink` channel is bounded (4096 entries). `sink.send(event).await` will
  **back-pressure** when the pipeline is saturated — that's the correct
  behaviour, do not drop events.
- The host expects `run` to return `Ok(())` when `shutdown.cancelled().await`
  fires. Returning `Err(_)` flags the plugin as `Failed` and triggers a
  restart with exponential back-off per `RestartPolicy`.

## What you implement

### 1. Produce `NormalizedEvent`

Every event you emit must have:

- `timestamp` — when the underlying event happened (not when you parsed it).
- `source_ip` — must be parseable as `IpAddr`. If the wire format doesn't
  carry an IP, your plugin probably shouldn't be a log source.
- `event_type` — pick the most specific variant of `EventType`. Use
  `EventType::Custom(String)` only as a last resort.
- `source_name` — your plugin id. Used by detectors to filter relevant
  events.
- `raw_line` — the original line/payload, untruncated. Forensic value.
- `metadata` — `HashMap<String, String>` of parser-extracted fields
  (e.g. `username`, `path`, `status_code`, `user_agent`). Detectors will
  read from here — establishing a stable vocabulary is part of plugin
  design.

### 2. Tail or poll

Choose a strategy by source type:

| Source | Strategy |
|--------|----------|
| Single file (`/var/log/auth.log`) | `inotify` watcher + offset persistence in `ctx.data_dir`. Reuse code from legacy `hiveguard-ingest::file_watcher` |
| Rotating file | Same, plus rename / inode-change detection |
| Network listener (syslog TCP/UDP/TLS) | `tokio::net::TcpListener` / `UdpSocket` loop |
| Message queue (Kafka, NATS, RabbitMQ) | Use the client library's consumer; commit offset/ack after `sink.send().await` succeeds |
| Polling (CloudWatch, Kinesis) | `tokio::time::interval` + cursor in `ctx.data_dir` |

### 3. Checkpoint / resume

For sources where event-loss matters (queues, log files), persist a cursor in
`ctx.data_dir`. The standard layout is:

```
<data_dir>/cursor.bincode       # last successfully processed position
```

Save on a timer (e.g. every 5 s) AND on shutdown. Use `bincode` or
`serde_json` — pick the one that's already in your dep tree.

```rust
let cursor_path = self.data_dir.join("cursor.bincode");
let cursor: Cursor = std::fs::read(&cursor_path)
    .ok()
    .and_then(|b| bincode::deserialize(&b).ok())
    .unwrap_or_default();
```

### 4. Honour `shutdown`

```rust
loop {
    tokio::select! {
        _ = shutdown.cancelled() => break,
        line = self.next_line() => match line {
            Some(line) => {
                let event = self.parse(line)?;
                if let Err(_) = sink.send(event).await {
                    // Pipeline closed; bail out.
                    break;
                }
            }
            None => break,
        }
    }
}
self.save_cursor()?;
Ok(())
```

## Parsing & normalisation

Each log source has its own raw format. Your job is to parse it into
`NormalizedEvent`. Best practices:

- Use `regex` lazily compiled once at struct construction, not per line.
- For structured formats (JSON syslog, CEF, LEEF), use `serde_json` /
  dedicated crates.
- Reject malformed lines with `debug!` (not `warn!`) — log noise is real.
- **Don't fail the whole `run` loop on a parse error** — skip and continue.

## Config

Required fields differ wildly by source type. Common ones:

| Field | Type | Purpose |
|-------|------|---------|
| `path` | string (file) | Path to log file |
| `listen` | string (host:port) | Network bind address |
| `tls` | object | TLS config (cert_path, key_path, client_ca) |
| `start_position` | enum `beginning` / `end` / `cursor` | First-run behaviour |
| `format` | enum | Wire format (`rfc5424`, `rfc3164`, `json`, …) |
| `routes` | array | For multiplex sources (e.g. syslog tagged by program) |

## Metrics

```
hiveguard_plugin_source_<name>_events_total{event_type}
hiveguard_plugin_source_<name>_parse_errors_total
hiveguard_plugin_source_<name>_cursor_lag_seconds   # for queue sources
hiveguard_plugin_source_<name>_last_event_timestamp_seconds
```

## Common pitfalls

- **No back-pressure handling** — calling `sink.try_send` and dropping on
  full channel = silent event loss. Always `await`.
- **No shutdown handling** — `tokio::spawn`-ed parser tasks that don't see
  `shutdown` will leak.
- **No cursor on restart** — replaying the entire log file on every restart
  is a denial of service against the pipeline. Persist your offset.
- **Wrong timestamp** — using `Utc::now()` instead of the event's own
  timestamp breaks timing-window detectors. Parse the timestamp from the
  log line if at all possible.
- **Hot regex compilation** — `Regex::new(...)` inside a tight loop is a
  classic Rust performance trap. Compile once.

## Source category vs detection category

Your log source produces events. **It does not decide what's suspicious** —
that's the detector's job. Keep `LogSourcePlugin` impls as dumb pumps. If you
want to enrich (e.g. GeoIP lookup), that's the pipeline's responsibility
(via `CtiProviderPlugin`), not yours.
