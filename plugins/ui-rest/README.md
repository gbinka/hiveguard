# ui.rest

REST + WebSocket backend plugin for HiveGuard — the **single** management API
for the daemon (REFACTOR 2.5). Exposes the full JSON surface under `/api/...`,
an unauthenticated Prometheus scrape at `/metrics`, an optional log-ingest
receiver, and a live event stream, all backed by the daemon's `UiApiHandle`.
Optionally serves a single-page application (e.g. the `plugins/ui-web/` build
output) from a local directory with `index.html` fallback so client-side
routing works out of the box.

This plugin is the canonical backend consumed by `plugins/ui-web/`
(WASM SPA), `ui-tui`, and any third-party UI client. It replaces the retired
legacy `api:` REST server; clients should migrate `/api/v1/<x>` → `/api/<x>`.

## API contract

The full HTTP + WebSocket surface is documented in [`openapi.yaml`](./openapi.yaml)
(OpenAPI 3.1). Schemas mirror the Rust wire types in
`hiveguard-plugin-api/src/traits/ui_server.rs` 1:1. Use it to generate typed
clients or drive Swagger UI / Redoc. The standalone React panel lives in
`../../hiveguard-web/`.

## Configuration

| field                | type      | required | default            | notes                                                                     |
| -------------------- | --------- | -------- | ------------------ | ------------------------------------------------------------------------- |
| `bind_addr`          | string    | no       | `127.0.0.1:8443`   | `host:port` to listen on.                                                 |
| `auth_token`         | string    | yes      | —                  | Bearer token required on every REST + WS request.                         |
| `static_dir`         | string    | no       | _none_             | Directory containing `index.html` and SPA assets. Enables SPA fallback.   |
| `cors_origins`       | string[]  | no       | `[]`               | Whitelist of allowed CORS origins. Leave empty to disable CORS entirely.  |
| `tick_interval_secs` | integer   | no       | `30`               | Keepalive `UiEvent::Tick` cadence for WebSocket connections (min `1`).    |
| `ingest`             | object    | no       | _none_             | HTTP-push log ingest receiver — see [Log ingest](#log-ingest). Disabled unless present with `enabled: true`. |

### Example `config.yaml`

```yaml
plugins:
  - id: ui.rest
    config:
      bind_addr: "0.0.0.0:8443"
      auth_token: "${env:HIVEGUARD_UI_TOKEN}"
      static_dir: "/var/lib/hiveguard/ui-web/dist"
      cors_origins:
        - "https://hiveguard.example.com"
      tick_interval_secs: 30
```

## Endpoints

| method   | path                          | auth   | description                                              |
| -------- | ----------------------------- | ------ | ------------------------------------------------------- |
| `GET`    | `/api/health`                 | no     | Liveness probe: `{"status":"ok","uptime_secs":N}`.      |
| `GET`    | `/metrics`                    | no     | Prometheus / OpenMetrics exposition (503 if disabled).  |
| `GET`    | `/api/info`                   | yes    | `NodeInfo` JSON.                                        |
| `GET`    | `/api/stats`                  | yes    | `StatsInfo` — uptime, ban + whitelist counts, version.  |
| `GET`    | `/api/bans`                   | yes    | `Vec<BanInfo>` JSON.                                    |
| `POST`   | `/api/bans`                   | yes    | Add a ban — body: `BanRequest` JSON, returns 201.       |
| `DELETE` | `/api/bans/{cidr}`            | yes    | Remove a ban — `cidr` path segment is URL-encoded.      |
| `GET`    | `/api/whitelist`              | yes    | `{"entries":[cidr,…]}`.                                 |
| `POST`   | `/api/whitelist`              | yes    | Add entry — body: `{"cidr":"…"}`, returns 201.          |
| `DELETE` | `/api/whitelist/{cidr}`       | yes    | Remove a whitelist entry (URL-encoded).                 |
| `GET`    | `/api/peers`                  | yes    | `{"peers":[…]}` (empty until PeerManager is wired in).  |
| `GET`    | `/api/bots`                   | yes    | `{"bots":[…]}` registry stats (503 if disabled).        |
| `POST`   | `/api/bots/{name}/policy`     | yes    | Set policy — body: `{"policy":"allow\|block\|monitor"}`. |
| `GET`    | `/api/config`                 | yes    | `{"content":"<yaml>"}` — raw config file.               |
| `PUT`    | `/api/config`                 | yes    | Replace config — body: `{"content":"<yaml>"}` (validated). |
| `GET`    | `/api/config/detectors`       | yes    | Effective detector config as JSON.                      |
| `PUT`    | `/api/config/detectors`       | yes    | Replace the `detectors:` block — body: detectors JSON.  |
| `GET`    | `/api/fail2ban/preview`       | yes    | `?db=&jail=` — preview bans without importing.          |
| `POST`   | `/api/fail2ban/import`        | yes    | Import bans — body: `{"db":…,"jail":…}` (both optional). |
| `GET`    | `/api/sigma/rules`            | yes    | `{"rules":[…],"total":N}` (503 if Sigma disabled).      |
| `POST`   | `/api/sigma/rules`            | yes    | Upsert a rule — body: `{"yaml":"…"}`.                   |
| `GET`    | `/api/sigma/rules/{id}`       | yes    | Full rule detail; 404 if not found.                     |
| `DELETE` | `/api/sigma/rules/{id}`       | yes    | Delete a rule; 404 if not found.                        |
| `GET`    | `/api/sigma/stats`            | yes    | `{"total_rules":N,"hit_counts":{…}}`.                   |
| `GET`    | `/api/threats`                | yes    | `Vec<ThreatInfo>` JSON.                                 |
| `GET`    | `/api/plugins`                | yes    | `Vec<PluginInfo>` JSON.                                 |
| `POST`   | `/api/ingest/logs`            | token  | Log-push receiver — only when `ingest.enabled`. See below. |
| `GET`    | `/api/stream`                 | yes    | WebSocket upgrade — pushes `UiEvent`s as JSON.          |

Management endpoints backed by a disabled subsystem (Sigma engine, bot
registry, metrics, config path) return `503 Service Unavailable`; unknown
rule/bot ids return `404`; invalid input (bad YAML, unknown policy) returns
`400`.

### Authentication

REST requests must include:

```
Authorization: Bearer <auth_token>
```

WebSocket clients should request the `bearer.<auth_token>` subprotocol on
upgrade — this is the same channel browsers expose for sending credentials
without leaking them into URLs:

```
Sec-WebSocket-Protocol: bearer.<auth_token>
```

A `?token=<auth_token>` query parameter is accepted as a fallback for
testing tools that cannot set subprotocol headers, but it is **not**
recommended in production because query strings often end up in access
logs.

Token comparison is constant-time (`subtle::ConstantTimeEq`).

### `BanRequest` body

```json
{
  "subject": "1.2.3.4/32",
  "duration": { "secs": 3600, "nanos": 0 },
  "reason": "manual override"
}
```

### WebSocket frames

Every frame is a JSON text frame containing a single `UiEvent` value:

```json
{ "type": "connected",        "data": { /* NodeInfo */ } }
{ "type": "bans_snapshot",    "data": [ /* BanInfo[] */ ] }
{ "type": "threats_snapshot", "data": [ /* ThreatInfo[] */ ] }
{ "type": "plugins_snapshot", "data": [ /* PluginInfo[] */ ] }
{ "type": "tick" }
```

A connection always opens with the four `*_snapshot` (and `connected`)
events, then forwards every broadcast event until close.

## Static SPA serving

If `static_dir` points to a directory containing an `index.html`, the
plugin serves files from that directory at `/` and falls back to
`index.html` for any unmatched path so deep links into the SPA
(`/bans`, `/threats`, `/plugins`, `/config`, …) work.

Build `plugins/ui-web/` and copy `dist/` into the path you reference here:

```sh
cd plugins/ui-web
trunk build --release
cp -r dist/ /var/lib/hiveguard/ui-web/dist
```

## Log ingest

When the optional `ingest` block is present with `enabled: true`, the plugin
mounts `POST /api/ingest/logs` — an HTTP-push receiver migrated from the legacy
`api.http_push`. It accepts a JSON array of entries, a single JSON object, or
newline-delimited (NDJSON) text. Each entry is reduced to a log line (strings
used as-is; objects probed for `message`/`log`/`msg`/`text`/`line`/`event`),
routed through the configured parser, and forwarded to the detection pipeline.

```yaml
plugins:
  - id: ui.rest
    config:
      auth_token: "${env:HIVEGUARD_UI_TOKEN}"
      ingest:
        enabled: true
        token: "${env:HIVEGUARD_INGEST_TOKEN}"  # falls back to auth_token
        parser: "auto"            # auto | ssh | nginx | postfix
        rate_limit_per_sec: 100
        max_request_size_mb: 4
```

| field                 | type    | default        | notes                                           |
| --------------------- | ------- | -------------- | ----------------------------------------------- |
| `enabled`             | bool    | `false`        | Mount the route. When `false`, returns 404.     |
| `token`               | string  | `auth_token`   | Dedicated Bearer token for this endpoint.       |
| `parser`              | string  | `auto`         | `auto`, `ssh`, `nginx`, or `postfix`.           |
| `rate_limit_per_sec`  | integer | `100`          | Per-process sliding-window limit (429 on excess). |
| `max_request_size_mb` | integer | `4`            | Body-size cap (413 on excess).                  |

Response: `{"accepted":N,"rejected":M}`. The endpoint uses its own Bearer token
(constant-time compared) independent of the main `require_auth` middleware.

## TODOs (Phase 7+)

- Handle client-to-server WS messages (currently ignored).
- Per-connection rate limiting on `POST /api/bans`.
- WS metrics: connected clients, lag count, send errors.
- Bidirectional unban / temporary mute via WS commands.
- mTLS / OIDC auth modes beyond static bearer tokens.
