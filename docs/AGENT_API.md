# HiveGuard Agent API (`/api/agent/*`)

Analysis surface for AI agents and analysts. It lives in the `ui.rest` plugin
next to the operator API, shares its bearer token and loopback bind, and is
**read-mostly**: the only mutations reachable through it are the pre-existing
ban/whitelist endpoints. It gives an agent, in one place:

- a one-call situation report (`overview`),
- filterable/aggregated views of bans and recent detection signals,
- query + statistics over the *raw logs the daemon already tails*
  (nginx, ssh, ufw, postfix …) and over extra files you allow-list,
- the daemon's own journal,
- the effective detector configuration, the catalogue of every plugin linked
  into the binary (enabled or not) and a config validator,
- a live incremental event stream (SSE).

Companion pieces: the stdio MCP server `tools/mcp/hiveguard_mcp.py` (exposes
every endpoint as an MCP tool) and the Claude Code skill
`hiveguard-sentinel` (the daily-review playbook).

## 1. Access

```
Authorization: Bearer <auth_token>        # same token as /api/*
Base URL: http://127.0.0.1:8443            # ui.rest bind_addr; tunnel or ssh to reach it
```

All endpoints return JSON. Errors are `{"error": "..."}` with 400 (bad
parameters: unknown `group_by`/field name, bad regex or time, `since` after
`until`), 404 (unknown log source, journal unit not allow-listed), 503 (log
file missing/unreadable, `journalctl` missing or failing, or a daemon that
does not implement the surface). Caps are never an error: `limit`/`top` above
`max_results` are clamped silently and a stopped scan is reported through
`truncated`. A bare 404 **without** an `error` body means the daemon predates
the Agent API.

Time parameters (`since`, `until`) accept RFC 3339 (`2026-10-09T05:00:00Z`),
`now`, **or** a relative age: `90s`, `15m`, `6h`, `7d` (meaning "now minus …").
Defaults: `since` = `1h` for logs/threats/journal, `24h` for the IP profile,
unbounded for bans; `until` = now. All timestamps in responses are UTC
(`…Z`), second precision in log results.

## 2. Configuration (`agent:` top-level section, optional)

```yaml
agent:
  log_sources:                 # extra files, in addition to the auto-discovered ones
    - name: nginx_error
      path: /var/log/nginx/error.log
      format: raw              # nginx | ssh | postfix | ufw | syslog | raw
  journal_units: [hiveguard]   # units readable through /api/agent/journal (default)
  max_scan_bytes: 268435456    # per query, read backwards from EOF (default 256 MiB)
  max_results: 5000            # hard cap on items per response (default)
  journal_timeout_secs: 20
  include_rotated: true        # also scan <path>.1 when the window predates the live file
```

Auto-discovered sources (no config needed):

| plugin entry | source name | format |
|---|---|---|
| `source.file.nginx` (`config.path`) | `name:` of the entry, else `nginx` | nginx combined |
| `source.file.ssh` | `name:`, else `ssh` | sshd syslog lines |
| `source.file.postfix` | `name:`, else `postfix` | postfix |
| `source.file.custom` | `name:`, else `custom` | raw |
| `source.firewall` (`config.path`) | `name:`, else `firewall` | ufw kernel log |
| `source.journald` (`config.units`) | `journal:<unit>` per unit (an entry without `units` adds nothing) | journal (via `journalctl`) |

Duplicate names get a `_2` suffix; a path configured twice is registered once.
Only these paths/units can ever be read. Arbitrary paths are rejected (404).
`logs/query` and `logs/stats` work on file sources only; `journal:*` sources
are served by `/api/agent/journal` (asking the other way round is a 400 that
says so).

## 3. Endpoints

### 3.1 `GET /api/agent/overview`

One-call situation report. Cheap (no log scanning).

```json
{
  "node": {"name": "node-a", "version": "0.1.0", "uptime_secs": 86400, "now": "2026-10-09T06:00:00Z"},
  "bans": {
    "total": 1463, "permanent": 12, "subnets": 31,
    "expiring_1h": 40, "created_1h": 22, "created_24h": 610,
    "by_source": {"detector": 1300, "peer": 150, "admin": 13},
    "by_detector": {"path_probe": 700, "ssh_bruteforce": 400, "http_flood": 31}
  },
  "threats": {
    "buffered": 500, "last_1h": 120, "last_24h": 500,
    "by_detector": {"path_probe": 300, "scanner_fingerprint": 200},
    "top_ips": [{"ip": "203.0.113.5", "count": 40, "max_severity": 90, "detectors": ["path_probe"]}]
  },
  "counters": {
    "events_processed": {"nginx": 1234567, "ssh": 4321, "firewall": 999},
    "detection_signals": {"detector.path_probe": 5000},
    "bans_created": {"path_probe": 700},
    "bans_expired": 300, "peer_count": 1,
    "memory_bytes": 85000000, "whitelisted": 9
  },
  "plugins": [{"id": "source.file.nginx", "kind": "Source", "health": "Running", "version": "0.1.0"}],
  "unhealthy_sources": [],
  "log_sources": ["nginx", "ssh", "firewall", "journal:hiveguard"]
}
```

`counters.*` come from the Prometheus registry (since daemon start).
`detection_signals` is keyed by plugin id, `bans_created` by core detector
name (pre-existing label mismatch).

### 3.2 `GET /api/agent/bans`

Query params: `source` (`detector|peer|admin`), `detector` (core name, e.g.
`ssh_bruteforce`), `since` (created_at ≥), `until`, `subnet_only` (`true` →
prefix < /32 or < /128), `permanent_only`, `q` (substring of subject or
reason), `sort` (`created_at|expires_at|severity|subject`, default
`created_at`), `order` (`desc` default | `asc`), `limit` (default 100, max
`max_results`), `offset`.

```json
{"total": 1463, "matched": 22, "limit": 100, "offset": 0,
 "by_source": {"detector": 20, "peer": 2}, "by_detector": {"path_probe": 18, "ssh_bruteforce": 2},
 "items": [{"subject": "203.0.113.5/32", "severity": 150, "reason": "…", "created_at": "…", "expires_at": "…|null", "source": "detector:path_probe"}]}
```

`source` is an exact match on the kind (`detector` matches `detector:*`);
`detector` takes the **core** name (`ssh_bruteforce`, as in `source`), not
the plugin id. `created_at` is also now present on the classic
`GET /api/bans` items (RFC 3339 with nanoseconds, like `expires_at`).

### 3.3 `GET /api/agent/threats`

Filters over the in-memory ring buffer of recent detection signals (500
newest). Params: `since`, `until`, `detector`, `ip` (exact IP or CIDR),
`min_severity`, `limit` (default 200), `offset`.

```json
{"buffered": 500, "matched": 120, "items": [ThreatInfo…],
 "by_detector": {"path_probe": 80, "ssh_bruteforce": 40},
 "top_ips": [{"ip": "…", "count": 12, "max_severity": 120, "detectors": ["path_probe"], "first_seen": "…", "last_seen": "…"}]}
```

### 3.4 `GET /api/agent/logs/sources`

```json
{"sources": [
  {"name": "nginx", "kind": "file", "format": "nginx", "path": "/var/log/nginx/access.log",
   "exists": true, "size_bytes": 123456789, "modified": "2026-10-09T05:59:58Z", "rotated_available": true},
  {"name": "journal:hiveguard", "kind": "journal", "units": ["hiveguard"]}
]}
```

### 3.5 `POST /api/agent/logs/query`

Return the **last N matching lines** (chronological order) of one source.

```json
{"source": "nginx", "since": "6h", "until": null,
 "grep": "wp-login|xmlrpc", "ip": "203.0.113.0/24",
 "fields": {"status": "4xx", "method": "POST", "path": "^/wp-", "user_agent": "python", "user": "root", "port": "22", "event_type": "AuthFailure"},
 "limit": 200, "parse": true}
```

- `grep`: Rust `regex` syntax (linear-time, 1 MiB compiled-size cap), matched
  against the raw line.
- `ip`: exact address or CIDR; matched against the parsed source IP (falls
  back to a textual search when the line could not be parsed).
- `fields`: parsed-field filters; a value that starts with `^`, contains `|`
  or ends with `$` is treated as a regex, else as exact match. `status`
  accepts `4xx`/`5xx` classes.
- `parse: false` returns raw lines only (`items[]` carry just `ts` and `raw`).
- `fields` names are validated per format (unknown name → 400); `status_code`
  is an alias of `status`; exact matches are case-insensitive. Per format:

  | format | `fields` keys | `event_type` |
  |---|---|---|
  | nginx | `method, path, protocol, status, bytes, user_agent` | `HttpRequest` / `Http4xx` / `Http5xx` |
  | ssh | `user, invalid_user ("true"/"false"), src_port` | `AuthFailure` / `AuthSuccess` |
  | postfix | `mechanism` | `SmtpAuthFailure` |
  | ufw | `action (BLOCK/ALLOW/AUDIT), in, out, dst, proto, spt, port (= DPT), flags` | `PortAccess` (has DPT) / `ConnectionEvent` |
  | syslog | `host, program, pid` | null |
  | raw | none | null |

  Unparseable lines have `fields: {}`, `event_type: null` and a best-effort
  `ip` (first address token in the line); the `ip` filter then tests every
  address token in the line against the CIDR.

```json
{"source": "nginx", "format": "nginx",
 "scanned_lines": 500000, "scanned_bytes": 90000000, "matched": 1234, "returned": 200, "truncated": true,
 "window": {"since": "…", "until": "…", "first_line_ts": "…", "last_line_ts": "…"},
 "items": [{"ts": "2026-10-09T05:12:01Z", "ip": "203.0.113.5", "event_type": "Http4xx",
            "fields": {"method": "POST", "path": "/wp-login.php", "status": "403", "user_agent": "…"},
            "raw": "203.0.113.5 - - [09/Oct/2026:05:12:01 +0000] …"}]}
```

`truncated: true` means either more than `limit` lines matched (only the
newest `limit` are returned) **or** the `max_scan_bytes` cap stopped the
backward scan before reaching `since` (`scan_capped: true`;
`window.first_line_ts` then tells you how far back the scan actually got).
`window.files` lists the files actually read (live file and, when needed,
`<path>.1`). `raw` is cut at 8 KiB. Timestamps without a zone (traditional
syslog, `YYYY-MM-DD HH:MM:SS`) are taken as UTC; traditional syslog gets the
current year unless that lands more than a day in the future.

### 3.6 `POST /api/agent/logs/stats`

Aggregate one source over a window.

```json
{"source": "nginx", "since": "24h", "until": null,
 "filter": {"ip": null, "grep": null, "fields": {"status": "4xx"}},
 "group_by": "ip", "top": 25, "buckets": "1h"}
```

`group_by` (default `ip`) ∈ `ip | ip24 | ip48 | path | status | method |
user_agent | user | port | proto | event_type | hour | minute | day`.
`ip24` = /24 for IPv4, /64 for IPv6; `ip48` = /16 for IPv4, /48 for IPv6.
`filter` keys may also be given at the top level. `top` defaults to 25
(500 for the time groupings, which are sorted by time and keep the newest).
`buckets` (optional, `1m` … `1d`, at most 10 000 buckets) adds a `series` of
matched counts per bucket including zero buckets; `since` defaults to `1h`.

```json
{"source": "nginx", "scanned_lines": 1200000, "matched": 56000, "distinct": 2400,
 "groups": [
   {"key": "203.0.113.5", "count": 4000, "pct": 7.1,
    "first_seen": "…", "last_seen": "…",
    "extras": {"status_4xx": 3900, "status_5xx": 0, "distinct_paths": 1200, "distinct_user_agents": 1,
               "sample_path": "/wp-login.php", "sample_user_agent": "python-requests/2.31", "banned": true, "whitelisted": false}}
 ],
 "series": [{"bucket": "2026-10-08T06:00:00Z", "count": 1200}],
 "truncated": false}
```

`extras` is populated for `ip|ip24|ip48` grouping (per-IP behaviour profile):
`distinct_<f>s` / `sample_<f>` where `<f>` depends on the format (nginx:
`path`, `user_agent`; ssh: `user`; ufw: `port`; postfix: `mechanism`; syslog:
`program`), `status_4xx`/`status_5xx` for nginx only, and `banned` /
`whitelisted` from the live ban store (a subnet key counts as banned when any
ban overlaps it). For `path` grouping it carries `distinct_ips`; otherwise it
is `{}`. Extra response keys: `format`, `group_by`, `no_key` (matched lines
without a group key), `window`, `distinct_capped` (10 000 distinct values per
group tracked), `other` + `groups_capped` (more than 100 000 groups).

### 3.7 `POST /api/agent/ip`

Everything the daemon knows about one address, across all sources. `ip` must
be a single address (a CIDR is a 400); `since` defaults to `24h`. Every file
source is scanned with its own `max_scan_bytes` budget; the `logs` keys
depend on the format (nginx: `status`, `top_paths` (10), `user_agents` (5),
`event_types`; ssh: `users` (10), `event_types`; ufw: `ports` (20),
`event_types`; others: counts only). A source with no hits is `{"count": 0}`,
an unreadable one `{"count": 0, "error": "…"}`; `threats.last` is the newest
buffered signal for that IP. `geo` is reserved (always null for now).

```json
{"ip": "203.0.113.5", "since": "24h"}
```

```json
{"ip": "203.0.113.5",
 "ban": {"banned": true, "record": BanInfo} , "whitelisted": false,
 "threats": {"count": 12, "by_detector": {...}, "last": ThreatInfo},
 "logs": {"nginx": {"count": 4000, "first_seen": "…", "last_seen": "…",
                    "status": {"200": 100, "403": 3900}, "top_paths": [["/wp-login.php", 3800]], "user_agents": ["…"]},
          "ssh": {"count": 0}, "firewall": {"count": 30, "ports": [["22", 10], ["23", 20]]}},
 "geo": null}
```

### 3.8 `GET /api/agent/journal`

`journalctl -u <unit> -o json` wrapper. Params: `unit` (default `hiveguard`,
`journal:` prefix accepted; must be in `agent.journal_units` or a
`source.journald` unit, else 404), `since` (default `1h`), `until`,
`priority` (`0..7` as string or number, or `emerg|alert|crit|err|error|warning|warn|notice|info|debug`
= max priority shown), `grep` (regex on MESSAGE, applied after fetching up to
20 000 lines), `limit` (default 200, newest `limit` returned).

```json
{"unit": "hiveguard", "matched": 12, "returned": 12, "truncated": false,
 "items": [{"ts": "…", "priority": 4, "message": "…", "pid": "1234"}]}
```

`priority`/`pid` are null when the journal entry lacks them. 503 if
`journalctl` is unavailable, exits non-zero, times out, or the daemon user
cannot read the journal.

### 3.9 `GET /api/agent/detectors`

Loaded detector plugins with their effective configuration and counters.

```json
{"detectors": [
  {"id": "detector.ssh_bruteforce", "name": "ssh-main", "description": "…", "version": "0.1.0",
   "config": {"threshold": 10, "window_secs": 300},
   "schema": {"threshold": {"type": "integer", "default": 5, "description": "…"}},
   "signals_total": 5000, "bans_total": 400}
], "scoring": {"id": "scoring.default", "config": {"ban_severity_threshold": 100}}}
```

`config` is exactly what the `plugins:` entry says (defaults are visible in
`schema.*.default`); `detector_name` is the core name used by `bans[].source`
and `bans_created`; `linked: false` flags an entry the binary cannot load.
`bans_total` counts ban *events* (a re-ban of the same subject counts
again), so it can exceed the number of distinct banned subjects.

### 3.10 `GET /api/agent/catalog?kind=detector`

Every plugin **linked into this binary**, enabled or not — the basis for
"which module would help against this attack" recommendations.

```json
{"plugins": [
  {"id": "detector.http_flood", "kind": "Detector", "version": "0.1.0", "description": "…", "docs_url": "…",
   "enabled": false, "instances": 0,
   "config_keys": [{"name": "window_secs", "type": "integer", "default": 60, "description": "…"}]}
]}
```

`kind` filter accepts the `PluginInfo.kind` strings (`Source`, `Detector`,
`Enforcer`, `Notifier`, `SiemSink`, `Cti`, `ScoringEngine`, `UiServer`),
case-insensitive.

### 3.11 `POST /api/agent/config/validate`

Dry-run of `PUT /api/config`: YAML parse → `HiveGuardConfig::validate()` →
plugin resolution (ids linked, schemas satisfied, secrets resolvable). Never
writes.

```json
{"content": "node:\n  name: …"}
```

```json
{"valid": false, "errors": ["plugin `detector.port_scan`: config: additional property `foo` is not allowed"],
 "warnings": ["unknown top-level key `detectorss` is ignored by the daemon"],
 "plugins": ["source.file.nginx", "detector.ssh_bruteforce", "…"]}
```

Returns 200 regardless of validity. Workflow for hardening: `GET /api/config`
→ edit text (keep comments/indentation) → `validate` → operator applies via
`PUT /api/config` (when `/etc` is writable) or by hand + restart.

### 3.12 `GET /api/agent/stream` (Server-Sent Events)

Incremental events — unlike `/api/stream` (WebSocket) which re-sends full
snapshots. Auth via the Bearer header (or `?token=` for browsers). Param
`types` = comma list of `signal,ban_added,ban_removed` (default all).

```
event: signal
data: {"ip":"203.0.113.5","severity":90,"confidence":80,"detector":"path_probe","reason":"…","timestamp":"…"}

event: ban_added
data: {"subject":"203.0.113.5/32","severity":150,"reason":"…","created_at":"…","expires_at":"…","source":"detector:path_probe"}

event: ban_removed
data: {"subject":"203.0.113.5/32"}

: keep-alive every 15 s
```

Signals are delivered per detection (not only when a ban results), so this is
the fastest way to watch an attack develop. `ban_added`/`ban_removed` come
from diffing the ban snapshot after every change and every 30 s (expiries),
so a removal can lag up to 30 s. No `id:`/`retry:` fields are sent and the
server never closes the stream on its own (only on shutdown); a slow consumer
gets an `event: lagged` with `{"skipped": n}`. `types` is a single
comma-separated parameter.

## 4. Limits and safety

- Only loopback by default; no new network exposure. Same token as the panel.
- Log reads are bounded (`max_scan_bytes`, `max_results`) and run on the
  blocking thread pool, never on the pipeline task. A query cannot stall
  detection.
- Paths are an allow-list derived from the config. Symlinks are followed only
  if the configured path itself is the symlink.
- Regexes use the `regex` crate (no backtracking) with a compiled-size cap.
- `journalctl` runs with a timeout and `--no-pager -o json`.
- The daemon user needs read access to the files (prod units carry
  `CAP_DAC_READ_SEARCH`) and membership in `systemd-journal` for the journal.
- Agents should not read the panel token out of `config.yaml`. Give them a
  copy in a dedicated file readable by the agent's Unix user, e.g.
  `sudo install -m 0640 -o root -g <agent-group> /dev/stdin /etc/hiveguard/agent-token <<< "<token>"`
  (the MCP server reads `HG_TOKEN_FILE`, default `/etc/hiveguard/agent-token`).
- Rolling deploys: the `agent:` section is a top-level key, so an older
  binary ignores it silently; the new binary accepts configs without it.
