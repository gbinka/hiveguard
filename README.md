# HiveGuard

**Distributed intrusion detection and automatic IP banning for Linux servers.**

HiveGuard ingests logs from many sources, scores hostile behaviour across a
suite of detectors, and bans offending IPs through nftables or ipset. Multiple
nodes form a cluster that shares ban records over a QUIC gossip protocol as
conflict-free replicated data (CRDTs), so a single attack seen by one server
protects the whole fleet — consistently and without a central coordinator.

It occupies the same niche as fail2ban, but is built for fleets rather than
single hosts: cross-source scoring instead of per-jail regex counting, a
plugin architecture instead of a fixed feature set, and cluster-wide ban
propagation instead of isolated per-host state.

---

## Why HiveGuard

- **Fleet-wide defense, no central server.** Nodes gossip ban records as CRDTs
  over QUIC/TLS 1.3 with SWIM failure detection and Merkle-tree delta sync. An
  IP banned on one node converges to every peer, and the cluster keeps working
  through network partitions.
- **Scoring, not thresholds-per-jail.** Signals from every source and detector
  accumulate into a per-IP severity score over a sliding window. A slow attack
  spread across SSH, HTTP, and SMTP still trips a ban that no single per-service
  counter would catch.
- **Everything is a plugin.** Sources, detectors, enforcers, threat-intel
  feeds, notifiers, SIEM sinks, and UIs are all plugins behind a stable
  contract. Enable only what you need; add your own without forking the core.
- **Poisoning-resistant clustering.** Per-node trust scoring, corroboration
  thresholds, rate limiting, and quarantine of anomalous reporters guard
  against a malicious or compromised peer injecting bad bans.
- **Operable and observable.** Prometheus `/metrics`, a REST + WebSocket API
  (OpenAPI 3.1), a Unix-socket CLI, and hardened systemd integration
  (sd-notify readiness, watchdog heartbeat).
- **Crash-safe.** Write-ahead log plus periodic CRDT-aware snapshots; bans
  survive restarts and unclean shutdowns.

---

## How it works

```
┌───────────────────────────────────────────────────────────┐
│                      hiveguard-daemon                       │
│                                                             │
│   sources ──▶  pipeline (detect + score)  ──▶  enforcement  │
│  (plugins)         │                            (plugins)   │
│                    ▼                                        │
│               ban store  ◀──▶  persistence (WAL + snapshot) │
│                (CRDT)                                        │
│                    ▲                                        │
│                    ▼                                        │
│             gossip / SWIM  ◀───────────▶  cluster peers     │
│              (QUIC / TLS 1.3)                               │
└───────────────────────────────────────────────────────────┘
```

Log lines enter through **source** plugins, are normalised into events, and
flow through the **pipeline**, where **detector** plugins emit weighted signals.
The **scoring** engine accumulates signals per IP; when a subject crosses the
ban threshold it is written to the **ban store** (a CRDT) and pushed to
**enforcer** plugins. The ban store is persisted (WAL + snapshots) and
replicated to peers over gossip.

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full design.

---

## Plugin catalog

All capabilities are plugins loaded from the daemon config. Highlights:

| Category   | Plugins |
|------------|---------|
| Sources    | file, firewall, syslog, journald, kafka, nats, rabbitmq, kinesis, cloudwatch |
| Detectors  | ssh-bruteforce, path-probe, http-4xx-flood, http-login-bruteforce, scanner-fingerprint, smtp-bruteforce, port-scan, distributed-slow, honeypot, entropy, timing, sigma |
| Enforcers  | nftables, ipset, cloudflare, observe (dry-run) |
| Threat intel | abuseipdb, spamhaus, tor, otx, geoip |
| Notifiers  | slack, teams, discord, telegram, pagerduty, email, webhook |
| SIEM sinks | syslog, elastic, splunk, datadog |
| Scoring    | scoring-default |
| UI         | ui-rest (REST + WebSocket API), ui-tui (terminal), ui-web (WASM SPA, in progress) |

---

## Quick start

### Build

```bash
cargo build --release -p hiveguard-daemon
```

The pinned toolchain is in [`rust-toolchain.toml`](rust-toolchain.toml)
(Rust 1.91.1). `rustup` will select it automatically.

### Install

```bash
sudo mkdir -p /etc/hiveguard
sudo cp config.example.yaml /etc/hiveguard/config.yaml
sudo nano /etc/hiveguard/config.yaml

# install.sh creates the service user, directories, and systemd unit
sudo ./scripts/install.sh ./target/release/hiveguard-daemon
sudo systemctl start hiveguard
```

### Docker

```bash
docker build -t hiveguard .
docker run -d \
  --cap-add NET_ADMIN \
  --cap-add DAC_READ_SEARCH \
  -v /etc/hiveguard:/etc/hiveguard \
  -v /var/lib/hiveguard:/var/lib/hiveguard \
  -v /var/log:/var/log:ro \
  hiveguard
```

---

## Configuration

Configuration is a single YAML file. See
[`config.example.yaml`](config.example.yaml) for every option with defaults and
inline documentation. A minimal shape:

```yaml
node:
  name: "web-prod-01"
  listen_gossip: "0.0.0.0:7946"      # QUIC/UDP cluster port
  data_dir: "/var/lib/hiveguard"
  cluster_mode: strict               # strict | auto-accept
  seeds:
    - address: "10.0.1.1:7946"
      fingerprint: "REPLACE_WITH_NODE_FINGERPRINT_HEX_64_CHARS"

whitelist:
  - "127.0.0.0/8"
  - "10.0.0.0/8"

sources:
  ssh:
    use_journald: true
  nginx:
    access_log: "/var/log/nginx/access.log"

detectors:
  ssh_bruteforce:
    enabled: true
    threshold: 5
    window: "5m"
    ban_duration: "24h"

scoring:
  accumulation_window: "30m"
  ban_severity_threshold: 100
  default_ban_duration: "24h"

enforcement:
  backend: "nftables"                # nftables | ipset | observe_only

# The REST API and web panel are served by the ui.rest plugin.
plugins:
  - id: ui.rest
    config:
      bind_addr: "127.0.0.1:8443"
      auth_token: "CHANGE_ME"
```

| Section       | Purpose |
|---------------|---------|
| `node`        | Identity, gossip address, data directory, seed peers, cluster mode |
| `whitelist`   | IP/CIDR ranges that are never banned |
| `sources`     | Built-in log sources (SSH, Nginx, Postfix, custom regex) |
| `detectors`   | Per-detector enable/disable, thresholds, windows, ban durations |
| `scoring`     | Severity accumulation window and ban threshold |
| `enforcement` | Backend: nftables, ipset, or observe-only |
| `trust`       | Cluster trust scoring and corroboration thresholds |
| `persistence` | Snapshot interval and WAL sync mode |
| `agent`       | Agent API: extra log files and journal units it may read, scan limits |
| `plugins`     | Loaded plugins and their config (sources, detectors, enforcers, UI, etc.) |

---

## CLI

HiveGuard exposes a Unix-socket CLI for management:

```bash
hiveguard -c /etc/hiveguard/config.yaml status
hiveguard -c /etc/hiveguard/config.yaml ban 192.0.2.10 -t 24h -r "manual"
hiveguard -c /etc/hiveguard/config.yaml unban 192.0.2.10
hiveguard -c /etc/hiveguard/config.yaml list-bans --limit 50
hiveguard -c /etc/hiveguard/config.yaml top --threats 10
hiveguard -c /etc/hiveguard/config.yaml export --format json
hiveguard -c /etc/hiveguard/config.yaml whitelist add 10.0.0.0/8
```

---

## REST API and web panel

With the `ui.rest` plugin loaded, HiveGuard serves an HTTP + WebSocket API under
`/api/...` on its configured `bind_addr` (default `127.0.0.1:8443`).

- **Contract:** [`plugins/ui-rest/openapi.yaml`](plugins/ui-rest/openapi.yaml)
  (OpenAPI 3.1) is the source of truth for the operator endpoints and payloads;
  the agent endpoints under `/api/agent/*` are specified in
  [`docs/AGENT_API.md`](docs/AGENT_API.md).
- **Auth:** Bearer token (`Authorization: Bearer <auth_token>`). Public
  endpoints: `GET /api/health`, `GET /api/stream` (WebSocket), `GET /metrics`.
- **Live updates:** WebSocket at `/api/stream`.

```bash
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8443/api/stats
curl http://127.0.0.1:8443/metrics
```

A standalone React web panel is maintained in [`web-panel/`](web-panel/), outside
the Rust workspace. It is a pure API client; serve its build output
through the `ui.rest` `static_dir` option or host it separately and whitelist
its origin via `cors_origins`.

### Agent API and MCP server

`ui.rest` also serves a read-mostly analysis surface for AI agents and analysts
under `/api/agent/*` (same bearer token): a one-call `overview`, filtered bans
and detection signals, query and statistics over the logs the daemon already
tails (plus allow-listed extra files and journal units from the top-level
`agent:` section), per-IP profiles, the plugin catalogue, a config dry-run
validator and a Server-Sent Events stream (`/api/agent/stream`). See
[`docs/AGENT_API.md`](docs/AGENT_API.md).

[`tools/mcp/`](tools/mcp/) contains a stdio MCP server (Python ≥ 3.10, stdlib
only) that exposes every agent endpoint as an `hg_*` tool, either against a local
API or over SSH. Write tools are disabled unless `HG_MCP_ALLOW_WRITE=1`.

```bash
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8443/api/agent/overview
```

### Selected Prometheus metrics

| Metric | Type | Description |
|--------|------|-------------|
| `hiveguard_active_bans` | Gauge | Current active bans |
| `hiveguard_peer_count` | Gauge | Cluster peers |
| `hiveguard_events_processed_total` | Counter | Events processed, by source |
| `hiveguard_bans_created_total` | Counter | Bans created, by detector |
| `hiveguard_detection_signals_total` | Counter | Detection signals, by detector |
| `hiveguard_event_processing_duration_seconds` | Histogram | Event processing latency |
| `hiveguard_enforcement_duration_seconds` | Histogram | Enforcement latency |

---

## Clustering

Nodes are identified by a blake3 fingerprint of their Ed25519 public key,
generated on first start and stored under `<data_dir>/identity/`. In `strict`
mode, seed peers are pinned by fingerprint; in `auto-accept` mode, any peer at a
seed address is trusted (development only).

Gossip runs over QUIC (UDP, default port `7946`) — open it between peers in your
firewall, and only between peers. For a small cluster of your own servers, list
each peer's fingerprint under `founder_nodes` and set `trust.ban_threshold: 1.0`
so a single trusted peer's ban is enforced without additional corroboration.

---

## Workspace layout

Core crates:

| Crate | Description |
|-------|-------------|
| `hiveguard-core` | Models, detectors, scoring, ban store, persistence, CRDT, HLC, trust, anti-poisoning |
| `hiveguard-ingest` | Built-in log source parsers with file tailing |
| `hiveguard-net` | QUIC transport, SWIM membership, gossip engine, Merkle digest sync |
| `hiveguard-enforce` | Enforcement backend primitives |
| `hiveguard-plugin-api` | Stable plugin contract: traits, manifest, registry, context |
| `hiveguard-host` | Plugin runtime: discovery, validation, instantiation, supervision |
| `hiveguard-config` | Core configuration model |
| `hiveguard-daemon` | Main binary: pipeline, CLI, systemd integration |
| `hiveguard-ui` | Render-agnostic UI library shared by ui-tui and ui-web |

Plugins live under [`plugins/`](plugins/); each is an independent crate with its
own `schema.json` and `README.md`. Outside the Rust workspace:
[`web-panel/`](web-panel/) (React panel), [`tools/mcp/`](tools/mcp/) (MCP server
for the Agent API) and [`scripts/upgrade/`](scripts/upgrade/) (guarded upgrade
packages).

---

## Building and testing

```bash
cargo build --release -p hiveguard-daemon
cargo test --workspace
cargo clippy --workspace

# Python helpers (stdlib unittest)
(cd scripts/upgrade && python3 -m unittest discover)
(cd tools/mcp && python3 -m unittest discover tests)
```

---

## Security

- Keep the `ui.rest` `bind_addr` on localhost (or behind a reverse proxy /
  firewall) and set a strong `auth_token`.
- Restrict the gossip port (`7946/udp`) to cluster peers only.
- `/metrics` is unauthenticated by design — do not expose it publicly; scrape it
  over localhost or a private network.
- Never commit real config: `config.yaml`, node identity keys, and tokens are
  git-ignored. Only `config.example.yaml` (with placeholders) is tracked.

### Audit fixes (2026-10-04)

The unverified User-Agent bot policy `allow` now behaves as `monitor`. The
`detector.distributed_slow` plugin remains loadable but emits no ban signals:
ordinary traffic from one subnet is not sufficient evidence for a subnet ban.
Previously stored subnet bans remain and need an operator's review.

All new bans, including manual bans and imports, respect overlapping whitelist
entries. nftables updates are atomic, retain covered host bans, and are retried
by full reconciliation every 60 seconds. Administrative errors distinguish a
saved intent awaiting firewall retry from a successful application.

Remote bans default to minimum prefixes `/24` (IPv4), `/48` (IPv6), and a maximum
lifetime of 86400 seconds; permanent remote bans are rejected. Configure these
under `trust.remote_min_prefix_v4`, `trust.remote_min_prefix_v6`, and
`trust.remote_max_ttl_secs`. Quorum counts independent originators, requiring
direct connections to enough reporting nodes; relays do not add votes.
Administrative unban persists a **local** cutoff against older remote records.
Cluster-wide signed revocations and durable forwarding of original signatures
remain future protocol work; apply cluster-wide unbans on every relevant node.

New snapshots use format V4 and read V1–V3. Back up the data directory before
upgrading; older binaries cannot read V4 or the new revocation WAL entry.
For syslog, remote collectors without mTLS now require an explicit
`trusted_senders` allowlist (see the source-syslog plugin README). Source health
shows task status; it does not certify end-to-end log delivery. SSH parsing
still does not deduplicate `Invalid user` and `Failed password` from one attempt.

The legacy Rules editor is disabled because it did not change active plugin
configuration. Configuration writes validate core settings and plugin schemas,
replace the file atomically, and take effect after restart. QUIC/TLS dependencies
were updated; older AWS/NATS/CTI dependency branches still need separate upgrades.

---

## Disclaimer

HiveGuard is provided on a **best-effort basis, "AS IS", without warranty of any
kind**, express or implied, including but not limited to the warranties of
merchantability, fitness for a particular purpose, and non-infringement. It is a
security tool that interacts with firewalls, log data, and network services; it
may contain bugs and can never guarantee complete protection.

To the maximum extent permitted by applicable law, the authors and contributors
**accept no liability** for any claim, damages, or other loss — including, without
limitation, security breaches, service disruption, data loss, or damages arising
from vulnerabilities, misconfiguration, or failure of the software — whether in an
action of contract, tort, or otherwise, arising from or in connection with the
software or its use. You are solely responsible for evaluating its suitability and
for operating it safely in your environment. See the [MIT](LICENSE-MIT) and
[Apache-2.0](LICENSE-APACHE) license texts for the full warranty disclaimer and
limitation of liability.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  http://www.apache.org/licenses/LICENSE-2.0)
- MIT License ([LICENSE-MIT](LICENSE-MIT) or
  http://opensource.org/licenses/MIT)

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this project by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.

---

## Contributing

Issues and pull requests are welcome. Please run `cargo fmt`, `cargo clippy`,
and `cargo test --workspace` before submitting.
