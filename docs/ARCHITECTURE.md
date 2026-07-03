# HiveGuard Architecture

## Overview

HiveGuard is a distributed intrusion detection and auto-ban system structured as a Rust workspace with five crates. Events flow through a pipeline: **Ingest → Detect → Score → Enforce**, with cluster-wide consistency via CRDT-based gossip.

## System Diagram

```
                        Log Files
                  (/var/log/auth.log, nginx, mail, custom)
                           │
                           ▼
              ┌────────────────────────┐
              │     hiveguard-ingest   │
              │  ┌────────┐ ┌───────┐ │
              │  │  SSH   │ │ Nginx │ │
              │  │ Parser │ │Parser │ │
              │  └───┬────┘ └──┬────┘ │
              │  ┌───┴────┐ ┌──┴────┐ │
              │  │Postfix │ │Custom │ │
              │  │ Parser │ │ Regex │ │
              │  └───┬────┘ └──┬────┘ │
              └──────┼─────────┼──────┘
                     │         │
                     ▼         ▼
              NormalizedEvent (mpsc channel, 4096 buffer)
                           │
                           ▼
              ┌────────────────────────┐
              │    Pipeline (daemon)   │
              │                        │
              │  1. Whitelist check    │
              │  2. Detector pass (×10)│
              │  3. Scoring engine     │
              │  4. Ban decision       │
              │  5. Enforcement        │
              │  6. Metrics update     │
              └─────────┬─────────────┘
                        │
              ┌─────────▼─────────────┐
              │   hiveguard-enforce    │
              │  ┌─────────┐ ┌──────┐ │
              │  │ nftables │ │ipset │ │
              │  │  backend │ │  bk  │ │
              │  └─────────┘ └──────┘ │
              └────────────────────────┘
                        │
                        ▼
                Linux Kernel (nftables/ipset rules)
```

## Module Descriptions

### hiveguard-core

The core library containing all domain logic.

| Module | Responsibility |
|--------|---------------|
| `models` | `NormalizedEvent`, `EventType`, `BanRecord`, `BanSource`, `DetectionSignal`, `Action` |
| `config` | YAML config parsing — `HiveGuardConfig` with all sub-configs |
| `ban_store` | `InMemoryBanStore` — thread-safe ban storage with add/remove/query/expiry |
| `whitelist` | `WhitelistManager` — IP/CIDR whitelist with subnet containment checks |
| `detector` | `Detector` trait — `analyze(event) → Option<DetectionSignal>`, `name() → &str` |
| `detectors/` | 10 detector implementations + `create_detectors()` factory |
| `scoring` | `ScoringEngine` — per-IP severity accumulation over time windows |
| `persistence/` | WAL (append-only log), snapshots (v1/v2 binary), `StateManager` |
| `crdt` | `CrdtBanRecord` — convergent replicated ban record with merge semantics |
| `hlc` | `HlcTimestamp` — Hybrid Logical Clock for causal ordering |
| `trust` | `TrustManager` — per-node trust scoring with seniority bonus |
| `anti_poison` | `RateLimiter`, `check_quarantine()` — anti-poisoning mechanisms |
| `api` | `ApiRequest`/`ApiResponse` enums for Unix socket protocol |
| `errors` | `HiveGuardError` unified error type |

### hiveguard-ingest

Log file parsers that tail files and emit `NormalizedEvent` values.

| Source | What it parses |
|--------|---------------|
| `SshLogSource` | `/var/log/auth.log` — failed passwords, invalid users, disconnects |
| `NginxLogSource` | Nginx access logs — combined format, extracts IP + path + status |
| `PostfixLogSource` | `/var/log/mail.log` — SASL auth failures, unknown users |
| `CustomLogSource` | Any log file via user-provided regex with named captures |

Each source implements `LogSource` trait: `start(tx)`, `stop()`, `name()`. Uses `notify`-based file watching with seek tracking (persisted in data dir).

### hiveguard-net

Networking layer for cluster communication.

| Module | Responsibility |
|--------|---------------|
| `identity` | Ed25519 keypair + self-signed cert generation, blake3 fingerprints |
| `transport` | QUIC/TLS 1.3 via `quinn` — `QuicTransport` with connect/accept |
| `peer` | `PeerManager` + `PeerInfo` — track cluster members and their state |
| `messages` | `ClusterMessage` enum — Ping, Pong, PingReq, BanSync, DigestExchange, etc. |
| `membership` | SWIM failure detection — probe cycles, pending pings, suspect/dead timeouts |
| `gossip` | Gossip engine — ban propagation, digest exchange, diff-based delta sync |
| `sync` | `SyncCoordinator` — orchestrates SWIM + gossip + trust filtering |
| `merkle` | `MerkleDigest` — order-independent hash tree for efficient diff detection |

### hiveguard-enforce

Firewall enforcement backends.

| Backend | How it works |
|---------|-------------|
| `NftablesEnforcer` | Manages an nftables set (`hiveguard_blocklist` in table `hiveguard`). Uses `nft` CLI commands. |
| `IpsetEnforcer` | Manages an ipset hash:net set. Uses `ipset` CLI commands. |
| `ObserveOnlyEnforcer` | Logs ban/unban actions without modifying firewall rules. |

All implement `Enforcer` trait: `apply_ban()`, `remove_ban()`, `sync_full()`, `list_active()`.

### hiveguard-daemon

Main binary and daemon runtime.

| Module | Responsibility |
|--------|---------------|
| `main` | CLI parsing (clap), daemon startup/shutdown sequence (10 steps) |
| `pipeline` | Main event loop — dequeue events, run detectors, score, ban, enforce |
| `socket_server` | Unix socket server for CLI ↔ daemon communication |
| `rest_api` | axum-based HTTP API — 6 endpoints + Prometheus metrics |
| `metrics` | Prometheus metrics — gauges, counters, histograms |
| `cli` | CLI client — sends `ApiRequest` to socket, prints `ApiResponse` |

## Pipeline Flow

```
Event arrives via mpsc channel
         │
         ▼
    ┌─────────────┐    yes
    │ Whitelisted? ├────────→ Skip (no detection)
    └──────┬──────┘
           │ no
           ▼
    ┌─────────────┐
    │  Detectors  │  Run all 10 detectors on the event
    │  (parallel) │  Each returns Option<DetectionSignal>
    └──────┬──────┘
           │ signals
           ▼
    ┌─────────────┐
    │  Scoring    │  Accumulate severity per IP
    │  Engine     │  over configurable time window
    └──────┬──────┘
           │ if threshold exceeded
           ▼
    ┌─────────────┐
    │  BanStore   │  Create BanRecord (subject, reason,
    │  + WAL      │  ban_until, source). WAL-first write.
    └──────┬──────┘
           │
           ▼
    ┌─────────────┐
    │  Enforcer   │  Apply ban to nftables/ipset
    └──────┬──────┘
           │
           ▼
    ┌─────────────┐
    │  Metrics    │  Update Prometheus counters/gauges
    └─────────────┘
```

## Detectors

| # | Detector | Signal Severity | Trigger |
|---|----------|----------------|---------|
| 1 | SSH Brute-force | 60 | N failed logins from same IP in window |
| 2 | SSH User Enum | 70 | N invalid user attempts in window |
| 3 | Path Probe | 80 | Request to known probe paths (/wp-login.php, /.env, etc.) |
| 4 | HTTP 4xx Flood | 50 | N 4xx responses in window |
| 5 | Scanner Fingerprint | 90 | Known scanner User-Agent patterns |
| 6 | SMTP Brute-force | 60 | N SASL auth failures in window |
| 7 | Port Scan | 70 | N distinct ports accessed in window |
| 8 | Distributed Slow | 60 | N IPs from same /24 in window |
| 9 | Honeypot | ≥250 | Any access to honeypot paths → immediate ban |
| 10 | Entropy Analysis | 50–80 | Abnormal URL entropy (shellcode, encoded payloads) |

## CRDT Merge Semantics

Ban records use a state-based CRDT (Convergent Replicated Data Type) for cluster-wide consistency without coordination:

```
merge(A, B) = CrdtBanRecord {
    subject:       A.subject,       // must be equal
    first_seen:    min(A, B),       // earliest observation wins
    ban_until:     max(A, B),       // longest ban wins
    severity:      max(A, B),       // highest severity wins
    reporters:     union(A, B),     // all reporters preserved
    evidence_hash: A (by HLC),     // latest modification's evidence
    reason:        A (by HLC),     // latest modification's reason
    tombstone:     A || B,          // any tombstone propagates
    last_modified: max(A, B),      // latest HLC timestamp
}
```

**Properties proven in tests:** commutativity, associativity, idempotency.

**Tombstones:** Deleted bans are marked with `tombstone = true` rather than removed, ensuring deletes propagate across the cluster.

## Hybrid Logical Clock (HLC)

Each node maintains an HLC for causal ordering of events:

- **Tick:** `max(wall_clock, prev_time) + 1` for local events
- **Update:** `max(wall_clock, prev_time, received_time) + 1` for received messages
- **Ordering:** `(wall_time_ms, counter, node_id_hash)` — total order across all nodes
- **Skew detection:** Rejects timestamps more than 5 minutes ahead of local wall clock

## Trust Model

Each cluster node maintains trust scores for all peers:

```
score = base + seniority_bonus

base = true_positives / (true_positives + false_positives + 1)    ∈ [0, 1]

seniority_bonus:
  < 24h:  0.0
  < 7d:   0.1
  ≥ 7d:   0.2
```

**Enforcement decision:** A ban is enforced if `sum(trust_scores of reporters) ≥ ban_threshold` (default: 2.0).

**Grace period:** New nodes (< 24h) face doubled enforcement threshold — requires more corroboration.

**Anti-poisoning defenses:**
1. **Rate limiting** — max 100 ban records per node per minute (sliding window)
2. **Quarantine** — if a node's ban count exceeds 10× the median of all nodes, all its records are rejected
3. **Trust filtering** — records from untrusted reporters (sum < threshold) are dropped

## Persistence Model

```
┌─────────────────────────────────────────┐
│               StateManager              │
│                                         │
│  ┌──────────┐  ┌──────────┐  ┌───────┐ │
│  │ BanStore │  │Whitelist │  │ CRDT  │ │
│  │(in-mem)  │  │ Manager  │  │ Store │ │
│  └────┬─────┘  └────┬─────┘  └───┬───┘ │
│       │              │            │     │
│       ▼              ▼            ▼     │
│  ┌──────────────────────────────────┐   │
│  │       WAL (Write-Ahead Log)      │   │
│  │  Append-only, fsync per entry    │   │
│  │  Entry types: AddBan, RemoveBan, │   │
│  │  AddWhitelist, RemoveWhitelist,  │   │
│  │  AddCrdtBan, TombstoneCrdtBan   │   │
│  └──────────────────────────────────┘   │
│                    │                    │
│                    ▼                    │
│  ┌──────────────────────────────────┐   │
│  │     Snapshot (periodic, v2)      │   │
│  │  Magic: HVGD0002                │   │
│  │  Contains: bans + whitelist +   │   │
│  │            CRDT ban records     │   │
│  │  Atomic write (tmp + rename)    │   │
│  └──────────────────────────────────┘   │
└─────────────────────────────────────────┘
```

**Recovery sequence:**
1. Load latest snapshot (v1 or v2 format, backward compatible)
2. Replay WAL entries written after snapshot
3. CRDT records are merged during replay (idempotent)
4. WAL is truncated after successful snapshot

**WAL sync modes:** `fdatasync` (default, durable), `sync` (full sync), `none` (buffered, fastest)

## Cluster Communication

```
Node A                          Node B
  │                                │
  │──── Ping ─────────────────────▶│
  │◀─── Pong ─────────────────────│
  │                                │
  │──── DigestExchange ──────────▶│  (Merkle root hash)
  │◀─── DiffRequest ──────────────│  (differing bucket IDs)
  │──── DiffResponse ────────────▶│  (CRDT records for those buckets)
  │                                │
  │──── BanSync ─────────────────▶│  (new ban records, trust-filtered)
  │                                │
  │──── PingReq(target=C) ───────▶│  (indirect probe via B)
  │◀─── Pong(from C via B) ───────│
```

**SWIM protocol:** Probe cycle every 1s → direct Ping → timeout 500ms → PingReq via K=3 random peers → Suspect after 5s → Dead after 30s → Remove.

**Merkle delta sync:** Nodes exchange root hashes. If different, exchange per-bucket (256 buckets, keyed by first byte of blake3 hash of subject). Only differing buckets' records are transferred.

## Systemd Integration

- **Type=notify:** Daemon sends `READY=1` after full initialization (step 8)
- **WatchdogSec=30:** Daemon sends watchdog heartbeat every 15s
- **Graceful shutdown:** `SIGTERM` → stop ingest → wait for tasks → final snapshot → WAL flush → `STOPPING=1`
- **Security hardening:** PrivateTmp, ProtectKernel*, RestrictNamespaces, MemoryDenyWriteExecute, etc.
