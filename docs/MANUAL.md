# HiveGuard Operations Manual

## Table of Contents

1. [Production Readiness Assessment](#1-production-readiness-assessment)
2. [Prerequisites](#2-prerequisites)
3. [Building from Source](#3-building-from-source)
4. [Installation](#4-installation)
5. [Configuration Reference](#5-configuration-reference)
6. [Deployment Scenarios](#6-deployment-scenarios)
7. [CLI Usage](#7-cli-usage)
8. [REST API](#8-rest-api)
9. [Monitoring & Observability](#9-monitoring--observability)
10. [Cluster Mode](#10-cluster-mode)
11. [Security Hardening](#11-security-hardening)
12. [Backup & Recovery](#12-backup--recovery)
13. [Troubleshooting](#13-troubleshooting)
14. [Upgrading](#14-upgrading)
15. [Known Limitations](#15-known-limitations)

---

## 1. Production Readiness Assessment

### Current Status: **Late Beta / Early Production-Ready (with caveats)**

HiveGuard is a well-engineered Rust system that has gone through 22 implementation phases. Below is a frank assessment of what works and what to watch out for.

#### Strengths (production-ready aspects)

| Area | Details |
|------|---------|
| **Test coverage** | 759 tests pass (0 failures, 2 ignored — require root for nftables). Unit, integration, and end-to-end tests across all crates. |
| **Code quality** | Zero clippy warnings. Strongly typed with `IpNet`, `chrono::DateTime`, `thiserror` errors. No `unwrap()` in production paths. |
| **Fuzzing** | SSH parser, Nginx parser, and ban store fuzz-tested with libFuzzer — 0 crashes found across 347+ corpus entries. |
| **Performance** | Benchmarked: parsers at ~1.85M lines/s (18x target), ban lookup <25ns at 500k entries (40x under 1µs target). |
| **Crash recovery** | WAL + periodic snapshots with CRC32 integrity checks. Survives partial WAL corruption (reads valid prefix). Atomic snapshot writes (temp + rename). |
| **Security** | Runs as dedicated user with only `CAP_NET_ADMIN` + `CAP_DAC_READ_SEARCH`. systemd hardening (ProtectSystem=strict, NoNewPrivileges, MemoryDenyWriteExecute). |
| **Persistence** | State survives restarts: WAL replay on top of snapshots, CRDT-aware v2 format. |

#### Caveats (proceed with caution)

| Area | Risk Level | Details |
|------|------------|---------|
| **Version 0.1.0** | Medium | No stable release yet. API and config format may change. |
| **Cluster gossip** | Medium | QUIC transport, SWIM membership, and gossip are implemented and tested in unit/integration tests, but **not battle-tested at scale in production multi-node clusters**. Start with single-node mode. |
| **nftables enforcement** | Low–Medium | Uses `nft` CLI (not native netlink). Tested in unit tests; integration tests require root. **Run in `observe_only` mode first** to verify detection accuracy before enabling firewall enforcement. |
| **No stable release cadence** | Medium | No published crate versions or tagged releases. Pin to a git commit hash for reproducibility. |
| **Limited log source variety** | Low | Supports SSH, Nginx, Postfix, and custom regex. Journald native API not yet wired (falls back to auth.log file). |
| **No TLS on REST API** | Medium | REST API listens on plain HTTP. Bind to `127.0.0.1` or put behind a reverse proxy with TLS for remote access. |

#### Recommendation

> **Safe to deploy in production** on a single node in `observe_only` mode for initial evaluation. After validating detection accuracy (reviewing logs for 1–2 weeks), enable `nftables` or `ipset` enforcement. Cluster mode should be tested in staging first.

---

## 2. Prerequisites

### System Requirements

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| OS | Linux (Debian/Ubuntu 22+, RHEL 9+) | Debian 12 / Ubuntu 24.04 |
| Kernel | 5.10+ | 6.1+ |
| Architecture | x86_64 | x86_64 |
| RAM | 64 MB | 256 MB |
| Disk | 100 MB (binary + data) | 1 GB |
| CPU | 1 core | 2+ cores |

### Build Dependencies

```bash
# Debian/Ubuntu
sudo apt-get update
sudo apt-get install -y build-essential pkg-config libssl-dev

# RHEL/Fedora
sudo dnf install -y gcc make openssl-devel pkg-config
```

### Rust Toolchain

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
rustup default stable    # Requires Rust 1.75+ (edition 2021)
```

### Runtime Dependencies

```bash
# For nftables enforcement backend
sudo apt-get install -y nftables      # Debian/Ubuntu
sudo dnf install -y nftables          # RHEL

# For ipset enforcement backend (alternative)
sudo apt-get install -y ipset         # Debian/Ubuntu
```

---

## 3. Building from Source

### Standard Build

```bash
git clone <repository-url> HiveGuard
cd HiveGuard/hiveguard

# Release build (optimized)
cargo build --release -p hiveguard-daemon

# Binary location
ls -la target/release/hiveguard-daemon
```

### Run Tests (recommended before deploying)

```bash
# All tests (excludes nftables integration tests that need root)
cargo test --workspace

# Include nftables integration tests (requires root)
sudo cargo test --workspace -- --include-ignored
```

### Docker Build

```bash
cd hiveguard
docker build -t hiveguard .
```

The multi-stage Dockerfile produces a minimal Debian-slim image (~80 MB) with only nftables and ca-certificates installed.

---

## 4. Installation

### Automated Install (recommended)

The install script creates the system user, directories, config, and systemd unit:

```bash
cd hiveguard

# Build first
cargo build --release -p hiveguard-daemon

# Run installer as root
sudo ./scripts/install.sh ./target/release/hiveguard-daemon
```

This performs:
1. Creates `hiveguard` system user (no login shell)
2. Installs binary to `/usr/local/bin/hiveguard`
3. Creates `/etc/hiveguard/` and copies `config.example.yaml` to `config.yaml`
4. Creates `/var/lib/hiveguard/` (data directory, owned by `hiveguard`)
5. Installs systemd unit to `/etc/systemd/system/hiveguard.service`
6. Enables the service (does **not** start it)

### Manual Install

```bash
# 1. Create system user
sudo useradd --system --no-create-home --shell /usr/sbin/nologin hiveguard

# 2. Install binary
sudo install -m 0755 target/release/hiveguard-daemon /usr/local/bin/hiveguard

# 3. Create config directory
sudo mkdir -p /etc/hiveguard
sudo cp config.example.yaml /etc/hiveguard/config.yaml
sudo chown root:hiveguard /etc/hiveguard/config.yaml
sudo chmod 0640 /etc/hiveguard/config.yaml

# 4. Create data directory
sudo mkdir -p /var/lib/hiveguard
sudo chown hiveguard:hiveguard /var/lib/hiveguard
sudo chmod 0750 /var/lib/hiveguard

# 5. Install systemd service
sudo cp hiveguard.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable hiveguard
```

### Docker Install

```bash
docker run -d \
  --name hiveguard \
  --restart unless-stopped \
  --cap-add NET_ADMIN \
  --cap-add DAC_READ_SEARCH \
  -v /etc/hiveguard:/etc/hiveguard:ro \
  -v /var/lib/hiveguard:/var/lib/hiveguard \
  -v /var/log:/var/log:ro \
  -p 7946:7946/udp \
  -p 8443:8443 \
  hiveguard
```

**Required capabilities:**
- `CAP_NET_ADMIN` — for nftables/ipset rule management
- `CAP_DAC_READ_SEARCH` — for reading log files owned by other users

---

## 5. Configuration Reference

Edit `/etc/hiveguard/config.yaml`. All sections except `node.name` are optional and have sensible defaults.

### Minimal Configuration

```yaml
node:
  name: "my-server-01"

enforcement:
  backend: "observe_only"    # Start here!
```

### Full Configuration with Comments

```yaml
# === Node Identity ===
node:
  name: "web-prod-01"                # REQUIRED: unique node name
  listen_gossip: "0.0.0.0:7946"      # Cluster gossip port (QUIC/TLS 1.3)
  listen_api: "127.0.0.1:8443"       # inert; REST API bind is set in the ui.rest plugin
  data_dir: "/var/lib/hiveguard"     # Snapshots, WAL, offsets, identity keys
  seeds:                              # Cluster seed nodes (empty = standalone)
    - "10.0.1.1:7946"
    - "10.0.1.2:7946"

# === Whitelist ===
# IPs/CIDRs that are NEVER banned. Always include your own IPs!
whitelist:
  - "127.0.0.0/8"
  - "::1/128"
  - "10.0.0.0/8"          # Internal network
  - "172.16.0.0/12"
  - "192.168.0.0/16"
  # Add your management IPs here!
  # - "203.0.113.50/32"   # your SSH jump host

# === Log Sources ===
sources:
  ssh:
    use_journald: true                # Preferred (not yet wired, falls back to auth_log_path)
    auth_log_path: "/var/log/auth.log"
  nginx:
    access_log: "/var/log/nginx/access.log"
    error_log: "/var/log/nginx/error.log"
  postfix:
    log_path: "/var/log/mail.log"
  custom:                             # Custom regex-based log parsers
    - path: "/var/log/myapp/security.log"
      pattern: 'FAILED_LOGIN ip=(?P<ip>\S+) user=(?P<user>\S+)'
      detector: "brute_force"         # Arbitrary label
      threshold: 5
      window: "5m"

# === Detectors ===
# Each detector can be independently enabled/disabled and tuned.
detectors:
  ssh_bruteforce:
    enabled: true
    threshold: 5              # Failed logins before ban
    window: "5m"              # Time window for threshold
    ban_duration: "24h"
  ssh_user_enum:
    enabled: true
    threshold: 3              # Invalid user attempts before ban
    window: "2m"
    ban_duration: "48h"
  path_probe:
    enabled: true
    paths:                    # Paths that trigger instant detection
      - "/wp-login.php"
      - "/xmlrpc.php"
      - "/.env"
      - "/phpmyadmin"
      - "/wp-admin"
    ban_duration: "72h"
  http_4xx_flood:
    enabled: true
    threshold: 50             # 4xx responses in window
    window: "1m"
    ban_duration: "1h"
  scanner_fingerprint:
    enabled: true
    ban_duration: "72h"
    # Detects: nikto, sqlmap, nuclei, nessus, openvas, w3af,
    #          skipfish, wpscan, dirbuster, gobuster, masscan, zgrab
  smtp_bruteforce:
    enabled: true
    threshold: 5
    window: "5m"
    ban_duration: "24h"
  port_scan:
    enabled: true
    threshold: 20             # Unique ports accessed
    window: "30s"
    ban_duration: "48h"
  distributed_slow:
    enabled: true
    subnet_threshold: 5       # IPs from same /24 subnet
    window: "10m"
    ban_duration: "12h"
  honeypot:
    enabled: true
    paths:                    # Instant permanent ban
      - "/backup.sql"
      - "/db-dump.sql"
      - "/admin-panel-secret"
    ban_duration: "permanent"
    severity: 250             # Minimum 250, guarantees immediate ban
  entropy:
    enabled: true
    min_entropy: 4.5          # Min Shannon entropy for suspicious URLs
    max_entropy: 6.5
  timing:
    enabled: true
    window: "1m"
    min_samples: 10           # Minimum requests before analysis
    stddev_threshold_ms: 50.0 # Bot-like timing regularity

# === Scoring Engine ===
scoring:
  accumulation_window: "30m"    # Severity scores accumulate within this window
  ban_severity_threshold: 100   # Total weighted severity >= this triggers a ban
  default_ban_duration: "24h"   # When no detector specifies a duration

# === Trust (cluster mode) ===
trust:
  ban_threshold: 2.0            # Sum of reporter trust scores required to enforce
  new_node_grace_period: "24h"
  new_node_threshold_multiplier: 2.0
  max_bans_per_minute: 100      # Rate limit per peer

# === Enforcement ===
enforcement:
  backend: "observe_only"       # Start with observe_only!
  # backend: "nftables"         # Production: nftables set-based blocking
  # backend: "ipset"            # Alternative: ipset hash:net

# === REST API + Web UI (ui.rest plugin) ===
plugins:
  - id: ui.rest
    config:
      bind_addr: "127.0.0.1:8443"
      auth_token: "CHANGE-ME-to-a-secure-random-string"

# === Persistence ===
persistence:
  snapshot_interval: "5m"       # How often to write a full snapshot
  wal_sync_mode: "fdatasync"    # fdatasync | sync | none
  max_wal_size_mb: 100
```

### Duration Format

Durations accept human-readable strings:
- `"30s"` — 30 seconds
- `"5m"` — 5 minutes
- `"24h"` — 24 hours
- `"7d"` — 7 days
- `"permanent"` — never expires

---

## 6. Deployment Scenarios

### Scenario A: Evaluation (observe-only)

The recommended way to start. **No firewall changes are made.**

```yaml
node:
  name: "eval-01"
enforcement:
  backend: "observe_only"
sources:
  ssh:
    auth_log_path: "/var/log/auth.log"
```

```bash
sudo systemctl start hiveguard
sudo journalctl -u hiveguard -f
```

Watch the logs for detection signals and would-be bans. Validate that:
- Whitelisted IPs are never flagged
- Detections match real attacks (check against your access logs)
- No false positives on legitimate traffic

### Scenario B: Single Server with nftables

After validating in observe-only mode:

```yaml
node:
  name: "web-prod-01"
whitelist:
  - "127.0.0.0/8"
  - "::1/128"
  - "10.0.0.0/8"
  - "YOUR.MANAGEMENT.IP/32"     # <-- CRITICAL: add your SSH IP!
enforcement:
  backend: "nftables"
sources:
  ssh:
    auth_log_path: "/var/log/auth.log"
  nginx:
    access_log: "/var/log/nginx/access.log"
```

> **WARNING:** Before enabling `nftables` backend, **always** whitelist your management IP addresses. Locking yourself out requires console/IPMI access to recover.

```bash
sudo systemctl restart hiveguard

# Verify nftables rules were created
sudo nft list table inet hiveguard
```

### Scenario C: Multi-node Cluster

Deploy HiveGuard on multiple servers with gossip enabled:

**Node 1 (seed):**
```yaml
node:
  name: "node-01"
  listen_gossip: "0.0.0.0:7946"
  seeds: []                       # First node has no seeds
```

**Node 2+:**
```yaml
node:
  name: "node-02"
  listen_gossip: "0.0.0.0:7946"
  seeds:
    - "10.0.1.1:7946"            # Point to seed node
```

Nodes auto-generate Ed25519 identity keys on first run (stored in `data_dir/identity/`). Ban records propagate via CRDT gossip with trust-weighted enforcement.

### Scenario D: Docker Compose (multi-service)

```yaml
version: "3.8"
services:
  hiveguard:
    build: ./hiveguard
    cap_add:
      - NET_ADMIN
      - DAC_READ_SEARCH
    volumes:
      - ./config.yaml:/etc/hiveguard/config.yaml:ro
      - hiveguard-data:/var/lib/hiveguard
      - /var/log:/var/log:ro
    network_mode: host            # Needed for nftables access
    restart: unless-stopped

volumes:
  hiveguard-data:
```

> Note: `network_mode: host` is required for nftables/ipset to affect the host's firewall.

---

## 7. CLI Usage

The HiveGuard binary serves as both the daemon and the CLI client. CLI commands communicate with the running daemon via a Unix socket at `/var/run/hiveguard/hiveguard.sock`.

### Start the Daemon

```bash
# Foreground (for debugging)
hiveguard -c /etc/hiveguard/config.yaml run

# Via systemd (production)
sudo systemctl start hiveguard
```

### Status

```bash
hiveguard -c /etc/hiveguard/config.yaml status
```
Output:
```
HiveGuard v0.1.0
Uptime: 2d 5h 32m 10s
Active bans: 47
Whitelisted: 5
```

### Ban Management

```bash
# Ban an IP for 24 hours
hiveguard -c /etc/hiveguard/config.yaml ban 203.0.113.42 -t 24h -r "manual: port scanning"

# Ban a CIDR permanently
hiveguard -c /etc/hiveguard/config.yaml ban 198.51.100.0/24 -t permanent -r "known botnet"

# Remove a ban
hiveguard -c /etc/hiveguard/config.yaml unban 203.0.113.42

# List active bans (with optional limit)
hiveguard -c /etc/hiveguard/config.yaml list-bans --limit 50

# Show top threats by severity
hiveguard -c /etc/hiveguard/config.yaml top --threats 10

# Export bans
hiveguard -c /etc/hiveguard/config.yaml export --format json
hiveguard -c /etc/hiveguard/config.yaml export --format csv
```

### Whitelist Management

```bash
hiveguard -c /etc/hiveguard/config.yaml whitelist add 10.0.0.0/8
hiveguard -c /etc/hiveguard/config.yaml whitelist remove 10.0.0.0/8
hiveguard -c /etc/hiveguard/config.yaml whitelist list
```

### Socket Path Override

```bash
hiveguard -s /custom/path/hiveguard.sock status
```

---

## 8. REST API

The REST API is served by the `ui.rest` plugin. Enable it in config:
```yaml
plugins:
  - id: ui.rest
    config:
      bind_addr: "127.0.0.1:8443"
      auth_token: "your-secret-token"
```

### Authentication

All API endpoints (except `/metrics`) require a Bearer token:
```
Authorization: Bearer your-secret-token
```

### Endpoints

#### GET /api/stats
```bash
curl -H "Authorization: Bearer TOKEN" http://127.0.0.1:8443/api/stats
```
```json
{"uptime_secs": 86400, "total_bans": 47, "total_whitelisted": 5, "version": "0.1.0"}
```

#### GET /api/bans?limit=N&offset=M
```bash
curl -H "Authorization: Bearer TOKEN" "http://127.0.0.1:8443/api/bans?limit=10&offset=0"
```

#### POST /api/bans
```bash
curl -X POST -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"ip":"1.2.3.4","reason":"manual ban","duration_secs":86400}' \
  http://127.0.0.1:8443/api/bans
```

#### DELETE /api/bans/{ip}
```bash
curl -X DELETE -H "Authorization: Bearer TOKEN" \
  http://127.0.0.1:8443/api/bans/1.2.3.4
```

#### GET /api/whitelist
```bash
curl -H "Authorization: Bearer TOKEN" http://127.0.0.1:8443/api/whitelist
```

#### GET /api/peers
```bash
curl -H "Authorization: Bearer TOKEN" http://127.0.0.1:8443/api/peers
```

#### GET /metrics (no auth required)
```bash
curl http://127.0.0.1:8443/metrics
```

### Rate Limiting

API responses include standard rate limit behavior. When exceeded:
- HTTP 429 with `Retry-After: 60` header
- Default: 100 requests/minute per token

---

## 9. Monitoring & Observability

### Prometheus Metrics

The `/metrics` endpoint (no authentication) exposes:

| Metric | Type | Description |
|--------|------|-------------|
| `hiveguard_active_bans` | Gauge | Current active ban count |
| `hiveguard_whitelisted_count` | Gauge | Whitelist entry count |
| `hiveguard_peer_count` | Gauge | Cluster peer count |
| `hiveguard_memory_usage_bytes` | Gauge | Process RSS memory (from /proc) |
| `hiveguard_events_processed_total{source}` | Counter | Events processed, labeled by source (ssh, nginx, postfix, custom) |
| `hiveguard_bans_created_total{detector}` | Counter | Bans created, labeled by detector |
| `hiveguard_bans_expired_total` | Counter | Expired bans auto-removed |
| `hiveguard_detection_signals_total{detector}` | Counter | Detection signals, labeled by detector |
| `hiveguard_event_processing_duration_seconds{source}` | Histogram | Per-event processing latency |
| `hiveguard_enforcement_duration_seconds{operation}` | Histogram | Enforcement operation timing (apply/remove) |

### Prometheus Scrape Config

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'hiveguard'
    static_configs:
      - targets: ['localhost:8443']
    scrape_interval: 15s
```

### Grafana Dashboard Queries (examples)

```promql
# Ban rate over time
rate(hiveguard_bans_created_total[5m])

# Events per second by source
rate(hiveguard_events_processed_total[1m])

# P95 event processing latency
histogram_quantile(0.95, rate(hiveguard_event_processing_duration_seconds_bucket[5m]))

# Active bans
hiveguard_active_bans
```

### systemd Journal Logs

```bash
# Follow live logs
sudo journalctl -u hiveguard -f

# Last 100 lines
sudo journalctl -u hiveguard -n 100

# Since boot
sudo journalctl -u hiveguard -b

# Filter by severity
sudo journalctl -u hiveguard -p warning
```

### Log Levels

HiveGuard uses `tracing` with standard levels:
- `ERROR` — failures requiring attention (WAL write errors, config issues)
- `WARN` — non-critical issues (malformed log lines, rate limit exceeded)
- `INFO` — operational events (bans created/removed, sources started, snapshots)
- `DEBUG` — per-event processing details
- `TRACE` — very verbose parser output

Set the log level via the `RUST_LOG` environment variable:
```bash
# In systemd override
sudo systemctl edit hiveguard
# Add:
# [Service]
# Environment="RUST_LOG=hiveguard=info"
```

---

## 10. Cluster Mode

### How It Works

1. **Identity:** Each node generates an Ed25519 keypair on first start. Keys are stored in `data_dir/identity/`.
2. **Transport:** Nodes communicate via QUIC/TLS 1.3 (mutual TLS with self-signed certificates).
3. **Membership:** SWIM protocol detects node failures (probe → suspect → dead).
4. **Gossip:** Ban records propagate as CRDTs (Conflict-free Replicated Data Types). Merges are commutative, associative, and idempotent.
5. **Trust:** Each node maintains per-peer trust scores. Bans from untrusted peers require corroboration from multiple reporters.
6. **Anti-poisoning:** Rate limiting (100 bans/min per peer), quarantine (10x median detection), and grace periods for new nodes.

### Cluster Setup

Configure seed nodes to bootstrap membership discovery:

```yaml
# Node A (seed — knows no one initially)
node:
  name: "node-a"
  listen_gossip: "0.0.0.0:7946"
  seeds: []

# Node B (joins via seed)
node:
  name: "node-b"
  listen_gossip: "0.0.0.0:7946"
  seeds: ["10.0.1.1:7946"]

# Node C (joins via seed)
node:
  name: "node-c"
  listen_gossip: "0.0.0.0:7946"
  seeds: ["10.0.1.1:7946"]
```

### Firewall Rules for Cluster

```bash
# Allow gossip traffic between nodes
sudo nft add rule inet filter input ip saddr { 10.0.1.0/24 } udp dport 7946 accept
sudo nft add rule inet filter input ip saddr { 10.0.1.0/24 } tcp dport 7946 accept
```

---

## 11. Security Hardening

### systemd Hardening (enabled by default)

The provided `hiveguard.service` includes:

```ini
# Minimal capabilities
AmbientCapabilities=CAP_NET_ADMIN CAP_DAC_READ_SEARCH
CapabilityBoundingSet=CAP_NET_ADMIN CAP_DAC_READ_SEARCH
NoNewPrivileges=true

# Filesystem protection
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/var/lib/hiveguard /run/hiveguard

# Kernel hardening
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true

# Additional restrictions
RestrictSUIDSGID=true
MemoryDenyWriteExecute=true
LockPersonality=true
RestrictRealtime=true
RestrictNamespaces=true
```

### REST API Security

1. **Always set `auth_token`** to a strong random value:
   ```bash
   # Generate a secure token
   openssl rand -hex 32
   ```
2. **Bind to localhost** (`127.0.0.1`) unless accessed remotely
3. **Use a reverse proxy with TLS** (nginx/caddy) for remote API access — HiveGuard's REST API is plain HTTP
4. **Set rate limits** to prevent brute-force against the API

### Config File Permissions

```bash
sudo chown root:hiveguard /etc/hiveguard/config.yaml
sudo chmod 0640 /etc/hiveguard/config.yaml
```

### Whitelist Best Practices

> **CRITICAL:** Always whitelist your management IPs before enabling nftables/ipset enforcement. Failure to do so can lock you out of the server.

```yaml
whitelist:
  - "127.0.0.0/8"
  - "::1/128"
  - "YOUR.SSH.JUMPHOST.IP/32"
  - "YOUR.OFFICE.CIDR/24"
  - "YOUR.MONITORING.IP/32"
```

---

## 12. Backup & Recovery

### What to Back Up

| Path | Contents | Priority |
|------|----------|----------|
| `/etc/hiveguard/config.yaml` | Configuration | Critical |
| `/var/lib/hiveguard/snapshot.bin` | Full state snapshot (bans, whitelist, CRDT bans) | High |
| `/var/lib/hiveguard/wal.bin` | Write-ahead log (changes since last snapshot) | High |
| `/var/lib/hiveguard/identity/` | Ed25519 keypair (node identity for cluster) | High (cluster mode) |
| `/var/lib/hiveguard/offsets/` | Log parser offsets (byte positions) | Low |

### Backup Script Example

```bash
#!/bin/bash
BACKUP_DIR="/backup/hiveguard/$(date +%Y%m%d)"
mkdir -p "$BACKUP_DIR"
cp /etc/hiveguard/config.yaml "$BACKUP_DIR/"
cp /var/lib/hiveguard/snapshot.bin "$BACKUP_DIR/" 2>/dev/null
cp /var/lib/hiveguard/wal.bin "$BACKUP_DIR/" 2>/dev/null
cp -r /var/lib/hiveguard/identity/ "$BACKUP_DIR/" 2>/dev/null
```

### Recovery Process

1. **Normal restart:** HiveGuard automatically recovers from snapshot + WAL replay.
2. **Corrupted WAL:** HiveGuard reads valid entries up to the first corruption point. Data loss is limited to entries after the last valid record.
3. **Corrupted snapshot:** Delete the snapshot file; HiveGuard will start fresh. If WAL is intact, it replays from the beginning.
4. **Full data loss:** Copy `snapshot.bin` from backup to `/var/lib/hiveguard/`, restart the service.

### Snapshot Behavior

- Snapshots are taken every `snapshot_interval` (default: 5 minutes)
- Snapshots use atomic writes (write to temp file, then rename) — no partial/corrupt snapshots
- After each snapshot, the WAL is truncated
- A final snapshot is taken on graceful shutdown
- Format: `HVGD0002` magic (v2, includes CRDT bans), backward-compatible with v1

---

## 13. Troubleshooting

### Service Won't Start

```bash
# Check service status
sudo systemctl status hiveguard

# Check logs for errors
sudo journalctl -u hiveguard -e --no-pager

# Common issues:
# - Config file missing or invalid YAML
# - Data directory permissions (must be owned by hiveguard user)
# - Socket file from previous crash (rm /var/run/hiveguard/hiveguard.sock)
```

### "Permission denied" on Log Files

The `hiveguard` user needs `CAP_DAC_READ_SEARCH` to read log files. Verify:
```bash
# Check the binary has capabilities
getcap /usr/local/bin/hiveguard

# Or verify systemd grants them
systemctl show hiveguard | grep -i capabilities
```

Alternatively, add the `hiveguard` user to the relevant log group:
```bash
sudo usermod -aG adm hiveguard          # Debian/Ubuntu (auth.log, syslog)
sudo usermod -aG www-data hiveguard     # Nginx logs
```

### No Detections Firing

1. Check that log sources are configured with correct paths
2. Verify log files exist and are being written to
3. Check that detectors are `enabled: true` in config
4. Review thresholds — they may be too high for your traffic
5. Run in foreground with debug logging:
   ```bash
   RUST_LOG=hiveguard=debug hiveguard -c /etc/hiveguard/config.yaml run
   ```

### False Positives

1. **Lower priority:** Start in `observe_only` mode to validate detections
2. **Whitelist known IPs:** Add monitoring systems, load balancers, CDN IPs
3. **Raise thresholds:** Increase `threshold` values for noisy detectors
4. **Disable detectors:** Set `enabled: false` for detectors that don't match your workload

### CLI Can't Connect to Daemon

```bash
# Check socket exists
ls -la /var/run/hiveguard/hiveguard.sock

# Check daemon is running
systemctl is-active hiveguard

# Check socket permissions
# The socket should be accessible by the user running the CLI
```

### High Memory Usage

- Check `hiveguard_active_bans` metric — a very large ban list consumes memory
- Review `max_wal_size_mb` setting
- Run `hiveguard list-bans` to check for unexpectedly large ban counts
- Consider lowering ban durations or enabling more aggressive expiry

### nftables Rules Not Working

```bash
# Check HiveGuard's table exists
sudo nft list table inet hiveguard

# Check sets have elements
sudo nft list set inet hiveguard hiveguard_blocklist
sudo nft list set inet hiveguard hiveguard_blocklist_v6

# Check chain priority (should be -10, before standard filter chains)
sudo nft list chain inet hiveguard input
```

---

## 14. Upgrading

### Procedure

1. **Build the new version:**
   ```bash
   git pull
   cd hiveguard
   cargo build --release -p hiveguard-daemon
   cargo test --workspace
   ```

2. **Stop the service:**
   ```bash
   sudo systemctl stop hiveguard
   ```
   HiveGuard takes a final snapshot on graceful shutdown.

3. **Replace the binary:**
   ```bash
   sudo install -m 0755 target/release/hiveguard-daemon /usr/local/bin/hiveguard
   ```

4. **Review config changes:**
   Compare your config against the latest `config.example.yaml` for new options.

5. **Start the service:**
   ```bash
   sudo systemctl start hiveguard
   sudo journalctl -u hiveguard -f   # Watch for startup success
   ```

### Data Compatibility

- Snapshot v2 format (`HVGD0002`) is backward-compatible with v1 (`HVGD0001`)
- New versions can read old snapshots
- WAL entries are versioned via bincode serialization
- No manual migration required for minor upgrades

---

## 15. Known Limitations

| Limitation | Impact | Workaround |
|------------|--------|------------|
| No journald native API | SSH log source reads `auth.log` file directly | Set `auth_log_path` in config |
| REST API is plain HTTP | No encryption for API traffic | Bind to localhost or use a TLS reverse proxy |
| nftables uses CLI wrapper | Slightly slower than native netlink | Sufficient for typical ban rates (<1000/min) |
| No web UI | Management via CLI and API only | Use Grafana for dashboards |
| Cluster mode not production-hardened | Gossip/SWIM tested in unit tests only | Start with single node; test cluster in staging |
| No automatic key rotation | Ed25519 keys generated once | Manually delete identity dir and restart to regenerate |
| No IPv6-only nftables chain | IPv6 bans use separate set | Transparent to users; both sets checked |
| Custom parsers limited to regex | Complex log formats may need code changes | Use named capture groups `(?P<ip>...)` |
| Version 0.1.0 | No stability guarantees | Pin to git commit for reproducibility |

---

## Appendix A: File Layout

```
/usr/local/bin/hiveguard                    # Daemon binary
/etc/hiveguard/config.yaml                  # Configuration
/etc/systemd/system/hiveguard.service       # systemd unit file
/var/lib/hiveguard/                         # Data directory
├── snapshot.bin                            # Full state snapshot (HVGD0002)
├── wal.bin                                 # Write-ahead log
├── identity/                               # Node identity (cluster mode)
│   ├── node.key                            # Ed25519 private key (PKCS#8 DER)
│   └── node.crt                            # Self-signed X.509 certificate (DER)
└── offsets/                                # Log parser offsets
    ├── ssh.offset                          # SSH parser byte offset
    ├── nginx.offset                        # Nginx parser byte offset
    └── postfix.offset                      # Postfix parser byte offset
/var/run/hiveguard/hiveguard.sock           # Unix domain socket (CLI ↔ daemon)
```

## Appendix B: Detector Summary

| Detector | Trigger | Default Ban | Severity |
|----------|---------|-------------|----------|
| SSH Brute-force | 5 failed logins in 5 min | 24h | 150 |
| SSH User Enum | 3 invalid users in 2 min | 48h | 180 |
| Path Probe | Single request to suspicious path | 72h | 200 |
| HTTP 4xx Flood | 50 4xx responses in 1 min | 1h | 120 |
| Scanner Fingerprint | Known scanner User-Agent (nikto, sqlmap, etc.) | 72h | 200 |
| SMTP Brute-force | 5 SASL auth failures in 5 min | 24h | 150 |
| Port Scan | 20 unique ports in 30 sec | 48h | 150 |
| Distributed Slow | 5 IPs from same /24 in 10 min | 12h | 130 |
| Honeypot | Single request to honeypot path | permanent | 250 |
| Entropy Analysis | High-entropy URL (shellcode/SQLi) | — | 50–80 |
| Timing Analysis | Bot-like request regularity | — | 70 |

Scoring: detectors produce severity signals weighted by confidence. When the accumulated weighted severity for an IP exceeds `ban_severity_threshold` (default: 100) within the `accumulation_window` (default: 30 min), a ban is issued.

## Appendix C: Quick Start Checklist

- [ ] Install Rust toolchain (1.75+)
- [ ] Build: `cargo build --release -p hiveguard-daemon`
- [ ] Run tests: `cargo test --workspace`
- [ ] Install: `sudo ./scripts/install.sh ./target/release/hiveguard-daemon`
- [ ] Edit config: `sudo nano /etc/hiveguard/config.yaml`
- [ ] Set `node.name` to a unique identifier
- [ ] Add your management IPs to `whitelist`
- [ ] Set `enforcement.backend` to `observe_only`
- [ ] Configure at least one log source (SSH recommended)
- [ ] Set a strong `api.auth_token` if enabling REST API
- [ ] Start: `sudo systemctl start hiveguard`
- [ ] Monitor: `sudo journalctl -u hiveguard -f`
- [ ] Validate detections for 1–2 weeks
- [ ] Switch `enforcement.backend` to `nftables` when confident
- [ ] Set up Prometheus scraping for `/metrics`
