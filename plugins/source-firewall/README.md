# source.firewall

Firewall log source plugin. Tails a firewall log file and emits
`EventType::PortAccess` events with the destination port in `metadata["port"]`,
feeding `detector.port_scan`.

## Why this exists

`detector.port_scan` counts distinct destination ports per source IP and bans
scanners, but it only consumes `PortAccess` events carrying a `port` in
metadata. None of the existing sources (journald=SSH auth, file=HTTP/mail)
produce those. This plugin closes that gap by reading the firewall's own record
of blocked connections — which, by definition, is suspicious traffic to closed
ports, so it is a naturally low-false-positive signal.

## Adapters

The plugin is built around an `adapter` field so more firewall data sources can
be added later without touching existing ones:

| adapter      | source                                   | status        |
|--------------|------------------------------------------|---------------|
| `ufw_file`   | tail a UFW/iptables log file             | implemented   |
| `journald_kernel` | kernel journal (`journalctl -k`)    | planned       |
| `nftlog`     | nftables `log prefix` entries            | planned       |
| `conntrack`  | netlink/conntrack (no logs)              | planned       |

## Configuration

```yaml
- plugin: source.firewall
  config:
    adapter: ufw_file          # only adapter implemented today
    path: /var/log/ufw.log     # firewall log to tail
    seek_to_end: true          # IMPORTANT: do not replay the existing backlog
    event_type: PortAccess     # what detector.port_scan consumes
    block_marker: "[UFW BLOCK]" # line must contain this to count as a block
    protocols: ["TCP", "UDP"]  # optional protocol allow-list (default: all)
    connection_attempts_only: true # default; see below
```

### `connection_attempts_only`

Default `true`. UFW also logs stray packets of flows conntrack has already
forgotten — e.g. a late `ACK RST` from a CDN on :443, or a DNS answer from
1.1.1.1:53 — and their destination is a random ephemeral port. Counted as port
accesses, a handful of those looks exactly like a scan, and banning your DNS
resolver breaks the host. With this option only bare TCP `SYN` packets and UDP
packets not sent from a well-known service port (53, 67, 68, 123, 443, 500,
853, 3478, 4500, 5353) are emitted.

### `seek_to_end`

Keep `true` on first run. A populated `ufw.log` can hold thousands of historical
`[UFW BLOCK]` entries; replaying them all at once would flood the detector and
could mass-ban stale source IPs. With `true` the plugin follows only new lines.
After the first run an offset is persisted under the plugin data dir, so
restarts resume where they left off regardless of this flag.

## Parsed line format

Standard UFW/iptables kernel log line:

```
... [UFW BLOCK] IN=eth0 ... SRC=203.0.113.5 DST=10.0.0.1 ... PROTO=TCP SPT=51000 DPT=23 ... SYN
```

Extracted: `SRC` → source IP, `DPT` → `metadata["port"]`, plus `PROTO`, `SPT`
and `DST` into metadata. The leading timestamp may be classic syslog
(`Jun 15 12:34:56`) or RFC 3339 (`2026-10-05T13:13:54.213419+00:00`, the
rsyslog default on recent Ubuntu); unparseable timestamps fall back to "now". Lines without the block marker, without a parseable
`SRC`, or without a numeric `DPT` are skipped.

## Permissions

The daemon process must be able to read the log file. On Debian/Ubuntu the
`hiveguard` service user typically needs to be in the `adm` group to read
`/var/log/ufw.log`. If the systemd unit hardens the filesystem
(`ProtectSystem`, `ReadOnlyPaths`), ensure `/var/log` is readable.
