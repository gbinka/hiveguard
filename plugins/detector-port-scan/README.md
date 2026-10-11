# detector.port_scan

Detects many unique destination ports probed by one source IP.

## YAML

```yaml
plugins:
  - id: detector.port_scan
    name: portscan-main
    config:
      window_secs: 600
      threshold: 6
      ban_duration_secs: 172800
      # long-window tier (optional; these are the defaults)
      long_window_secs: 21600
      long_threshold: 25
      long_ban_duration_secs: 604800
      max_tracked_ips: 50000
```

## Config fields

- `window_secs`: tracking window in seconds (default 600).
- `threshold`: unique port threshold (default 6).

The defaults are tuned for `source.firewall` reading UFW logs. UFW rate-limits
its BLOCK logging (~3 entries/min for the whole host), so the detector only
sees a sample of each scan; a short window with a high threshold (the old
30 s / 20 ports) never fired on real traffic. On a month of production logs
600 s / 6 ports banned ~5 scanners per day. Keep `source.firewall`'s
`connection_attempts_only` enabled with these values, otherwise late replies
from DNS/HTTPS servers (to random ephemeral ports) can look like scans.
- `ban_duration_secs`: suggested ban duration in seconds.

### Long-window ("slow scan") tier

Scanners that probe a couple of ports per 10 minutes for a whole day (one
production scanner: 1757 blocked ports in 24 h; another: 502) never reach
the short threshold. A second tier counts distinct ports per IP over
`long_window_secs` and bans with detector name `port_scan_slow`:

- `long_window_secs`: default 21600 (6 h).
- `long_threshold`: distinct ports in that window, default 25; `0` disables the tier.
- `long_ban_duration_secs`: default 604800 (7 days).
- `max_tracked_ips`: cap of IPs tracked per tier, default 50000. Each IP keeps
  at most `long_threshold` entries (fires and resets on reaching it); expired
  IPs are swept every 4096 port events; when full, new IPs are not tracked
  until a sweep frees room (fail-open).

All keys are optional; configs without them keep working (the tier is on with
the defaults above).

### IPv6 prefix aggregation

- `ipv6_prefix`: default `64`. IPv6 sources are counted per /64 in both tiers
  and banned as that /64 (a scanner rotated 37 addresses inside one /64).
  `0` or `128` = per address; otherwise `48..128`. IPv4 is always per address.

### Distributed slow tier (per IPv4 subnet, optional)

Several hosts of one /24, each probing 17–25 ports in 6 h (under the per-IP
`long_threshold`), are counted together:

- `long_subnet_v4_prefix`: `0` = off (default); e.g. `24`. Allowed `16..32`.
- `long_subnet_threshold`: distinct ports from the subnet within
  `long_window_secs` (default 40; `0` disables).
- `long_subnet_min_ips`: distinct source addresses required (default 3).

Fires `port_scan_slow` with the subnet as subject and `long_ban_duration_secs`.
Memory: one entry per (port, address) per subnet, capped at
`4 × long_subnet_threshold + 64`; subnets are counted against `max_tracked_ips`.

```yaml
      ipv6_prefix: 64
      long_subnet_v4_prefix: 24
      long_subnet_threshold: 40
      long_subnet_min_ips: 3
```

