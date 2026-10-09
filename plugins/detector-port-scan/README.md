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
