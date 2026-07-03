# detector.port_scan

Detects many unique destination ports probed by one source IP.

## YAML

```yaml
plugins:
  - id: detector.port_scan
    name: portscan-main
    config:
      window_secs: 30
      threshold: 20
      ban_duration_secs: 172800
```

## Config fields

- `window_secs`: tracking window in seconds.
- `threshold`: unique port threshold.
- `ban_duration_secs`: suggested ban duration in seconds.
