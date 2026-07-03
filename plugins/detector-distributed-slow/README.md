# detector.distributed_slow

Detects coordinated slow attacks from multiple IPs within one subnet.

## YAML

```yaml
plugins:
  - id: detector.distributed_slow
    name: dist-slow
    config:
      window_secs: 600
      subnet_threshold: 5
      ban_duration_secs: 43200
      ban_scope: "/24"
```

## Config fields

- `window_secs`: tracking window in seconds.
- `subnet_threshold`: unique IP threshold per subnet.
- `ban_duration_secs`: suggested ban duration in seconds.
- `ban_scope`: compatibility field from legacy config.
