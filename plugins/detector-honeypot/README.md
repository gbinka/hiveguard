# detector.honeypot

High-confidence detector for accesses to trap endpoints.

## YAML

```yaml
plugins:
  - id: detector.honeypot
    name: web-honeypot
    config:
      paths: ["/backup.sql", "/db-dump.sql"]
      ban_duration_secs: 86400
      severity: 250
```

## Config fields

- `paths`: honeypot endpoint list.
- `ban_duration_secs`: optional ban duration hint in seconds.
- `severity`: signal severity (minimum enforced by legacy detector).
