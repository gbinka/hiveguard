# detector.scanner_fingerprint

Detects known scanner user-agent signatures.

## YAML

```yaml
plugins:
  - id: detector.scanner_fingerprint
    name: web-scanners
    config:
      scanners: ["nikto", "sqlmap", "nuclei"]
      ban_duration_secs: 259200
```

## Config fields

- `scanners`: user-agent signature substrings.
- `ban_duration_secs`: suggested ban duration in seconds.
