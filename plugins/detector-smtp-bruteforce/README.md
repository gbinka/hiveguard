# detector.smtp_bruteforce

Detects repeated SMTP auth failures from one source IP.

## YAML

```yaml
plugins:
  - id: detector.smtp_bruteforce
    name: mail-auth-bf
    config:
      threshold: 5
      window_secs: 300
      ban_duration_secs: 86400
```

## Config fields

- `threshold`: auth failure threshold.
- `window_secs`: sliding window in seconds.
- `ban_duration_secs`: suggested ban duration in seconds.
