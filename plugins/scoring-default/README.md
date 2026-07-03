# scoring.default

Default weighted sliding-window accumulator scoring engine.

## Config example

```yaml
plugins:
  - id: scoring.default
    name: default-score
    config:
      accumulation_window_secs: 1800
      ban_severity_threshold: 100
      default_ban_duration_secs: 86400
```
