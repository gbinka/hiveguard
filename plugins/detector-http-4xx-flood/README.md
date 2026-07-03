# detector.http_4xx_flood

Detects high-rate HTTP 4xx responses from a single source IP.

## Config example

```yaml
plugins:
  - id: detector.http_4xx_flood
    name: web-4xx
    config:
      threshold: 50
      window_secs: 60
      ban_duration_secs: 3600
```
