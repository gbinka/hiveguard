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

Signal weight: severity 120 × confidence 0.85 = 102, i.e. **one signal bans**
under the default `scoring.default` threshold (100). Before 2026-10 the
confidence was 0.8 (= 96), so the detector needed a second signal in the
scoring window and most floods (e.g. the WordPress `batch/v1` exploit wave)
were never banned by it alone.
