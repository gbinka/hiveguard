# detector.timing

Detects bot-like request cadence from low inter-arrival-time variance.

## YAML

```yaml
plugins:
  - id: detector.timing
    name: timing-main
    config:
      window_secs: 60
      min_samples: 10
      stddev_threshold_ms: 50.0
```

## Config fields

- `window_secs`: rolling timing window in seconds.
- `min_samples`: minimum events required before evaluation.
- `stddev_threshold_ms`: max stddev considered bot-like.
