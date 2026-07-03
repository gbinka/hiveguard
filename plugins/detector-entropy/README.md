# detector.entropy

Detects anomalous entropy patterns in HTTP payload paths and query strings.

## YAML

```yaml
plugins:
  - id: detector.entropy
    name: entropy-main
    config:
      score_threshold: 25.0
      benign_penalty: 30.0
      error_response_multiplier: 1.5
      min_entropy: 5.5
      max_entropy: 6.5
```

## Config fields

- `score_threshold`: composite anomaly threshold.
- `benign_penalty`: score reduction for known benign patterns.
- `error_response_multiplier`: multiplier for 4xx/5xx responses.
- `min_entropy` / `max_entropy`: legacy compatibility fields.
