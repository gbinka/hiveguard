# detector.http_login_bruteforce

Threshold-based detector for POST brute-force attempts on login endpoints.

## YAML

```yaml
plugins:
  - id: detector.http_login_bruteforce
    name: web-login-bf
    config:
      paths: ["/wp-login.php", "/xmlrpc.php"]
      threshold: 5
      window_secs: 600
      ban_duration_secs: 86400
```

## Config fields

- `paths`: monitored login paths.
- `threshold`: request count threshold.
- `window_secs`: sliding window in seconds.
- `ban_duration_secs`: suggested ban duration in seconds.
