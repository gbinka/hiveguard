# detector.ssh_bruteforce

Detects SSH brute-force and user-enumeration patterns.

## Config example

```yaml
plugins:
  - id: detector.ssh_bruteforce
    name: ssh-main
    config:
      threshold: 5
      window_secs: 300
      ban_duration_secs: 86400
      enum_threshold: 3
      enum_window_secs: 120
      enum_ban_duration_secs: 172800
```
