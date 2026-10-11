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

- `ipv6_prefix` (default `64`): IPv6 failures are counted per /64 and the ban
  covers that /64, so rotating addresses inside one /64 does not reset the
  counter. `0` or `128` = per address; otherwise `48..128`. IPv4 is unchanged
  (per address).
