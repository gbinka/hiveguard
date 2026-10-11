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

### Subnet aggregation (UA-rotating botnets)

A botnet spreading `POST /wp-login.php` over 50 addresses of one /24, each with
a different User-Agent, stays under the per-IP `threshold` and is invisible to
`detector.campaign` (which groups by UA). With subnet aggregation every POST is
also counted per subnet:

- `subnet_v4_prefix`: IPv4 subnet prefix, e.g. `24`; `0` = off (default).
  Allowed `0` or `16..32`.
- `subnet_v6_prefix`: IPv6 prefix, e.g. `64`; `0` = off (default). Allowed `0`
  or `48..128`.
- `subnet_threshold`: POSTs from one subnet within `window_secs` (default 20;
  `0` disables subnet aggregation).
- `subnet_min_distinct_ips`: distinct addresses required in that subnet
  (default 5) — a single noisy host never bans its neighbours (it is banned
  per IP anyway).

When both are reached the signal's `source_ip` is the whole truncated subnet
(`100.64.53.0/24`), severity 180 × confidence 0.9 = 162 ≥ 100, so the scoring
engine bans the subnet (the broadest prefix in the bucket wins). Peers
replicate at most a /24 (v4) / /48 (v6).

```yaml
      subnet_v4_prefix: 24
      subnet_v6_prefix: 64
      subnet_threshold: 20
      subnet_min_distinct_ips: 5
```

False positives: an office/university NAT pool in one /24 with 5+ users
failing WordPress logins 20 times in 10 minutes. Keep the feature off on sites
whose editors share such a network, or whitelist that network.
