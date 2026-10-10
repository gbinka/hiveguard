# detector.campaign

Cross-IP **login campaign** detector: distributed low-and-slow credential
stuffing where a proxy pool spreads `POST /wp-login.php` over thousands of IPs
(a few requests per IP per day, every response `200`). Per-IP detectors
(`http_login_bruteforce`, `http_4xx_flood`, `http_flood`) are blind to it.

Logic: `hiveguard-core/src/detectors/campaign.rs`. Ban/detector name in
`/api/bans[].source`: `detector:campaign`.

## How it works

Requests whose method is in `methods` and whose path (query ignored,
case-insensitive prefix) is in `paths` are grouped by a **fingerprint**:

- `UA + method + endpoint` (always on);
- `vhost + method + endpoint` (only when `vhost_min_distinct_ips > 0`; needs the
  trailing `"$host"` field in the nginx log — `source.file.nginx` exposes it as
  `metadata.vhost`).

When one fingerprint reaches `min_distinct_ips` distinct IPs **and**
`min_requests` requests inside `window_secs`, the campaign becomes **hot** for
`hot_secs` (extended by every new hit):

- every IP seen in the window is banned retroactively (`retro_ban`, at most
  `max_retro_bans`, drained `retro_batch` per processed event so a 400-IP
  campaign does not stall the pipeline with 400 consecutive nft syncs);
- every new IP with that fingerprint is banned on its first hit while hot.

Bans are host-scoped (`/32`, `/128`) — never subnets. Signal severity 200 ×
confidence 0.9 = 180, i.e. one signal is enough for `scoring.default`
(threshold 100). Whitelisted IPs are protected by the pipeline as usual.

Protections against false positives:
- `ignore_redirects` (default true): `3xx` is skipped; a successful WordPress
  login answers `302`, so real users who log in correctly are never counted.
- `ignore_user_agents` (case-insensitive substrings), default
  `Googlebot, bingbot, Jetpack, WordPress/, UptimeRobot`
  (`WordPress/` = the site's own loopback / cron). `extra_ignore_user_agents`
  appends without retyping the defaults — add your own uptime monitor's UA there.
- `ignore_vhosts`: vhosts never counted.
- While a campaign keyed on a very common browser UA is hot, a real user with
  that exact UA who *fails* a login would be banned too — keep
  `min_distinct_ips` well above the number of distinct people failing a login
  in `window_secs` across all your sites.

Memory: `max_keys` fingerprints (LRU-ish eviction, hot keys kept), each with at
most `max_hits_per_key` remembered hits; flagged sets ≤ 50k IPs per campaign;
retro queue ≤ 20k. Only matching requests (login POSTs) create state.

## YAML

```yaml
plugins:
  - id: detector.campaign
    config:
      paths: ["/wp-login.php", "/xmlrpc.php"]   # default
      methods: ["POST"]                          # default
      window_secs: 1800                          # default
      min_distinct_ips: 20                       # default
      min_requests: 30                           # default
      hot_secs: 21600                            # default (6 h)
      ban_duration_secs: 86400                   # default (24 h, still replicates to peers)
      extra_ignore_user_agents: []
      ignore_vhosts: []
      ignore_redirects: true
      vhost_min_distinct_ips: 0                  # 0 = off
      retro_ban: true
      max_retro_bans: 2000
      retro_batch: 32
      max_keys: 5000
      max_hits_per_key: 4096
```

All keys are optional. `ignore_user_agents` *replaces* the default list.

## Pipeline contract

This is the first detector that returns several signals per event
(`DetectorPlugin::process_multi`, default-implemented for all other
detectors). The pipeline attaches the event's GeoIP data (and the datacenter
severity multiplier) only to signals/bans about the event's own source IP.
