# detector.distributed_crawl

Detects a **distributed crawl through residential proxies**: about one request
per IP, tens of thousands of IPs a day across hundreds of ASNs, all hitting an
expensive endpoint (catalogue search, faceted shop listings). Per-IP and
per-subnet bans cannot stop such traffic, so this detector **never bans and
never emits a detection signal**. It switches an *under attack* state that the
web server acts on (e.g. a JavaScript/cookie challenge only while the flag is
up).

Logic: `hiveguard-core/src/detectors/distributed_crawl.rs`.

## How it counts

Over a sliding `window_secs` it counts distinct sources (IPv4 address, IPv6
`/ipv6_prefix`) that

1. request a path starting with one of `path_prefixes` (raw request target,
   query included, case-sensitive),
2. were **not seen at all** (any HTTP request) within `fresh_ip_memory_secs` —
   a returning visitor or someone who opened the home page first is not
   "fresh",
3. with `exclude_static_fetchers` (default on): did not fetch a static asset
   (`static_extensions`, default `.css .js .png .woff2 …`) afterwards inside
   the window — a browser rendering the page does, an HTML-only crawler does
   not. If your assets come from a CDN, this exclusion simply never triggers,
4. with `require_no_referer` (default off): carry no `Referer`. The built-in
   nginx parser does not extract the referer yet, so this only works with a
   source that fills the `referer` metadata key.

State machine with hysteresis: **ON** when the count is `> fresh_ip_threshold`;
**OFF** again when the count stays `< off_threshold` for `cooldown_secs`.
Evaluated every `eval_interval_secs` by a background task (the event pipeline
only records; no file I/O on the hot path), using wall-clock time, so replaying
old log lines after a restart does not raise a false alarm.

Memory is bounded: remembered sources are two hash-set generations rotated
every `fresh_ip_memory_secs / 2` (or when one reaches `max_tracked_ips / 2`);
candidates are capped at `max_tracked_ips`.

## Actions on a state change

- **Flag file** `flag_file` (default `/run/hiveguard/under_attack`): created
  atomically (temp file + rename, mode 0644) on ON, removed on OFF, removed on
  startup (stale) and on shutdown (fail-open). While ON it is re-created if
  something deletes it. Content: `under_attack since=… fresh_ips=N …`.
  `flag_file: ""` disables the file.
- **Log**: `WARN distributed_crawl: UNDER ATTACK …` / `… attack over …`.
- **Metrics** (`/metrics`): `hiveguard_under_attack{detector="distributed_crawl"}`
  (0/1) and `hiveguard_under_attack_fresh_ips{detector="distributed_crawl"}`
  (last count, also while OFF — use it to tune the threshold).
- **Notifiers**: no alert is sent. `AlertEvent` (plugin API) has no variant
  for a non-ban state change and detector plugins cannot reach the alert
  dispatcher; adding `AlertEvent::UnderAttack` needs a plugin-API change plus
  support in `notifier.webhook`. Until then alert on the gauge (Prometheus /
  Alertmanager) or on the WARN line.

## Config

| key | default | |
|---|---|---|
| `path_prefixes` | — (**required**) | e.g. `/cgi-bin/koha/opac-search.pl`, `/catalogsearch/` |
| `window_secs` | 300 | 10..86400 |
| `fresh_ip_memory_secs` | 86400 | 60..2592000 |
| `fresh_ip_threshold` | 30 | ON when count > this |
| `off_threshold` | `fresh_ip_threshold / 3` | must be ≤ `fresh_ip_threshold` |
| `cooldown_secs` | 900 | |
| `max_tracked_ips` | 500000 | memory bound |
| `exclude_static_fetchers` | true | |
| `static_extensions` | http_flood list | |
| `require_no_referer` | false | |
| `ipv6_prefix` | 64 | 0/128 = per address, else 48..128 |
| `flag_file` | `/run/hiveguard/under_attack` | absolute path, `""` = none |
| `eval_interval_secs` | 5 | 1..300 |

```yaml
plugins:
  - id: detector.distributed_crawl
    config:
      path_prefixes: ["/cgi-bin/koha/opac-search.pl"]
      window_secs: 300
      fresh_ip_threshold: 30
      off_threshold: 10
      cooldown_secs: 900
      flag_file: /run/hiveguard/under_attack
```

Tuning: start with a high `fresh_ip_threshold` (e.g. 1000), watch
`hiveguard_under_attack_fresh_ips` for a few days of normal traffic and under
attack, then set the threshold between the two.

## Where to put the flag (systemd)

The daemon runs with `ProtectSystem=strict`, so it can only write inside
`ReadWritePaths`.

- `hiveguard.service` in the repository: `RuntimeDirectory=hiveguard`
  (mode 0755 by default) and `ReadWritePaths=/var/lib/hiveguard /run/hiveguard`
  → the default `/run/hiveguard/under_attack` works and nginx (www-data) can
  `stat` it. systemd removes the directory when the service stops (fail-open).
- Units created by `scripts/upgrade/fresh_install.py` use
  `RuntimeDirectoryMode=0750` and `UMask=0027`: nginx cannot traverse
  `/run/hiveguard`. Do **not** open that directory (it holds the control
  socket). Use a separate world-readable directory instead:

  ```ini
  # /etc/tmpfiles.d/hiveguard-flags.conf
  d /run/hiveguard-flags 0755 hiveguard hiveguard -
  # systemctl edit hiveguard  →
  [Service]
  ReadWritePaths=/run/hiveguard-flags
  ```

  and set `flag_file: /run/hiveguard-flags/under_attack`.

## nginx example

```nginx
# Challenge only while HiveGuard reports a distributed crawl.
location /cgi-bin/koha/opac-search.pl {
    set $hg_challenge 0;
    if (-f /run/hiveguard/under_attack) { set $hg_challenge 1; }
    if ($cookie_hg_ok = "1") { set $hg_challenge 0; }
    if ($hg_challenge) { return 302 /challenge.html?next=$request_uri; }
    # … normal proxy_pass / fastcgi_pass …
}
```

`/challenge.html` sets the `hg_ok` cookie with a little JavaScript and
redirects back; crawlers that do not execute JavaScript stay out while real
users pass once. A fixed cookie value is the simplest form and easy to copy
once a crawler operator notices it; prefer a signed or rotating value (or a
ready-made challenge such as Anubis, a CAPTCHA, or a stricter `limit_req`),
switched on and off by the same `-f` test.
