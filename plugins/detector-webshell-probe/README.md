# detector.webshell_probe

Detects **webshell / backdoor filename probing**: a scanner requesting many
distinct random-looking PHP files (`/0.php`, `/bro.php`, `/scx.php7/`,
`/wp-content/plugins/hellopress/wp_filemanager.php`, `/3PJcpMFsD8B.php`, …),
slowly and often twice (http → 301, https → 404). Works **regardless of the
status code**, so catch-all vhosts that answer `200` for every path do not
hide the probe. `path_probe` only knows a fixed list; the rate detectors never
trip on ~1 request per minute.

Logic: `hiveguard-core/src/detectors/webshell_probe.rs`. Ban/detector name:
`webshell_probe`.

## Scoring

Per source IP, over a sliding `window_secs`, each **distinct** PHP-like path
(`.php`, `.php3`–`.php9`, `.phtml`, `.phar`, `.pht`, `.phps`; query string and
trailing `/` ignored) that is **not** a legit entry point scores:

| feature | points |
|---|---|
| base, response not 2xx | 1.0 |
| base, response 2xx | 0.5 |
| empty User-Agent (`-`) | +1.0 |
| unusual extension (`.php7`, `.phtml`, `.PhP`) or trailing `/` | +1.5 |
| random/shell-like name (all digits, ≥8 chars mixed case+digits, `wso`, `alfa`, `filemanager`, `shell`, …) | +1.0 |
| under `/wp-content/uploads/` | +2.0 |
| same path probed by ≥ `shared_path_min_ips` other IPs in the window | +1.0 |

Fires when distinct paths ≥ `min_distinct_paths` **and** score ≥
`score_threshold`, then resets the IP. A repeated path is counted once.

Legit paths (default, replace with `legit_paths` or append with
`extra_legit_paths`):
`/index.php` (exact), basenames `wp-login.php wp-cron.php xmlrpc.php
wp-comments-post.php wp-signup.php wp-activate.php wp-trackback.php
wp-links-opml.php wp-mail.php` at any depth outside `/wp-content/`, and any
path containing `/wp-admin/`, `/wp-json/`, `/wp-includes/js/tinymce/`.
Rule syntax: `/dir/` = segment anywhere, `/x.php` = exact path, `x.php` =
basename.

Crawlers are skipped by UA substring (`ignore_user_agents`, default Googlebot,
bingbot, YandexBot, DuckDuckBot, Applebot; `extra_ignore_user_agents` appends). A legacy non-WordPress
PHP site can be excluded with `ignore_vhosts` (needs the `"$host"` field in the
nginx log). A visitor with a browser UA browsing a legacy PHP site scores 0.5
per page, i.e. needs 24 distinct pages in the window to reach 12.

Memory: ≤ `max_tracked_ips` IPs × ≤ 256 paths, ≤ `max_tracked_paths` shared
path entries; expired state swept every 4096 matching events, oldest 10 %
evicted when full. Only PHP-like non-legit requests create state.

## YAML

```yaml
plugins:
  - id: detector.webshell_probe
    config:
      window_secs: 21600        # default 6 h
      min_distinct_paths: 6     # default
      score_threshold: 12       # default
      ban_duration_secs: 259200 # default 72 h
      extra_legit_paths: []
      extra_ignore_user_agents: []
      ignore_vhosts: []
      shared_path_min_ips: 3    # default, 0 = off
      max_tracked_ips: 50000
      max_tracked_paths: 20000
```
