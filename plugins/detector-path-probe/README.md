# detector.path_probe

Detects requests to suspicious paths like `/wp-login.php` and `/.env`.

## Config example

```yaml
plugins:
  - id: detector.path_probe
    name: web-probe
    config:
      paths: ["/wp-login.php", "/xmlrpc.php", "/.env", "/phpmyadmin", "/wp-admin"]
      ban_duration_secs: 259200
```

A single hit bans (severity 200 × confidence 0.95). Four kinds of patterns:

| key | match | default |
|---|---|---|
| `paths` | `starts_with` on the raw request target (query included), case-sensitive — unchanged | `/wp-login.php /xmlrpc.php /.env /phpmyadmin /wp-admin` |
| `segment_paths` | case-insensitive, anywhere in the path (query excluded; also after one percent-decode), on a **segment boundary**: the pattern starts a segment and is followed by end, `/`, `.`, `-`, `_` or `~` | `/.git /.svn /.hg /.env /.aws /.ssh /.DS_Store /.htpasswd /vendor/phpunit` |
| `query_patterns` | case-insensitive substring of the query string, checked raw and after one and two percent-decodes | `pearcmd peclcmd allow_url_include auto_prepend_file /etc/passwd /proc/self/environ win.ini ..%2f php://filter php://input jndi:` |
| `exact_paths` | path without query, trailing `/` ignored, case-insensitive, exact | `/mcp /api/mcp /v1/models` |

`segment_paths`, `query_patterns` and `exact_paths` are **on by default even
when `paths` is overridden**; set a list to `[]` to disable it.
`ipv6_prefix` (default `128` = per address; `48..128` allowed) widens the
IPv6 ban subject.

Examples caught: `/kontakt/.git/config`, `/app/.env.bak`,
`/?pagename=templates%252f%252e%252e…/usr/lib/php/peclcmd`,
`/cgi-bin/php-cgi?-d+allow_url_include%3d1…`, `?file=..%2f..%2fetc%2fpasswd`,
`${jndi:ldap://…}`, `/mcp`.

Why the defaults are safe (no false positives expected):

- Segment patterns are dot-directories / files that are never linked from a
  site (VCS metadata, credentials, macOS metadata, `vendor/phpunit` which only
  exists in dev installs); the boundary rule keeps `/.github/`,
  `/.gitignore-tips`, `/.environment` out.
- Query patterns are exploit primitives (PEAR/PECL LFI→RCE, PHP-CGI argument
  injection, traversal to system files, PHP stream wrappers, Log4Shell). A
  plain `../` is **not** a pattern (some apps pass relative return paths);
  `..%2f` only appears when traversal is URL-encoded. Residual risk: a site
  search for the literal text `/etc/passwd` or `win.ini` (e.g. a Linux
  tutorial blog) — override `query_patterns` there.
- `batch/v1` is deliberately absent: the WordPress block editor calls
  `/wp-json/batch/v1`.
- `exact_paths` targets reconnaissance for exposed MCP servers and
  OpenAI-compatible LLM APIs. Exact matching means `/mcp-news` or
  `/blog/mcp` never match. **Set `exact_paths: []` on hosts that serve MCP or
  an LLM API.** Not included on purpose: `/.well-known/mcp` and `/llms.txt`
  (legitimate discovery files AI agents fetch on behalf of users) and `/sse`
  (too generic, used by real streaming endpoints).

```yaml
  - id: detector.path_probe
    config:
      paths: ["/wp-login.php", "/xmlrpc.php", "/.env", "/phpmyadmin", "/wp-admin"]
      segment_paths: ["/.git", "/.svn", "/.hg", "/.env", "/.aws", "/.ssh", "/.DS_Store", "/.htpasswd", "/vendor/phpunit"]
      query_patterns: ["pearcmd", "peclcmd", "allow_url_include", "auto_prepend_file", "/etc/passwd", "/proc/self/environ", "win.ini", "..%2f", "php://filter", "php://input", "jndi:"]
      exact_paths: ["/mcp", "/api/mcp", "/v1/models"]
      ipv6_prefix: 128
      ban_duration_secs: 259200
```
