# detector.scanner_fingerprint

Detects known scanner user-agent signatures.

## YAML

```yaml
plugins:
  - id: detector.scanner_fingerprint
    name: web-scanners
    config:
      scanners: ["nikto", "sqlmap", "nuclei"]
      ban_duration_secs: 259200
```

## Config fields

- `scanners`: user-agent signature substrings.
- `ban_duration_secs`: suggested ban duration in seconds.
- `extra_scanners`: appended to `scanners` (or to the built-in defaults when
  `scanners` is not set) — the easiest way to add signatures on a host whose
  config already overrides the list.
- `ipv6_prefix` (default `64`): ban the scanner's whole /64 (`0`/`128` = per
  address; otherwise `48..128`).

Matching is a case-insensitive substring of the `User-Agent`.

Built-in defaults (used when `scanners` is absent): `nikto sqlmap nuclei
nessus openvas w3af skipfish wpscan dirbuster gobuster masscan zgrab wp2shell
cve-20 l9scan l9explore infrawatch pbx-scanner censysinspect odin-scanner
modatscanner`, plus exploit payloads carried in the UA itself: `jndi:`
(Log4Shell), `/etc/passwd`, `win.ini`, `boot.ini`, `() {` (Shellshock),
`sleep(` (time-based SQLi), `<script` (XSS). None of these occurs in browser
or search-engine UAs.

**Production configs that set `scanners:` explicitly do not get the new
defaults.** Add them with `extra_scanners` (binary with this key first):

```yaml
      extra_scanners: ["wp2shell", "cve-20", "l9scan", "l9explore", "infrawatch",
                       "pbx-scanner", "censysinspect", "odin-scanner", "modatscanner",
                       "jndi:", "/etc/passwd", "win.ini", "boot.ini", "() {", "sleep(", "<script"]
```
