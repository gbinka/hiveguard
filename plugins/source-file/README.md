# source-file

File-backed log source plugin bundle for HiveGuard.

This crate registers four log-source plugin ids:

- `source.file.ssh`
- `source.file.nginx`
- `source.file.postfix`
- `source.file.custom`

Example configuration:

```yaml
plugins:
  - id: source.file.ssh
    config:
      path: /var/log/auth.log

  - id: source.file.nginx
    config:
      path: /var/log/nginx/access.log

  - id: source.file.postfix
    config:
      path: /var/log/mail.log

  - id: source.file.custom
    config:
      path: /var/log/app/security.log
      detector: app_abuse
      pattern: 'FAILED_LOGIN ip=(?P<ip>\S+) user=(?P<user>\S+)'
```

All file-backed sources persist offsets under the plugin `data_dir` so they can
resume after restart.

## nginx event metadata

`source.file.nginx` parses the `combined` format and sets `metadata` keys
`path`, `method`, `user_agent`, `status_code` and — when the log line ends with
an extra quoted field such as `"$host"` (e.g. `log_format` `... "$http_user_agent" "$host"`) —
`vhost` (lower-cased; `-`/empty ignored). `detector.campaign` and
`detector.webshell_probe` use `vhost` (per-vhost keys, `ignore_vhosts`).
