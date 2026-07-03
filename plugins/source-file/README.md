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
