# source-syslog

Network syslog source plugin bundle for HiveGuard.

This crate registers three log-source plugin ids:

- `source.syslog.udp`
- `source.syslog.tcp`
- `source.syslog.tls`

Example configuration:

```yaml
plugins:
  - id: source.syslog.udp
    config:
      listen: 0.0.0.0:514
      routes:
        - match: { app_name: kernel }
          parser: iptables

  - id: source.syslog.tcp
    config:
      listen: 0.0.0.0:601

  - id: source.syslog.tls
    config:
      listen: 0.0.0.0:6514
      cert: /etc/hiveguard/cert.pem
      key: /etc/hiveguard/key.pem
      ca_cert: /etc/hiveguard/ca.pem
```

User routes are evaluated in order; built-in defaults still map `sshd`,
`nginx`, and `postfix` payloads to the legacy normalizers.
