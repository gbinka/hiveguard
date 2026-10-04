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
      trusted_senders: ["10.20.0.5/32"]
      routes:
        - match: { app_name: kernel }
          parser: iptables

  - id: source.syslog.tcp
    config:
      listen: 0.0.0.0:601
      trusted_senders: ["10.20.0.5/32"]

  - id: source.syslog.tls
    config:
      listen: 0.0.0.0:6514
      cert: /etc/hiveguard/cert.pem
      key: /etc/hiveguard/key.pem
      ca_cert: /etc/hiveguard/ca.pem
```

User routes are evaluated in order; built-in defaults still map `sshd`,
`nginx`, and `postfix` payloads to the legacy normalizers.

Without `ca_cert`, all transports accept loopback peers only by default.
Remote UDP/TCP collectors must be explicitly listed in `trusted_senders` as
CIDRs, including when upgrading an existing configuration. The ACL applies to
the actual transport peer, before parsing the message. An empty list denies all.
With TLS `ca_cert`, a valid client certificate is required; `trusted_senders`
can additionally restrict those authenticated peers. UDP source addresses can
be spoofed, so use mTLS or an isolated trusted network for remote collectors.

Both newline and octet-counted frames are limited to 65,535 bytes. Each frame
must complete within 30 seconds, and TLS handshakes within 10 seconds. Oversized
or stalled streams are closed. UDP rate-limit bookkeeping is bounded to 10,000
senders; up to 1,000 simultaneous TCP/TLS connections are accepted per listener.
