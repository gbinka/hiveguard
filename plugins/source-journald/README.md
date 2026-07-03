# source.journald

Tails the systemd journal by spawning `journalctl -f -o json` and parses
each JSON line into a `NormalizedEvent`.

## When to use

- Linux deployments where logs are centralised in journald (most modern
  systemd-based distros).
- Sources that don't have a stable on-disk log file (services using
  `StandardOutput=journal`).

## Configuration

```yaml
plugins:
  - id: source.journald
    config:
      units: [sshd.service, nginx.service]   # optional unit filter
      priority: 5                            # syslog priority threshold (default 7=all)
      ip_field: MESSAGE                      # field to scan for IPs (default MESSAGE)
      ip_pattern: 'from (?P<ip>[0-9a-fA-F.:]+)'  # optional regex with named (?P<ip>) capture
      since_boot: false                      # replay since boot before following
      event_type: AuthFailure                # EventType label
```

If `ip_pattern` is omitted, the first IPv4/IPv6 substring found in the
chosen field is used. Lines without a parseable IP are dropped silently
(visible only at `tracing` `debug` level).

## Requirements

The `journalctl` binary must be available on `$PATH`. The HiveGuard daemon
user needs read permission for `/var/log/journal/*` (typically `systemd-journal`
group, see `man systemd.journal-fields`).

## Operational notes

- This plugin spawns one `journalctl --follow` process per active config.
  On shutdown, the process is sent SIGTERM via tokio's `Child::kill`.
- If `journalctl` exits unexpectedly, the plugin returns `Err`. The host's
  `RestartPolicy` then restarts the plugin with exponential backoff.
- For a non-Linux host (no journalctl), this plugin will fail at startup
  with a clear error — fail-loud rather than silent degrade.
