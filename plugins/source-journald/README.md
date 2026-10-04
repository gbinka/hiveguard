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
      units: [sshd.service]   # optional unit filter
      priority: 5                            # syslog priority threshold (default 7=all)
      ip_field: MESSAGE                      # field to scan for IPs (default MESSAGE)
      ip_pattern: 'from (?P<ip>[0-9a-fA-F.:]+)'  # optional regex with named (?P<ip>) capture
      since_boot: false                      # replay since boot before following
      event_type: AuthFailure                # fallback label for non-SSH services
```

For SSH services, the source validates journald's `_COMM` (`sshd`,
`sshd-session` or `sshd-auth`) and `_UID` (`0`) before parsing `MESSAGE`.
It uses the same parser as `source.file.ssh`: the address comes from the
connection suffix, accepted authentication produces `AuthSuccess`, and
invalid users carry `invalid_user=true`. Connection-close and PAM diagnostics
are ignored. For SSH, `ip_pattern` is only an additional message filter;
it cannot override the parsed connection address or event type. Forwarded
SSH records without these trusted identity fields are ignored.

For other services, `event_type` remains the configured label. If
`ip_pattern` is omitted, the first IPv4/IPv6 token in the chosen field is
used. Lines without a parseable IP are dropped.

## Requirements

The `journalctl` binary must be available on `$PATH`. The HiveGuard daemon
user needs read permission for `/var/log/journal/*` (typically `systemd-journal`
group, see `man systemd.journal-fields`).

## Operational notes

- This plugin spawns one `journalctl --follow` process per active config.
  On shutdown or read failure, the child is killed and reaped.
- If `journalctl` exits unexpectedly, the plugin returns `Err`. The host's
  supervisor must restart the source. A restart of the same plugin instance
  resumes after its last processed journal cursor, avoiding replay of the
  default journal tail. The cursor is held in memory, not persisted across
  daemon restarts. `since_boot: false` starts at new entries only;
  `since_boot: true` explicitly replays this boot.
- For a non-Linux host (no journalctl), this plugin will fail at startup
  with a clear error — fail-loud rather than silent degrade.
