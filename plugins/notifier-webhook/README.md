# notifier-webhook

Generic HTTP webhook notifier for HiveGuard. POSTs alert events as JSON (or a
rendered template) to a configurable URL.

This plugin is the **reference end-to-end implementation** — when in doubt
about plugin structure, look here first.

## Configuration

```yaml
plugins:
  - id: notifier.webhook
    name: ops-ingest
    config:
      url: "https://example.com/hooks/hiveguard"
      method: POST                       # POST | PUT (default: POST)
      content_type: application/json     # default: application/json
      auth_header: "Bearer ${env:WEBHOOK_TOKEN}"
      timeout_secs: 10                   # default: 10
      events: [IpBanned, HoneypotHit]    # optional filter
      template: |                        # optional; default = full JSON event
        {"text": "Banned {{ip}}: {{reason}}"}
```

## Template variables

Available in `template` strings:

| Variable | Source events |
|----------|--------------|
| `{{type}}` | All — snake-case event kind |
| `{{ip}}` | `IpBanned`, `HighThreatDetected`, `HoneypotHit` |
| `{{subnet}}` | `SubnetBanned` |
| `{{ip_count}}` | `SubnetBanned` |
| `{{severity}}` | `IpBanned` |
| `{{reason}}` | `IpBanned`, `SubnetBanned`, `PeerQuarantined` |
| `{{country}}` | `IpBanned` (GeoIP) |
| `{{asn}}` | `IpBanned` (GeoIP) |
| `{{node_id}}` | `PeerDown`, `PeerQuarantined` |
| `{{address}}` | `PeerDown` |
| `{{score}}` | `HighThreatDetected` |
| `{{top_detectors}}` | `HighThreatDetected` (comma-separated) |
| `{{path}}` | `HoneypotHit` |
| `{{bans_per_minute}}` | `BanRateAnomaly` |
| `{{threshold}}` | `BanRateAnomaly` |

Unknown placeholders are preserved literally.

## When to use

- You want HiveGuard to push alerts somewhere not covered by a dedicated
  notifier plugin (custom internal tool, MQTT bridge, ServiceNow, etc.).
- You're prototyping a new integration before writing a dedicated plugin.
- You want a "tee" to log alerts to a generic ingestion endpoint.

For Slack / Teams / Discord / PagerDuty, prefer the dedicated plugin which
formats the payload natively (richer cards, deduplication keys, etc.).
