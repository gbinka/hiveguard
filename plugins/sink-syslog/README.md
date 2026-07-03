# sink.syslog

Forwards `NormalizedEvent`s to a remote syslog server as RFC 5424 messages
over TCP (default) or UDP.

```yaml
plugins:
  - id: sink.syslog
    config:
      host: "log-aggregator.internal:514"
      protocol: tcp
      facility: 1
      severity: 5
      app_name: hiveguard
```

## Wire format

Each `NormalizedEvent` is serialised as JSON and embedded in an RFC 5424
message:

```
<PRI>1 TIMESTAMP HOST APP-NAME PROCID MSGID STRUCTURED-DATA MSG
```

Where `MSG` is the JSON serialisation of the event. For TCP transport,
messages are framed with octet-counting (RFC 6587).

## Operational notes

- TCP reconnects automatically on disconnect.
- UDP is fire-and-forget; lossy under network stress.
- For high-volume deployments, prefer `sink.elastic` or `sink.splunk`.
