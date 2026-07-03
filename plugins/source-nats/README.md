# source.nats

NATS / JetStream consumer log source. Wraps the legacy
`hiveguard_queue::NatsSource` behind the plugin contract.

Supports both core NATS pub/sub and JetStream pull consumers (set
`jetstream` block in config). Authentication via `.creds` files
(NKey+JWT) or TLS.

Full config shape: `hiveguard_core::config::NatsSourceConfig`.

```yaml
plugins:
  - id: source.nats
    config:
      servers: ["nats://nats:4222"]
      subject: "logs.>"
      parser: rfc5424
```
