# source.kafka

Apache Kafka consumer log source. Wraps the legacy `hiveguard_queue::KafkaSource`
behind the plugin contract.

## Configuration

The `config` block is forwarded as-is to `hiveguard_core::config::KafkaSourceConfig`.
See the legacy docs or `hiveguard-core/src/config.rs` for the full schema
(SASL, TLS, per-topic routing, backpressure).

Minimal example:

```yaml
plugins:
  - id: source.kafka
    config:
      brokers: ["broker1:9092", "broker2:9092"]
      topics:
        - name: syslog-edge
          format: syslog
          parser: rfc5424
      group_id: hiveguard-prod
```
