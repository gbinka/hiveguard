# source.rabbitmq

RabbitMQ AMQP 0-9-1 consumer log source. Wraps the legacy
`hiveguard_queue::RabbitMqSource` behind the plugin contract.

Full config shape: `hiveguard_core::config::RabbitMqSourceConfig`.

```yaml
plugins:
  - id: source.rabbitmq
    config:
      amqp_url: "amqps://user:${env:RMQ_PASSWORD}@host:5671/vhost"
      queue: hiveguard.events
      parser: rfc5424
```
