# source.kinesis

AWS Kinesis Data Streams consumer log source. Wraps the legacy
`hiveguard_queue::KinesisSource`. Shard cursors are persisted in the
plugin's `data_dir` for at-least-once delivery across restarts.

Full config shape: `hiveguard_core::config::KinesisSourceConfig`.

```yaml
plugins:
  - id: source.kinesis
    config:
      stream_name: hiveguard-edge
      region: eu-west-1
      parser: rfc5424
```

## AWS credentials

Picked up from the default AWS credential chain (env vars, instance profile,
~/.aws/credentials). Pass static credentials via `${env:AWS_ACCESS_KEY_ID}`
in config only if you really must.
