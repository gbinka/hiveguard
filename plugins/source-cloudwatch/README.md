# source.cloudwatch

AWS CloudWatch Logs poller log source. Wraps the legacy
`hiveguard_queue::CloudWatchSource`. Per-log-group cursor state is
persisted in the plugin's `data_dir`.

Full config shape: `hiveguard_core::config::CloudWatchSourceConfig`.

```yaml
plugins:
  - id: source.cloudwatch
    config:
      log_group_names: ["/aws/lambda/api", "/aws/ec2/edge"]
      region: eu-west-1
      parser: rfc5424
      poll_interval_secs: 30
```
