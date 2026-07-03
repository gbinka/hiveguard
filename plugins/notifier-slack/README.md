# notifier.slack

Slack notifier using incoming webhooks. Formats events with Slack mrkdwn.

```yaml
plugins:
  - id: notifier.slack
    config:
      webhook_url: "${env:SLACK_WEBHOOK}"
      channel: ops-security
      username: HiveGuard
      icon_emoji: ":no_entry:"
```

For Block Kit / rich card layouts, use `notifier.webhook` with a custom
`template` instead.
