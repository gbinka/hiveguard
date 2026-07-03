# notifier.discord

Discord webhook notifier. Sends `{"content": "..."}` payload to a Discord
webhook URL.

```yaml
plugins:
  - id: notifier.discord
    config:
      webhook_url: "${env:DISCORD_WEBHOOK}"
```

For Discord embeds with colours / fields, use `notifier.webhook` with a
custom `template` that produces the embed structure.
