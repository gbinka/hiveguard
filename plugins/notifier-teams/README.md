# notifier.teams

Microsoft Teams notifier using incoming webhooks with Adaptive Card payload.

```yaml
plugins:
  - id: notifier.teams
    config:
      webhook_url: "${env:TEAMS_WEBHOOK}"
```

Payload uses minimal Adaptive Card 1.4 with a single `TextBlock`. For richer
cards, use `notifier.webhook` with a custom `template`.
