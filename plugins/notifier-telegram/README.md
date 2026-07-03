# notifier.telegram

Telegram Bot API notifier. Sends `sendMessage` POST to the bot's API endpoint.

```yaml
plugins:
  - id: notifier.telegram
    config:
      bot_token: "${env:TG_BOT_TOKEN}"
      chat_id: "-1001234567890"      # use @userinfobot to find chat id
      parse_mode: Markdown
```

Get a bot token from [@BotFather](https://t.me/BotFather).
