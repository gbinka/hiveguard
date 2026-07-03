# Notifier plugin

Push alerts to humans through chat, paging, email, webhooks. Reference impl:
[`plugins/notifier-webhook/`](../../plugins/notifier-webhook/).

> Before reading this: finish [AUTHORING.md](./AUTHORING.md).

## Trait

```rust
#[async_trait]
pub trait NotifierPlugin: Plugin {
    async fn notify(&self, event: &AlertEvent) -> PluginResult<()>;
    fn supports(&self, _kind: AlertKind) -> bool { true }
}
```

## What the host guarantees

- `notify` is called **after** filtering against `supports(kind)`.
- Deduplication and cooldown windows are handled by the dispatcher in
  `hiveguard-host` — your plugin sees every event the dispatcher decides to
  emit, without further suppression.
- Multiple notifications may be in flight concurrently. **`notify` must be
  safe to call from multiple tasks at once.** That's why the signature is
  `&self`, not `&mut self`.
- Retry policy lives in the dispatcher. If your `notify` returns `Err`, the
  dispatcher will retry with exponential back-off (5 s → 30 s → 2 min → 10
  min, max 4 attempts) before dropping. **Do not retry inside `notify`.**

## What you implement

### 1. Render the payload

`AlertEvent` is a tagged enum with seven variants. Use a `match` to render
each one for your channel's format. The simplest plugins serialize to JSON
and POST; richer ones produce a Markdown / BlockKit / AdaptiveCard payload.

```rust
fn render_slack(event: &AlertEvent) -> serde_json::Value {
    match event {
        AlertEvent::IpBanned { ip, severity, reason, .. } => json!({
            "text": format!(":no_entry: Banned {ip} (severity {severity}): {reason}"),
        }),
        AlertEvent::HoneypotHit { ip, path } => json!({
            "text": format!(":honeybee: Honeypot {path} hit from {ip}"),
        }),
        // … other variants
        _ => json!({ "text": format!("HiveGuard alert: {:?}", event.kind()) }),
    }
}
```

### 2. Deliver

Use the HTTP client from `hiveguard-plugin-utils`:

```rust
use hiveguard_plugin_utils::http::build_client;

let client = build_client(timeout_secs)?;
let resp = client.post(&self.webhook_url).json(&payload).send().await
    .map_err(|e| PluginError::Runtime(e.to_string()))?;
if !resp.status().is_success() {
    return Err(PluginError::Runtime(format!("HTTP {}", resp.status())));
}
```

### 3. Filter (optional)

If your channel only makes sense for some alert kinds (e.g. pager only for
`HighThreatDetected`), override `supports`:

```rust
fn supports(&self, kind: AlertKind) -> bool {
    matches!(kind, AlertKind::HighThreatDetected | AlertKind::HoneypotHit)
}
```

Users can additionally narrow via config (`events: [IpBanned, HoneypotHit]`)
— that's enforced by the dispatcher, not your plugin. `supports` is for
hard-coded restrictions inherent to the channel.

## Config

Common fields used by webhook-style notifiers:

| Field | Type | Purpose |
|-------|------|---------|
| `url` | string (uri) | Destination endpoint |
| `events` | array of `AlertKind` | Whitelist of event kinds (optional) |
| `severity_min` | int 0-255 | Minimum severity to forward (optional) |
| `template` | string | Optional payload template with `{{ip}}`, `{{reason}}`, … |
| `timeout_secs` | int 1-300 | HTTP timeout |
| `auth_header` | string | Optional `Authorization` header value |

Render templates with `hiveguard_plugin_utils::template::render(template, &ctx)`.

## Metrics

Recommended (the dispatcher emits the global ones, but per-plugin granularity
is nice):

```
hiveguard_plugin_notifier_<name>_sent_total
hiveguard_plugin_notifier_<name>_failed_total
hiveguard_plugin_notifier_<name>_duration_seconds (histogram)
```

## Common pitfalls

- **Don't retry inside `notify`.** The dispatcher does it.
- **Don't block on user-controlled URLs without timeout** — always set a
  reasonable `timeout_secs` default.
- **Don't log payloads.** Alert events contain IP addresses; channel
  webhooks may be sensitive. Use `debug!` at most, never `info!`.
- **Mind your channel's rate limits.** Slack's incoming webhook caps at
  1 req/sec per webhook. The dispatcher's global cooldown helps, but you may
  want to surface 429 responses as `Err` so the dispatcher backs off.

## Channel-specific notes

### Slack
- Webhook returns 200 + body "ok" on success, plain text 4xx on failure.
- Use [Block Kit](https://api.slack.com/block-kit) for rich layouts.

### Microsoft Teams
- Incoming webhook expects [Adaptive Card](https://adaptivecards.io/) wrapped
  in `{"type": "message", "attachments": [{"contentType": "application/vnd.microsoft.card.adaptive", "content": <card>}]}`.
- Hard 28 KB payload limit.

### PagerDuty
- Use [Events API v2](https://developer.pagerduty.com/api-reference/368ae3d938c9e-send-an-event-to-pager-duty);
  requires `routing_key`, `event_action`, `payload`.
- For `dedup_key`, use `format!("{plugin_id}:{alert_dedup_key}")`.

### Generic webhook
- Already implemented — see `plugins/notifier-webhook/`. Use it as the
  fallback for any HTTP target.
