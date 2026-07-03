# HiveGuard Plugins — Documentation Index

This directory contains everything a developer (human or agent) needs to write
plugins for HiveGuard. Plugins are how HiveGuard scales from a fail2ban-style
single-node deployment to a multi-node enterprise cluster — every category of
functionality (log sources, enforcers, notifiers, CTI providers, SIEM sinks,
UI frontends, detectors, scoring engines) lives in its own crate under
[`plugins/`](../../plugins/) and registers itself with the host via the
`inventory` crate.

## Start here

1. **[AUTHORING.md](./AUTHORING.md)** — the universal guide. **Read this first.**
   Covers the lifecycle (`Plugin` trait), `PluginDescriptor` registration,
   config validation, secrets, metrics, testing, and the conventions every
   plugin must follow regardless of category.

2. Then read the **category-specific guide** for whatever you're building:

   | Category | Trait | Guide |
   |----------|-------|-------|
   | Log source (file, syslog, MQ, …) | `LogSourcePlugin` | [log_source.md](./log_source.md) |
   | Notifier (Slack, Teams, webhook, …) | `NotifierPlugin` | [notifier.md](./notifier.md) |
   | Enforcer (nftables, ipset, CDN, …) | `EnforcerPlugin` | [enforcer.md](./enforcer.md) |
   | CTI provider (AbuseIPDB, GeoIP, …) | `CtiProviderPlugin` | [cti_provider.md](./cti_provider.md) |
   | SIEM sink (Elastic, Splunk, …) | `SiemSinkPlugin` | [siem_sink.md](./siem_sink.md) |
   | Detector | `DetectorPlugin` | [detector.md](./detector.md) |
   | Scoring engine | `ScoringEnginePlugin` | [scoring_engine.md](./scoring_engine.md) |
   | UI server (REST, TUI, Web, …) | `UiServerPlugin` | [ui_server.md](./ui_server.md) |

3. **[reference implementation](../../plugins/notifier-webhook/)** — `notifier-webhook`
   is the smallest end-to-end plugin in the tree. Mirror its structure when in
   doubt.

## Quick decision tree: which trait do I implement?

```
Does it READ logs / events from outside?       → LogSourcePlugin
Does it APPLY firewall bans?                   → EnforcerPlugin
Does it PUSH alerts to humans?                 → NotifierPlugin
Does it LOOK UP reputation of an IP?           → CtiProviderPlugin
Does it SHIP events to SIEM/log storage?       → SiemSinkPlugin
Does it INSPECT events and emit signals?       → DetectorPlugin
Does it DECIDE when to ban from signals?       → ScoringEnginePlugin
Does it SERVE a UI (web/TUI/gRPC)?             → UiServerPlugin
```

If you find yourself wanting two — your plugin is doing too much. Split it.

## Conventions that apply to every plugin

- **Naming:** crate `hiveguard-plugin-<category>-<name>`, id `<category>.<name>`.
  Examples: `hiveguard-plugin-notifier-slack` with id `notifier.slack`;
  `hiveguard-plugin-source-syslog` with id `source.syslog`.
- **Dependencies:** depend only on `hiveguard-plugin-api`, `hiveguard-core` (for
  domain types), `hiveguard-plugin-utils` (for HTTP/retry/backoff helpers).
  **Never depend on the daemon or on sibling plugins.**
- **Edition:** Rust 2021. Match the workspace.
- **Logging:** use `tracing::{info, warn, error, debug}`. Span with
  `plugin = self.manifest().id` when emitting from background tasks.
- **No `unwrap()` outside tests.** Errors propagate as `PluginError`.

## When in doubt

- Look at `plugins/notifier-webhook/` — the reference implementation.
- Read `hiveguard-plugin-api/src/lib.rs` doc comments.
- Don't invent new mechanisms — if you find yourself needing something not
  covered by the existing traits, that's a plugin-api change that needs to be
  discussed before you start coding.
