# Authoring a HiveGuard Plugin

This is the **universal contract** every plugin obeys, regardless of category.
Read this once; then jump to the category-specific guide.

The reference end-to-end plugin is [`plugins/notifier-webhook/`](../../plugins/notifier-webhook/).
Copy its skeleton when starting a new plugin.

---

## 1. Anatomy of a plugin crate

```
plugins/<category>-<name>/
├── Cargo.toml
├── schema.json              # JSON Schema for this plugin's config
├── README.md                # One-paragraph description + config example
└── src/
    ├── lib.rs               # Trait impls + inventory::submit!
    └── (optional submodules)
```

### `Cargo.toml`

```toml
[package]
name = "hiveguard-plugin-<category>-<name>"
version = "0.1.0"
edition = "2021"

[dependencies]
hiveguard-plugin-api = { path = "../../hiveguard-plugin-api" }
hiveguard-core       = { path = "../../hiveguard-core" }
hiveguard-plugin-utils = { path = "../../hiveguard-plugin-utils" }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
async-trait = "0.1"
tracing = "0.1"
tokio = { version = "1", features = ["sync"] }

# Plugin-specific deps below — keep them tightly scoped.
```

Do **not** depend on `hiveguard-daemon`, `hiveguard-ingest`, `hiveguard-net`,
`hiveguard-enforce`, `hiveguard-cti`, or any sibling plugin. If you think you
need to, ask first.

### `src/lib.rs` skeleton

```rust
use hiveguard_plugin_api::prelude::*;
use serde::Deserialize;

const PLUGIN_ID: &str = "notifier.example";
const PLUGIN_VERSION: &str = "0.1.0";

#[derive(Debug, Deserialize)]
struct Config {
    url: String,
    timeout_secs: Option<u64>,
}

pub struct ExamplePlugin {
    manifest: PluginManifest,
    config: Option<Config>,
}

impl ExamplePlugin {
    pub fn manifest_fn() -> PluginManifest {
        PluginManifest {
            id: PLUGIN_ID,
            version: PLUGIN_VERSION,
            description: "One-line description of what it does.",
            kind: PluginKind::Notifier,            // pick your kind
            author: "HiveGuard",
            docs_url: Some("https://example.com"),
        }
    }

    pub fn create(
        ctx: PluginContext,
        cfg: serde_json::Value,
    ) -> BoxFuture<'static, PluginResult<Box<dyn NotifierPlugin>>> {
        Box::pin(async move {
            let mut p = ExamplePlugin {
                manifest: Self::manifest_fn(),
                config: None,
            };
            <ExamplePlugin as Plugin>::init(&mut p, cfg).await?;
            tracing::info!(plugin = PLUGIN_ID, "initialised");
            let _ = ctx; // use ctx.data_dir, ctx.secrets etc. as needed
            Ok(Box::new(p) as Box<dyn NotifierPlugin>)
        })
    }
}

#[async_trait]
impl Plugin for ExamplePlugin {
    fn manifest(&self) -> &PluginManifest { &self.manifest }

    async fn init(&mut self, cfg: serde_json::Value) -> PluginResult<()> {
        let parsed: Config = serde_json::from_value(cfg)
            .map_err(|e| PluginError::ConfigValidation(e.to_string()))?;
        self.config = Some(parsed);
        Ok(())
    }
}

#[async_trait]
impl NotifierPlugin for ExamplePlugin {
    async fn notify(&self, event: &AlertEvent) -> PluginResult<()> {
        // Implementation here.
        let _ = event;
        Ok(())
    }
}

inventory::submit! {
    PluginDescriptor {
        id: PLUGIN_ID,
        kind: PluginKind::Notifier,
        api_version: API_VERSION,
        manifest: ExamplePlugin::manifest_fn,
        config_schema: include_str!("../schema.json"),
        factory: PluginFactory::Notifier(ExamplePlugin::create),
    }
}
```

---

## 2. The `Plugin` base trait

Every plugin implements `Plugin` plus exactly one category trait:

```rust
#[async_trait]
pub trait Plugin: Send + Sync + 'static {
    fn manifest(&self) -> &PluginManifest;
    async fn init(&mut self, cfg: serde_json::Value) -> PluginResult<()>;
    async fn shutdown(&mut self) -> PluginResult<()> { Ok(()) }   // override if needed
    fn health(&self) -> HealthState { HealthState::Healthy }      // override if needed
}
```

### `init`

Called once, after the host has:

1. Resolved every `${env:VAR}` / `${file:/path}` placeholder in `cfg`.
2. Validated `cfg` against your JSON Schema.

So inside `init` you can assume `cfg` is well-formed and secrets are dereferenced.
Use `serde_json::from_value::<YourConfig>(cfg)` to deserialise.

Fail fast on conditions JSON Schema cannot express (e.g. live HTTP HEAD check
against the webhook URL). Returning `Err` here aborts daemon startup unless
the plugin entry has `optional: true` in YAML.

### `shutdown`

Called during graceful shutdown. **Drain in-flight work** (e.g. flush pending
HTTP requests, close connections). The host enforces a deadline (currently 30s).
Default impl is a no-op; override when you hold resources.

### `health`

Cheap, non-blocking. Polled periodically by the host and surfaced on
`GET /api/plugins`. Default is `Healthy`. Return `Degraded(_)` for
transient issues, `Failed(_)` when the plugin is non-functional.

---

## 3. JSON Schema for config

Every plugin ships a `schema.json` (draft-07). The host validates the user's
YAML against this schema before calling `init`. **Be strict** — declare every
field, use `"required"`, use `"additionalProperties": false`.

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "additionalProperties": false,
  "required": ["url"],
  "properties": {
    "url":          { "type": "string", "format": "uri" },
    "timeout_secs": { "type": "integer", "minimum": 1, "maximum": 300 }
  }
}
```

Reference it from `lib.rs`:

```rust
config_schema: include_str!("../schema.json"),
```

If your schema gets long, see [examples in existing plugins](../../plugins/) for
how to organise it. Schemas are exposed at `GET /api/plugins/{id}/schema` so
the UI can auto-render config forms.

---

## 4. Registering with `inventory`

The host discovers plugins at startup by iterating
`inventory::iter::<PluginDescriptor>`. You register exactly one descriptor per
crate at module scope:

```rust
inventory::submit! {
    PluginDescriptor {
        id: PLUGIN_ID,
        kind: PluginKind::Notifier,
        api_version: API_VERSION,            // imported from prelude
        manifest: ExamplePlugin::manifest_fn,
        config_schema: include_str!("../schema.json"),
        factory: PluginFactory::Notifier(ExamplePlugin::create),
    }
}
```

**The `kind` and the `PluginFactory::*` variant must match.** The host will
panic at link time if they don't, but check yourself first — typos here are a
common bug.

`api_version` always uses the constant from `hiveguard-plugin-api`. The host
refuses to load plugins built against a different version.

---

## 5. The `PluginContext`

Passed to your factory. Contains everything you need from the host:

```rust
pub struct PluginContext {
    pub plugin_id: String,
    pub data_dir: PathBuf,                                 // <node.data_dir>/plugins/<id>/
    pub secrets: Arc<SecretResolver>,
    pub metrics: PluginMetrics,
    pub shutdown: CancellationToken,
}
```

- `data_dir` — writable directory unique to your plugin instance. Use it for
  state files, caches, etc. Created by the host before `init`.
- `secrets` — already-resolved most of the time; only relevant if you need to
  resolve a string at runtime (rare).
- `metrics` — see "Metrics" below.
- `shutdown` — clone it into background tasks. They must check it.

Stash whatever you need from `ctx` as fields on your struct before `init`
returns — the context isn't passed to other methods.

---

## 6. Configuration secrets

Users write `${env:VAR}` or `${file:/run/secrets/x}` in YAML. **By the time
your `init` is called, these are already dereferenced** — `cfg` contains the
real values. You never need to call `SecretResolver` yourself for normal
config strings.

The only time you'd touch `secrets.resolve()` is for dynamic strings (e.g. an
auth header template the user provides). In that case, treat the resolved
string as sensitive — never log it.

---

## 7. Metrics

Plugins emit metrics under the prefix `hiveguard_plugin_{plugin_id}_*`.
Register them via the shared registry:

```rust
use prometheus_client::metrics::counter::Counter;

let sent: Counter = Counter::default();
ctx.metrics.registry.with_registry(|r| {
    r.register(
        format!("hiveguard_plugin_{}_sent_total", ctx.plugin_id),
        "Total alerts sent by this plugin",
        sent.clone(),
    );
});
```

Standard names to use when applicable:

| Suffix | Type | Meaning |
|--------|------|---------|
| `_total` | Counter | Cumulative event count |
| `_failed_total` | Counter | Cumulative failure count |
| `_duration_seconds` | Histogram | Operation latency |
| `_queue_depth` | Gauge | Outstanding work |
| `_last_success_timestamp_seconds` | Gauge | Unix timestamp of last success |

---

## 8. Logging

```rust
use tracing::{debug, info, warn, error};

info!(plugin = self.manifest().id, "starting up");
warn!(plugin = self.manifest().id, error = %e, "delivery failed");
```

- Use structured fields, not string concatenation.
- Use the appropriate level — `info` for lifecycle, `warn` for recoverable
  failures, `error` only for things that should page a human.
- Never log user data (alert payloads, IP addresses outside of debug spans).
- Never log resolved secrets.

---

## 9. Testing

### Unit tests

Inside `src/lib.rs` (or a sibling module), test your plugin in isolation:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use hiveguard_plugin_api::prelude::*;

    fn test_ctx() -> PluginContext {
        PluginContext::new(
            PLUGIN_ID.to_string(),
            std::env::temp_dir(),
            std::sync::Arc::new(SecretResolver::new()),
            PluginMetrics {
                registry: std::sync::Arc::new(Default::default()),
                plugin_id: PLUGIN_ID.to_string(),
            },
            CancellationToken::new(),
        )
    }

    #[tokio::test]
    async fn init_accepts_valid_config() {
        let cfg = serde_json::json!({ "url": "https://example.com" });
        // Use ::create directly to exercise the factory:
        let _plugin = ExamplePlugin::create(test_ctx(), cfg).await.unwrap();
    }
}
```

Unit tests **must not** rely on `inventory` — the linker discards symbols from
unused crates in test binaries. Instantiate plugins via the factory directly.

### Integration tests

Optional, in `plugins/<your>/tests/`. Use `tokio::test` + mock servers
(`wiremock`, `httpmock`) for HTTP-based plugins. See
`plugins/notifier-webhook/tests/` for the canonical example.

---

## 10. Naming & ids

- **Crate name:** `hiveguard-plugin-<category>-<name>`, kebab-case.
- **Plugin id:** `<category>.<name>`, dot-separated, lowercase. Examples:
  `notifier.slack`, `source.syslog.tcp`, `enforcer.nftables`, `cti.abuseipdb`.
- **Sub-flavours** (e.g. tcp vs udp transport) use a third dot:
  `source.syslog.tcp`, `source.syslog.udp`, `source.syslog.tls`.

The id is **the** stable identifier — users reference it in YAML, the host
matches on it, and it appears in metrics. Don't change it after release.

---

## 11. Where to put plugin-specific config sections

There are no plugin-specific sections in the core config. Everything lives
under the `plugins:` list:

```yaml
plugins:
  - id: notifier.example
    name: ops-channel
    config:
      url: "${env:OPS_WEBHOOK}"
      timeout_secs: 10
```

If your plugin needs multiple instances (e.g. two Slack channels), the user
adds two entries with different `name:` values. Your factory will be called
twice with different `cfg` values.

---

## 12. Forbidden patterns

- ❌ Holding `&mut self` in a long-running method other than `init` / `shutdown`.
  Use interior mutability (`RwLock`, `DashMap`).
- ❌ `tokio::spawn` of detached tasks. Spawn into a `JoinSet` tied to `shutdown`
  or you'll leak on graceful exit.
- ❌ Blocking I/O (`std::fs`, `std::net`, `reqwest::blocking`) in async code.
- ❌ Calling `std::process::exit`. Return `PluginError` instead.
- ❌ Modifying `data_dir` outside the plugin's own subtree.
- ❌ Reading other plugins' `data_dir`s.
- ❌ Reaching into `hiveguard-core` internals (anything beyond
  `hiveguard_core::models::*` and `hiveguard_core::errors::*`).
- ❌ Adding a new dependency to `hiveguard-plugin-api`. If you need something,
  put it in `hiveguard-plugin-utils` or your own crate.

---

## 13. When you need to extend the plugin API itself

If your design genuinely doesn't fit the existing traits — e.g. you need a
trait that polls events asynchronously and pushes to a sink, neither pure
source nor pure sink — **don't fork the trait**. Open a discussion to evolve
the plugin API. Bumping `API_VERSION` is fine for major releases; we'd rather
do that than have N forks of the contract.
