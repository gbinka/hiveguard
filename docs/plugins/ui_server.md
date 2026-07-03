# UI server plugin

Serve a user interface — REST API, embedded SPA, TUI, gRPC, etc. Reference
impls (after Fala B1): `plugins/ui-rest`, `plugins/ui-web`, `plugins/ui-tui`.

> Before reading this: finish [AUTHORING.md](./AUTHORING.md).

UI server plugins are unusual because they consume the same `UiApiHandle`,
which means TUI + Web + REST can run **concurrently in the same binary**,
giving operators their preferred interface without code duplication.

## Trait

```rust
#[async_trait]
pub trait UiServerPlugin: Plugin {
    async fn run(
        &mut self,
        api: Arc<dyn UiApiHandle>,
        shutdown: CancellationToken,
    ) -> PluginResult<()>;
}

pub trait UiApiHandle: Send + Sync + 'static {
    fn daemon_version(&self) -> String;
    fn node_name(&self) -> String;
    // … expanded in Phase 5
}
```

## What the host guarantees

- `run` is called exactly once, after `init`. Loop until `shutdown` fires.
- `api` is an `Arc<dyn UiApiHandle>` — share it with as many concurrent
  request handlers as you want.
- Multiple UI plugins may be active simultaneously. They must not collide
  on listen ports — that's a config-validation issue, surface it in `init`.

## What you implement

### 1. The serving loop

```rust
async fn run(&mut self, api: Arc<dyn UiApiHandle>, shutdown: CancellationToken)
    -> PluginResult<()>
{
    let app = axum::Router::new()
        .route("/api/info", get({
            let api = api.clone();
            move || async move {
                axum::Json(serde_json::json!({
                    "version": api.daemon_version(),
                    "node": api.node_name(),
                }))
            }
        }));

    let listener = tokio::net::TcpListener::bind(&self.listen).await
        .map_err(PluginError::Io)?;

    axum::serve(listener, app)
        .with_graceful_shutdown(async move { shutdown.cancelled().await })
        .await
        .map_err(|e| PluginError::Runtime(e.to_string()))?;

    Ok(())
}
```

### 2. Authentication

Every UI plugin authenticates **separately**. The host does not provide a
shared auth layer. Recommended:

- REST/Web: bearer token (`Authorization: Bearer <token>`), token in config
  as `${env:HIVEGUARD_TOKEN}` or `${file:/run/secrets/token}`.
- TUI: socket-based (Unix domain socket with file mode 600).
- gRPC: mutual TLS with client certs.

Plugins serving from `0.0.0.0` MUST require authentication. Plugins bound
to `127.0.0.1` SHOULD (defense in depth).

### 3. Sharing UI state via `hiveguard-ui`

`hiveguard-ui` (added in Phase 5) holds the render-agnostic model
(`AppModel`, `Msg`, `view(model) -> ViewTree`). Three known consumers:

- `ui-rest`: serves the raw `AppModel` snapshots via WebSocket + accepts
  `Msg` over HTTP POST.
- `ui-web`: WASM (Leptos/Dioxus). Loads `hiveguard-ui`, fetches model,
  dispatches `Msg` to `ui-rest`.
- `ui-tui`: ratatui. Loads `hiveguard-ui`, fetches model via `ui-rest`,
  dispatches `Msg`.

If you write a new UI plugin (Tauri desktop, native Android, gRPC), it
should follow the same pattern: import `hiveguard-ui`, communicate with
`ui-rest` for live data + mutation intent.

## Config

| Field | Type | Purpose |
|-------|------|---------|
| `listen` | string `host:port` | REST/Web bind address |
| `socket_path` | string | Unix socket path (TUI/CLI) |
| `auth_token` | string `${env:…}` or `${file:…}` | Bearer token |
| `cors_origins` | array | Allowed CORS origins for `ui-web` |
| `tls_cert` / `tls_key` | string | Optional TLS termination |
| `refresh_secs` | int | TUI auto-refresh interval |
| `embed_assets` | bool | Web SPA: serve embedded build vs. proxy to dev server |

## Metrics

```
hiveguard_plugin_ui_<name>_requests_total{method, path}
hiveguard_plugin_ui_<name>_active_connections      # gauge
hiveguard_plugin_ui_<name>_auth_failures_total
hiveguard_plugin_ui_<name>_request_duration_seconds  # histogram
```

## Common pitfalls

- **Auth disabled in dev mode and shipped to prod** — never. Make auth
  required at the type level (no `Option<AuthToken>` — use `AuthToken` and
  fail `init` if not configured).
- **Wide-open CORS** — `Access-Control-Allow-Origin: *` with credentials
  enabled is a CSRF vector. Restrict to configured origins.
- **No rate limiting** — REST endpoints that walk large data sets
  (ban list, metrics) get pounded by curious clients. Use
  `tower-governor` or `hiveguard_plugin_utils::ratelimit`.
- **Streaming unbounded data** — `GET /api/bans` returning all 50k bans
  in one shot kills clients and exhausts memory. Paginate by default.
- **WebSocket reconnect storms** — if many UI clients reconnect after a
  restart, they hammer your server. Stagger with jitter on the client
  side; on server, queue connections beyond a cap.
- **Embedded assets out of date** — `rust-embed` snapshots at compile time.
  Document that `cargo build` must follow `npm run build` (or wire it via
  `build.rs`).

## UI plugin vs UI library

Distinction matters in Phase 5:

- **`hiveguard-ui`** (the library) — `model/`, `view/`, `intent/`. NOT a
  plugin. Used by ui-tui, ui-web, and any future UI plugin.
- **`plugins/ui-rest`** — REST + WebSocket backend. Required by all
  UI plugins (they don't talk directly to the daemon state).
- **`plugins/ui-tui`** — ratatui renderer over `hiveguard-ui`.
- **`plugins/ui-web`** — WASM renderer over `hiveguard-ui`.

If you write a `ui-grpc` or `ui-tauri`, follow the same split: a plugin
shell that owns the connection + a use of `hiveguard-ui` for state.
