# ui.web — HiveGuard Leptos SPA

Phase 5 scaffold. Provides:

- A `UiServerPlugin` registration (`ui.web`) on the **native** target.
  Currently a fail-loud stub that returns `PluginError::Init` from `init`;
  the host-side static file server + WebSocket bridge land later in Phase 5.
- A working **Leptos 0.7 CSR SPA** on the **wasm32-unknown-unknown** target,
  with router (`/`, `/bans`, `/threats`, `/plugins`, `/config`), a real
  `Dashboard` view, a `ConnectionIndicator`, and a WebSocket reconnect loop
  that drives `hiveguard_ui::AppModel` through `Msg`-based updates.

## Architecture

Single Cargo package, two targets:

```
plugins/ui-web/
├── Cargo.toml          # cfg-gated deps: tokio native, leptos wasm
├── Trunk.toml          # build config for wasm bundle
├── index.html          # Trunk entry
├── style.css           # minimal CSS, no Tailwind for now
└── src/
    ├── lib.rs          # lib target — re-exports `plugin` module on native
    ├── plugin.rs       # native plugin (UiServerPlugin impl, inventory)
    └── web/            # bin target — Leptos SPA (wasm-only)
        ├── main.rs     # mount_to_body
        ├── app.rs      # Router + provide_context
        ├── state.rs    # RwSignal<AppModel>
        ├── ws.rs       # WebSocket reconnect loop
        └── components/
            ├── nav.rs
            ├── dashboard.rs
            ├── connection_indicator.rs
            └── placeholder.rs
```

State lives in `hiveguard-ui` (`AppModel` / `Msg` / `update`). Leptos is the
*renderer* — every state change goes through the pure
`hiveguard_ui::update(model, msg) -> AppModel` function. The same will hold
for `plugins/ui-tui/` (ratatui renderer) in Phase 5.

## Build

### Native check (plugin side)

```bash
PATH=/usr/bin:$PATH cargo check --ignore-rust-version -p hiveguard-ui-web
```

### WASM check (SPA side)

```bash
PATH=/usr/bin:$PATH cargo check --ignore-rust-version \
  -p hiveguard-ui-web --target wasm32-unknown-unknown
```

### Production bundle

Trunk is the canonical build tool for Leptos CSR apps. Install once:

```bash
cargo install trunk
```

Then, from `plugins/ui-web/`:

```bash
trunk build --release
# → dist/index.html + dist/hiveguard-ui-web-<hash>.wasm + dist/style-<hash>.css
```

The native plugin will eventually serve `dist/` over HTTPS (Phase 5
TODO in `src/plugin.rs::run`).

### Dev server

```bash
trunk serve
# http://127.0.0.1:8080 — auto-reloads on source change
```

The SPA will try to connect to `ws://localhost:8443/api/stream` (see
`src/web/ws.rs::DEFAULT_WS_URL`). Until the daemon's `ui-rest` plugin
implements that endpoint the `ConnectionIndicator` will stay in
`Failed: …` and the reconnect loop will back off up to 30 s.

## Phase 5 TODOs

Grep for `TODO(phase-5)`:

- `src/plugin.rs` — Axum static file server, `/api/stream` WS handler.
- `src/web/ws.rs` — outbound channel, re-auth on 401, binary protocol.
- `src/web/components/dashboard.rs` — wire counters once `AppModel`
  gains `recent_bans` and `active_threats` fields.
- `Cargo.toml` — promote Leptos pin to `0.8` once the rest of the
  ecosystem (gloo-net, web-sys) stabilises against it.
