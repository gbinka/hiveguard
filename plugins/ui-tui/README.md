# ui.tui — HiveGuard terminal UI

`ui.tui` is the ratatui-based terminal renderer for HiveGuard. It connects to
a running daemon over REST + WebSocket and presents the same `AppModel` /
`Msg` surface as the browser SPA (`ui.web`).

The crate ships two faces:

- **Binary (`hiveguard-tui`)** — the operator-facing tool. Connects over
  the network to a daemon at `--server`.
- **Plugin (`hiveguard_plugin_ui_tui::TuiPlugin`)** — registered via
  `inventory`. Embedded mode is opt-in (`enabled: true` in plugin config);
  by default the plugin stays inert so adding it to a registry never
  steals the terminal.

## Building

```sh
# From the workspace root.
PATH=/usr/bin:$PATH cargo build --ignore-rust-version \
    -p hiveguard-plugin-ui-tui --bin hiveguard-tui
```

## Running

```sh
# Production-style: bearer token via env var.
HIVEGUARD_TOKEN=… hiveguard-tui --server https://node.example.com

# Dev / self-signed certs:
hiveguard-tui --server https://localhost:8443 --insecure
```

| Flag           | Default                 | Notes                                    |
|----------------|-------------------------|------------------------------------------|
| `--server`     | `http://localhost:8443` | Daemon REST/WS base URL.                 |
| `--token`      | `$HIVEGUARD_TOKEN`      | Bearer token.                            |
| `--insecure`   | off                     | Skip TLS verification.                   |
| `--poll-secs`  | `5`                     | REST poll interval (WS push is primary). |

## Key bindings

| Key       | Action                                                |
|-----------|-------------------------------------------------------|
| `1`–`5`   | Switch view: Dashboard / Bans / Threats / Plugins / Config |
| `↑` `↓`   | Move row selection                                    |
| `PgUp` `PgDn` | Page selection by 10                              |
| `r`       | Refresh from daemon                                   |
| `Enter`   | Activate / submit (reserved for forms)                |
| `d`       | Unban selected row (Bans view only)                   |
| `?`       | Toggle help overlay                                   |
| `q` / `Ctrl-C` | Quit                                             |

## Architecture

The TUI follows the Elm Architecture: `hiveguard_ui::update(model, msg)` is
the single source of truth for state transitions. ratatui only renders
`&AppModel`; crossterm key events are routed through `event::route_key` and
become either a `Msg` (state-changing) or a `KeyAction` (renderer-local, e.g.
move selection cursor).

```
                       ┌─────────────────┐
   crossterm event ──▶ │ event::route_key│──▶ Msg / KeyAction
                       └─────────────────┘
                                │
                                ▼
   WS frame ────────────▶ ┌──────────┐
   REST poll ───────────▶ │  update  │──▶ AppModel
                          └──────────┘
                                │
                                ▼
                         ┌──────────┐
                         │ views::* │──▶ ratatui Frame
                         └──────────┘
```

WebSocket and REST clients run as independent tokio tasks; they push `Msg`
values into a shared `mpsc::Sender<Msg>`. The main loop selects between the
crossterm event stream, the `Msg` channel, and `ctrl_c()`.

On clean exit, panic, or any error the terminal is restored to cooked mode
(`disable_raw_mode` + `LeaveAlternateScreen`) so the operator's shell is
never left scrambled.

## Why not render the `ViewTree` IR?

`hiveguard_ui::ViewTree` exists for renderers that need a serialisable
intermediate form (e.g. a future gRPC frontend). ratatui has its own rich
widget set (`Table`, `Tabs`, `Gauge`, `Paragraph`), so the TUI bypasses
`ViewTree` and renders directly from `&AppModel` — fewer translation steps,
better-looking output. The contract that matters is `AppModel` + `Msg` +
`update`, all of which the TUI shares verbatim with `ui.web`.
