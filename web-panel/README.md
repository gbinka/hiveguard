# HiveGuard Web Panel

Standalone React + Vite + TypeScript frontend for the HiveGuard daemon. It is a
pure API client — it talks to the daemon's **`ui.rest`** HTTP + WebSocket API and
holds no server-side state of its own.

Previously this lived inside the Rust workspace as the `hiveguard-web` crate
(which embedded the built `dist/` into the daemon binary via `rust-embed`). It is
now a standalone npm project in `web-panel/`, outside the Rust workspace, so
the frontend and daemon can be built and deployed independently. Its source is
versioned together with the API to keep security fixes reproducible.

## Requirements

- Node.js 18+ (developed on 24.x)

## Develop

```bash
npm ci
npm run dev        # Vite dev server on http://localhost:5173
```

The dev server proxies `/api` and `/metrics` to `http://127.0.0.1:8443`
(see `vite.config.ts`) — point that at a running daemon's `ui.rest` bind address.

## Build

```bash
npm run build      # → dist/
```

## Deploy

Two supported models (both already handled by the daemon's `ui.rest` plugin):

1. **Served by the daemon** — point the `ui.rest` plugin's `static_dir` config at
   this project's `dist/` directory. The API serves the SPA with `index.html`
   fallback on the same origin (no CORS needed).
2. **Hosted separately** — serve `dist/` from any static host. Add the frontend's
   origin to the `ui.rest` plugin's `cors_origins` list so browser requests are
   allowed.

## API

- Contract: [`../plugins/ui-rest/openapi.yaml`](../plugins/ui-rest/openapi.yaml) (OpenAPI 3.1)
- Auth: Bearer token (`auth_token` in the plugin config). The panel stores it in
  `localStorage` under `hg-token` after login.
- Live updates: WebSocket at `/api/stream`.

TypeScript types in `src/api/types.ts` mirror the Rust wire types in
`hiveguard-plugin-api/src/traits/ui_server.rs`.
