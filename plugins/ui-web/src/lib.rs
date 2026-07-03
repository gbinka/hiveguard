//! `hiveguard-ui-web` — Leptos SPA + `UiServer` plugin.
//!
//! This crate has two faces:
//!
//! * **Native (`cfg(not(target_arch = "wasm32"))`)** — the [`plugin`] module
//!   exposes [`WebPlugin`], a [`UiServerPlugin`] registered with `inventory`.
//!   The host instantiates it and lets it serve the SPA bundle + REST/WS
//!   endpoints to the browser.
//!
//! * **WASM (`cfg(target_arch = "wasm32")`)** — the `web/main.rs` binary
//!   target is the Leptos SPA. Trunk builds it (`trunk build --release`)
//!   into `dist/`, which the native plugin then serves.
//!
//! Splitting native vs wasm at the *target* level (not feature flags) keeps
//! `cargo check` simple on both targets and avoids accidental wasm builds
//! pulling in tokio.

// Native-only surface: only compile the plugin glue off-wasm.
#[cfg(not(target_arch = "wasm32"))]
mod plugin;

#[cfg(not(target_arch = "wasm32"))]
pub use plugin::*;

// The `web/` module is the SPA — it lives in its own bin target
// (`src/web/main.rs`). We don't `mod web;` here because Leptos is wasm-only
// and pulling its types into the lib would break the native build.
