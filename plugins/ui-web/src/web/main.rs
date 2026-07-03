//! HiveGuard Web UI — Leptos SPA entry point.
//!
//! Only compiles when targeting `wasm32-unknown-unknown`. On native targets
//! `main()` is a no-op stub so `cargo check -p hiveguard-ui-web` (without
//! `--target wasm32-...`) still passes — Cargo insists every `[[bin]]` has
//! a `main`, even if it's never linked into the host binary.
//!
//! Bundle this with Trunk:
//!
//! ```bash
//! cd plugins/ui-web
//! trunk build --release            # → dist/
//! trunk serve                      # dev server on http://localhost:8080
//! ```

#[cfg(target_arch = "wasm32")]
mod app;
#[cfg(target_arch = "wasm32")]
mod components;
#[cfg(target_arch = "wasm32")]
mod state;
#[cfg(target_arch = "wasm32")]
mod ws;

#[cfg(target_arch = "wasm32")]
fn main() {
    // Surface Rust panics in the browser devtools console instead of an
    // opaque `RuntimeError: unreachable executed`.
    console_error_panic_hook::set_once();
    leptos::mount::mount_to_body(app::App);
}

#[cfg(not(target_arch = "wasm32"))]
fn main() {
    // This bin is only meaningful on wasm32 — Trunk drives the actual build.
    // On native, calling it would be a user error, but we keep `main`
    // compiling so the workspace check succeeds.
    eprintln!(
        "hiveguard-ui-web is a WASM-only binary. Build with: \
         `trunk build --release` (from plugins/ui-web/)."
    );
    std::process::exit(2);
}
