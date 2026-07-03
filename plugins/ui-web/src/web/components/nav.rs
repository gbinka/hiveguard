//! `<Nav />` — top-level navigation. Uses Leptos Router's `<A />` for
//! client-side navigation (no full reloads).
//!
//! Route paths here mirror `ViewKind` variants in `hiveguard_ui::model`.
//! Keep them in sync — Phase 5 introduces a `ViewKind <-> path` helper to
//! enforce the mapping at the type level.

use leptos::prelude::*;
use leptos_router::components::A;

#[component]
pub fn Nav() -> impl IntoView {
    view! {
        <nav class="nav">
            <span class="nav-brand">"HiveGuard"</span>
            <ul class="nav-links">
                <li><A href="/">"Dashboard"</A></li>
                <li><A href="/bans">"Bans"</A></li>
                <li><A href="/threats">"Threats"</A></li>
                <li><A href="/plugins">"Plugins"</A></li>
                <li><A href="/config">"Config"</A></li>
            </ul>
        </nav>
    }
}
