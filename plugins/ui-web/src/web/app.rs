//! Top-level Leptos component: provides global state, kicks off the
//! WebSocket reconnect loop, and mounts the router.
//!
//! ## Why provide state via context, not import
//!
//! `hiveguard_ui::AppModel` is the source of truth. We wrap it in a
//! `RwSignal<AppModel>` and put that signal in Leptos context so every
//! component (including those reached via the router) reads the *same*
//! reactive slot. Importing a `static` would defeat reactivity.

use leptos::prelude::*;
use leptos_router::components::{Route, Router, Routes};
use leptos_router::path;

use crate::components::bans::BansView;
use crate::components::config::ConfigView;
use crate::components::dashboard::Dashboard;
use crate::components::nav::Nav;
use crate::components::placeholder::Placeholder;
use crate::components::plugins::PluginsView;
use crate::components::threats::ThreatsView;
use crate::state::AppState;
use crate::ws;

#[component]
pub fn App() -> impl IntoView {
    // Build the global state once and stash it in Leptos context.
    let state = AppState::new();
    provide_context(state);

    // Spawn the WS reconnect loop. Runs for the lifetime of the page —
    // mount/unmount of `<App />` happens exactly once in a CSR build.
    ws::connect_loop(state);

    view! {
        <Router>
            <Nav />
            <main class="container">
                <Routes fallback=|| view! { <Placeholder title="Not found" /> }>
                    <Route path=path!("/") view=Dashboard />
                    <Route path=path!("/bans") view=BansView />
                    <Route path=path!("/threats") view=ThreatsView />
                    <Route path=path!("/plugins") view=PluginsView />
                    <Route path=path!("/config") view=ConfigView />
                </Routes>
            </main>
        </Router>
    }
}
