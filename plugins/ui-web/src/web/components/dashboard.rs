//! `<Dashboard />` — the landing view.
//!
//! Shows daemon identity (`node_name`, `daemon_version`), the connection
//! indicator, live counters for `bans` / `threats` / `plugins`, and a
//! dev-only "Load sample data" button that fakes a populated model so the
//! layout is exercisable without a backend.

use hiveguard_ui::Msg;
use leptos::prelude::*;

use crate::components::connection_indicator::ConnectionIndicator;
use crate::state::use_app_state;

#[component]
pub fn Dashboard() -> impl IntoView {
    let state = use_app_state();

    let node_name = move || {
        let n = state.get().node_name;
        if n.is_empty() { "—".to_string() } else { n }
    };
    let version = move || {
        let v = state.get().daemon_version;
        if v.is_empty() { "—".to_string() } else { v }
    };
    let bans_count = move || state.get().bans.len();
    let threats_count = move || state.get().threats.len();
    let plugins_count = move || state.get().plugins_status.len();

    let load_sample = move |_| state.dispatch(Msg::LoadSampleData);

    view! {
        <section class="dashboard">
            <header class="dashboard-header">
                <h1>"Dashboard"</h1>
                <ConnectionIndicator />
            </header>

            <div class="grid">
                <article class="card">
                    <h2>"Node"</h2>
                    <p class="metric">{node_name}</p>
                </article>

                <article class="card">
                    <h2>"Daemon version"</h2>
                    <p class="metric">{version}</p>
                </article>

                <article class="card">
                    <h2>"Active bans"</h2>
                    <p class="metric">{bans_count}</p>
                </article>

                <article class="card">
                    <h2>"Recent threats"</h2>
                    <p class="metric">{threats_count}</p>
                </article>

                <article class="card">
                    <h2>"Plugins loaded"</h2>
                    <p class="metric">{plugins_count}</p>
                </article>
            </div>

            <div class="dashboard-actions">
                <button class="btn btn-primary" on:click=load_sample>
                    "Load sample data"
                </button>
                <span class="muted">
                    "Fills the model with deterministic fixtures so the views are exercisable without a live daemon. \
                     A real WebSocket snapshot replaces these on the next frame."
                </span>
            </div>
        </section>
    }
}
