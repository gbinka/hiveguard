//! `<ConfigView />` — read-only summary of the running daemon.
//!
//! Editing daemon configuration from the browser is a Phase 6 feature
//! (needs a RBAC + audit trail layer first). For now we just surface
//! what we already have in `AppModel`.

use std::collections::BTreeMap;

use hiveguard_ui::ConnectionStatus;
use leptos::prelude::*;

use crate::state::use_app_state;

#[component]
pub fn ConfigView() -> impl IntoView {
    let state = use_app_state();

    let node_name = move || {
        let n = state.get().node_name;
        if n.is_empty() { "(unknown)".to_string() } else { n }
    };
    let version = move || {
        let v = state.get().daemon_version;
        if v.is_empty() { "(unknown)".to_string() } else { v }
    };

    let status_text = move || match state.get().status {
        ConnectionStatus::Connected => ("Connected", "badge badge-success"),
        ConnectionStatus::Connecting => ("Connecting", "badge badge-info"),
        ConnectionStatus::Disconnected => ("Disconnected", "badge badge-warning"),
        ConnectionStatus::Failed(_) => ("Failed", "badge badge-danger"),
    };

    let plugin_counts: Memo<Vec<(String, usize)>> = Memo::new(move |_| {
        let model = state.get();
        let mut by_kind: BTreeMap<String, usize> = BTreeMap::new();
        for p in &model.plugins_status {
            *by_kind.entry(p.kind.clone()).or_insert(0) += 1;
        }
        by_kind.into_iter().collect()
    });

    view! {
        <section class="view config-view">
            <header class="view-header">
                <h1>"Config"</h1>
                <p class="muted">
                    "Read-only snapshot of the running daemon. Editing lands in Phase 6."
                </p>
            </header>

            <div class="config-sections">
                <article class="card">
                    <h2>"Node"</h2>
                    <dl class="kv">
                        <dt>"Name"</dt>
                        <dd>{node_name}</dd>
                        <dt>"Daemon version"</dt>
                        <dd>{version}</dd>
                    </dl>
                </article>

                <article class="card">
                    <h2>"Connection"</h2>
                    <dl class="kv">
                        <dt>"Status"</dt>
                        <dd>
                            <span class=move || status_text().1>{move || status_text().0}</span>
                        </dd>
                    </dl>
                </article>

                <article class="card">
                    <h2>"Plugins"</h2>
                    {move || {
                        let counts = plugin_counts.get();
                        if counts.is_empty() {
                            view! { <p class="muted">"No plugins reported."</p> }.into_any()
                        } else {
                            view! {
                                <dl class="kv">
                                    {counts
                                        .into_iter()
                                        .map(|(kind, count)| {
                                            view! {
                                                <>
                                                    <dt>{kind}</dt>
                                                    <dd>{count.to_string()}</dd>
                                                </>
                                            }
                                        })
                                        .collect::<Vec<_>>()}
                                </dl>
                            }.into_any()
                        }
                    }}
                </article>
            </div>
        </section>
    }
}
