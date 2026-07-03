//! `<PluginsView />` — plugin health grouped by kind.
//!
//! The canonical plugin kinds (Source, Detector, Enforcer, Notifier,
//! SiemSink, Cti, ScoringEngine, UiServer) are listed in a fixed order;
//! plugins of an unknown kind fall into an "Other" bucket so we never lose
//! data on a schema bump.

use std::collections::BTreeMap;

use hiveguard_ui::PluginStatus;
use leptos::prelude::*;

use crate::state::use_app_state;

const KIND_ORDER: &[&str] = &[
    "Source",
    "Detector",
    "Enforcer",
    "Notifier",
    "SiemSink",
    "Cti",
    "ScoringEngine",
    "UiServer",
];

fn health_badge_class(health: &str) -> &'static str {
    match health {
        "Healthy" => "badge badge-success",
        "Degraded" => "badge badge-warning",
        "Failed" => "badge badge-danger",
        _ => "badge badge-info",
    }
}

#[component]
pub fn PluginsView() -> impl IntoView {
    let state = use_app_state();

    // Group by kind. `BTreeMap` for stable iteration over "Other" entries;
    // canonical kinds are emitted in the fixed `KIND_ORDER` below.
    let grouped: Memo<(Vec<(String, Vec<PluginStatus>)>, usize)> = Memo::new(move |_| {
        let model = state.get();
        let mut by_kind: BTreeMap<String, Vec<PluginStatus>> = BTreeMap::new();
        for p in &model.plugins_status {
            by_kind.entry(p.kind.clone()).or_default().push(p.clone());
        }

        let mut out: Vec<(String, Vec<PluginStatus>)> = Vec::new();
        // Canonical kinds first, in display order.
        for k in KIND_ORDER {
            if let Some(rows) = by_kind.remove(*k) {
                out.push(((*k).to_string(), rows));
            }
        }
        // Anything left over (forwards-compat).
        for (k, rows) in by_kind {
            out.push((k, rows));
        }

        let total = model.plugins_status.len();
        (out, total)
    });

    view! {
        <section class="view plugins-view">
            <header class="view-header">
                <h1>"Plugins"</h1>
                <p class="muted">
                    {move || {
                        let (_, total) = grouped.get();
                        format!("{total} plugin(s) loaded")
                    }}
                </p>
            </header>

            <div class="view-body view-body-full">
                {move || {
                    let (groups, total) = grouped.get();
                    if total == 0 {
                        view! {
                            <div class="empty-state">
                                <p>"No plugins loaded."</p>
                                <p class="muted">
                                    "The daemon has not yet reported a plugin inventory."
                                </p>
                            </div>
                        }.into_any()
                    } else {
                        view! {
                            <div class="plugin-groups">
                                {groups
                                    .into_iter()
                                    .map(|(kind, rows)| {
                                        view! {
                                            <section class="plugin-group">
                                                <h2>{kind.clone()} " "
                                                    <span class="muted">
                                                        {format!("({})", rows.len())}
                                                    </span>
                                                </h2>
                                                <table class="data-table">
                                                    <thead>
                                                        <tr>
                                                            <th>"ID"</th>
                                                            <th>"Health"</th>
                                                            <th>"Version"</th>
                                                        </tr>
                                                    </thead>
                                                    <tbody>
                                                        {rows
                                                            .into_iter()
                                                            .map(|p| {
                                                                let cls = health_badge_class(&p.health);
                                                                view! {
                                                                    <tr>
                                                                        <td><code>{p.id.clone()}</code></td>
                                                                        <td>
                                                                            <span class=cls>{p.health.clone()}</span>
                                                                        </td>
                                                                        <td class="muted">{p.version.clone()}</td>
                                                                    </tr>
                                                                }
                                                            })
                                                            .collect::<Vec<_>>()}
                                                    </tbody>
                                                </table>
                                            </section>
                                        }
                                    })
                                    .collect::<Vec<_>>()}
                            </div>
                        }.into_any()
                    }
                }}
            </div>
        </section>
    }
}
