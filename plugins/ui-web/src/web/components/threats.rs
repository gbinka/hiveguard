//! `<ThreatsView />` — recent threat detections.
//!
//! Filters by detector (dropdown built from the distinct detectors present
//! in the current snapshot) and by severity (slider). The severity column
//! is sortable; default sort is descending. Sort direction is stored in a
//! component-local signal because it's purely view state — toggling sort
//! shouldn't bounce through `AppModel`.

use hiveguard_ui::{Msg, ThreatRow};
use leptos::ev;
use leptos::prelude::*;
use std::collections::BTreeSet;

use crate::state::use_app_state;

#[derive(Clone, Copy, PartialEq, Eq)]
enum SortDir {
    Asc,
    Desc,
}

fn severity_badge_class(sev: u8) -> &'static str {
    match sev {
        0..=63 => "badge badge-info",
        64..=127 => "badge badge-warning",
        _ => "badge badge-danger",
    }
}

#[component]
pub fn ThreatsView() -> impl IntoView {
    let state = use_app_state();
    let sort_dir = RwSignal::new(SortDir::Desc);

    // Distinct detectors in current snapshot — populates the filter dropdown.
    let detectors: Memo<Vec<String>> = Memo::new(move |_| {
        let m = state.get();
        let set: BTreeSet<String> = m.threats.iter().map(|t| t.detector.clone()).collect();
        set.into_iter().collect()
    });

    let filtered: Memo<Vec<ThreatRow>> = Memo::new(move |_| {
        let model = state.get();
        let detector = model.filters.threats_detector.clone();
        let min_sev = model.filters.threats_severity_min;
        let mut rows: Vec<ThreatRow> = model
            .threats
            .into_iter()
            .filter(|t| t.severity >= min_sev)
            .filter(|t| detector.is_empty() || t.detector == detector)
            .collect();
        match sort_dir.get() {
            SortDir::Desc => rows.sort_by(|a, b| b.severity.cmp(&a.severity)),
            SortDir::Asc => rows.sort_by(|a, b| a.severity.cmp(&b.severity)),
        }
        rows
    });

    let on_severity_input = move |ev: ev::Event| {
        let v: u8 = event_target_value(&ev).parse().unwrap_or(0);
        state.dispatch(Msg::FilterThreatsSeverity(v));
    };
    let on_detector_change = move |ev: ev::Event| {
        state.dispatch(Msg::FilterThreatsDetector(event_target_value(&ev)));
    };
    let toggle_sort = move |_| {
        sort_dir.update(|d| {
            *d = match *d {
                SortDir::Asc => SortDir::Desc,
                SortDir::Desc => SortDir::Asc,
            }
        });
    };

    view! {
        <section class="view threats-view">
            <header class="view-header">
                <h1>"Threats"</h1>
                <p class="muted">
                    "Detector output before any ban policy is applied. Click the severity header to flip sort order."
                </p>
            </header>

            <div class="view-body">
                <aside class="filters">
                    <h2>"Filters"</h2>

                    <label class="filter-field">
                        <span>"Detector"</span>
                        <select
                            on:change=on_detector_change
                            prop:value=move || state.get().filters.threats_detector
                        >
                            <option value="">"(all)"</option>
                            {move || {
                                detectors
                                    .get()
                                    .into_iter()
                                    .map(|d| view! { <option value=d.clone()>{d.clone()}</option> })
                                    .collect::<Vec<_>>()
                            }}
                        </select>
                    </label>

                    <label class="filter-field">
                        <span>
                            "Min severity: "
                            {move || state.get().filters.threats_severity_min}
                        </span>
                        <input
                            type="range"
                            min="0"
                            max="255"
                            prop:value=move || {
                                state.get().filters.threats_severity_min.to_string()
                            }
                            on:input=on_severity_input
                        />
                    </label>
                </aside>

                <div class="table-wrap">
                    {move || {
                        let rows = filtered.get();
                        let arrow = match sort_dir.get() {
                            SortDir::Desc => " v",
                            SortDir::Asc => " ^",
                        };
                        if rows.is_empty() {
                            view! {
                                <div class="empty-state">
                                    <p>"No threats matching filters."</p>
                                </div>
                            }.into_any()
                        } else {
                            view! {
                                <table class="data-table">
                                    <thead>
                                        <tr>
                                            <th>"IP"</th>
                                            <th
                                                class="sortable"
                                                on:click=toggle_sort
                                            >
                                                "Severity"
                                                <span class="sort-arrow">{arrow}</span>
                                            </th>
                                            <th>"Confidence"</th>
                                            <th>"Detector"</th>
                                            <th>"Reason"</th>
                                            <th>"Timestamp"</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {rows
                                            .into_iter()
                                            .map(|t| {
                                                let badge_cls = severity_badge_class(t.severity);
                                                view! {
                                                    <tr>
                                                        <td><code>{t.ip.clone()}</code></td>
                                                        <td>
                                                            <span class=badge_cls>{t.severity.to_string()}</span>
                                                        </td>
                                                        <td>{format!("{}%", t.confidence)}</td>
                                                        <td><code class="muted">{t.detector.clone()}</code></td>
                                                        <td>{t.reason.clone()}</td>
                                                        <td class="muted">{t.timestamp.clone()}</td>
                                                    </tr>
                                                }
                                            })
                                            .collect::<Vec<_>>()}
                                    </tbody>
                                </table>
                            }.into_any()
                        }
                    }}
                </div>
            </div>
        </section>
    }
}
