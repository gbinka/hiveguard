//! `<BansView />` — active bans table with filtering and ban creation form.
//!
//! Reads `AppModel::bans` and `AppModel::filters` reactively; filtering is
//! a derived `Memo` so each keystroke / slider change only retouches the
//! tbody, not the whole view.
//!
//! User actions:
//! * Per-row "Unban" button → `Msg::UnbanRequested(subject)`.
//! * Create-ban form (inline panel) → `Msg::BanRequested { subject, duration_secs, reason }`.
//!
//! Outbound transport is the renderer's responsibility (see `ws.rs` TODO).
//! For now the optimistic mutation in `hiveguard_ui::update` is enough to
//! see the table react.

use hiveguard_ui::{BanRow, Msg};
use leptos::ev;
use leptos::prelude::*;

use crate::state::use_app_state;

/// Helper: bucket severity (0–255) into a CSS badge variant.
fn severity_badge_class(sev: u8) -> &'static str {
    match sev {
        0..=63 => "badge badge-info",
        64..=127 => "badge badge-warning",
        128..=191 => "badge badge-danger",
        _ => "badge badge-danger",
    }
}

#[component]
pub fn BansView() -> impl IntoView {
    let state = use_app_state();

    // Form-local signals — these are *not* part of AppModel because they
    // only matter while the user is typing. Once "Ban" is pressed we
    // dispatch a Msg and reset the inputs.
    let subject = RwSignal::new(String::new());
    let duration_hours = RwSignal::new(1u64);
    let reason = RwSignal::new(String::new());

    // Derived filtered list. `Memo` only re-runs when bans or filters change.
    let filtered: Memo<Vec<BanRow>> = Memo::new(move |_| {
        let model = state.get();
        let needle = model.filters.bans_search.to_lowercase();
        let min = model.filters.bans_severity_min;
        model
            .bans
            .into_iter()
            .filter(|b| b.severity >= min)
            .filter(|b| {
                if needle.is_empty() {
                    true
                } else {
                    b.subject.to_lowercase().contains(&needle)
                        || b.reason.to_lowercase().contains(&needle)
                }
            })
            .collect()
    });

    let on_severity_input = move |ev: ev::Event| {
        let v: u8 = event_target_value(&ev).parse().unwrap_or(0);
        state.dispatch(Msg::FilterBansSeverity(v));
    };
    let on_search_input = move |ev: ev::Event| {
        state.dispatch(Msg::FilterBansSearch(event_target_value(&ev)));
    };

    let submit_ban = move |ev: ev::SubmitEvent| {
        ev.prevent_default();
        let s = subject.get();
        if s.trim().is_empty() {
            return;
        }
        let duration_secs = duration_hours.get().saturating_mul(3600);
        state.dispatch(Msg::BanRequested {
            subject: s.trim().to_string(),
            duration_secs,
            reason: reason.get(),
        });
        // Reset form.
        subject.set(String::new());
        reason.set(String::new());
        duration_hours.set(1);
    };

    view! {
        <section class="view bans-view">
            <header class="view-header">
                <h1>"Bans"</h1>
                <p class="muted">"Active bans across the cluster. Filters apply client-side."</p>
            </header>

            <div class="view-body">
                <aside class="filters">
                    <h2>"Filters"</h2>

                    <label class="filter-field">
                        <span>"Search"</span>
                        <input
                            type="text"
                            placeholder="subject or reason"
                            prop:value=move || state.get().filters.bans_search
                            on:input=on_search_input
                        />
                    </label>

                    <label class="filter-field">
                        <span>
                            "Min severity: "
                            {move || state.get().filters.bans_severity_min}
                        </span>
                        <input
                            type="range"
                            min="0"
                            max="255"
                            prop:value=move || state.get().filters.bans_severity_min.to_string()
                            on:input=on_severity_input
                        />
                    </label>

                    <hr />

                    <h2>"Create ban"</h2>
                    <form class="ban-form" on:submit=submit_ban>
                        <label class="filter-field">
                            <span>"Subject (CIDR)"</span>
                            <input
                                type="text"
                                placeholder="e.g. 10.0.0.1/32"
                                prop:value=move || subject.get()
                                on:input=move |ev| subject.set(event_target_value(&ev))
                                required
                            />
                        </label>
                        <label class="filter-field">
                            <span>"Duration (hours, 0 = permanent)"</span>
                            <input
                                type="number"
                                min="0"
                                prop:value=move || duration_hours.get().to_string()
                                on:input=move |ev| {
                                    duration_hours.set(
                                        event_target_value(&ev).parse().unwrap_or(0),
                                    );
                                }
                            />
                        </label>
                        <label class="filter-field">
                            <span>"Reason"</span>
                            <input
                                type="text"
                                placeholder="manual entry"
                                prop:value=move || reason.get()
                                on:input=move |ev| reason.set(event_target_value(&ev))
                            />
                        </label>
                        <button class="btn btn-primary" type="submit">"Ban"</button>
                    </form>
                </aside>

                <div class="table-wrap">
                    {move || {
                        let rows = filtered.get();
                        if rows.is_empty() {
                            view! {
                                <div class="empty-state">
                                    <p>"No active bans."</p>
                                    <p class="muted">
                                        "When the daemon reports bans they will appear here in real time."
                                    </p>
                                </div>
                            }.into_any()
                        } else {
                            view! {
                                <table class="data-table">
                                    <thead>
                                        <tr>
                                            <th>"Subject"</th>
                                            <th>"Severity"</th>
                                            <th>"Reason"</th>
                                            <th>"Expires"</th>
                                            <th>"Source"</th>
                                            <th class="col-actions">"Actions"</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {rows
                                            .into_iter()
                                            .map(|b| {
                                                let subject_for_unban = b.subject.clone();
                                                let badge_cls = severity_badge_class(b.severity);
                                                let expires = b
                                                    .expires_at
                                                    .clone()
                                                    .unwrap_or_else(|| "permanent".into());
                                                view! {
                                                    <tr>
                                                        <td><code>{b.subject.clone()}</code></td>
                                                        <td>
                                                            <span class=badge_cls>{b.severity.to_string()}</span>
                                                        </td>
                                                        <td>{b.reason.clone()}</td>
                                                        <td class="muted">{expires}</td>
                                                        <td><code class="muted">{b.source.clone()}</code></td>
                                                        <td class="col-actions">
                                                            <button
                                                                class="btn btn-danger"
                                                                on:click=move |_| {
                                                                    state
                                                                        .dispatch(
                                                                            Msg::UnbanRequested(subject_for_unban.clone()),
                                                                        );
                                                                }
                                                            >
                                                                "Unban"
                                                            </button>
                                                        </td>
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
