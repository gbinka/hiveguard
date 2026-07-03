//! Generic "coming in Phase 5" panel used by the non-Dashboard routes.
//! Keeps the router wiring exercisable without committing to view content
//! that's still being designed.

use leptos::prelude::*;

#[component]
pub fn Placeholder(#[prop(into)] title: String) -> impl IntoView {
    view! {
        <section class="placeholder">
            <h1>{title}</h1>
            <p class="muted">
                "This view is a Phase 5 scaffold. \
                 Functionality will land alongside the matching \
                 `UiApiHandle` endpoints in `hiveguard-plugin-api`."
            </p>
        </section>
    }
}
