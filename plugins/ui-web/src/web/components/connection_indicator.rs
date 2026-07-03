//! `<ConnectionIndicator />` — pill badge showing the current
//! [`ConnectionStatus`]. Colour coding mirrors `hiveguard_ui::view::Severity`:
//!
//! | status        | severity | css class       |
//! |---------------|----------|-----------------|
//! | Connected     | Success  | `badge-success` |
//! | Connecting    | Info     | `badge-info`    |
//! | Disconnected  | Warning  | `badge-warning` |
//! | Failed(_)     | Danger   | `badge-danger`  |

use hiveguard_ui::ConnectionStatus;
use leptos::prelude::*;

use crate::state::use_app_state;

#[component]
pub fn ConnectionIndicator() -> impl IntoView {
    let state = use_app_state();

    // Derived signal — recomputes only when `status` changes.
    let label = move || match state.get().status {
        ConnectionStatus::Connected => ("Connected".to_string(), "badge badge-success"),
        ConnectionStatus::Connecting => ("Connecting…".to_string(), "badge badge-info"),
        ConnectionStatus::Disconnected => ("Disconnected".to_string(), "badge badge-warning"),
        ConnectionStatus::Failed(reason) => {
            (format!("Failed: {reason}"), "badge badge-danger")
        }
    };

    view! {
        <span class=move || label().1>
            {move || label().0}
        </span>
    }
}
