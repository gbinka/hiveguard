//! Global reactive state for the Leptos SPA.
//!
//! `hiveguard-ui` owns the model (`AppModel`) and the transition function
//! (`update`). Leptos owns the *reactivity* — we wrap the model in a single
//! `RwSignal<AppModel>` and expose a `dispatch(msg)` helper that routes
//! every intent through the pure `update` function. That keeps the
//! single-source-of-truth contract documented in `hiveguard-ui/src/lib.rs`.

use hiveguard_ui::{update, AppModel, Msg};
use leptos::prelude::*;

/// Wrapper around the global `RwSignal<AppModel>` so we can pass it via
/// Leptos context without ambiguity (`RwSignal<AppModel>` alone collides
/// if other code provides similar signals).
#[derive(Clone, Copy)]
pub struct AppState(pub RwSignal<AppModel>);

impl AppState {
    pub fn new() -> Self {
        Self(RwSignal::new(AppModel::default()))
    }

    /// Read the current model. Subscribes the calling reactive scope.
    pub fn get(&self) -> AppModel {
        self.0.get()
    }

    /// Dispatch a `Msg` — runs `hiveguard_ui::update` and stores the result.
    /// Identical to the TUI's event loop, just behind a reactive signal.
    pub fn dispatch(&self, msg: Msg) {
        self.0.update(|m| {
            // `update` takes ownership; clone the current value, mutate,
            // then write back. Cheap because `AppModel` is small.
            *m = update(m.clone(), msg);
        });
    }
}

/// Pull `AppState` out of Leptos context. Panics if `provide_context` wasn't
/// called — that's a programming error (always call from `App`).
pub fn use_app_state() -> AppState {
    use_context::<AppState>().expect("AppState not provided — call provide_context in App")
}
