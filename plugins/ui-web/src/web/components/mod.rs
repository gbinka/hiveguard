//! Leptos UI components.
//!
//! Phase 5: the four data views (Bans, Threats, Plugins, Config) are now
//! real components driven by `hiveguard_ui::AppModel`. `Placeholder` stays
//! around as the router's 404 fallback.

pub mod bans;
pub mod config;
pub mod connection_indicator;
pub mod dashboard;
pub mod nav;
pub mod placeholder;
pub mod plugins;
pub mod threats;
