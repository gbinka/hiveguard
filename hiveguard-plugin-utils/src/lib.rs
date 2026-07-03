//! # hiveguard-plugin-utils
//!
//! Shared helpers for plugin authors. **Optional dependency** — plugins that
//! don't need these can ignore the crate entirely.
//!
//! Goals:
//!
//! * Eliminate the most common copy-paste between plugin implementations
//!   (HTTP client building, retry-with-backoff, payload templating).
//! * Be small and unopinionated. Anything more than ~30 lines goes into the
//!   plugin's own code, not here.
//!
//! Modules:
//!
//! * [`http`]     — `reqwest::Client` builder with sensible defaults.
//! * [`retry`]    — exponential backoff helper.
//! * [`template`] — `{{var}}` substitution for payload templates.
//! * [`ratelimit`]— in-process token bucket for self-throttling.

pub mod http;
pub mod ratelimit;
pub mod retry;
pub mod template;
