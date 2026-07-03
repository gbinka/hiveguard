//! `ApiClient` trait — abstraction over the transport used to talk to the
//! daemon's REST/WebSocket API. Implementations live in renderer crates:
//!
//! - `plugins/ui-tui` ships a `ReqwestClient` (native HTTP)
//! - `plugins/ui-web` ships a `FetchClient` (browser `fetch` via gloo-net)
//!
//! Both expose the same interface so `hiveguard-ui` can stay platform-agnostic.

use std::fmt;

/// Error type that any transport can return. Concrete error chains live in
/// the implementing crates.
#[derive(Debug)]
pub struct ApiError(pub String);

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "API error: {}", self.0)
    }
}

impl std::error::Error for ApiError {}

/// Trait every UI transport implements. Phase 5 expands with concrete
/// endpoints (`list_bans`, `subscribe_threats`, etc.) once `plugins/ui-rest`
/// stabilises its API surface.
pub trait ApiClient {
    /// Smoke endpoint — returns "ok" when the daemon is reachable.
    fn ping(&self) -> Result<(), ApiError>;
}
