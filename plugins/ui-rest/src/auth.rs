//! Authentication + authorisation for the REST surface.
//!
//! Two bearer tokens are recognised, both compared in constant time:
//!
//! - the **admin** token (`auth_token` of `ui.rest`) — everything;
//! - the optional **read-only** agent token (`agent.read_token_file` on the
//!   host) — every `GET` (except `/api/fail2ban/preview`, which opens an
//!   arbitrary SQLite path), the read-only agent `POST`s
//!   ([`READ_ONLY_POSTS`]) and the streams. Anything else → `403`.
//!
//! The middleware stores an [`AuthContext`] in the request extensions so
//! handlers can write audit records (`target: "hiveguard::audit"`).

use std::sync::Arc;

use axum::{
    extract::State,
    http::{HeaderMap, Method, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Json, Response},
};
use serde_json::json;
use subtle::ConstantTimeEq;
use tracing::info;

use crate::state::AppState;

/// `POST` routes that only read (query bodies) — allowed for the read-only token.
pub const READ_ONLY_POSTS: &[&str] = &[
    "/api/agent/logs/query",
    "/api/agent/logs/stats",
    "/api/agent/ip",
    "/api/agent/config/validate",
];

/// `GET` routes the read-only token may NOT use.
pub const READ_DENIED_GETS: &[&str] = &["/api/fail2ban/preview"];

/// Which token authenticated the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenKind {
    Admin,
    Read,
}

impl TokenKind {
    pub fn as_str(self) -> &'static str {
        match self {
            TokenKind::Admin => "admin",
            TokenKind::Read => "read",
        }
    }
}

/// Stored in request extensions by [`require_auth`].
#[derive(Debug, Clone)]
pub struct AuthContext {
    pub token: TokenKind,
    /// Best-effort client class for the audit log: `agent` (read-only token,
    /// or a `hiveguard-mcp` / `hg-agent-proxy` User-Agent) or `rest`.
    pub source: &'static str,
}

/// Compare two byte slices in constant time.
///
/// `ConstantTimeEq` requires equal-length inputs to be meaningful — when
/// the lengths differ we still scan one of them (against a zero buffer of
/// matching length) so that the work performed is independent of the
/// expected token's value. The end result is always `false` for different
/// lengths.
pub(crate) fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        // Touch `a` to discourage easy length-side-channel optimisation.
        let zeros = vec![0u8; a.len()];
        let _: bool = a.ct_eq(&zeros).into();
        return false;
    }
    a.ct_eq(b).into()
}

/// Classify a presented token. Both comparisons always run (no early exit
/// revealing which token was close). Admin wins if both match.
pub fn classify_token(state: &AppState, presented: &[u8]) -> Option<TokenKind> {
    let admin = ct_eq(presented, state.auth_token.as_bytes());
    let read = match &state.read_token {
        Some(rt) => ct_eq(presented, rt.as_bytes()),
        None => {
            let _ = ct_eq(presented, state.auth_token.as_bytes());
            false
        }
    };
    if admin {
        Some(TokenKind::Admin)
    } else if read {
        Some(TokenKind::Read)
    } else {
        None
    }
}

/// May the read-only token call `method path`?
pub fn read_token_allows(method: &Method, path: &str) -> bool {
    if method == Method::GET || method == Method::HEAD {
        return !READ_DENIED_GETS.contains(&path);
    }
    method == Method::POST && READ_ONLY_POSTS.contains(&path)
}

/// Audit source for a request authenticated with `token`.
pub fn client_source(headers: &HeaderMap, token: TokenKind) -> &'static str {
    if token == TokenKind::Read {
        return "agent";
    }
    let ua = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if ua.starts_with("hiveguard-mcp") || ua.starts_with("hg-agent-proxy") {
        "agent"
    } else {
        "rest"
    }
}

/// `Authorization: Bearer <token>` value, if well-formed.
pub fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
}

/// Axum middleware: require a valid Bearer token on every request and
/// enforce the read-only token's policy.
pub async fn require_auth(
    State(state): State<Arc<AppState>>,
    mut req: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let auth_header = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok());

    let kind = match auth_header {
        Some(value) if value.starts_with("Bearer ") => {
            match classify_token(&state, &value.as_bytes()["Bearer ".len()..]) {
                Some(k) => k,
                None => return unauthorized("Invalid authentication token"),
            }
        }
        Some(_) => return unauthorized("Malformed Authorization header (expected: Bearer <token>)"),
        None => return unauthorized("Missing Authorization header"),
    };

    let source = client_source(req.headers(), kind);
    if kind == TokenKind::Read && !read_token_allows(req.method(), req.uri().path()) {
        info!(
            target: "hiveguard::audit",
            op = %format!("{} {}", req.method(), req.uri().path()),
            source,
            token = kind.as_str(),
            outcome = "denied",
            "read-only token refused"
        );
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "read-only token: this operation needs the admin token" })),
        )
            .into_response();
    }
    req.extensions_mut().insert(AuthContext { token: kind, source });
    next.run(req).await
}

fn unauthorized(msg: &'static str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({ "error": msg })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ct_eq_returns_true_for_equal_inputs() {
        assert!(ct_eq(b"secret-token", b"secret-token"));
    }

    #[test]
    fn ct_eq_returns_false_for_different_inputs_same_length() {
        assert!(!ct_eq(b"secret-token", b"OtHeR-Token!"));
    }

    #[test]
    fn ct_eq_returns_false_for_different_lengths() {
        assert!(!ct_eq(b"short", b"much-longer-string"));
    }

    #[test]
    fn read_policy() {
        assert!(read_token_allows(&Method::GET, "/api/bans"));
        assert!(read_token_allows(&Method::GET, "/api/agent/config"));
        assert!(read_token_allows(&Method::POST, "/api/agent/logs/query"));
        assert!(read_token_allows(&Method::POST, "/api/agent/config/validate"));
        assert!(!read_token_allows(&Method::GET, "/api/fail2ban/preview"));
        assert!(!read_token_allows(&Method::POST, "/api/bans"));
        assert!(!read_token_allows(&Method::DELETE, "/api/bans/100.64.0.1"));
        assert!(!read_token_allows(&Method::PUT, "/api/config"));
        assert!(!read_token_allows(&Method::POST, "/api/whitelist"));
    }
}
