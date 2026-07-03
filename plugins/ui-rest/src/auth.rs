//! Authentication middleware for the REST surface.
//!
//! Validates the `Authorization: Bearer <token>` header against the
//! plugin's configured token using constant-time comparison.

use std::sync::Arc;

use axum::{
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Json, Response},
};
use serde_json::json;
use subtle::ConstantTimeEq;

use crate::state::AppState;

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

/// Axum middleware: require a valid Bearer token on every request.
pub async fn require_auth(
    State(state): State<Arc<AppState>>,
    req: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let auth_header = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok());

    match auth_header {
        Some(value) if value.starts_with("Bearer ") => {
            let token = &value.as_bytes()["Bearer ".len()..];
            if ct_eq(token, state.auth_token.as_bytes()) {
                return next.run(req).await;
            }
            unauthorized("Invalid authentication token")
        }
        Some(_) => unauthorized("Malformed Authorization header (expected: Bearer <token>)"),
        None => unauthorized("Missing Authorization header"),
    }
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
    use super::ct_eq;

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
}
