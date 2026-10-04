//! Authentication-focused tests for the REST surface.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use common::test_router;

const TOKEN: &str = "correct-horse-battery-staple";

#[tokio::test]
async fn invalid_bearer_token_returns_401() {
    let app = test_router(TOKEN);
    let req = Request::builder()
        .method("GET")
        .uri("/api/info")
        .header("Authorization", "Bearer wrong-token")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn malformed_authorization_header_returns_401() {
    let app = test_router(TOKEN);
    let req = Request::builder()
        .method("GET")
        .uri("/api/bans")
        .header("Authorization", "Basic abcdef")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn missing_authorization_header_returns_401() {
    let app = test_router(TOKEN);
    let req = Request::builder()
        .method("GET")
        .uri("/api/plugins")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn token_of_wrong_length_still_rejected() {
    let app = test_router(TOKEN);
    let req = Request::builder()
        .method("GET")
        .uri("/api/threats")
        .header("Authorization", "Bearer short")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn ingest_requires_nonempty_token_and_explicit_bearer_header() {
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    use hiveguard_plugin_ui_rest::state::{AppState, IngestState};
    use hiveguard_plugin_ui_rest::routes::build_router;
    use tokio_util::sync::CancellationToken;
    for (token, auth, expected) in [
        (Some(""), None, StatusCode::UNAUTHORIZED),
        (Some("  "), Some("Bearer   "), StatusCode::UNAUTHORIZED),
        (None, None, StatusCode::UNAUTHORIZED),
        (Some("ingest-secret"), None, StatusCode::UNAUTHORIZED),
        (Some("ingest-secret"), Some("Basic ingest-secret"), StatusCode::UNAUTHORIZED),
        (Some("ingest-secret"), Some("Bearer ingest-secret"), StatusCode::OK),
    ] {
        let state = Arc::new(AppState {
            api: Arc::new(common::MockUiApi::new()), auth_token: TOKEN.into(),
            started_at: Instant::now(), tick_interval: Duration::from_secs(30),
            shutdown: CancellationToken::new(),
            ingest: IngestState { enabled: true, token: token.map(str::to_string), ..Default::default() },
        });
        let router = build_router(state, None, &[]);
        let mut request = Request::builder().method("POST").uri("/api/ingest/logs");
        if let Some(auth) = auth { request = request.header("Authorization", auth); }
        let response = router.oneshot(request.body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(response.status(), expected);
    }
}
