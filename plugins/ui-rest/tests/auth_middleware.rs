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
