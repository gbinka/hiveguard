//! Integration tests for the consolidated `/api/...` surface migrated from the
//! legacy `/api/v1` REST server (REFACTOR 2.5). Uses `tower::ServiceExt::oneshot`
//! against a router backed by `MockUiApi`.

mod common;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use common::test_router;

const TOKEN: &str = "test-token-xyz";

fn get(path: &str, with_auth: bool) -> Request<Body> {
    let mut builder = Request::builder().method("GET").uri(path);
    if with_auth {
        builder = builder.header("Authorization", format!("Bearer {TOKEN}"));
    }
    builder.body(Body::empty()).unwrap()
}

fn json_req(method: &str, path: &str, body: serde_json::Value, with_auth: bool) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header("Content-Type", "application/json");
    if with_auth {
        builder = builder.header("Authorization", format!("Bearer {TOKEN}"));
    }
    builder.body(Body::from(body.to_string())).unwrap()
}

async fn body_to_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

// --- /api/stats -----------------------------------------------------------

#[tokio::test]
async fn stats_requires_auth_and_returns_version() {
    let app = test_router(TOKEN);

    let resp = app.clone().oneshot(get("/api/stats", false)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let resp = app.oneshot(get("/api/stats", true)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_to_json(resp).await;
    // Default `stats()` derives from `node_info()` — one ban, mock version.
    assert_eq!(json["version"], "0.0.0-test");
    assert_eq!(json["total_bans"], 1);
}

// --- /api/whitelist -------------------------------------------------------

#[tokio::test]
async fn whitelist_get_requires_auth() {
    let app = test_router(TOKEN);
    let resp = app.oneshot(get("/api/whitelist", false)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn whitelist_get_returns_entries() {
    let app = test_router(TOKEN);
    let resp = app.oneshot(get("/api/whitelist", true)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_to_json(resp).await;
    assert_eq!(json["entries"][0], "10.0.0.0/8");
}

#[tokio::test]
async fn whitelist_post_then_get_reflects_addition() {
    let app = test_router(TOKEN);

    let resp = app
        .clone()
        .oneshot(json_req(
            "POST",
            "/api/whitelist",
            serde_json::json!({ "cidr": "203.0.113.0/24" }),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    let resp = app.oneshot(get("/api/whitelist", true)).await.unwrap();
    let json = body_to_json(resp).await;
    let entries = json["entries"].as_array().unwrap();
    assert!(entries.iter().any(|e| e == "203.0.113.0/24"));
}

#[tokio::test]
async fn whitelist_post_rejects_garbage_cidr() {
    let app = test_router(TOKEN);
    let resp = app
        .oneshot(json_req(
            "POST",
            "/api/whitelist",
            serde_json::json!({ "cidr": "not-an-ip" }),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// --- /metrics (public) ----------------------------------------------------

#[tokio::test]
async fn metrics_is_public_and_returns_exposition() {
    let app = test_router(TOKEN);
    // No Authorization header — must NOT be 401 (endpoint is unauthenticated).
    let resp = app.oneshot(get("/metrics", false)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let ct = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(ct.contains("openmetrics-text"), "unexpected content-type: {ct}");
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let text = String::from_utf8(bytes.to_vec()).unwrap();
    assert!(text.contains("hiveguard_up"));
}

// --- PUT /api/config validation ------------------------------------------

#[tokio::test]
async fn put_config_accepts_valid_and_rejects_invalid() {
    let app = test_router(TOKEN);

    let resp = app
        .clone()
        .oneshot(json_req(
            "PUT",
            "/api/config",
            serde_json::json!({ "content": "node:\n  name: ok\n" }),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // The mock flags any content containing INVALID as a validation failure.
    let resp = app
        .oneshot(json_req(
            "PUT",
            "/api/config",
            serde_json::json!({ "content": "INVALID: : :" }),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// --- Disabled subsystems map to 503 --------------------------------------

#[tokio::test]
async fn sigma_rules_disabled_returns_503() {
    // MockUiApi uses the default `list_sigma_rules` impl → "not supported".
    let app = test_router(TOKEN);
    let resp = app.oneshot(get("/api/sigma/rules", true)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn bots_disabled_returns_503() {
    let app = test_router(TOKEN);
    let resp = app.oneshot(get("/api/bots", true)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
}

// --- Ingest route is unmounted when disabled ------------------------------

#[tokio::test]
async fn ingest_route_absent_when_disabled() {
    // `test_router` builds with `IngestState::default()` (disabled) → 404.
    let app = test_router(TOKEN);
    let resp = app
        .oneshot(json_req(
            "POST",
            "/api/ingest/logs",
            serde_json::json!(["test line"]),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}
