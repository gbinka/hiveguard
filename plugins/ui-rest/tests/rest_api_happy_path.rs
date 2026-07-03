//! REST happy-path integration tests using `tower::ServiceExt::oneshot`.

mod common;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use hiveguard_plugin_api::prelude::{BanInfo, NodeInfo};
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

async fn body_to_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn health_endpoint_does_not_require_auth() {
    let app = test_router(TOKEN);
    let resp = app.oneshot(get("/api/health", false)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_to_json(resp).await;
    assert_eq!(json["status"], "ok");
    assert!(json["uptime_secs"].is_u64());
}

#[tokio::test]
async fn info_endpoint_requires_auth() {
    let app = test_router(TOKEN);
    let resp = app.oneshot(get("/api/info", false)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn info_endpoint_returns_node_info_with_auth() {
    let app = test_router(TOKEN);
    let resp = app.oneshot(get("/api/info", true)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let info: NodeInfo = serde_json::from_slice(&bytes).expect("body parses as NodeInfo");
    assert_eq!(info.node_name, "test-node");
    assert_eq!(info.daemon_version, "0.0.0-test");
}

#[tokio::test]
async fn bans_endpoint_returns_list() {
    let app = test_router(TOKEN);
    let resp = app.oneshot(get("/api/bans", true)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let bans: Vec<BanInfo> = serde_json::from_slice(&bytes).expect("body parses as Vec<BanInfo>");
    assert_eq!(bans.len(), 1);
    assert_eq!(bans[0].subject, "1.2.3.4/32");
}

#[tokio::test]
async fn threats_and_plugins_endpoints_return_lists() {
    let app = test_router(TOKEN);

    let resp = app.clone().oneshot(get("/api/threats", true)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_to_json(resp).await;
    assert!(json.is_array());

    let resp = app.oneshot(get("/api/plugins", true)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_to_json(resp).await;
    assert!(json.is_array());
}

#[tokio::test]
async fn post_ban_creates_new_ban() {
    let app = test_router(TOKEN);
    let body = serde_json::json!({
        "subject": "5.6.7.8/32",
        "duration": { "secs": 3600, "nanos": 0 },
        "reason": "test add",
    });
    let req = Request::builder()
        .method("POST")
        .uri("/api/bans")
        .header("Authorization", format!("Bearer {TOKEN}"))
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn delete_ban_removes_existing_ban() {
    let app = test_router(TOKEN);
    // The mock starts with "1.2.3.4/32" — URL-encode the slash.
    let req = Request::builder()
        .method("DELETE")
        .uri("/api/bans/1.2.3.4%2F32")
        .header("Authorization", format!("Bearer {TOKEN}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn delete_ban_returns_400_for_invalid_cidr() {
    let app = test_router(TOKEN);
    let req = Request::builder()
        .method("DELETE")
        .uri("/api/bans/not-a-cidr")
        .header("Authorization", format!("Bearer {TOKEN}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}
