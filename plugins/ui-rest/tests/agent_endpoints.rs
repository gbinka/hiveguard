//! Integration tests for the `/api/agent/*` analysis surface (docs/AGENT_API.md):
//! auth, parameter plumbing (query → JSON object / body → JSON), error mapping
//! (400 / 404 / 503) and the SSE stream.

mod common;

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

use common::{test_router, test_router_with, MockUiApi};
use hiveguard_plugin_api::prelude::{AgentEvent, ThreatInfo};

const TOKEN: &str = "agent-token";

fn get(path: &str, with_auth: bool) -> Request<Body> {
    let mut b = Request::builder().method("GET").uri(path);
    if with_auth {
        b = b.header("Authorization", format!("Bearer {TOKEN}"));
    }
    b.body(Body::empty()).unwrap()
}

fn post(path: &str, body: serde_json::Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(path)
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {TOKEN}"))
        .body(Body::from(body.to_string()))
        .unwrap()
}

async fn json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn agent_routes_require_auth() {
    let app = test_router(TOKEN);
    for path in [
        "/api/agent/overview",
        "/api/agent/bans",
        "/api/agent/threats",
        "/api/agent/logs/sources",
        "/api/agent/journal",
        "/api/agent/detectors",
        "/api/agent/catalog",
    ] {
        let resp = app.clone().oneshot(get(path, false)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "{path}");
    }
    let resp = app.clone().oneshot(get("/api/agent/stream", false)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let resp = app.oneshot(get("/api/agent/stream?token=wrong", false)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn query_params_are_forwarded_as_json_object() {
    let app = test_router(TOKEN);
    let resp = app
        .oneshot(get("/api/agent/bans?source=detector&since=24h&limit=5&subnet_only=true", true))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v = json(resp).await;
    assert_eq!(v["op"], "bans");
    assert_eq!(v["params"]["source"], "detector");
    assert_eq!(v["params"]["since"], "24h");
    assert_eq!(v["params"]["limit"], "5");
    assert_eq!(v["params"]["subnet_only"], "true");
}

#[tokio::test]
async fn bodies_are_forwarded_verbatim() {
    let app = test_router(TOKEN);
    let body = serde_json::json!({"source": "nginx", "group_by": "ip", "filter": {"fields": {"status": "4xx"}}, "top": 10});
    let resp = app.clone().oneshot(post("/api/agent/logs/stats", body.clone())).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v = json(resp).await;
    assert_eq!(v["op"], "log_stats");
    assert_eq!(v["params"], body);

    let resp = app.clone().oneshot(post("/api/agent/logs/query", serde_json::json!({"source": "ssh", "limit": 3}))).await.unwrap();
    assert_eq!(json(resp).await["op"], "log_query");

    let resp = app.oneshot(post("/api/agent/ip", serde_json::json!({"ip": "11.0.0.1"}))).await.unwrap();
    let v = json(resp).await;
    assert_eq!(v["op"], "ip");
    assert_eq!(v["params"]["ip"], "11.0.0.1");
}

#[tokio::test]
async fn catalog_kind_and_validate_body() {
    let app = test_router(TOKEN);
    let resp = app.clone().oneshot(get("/api/agent/catalog?kind=detector", true)).await.unwrap();
    assert_eq!(json(resp).await["params"]["kind"], "detector");
    let resp = app.clone().oneshot(get("/api/agent/catalog", true)).await.unwrap();
    assert!(json(resp).await["params"]["kind"].is_null());

    let resp = app.clone().oneshot(post("/api/agent/config/validate", serde_json::json!({"content": "node: {}"}))).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(json(resp).await["valid"], true);
    let resp = app.clone().oneshot(post("/api/agent/config/validate", serde_json::json!({"content": "INVALID"}))).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(json(resp).await["valid"], false);
    // Missing `content` → axum JSON rejection (422).
    let resp = app.oneshot(post("/api/agent/config/validate", serde_json::json!({}))).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn error_mapping_400_404_503() {
    let app = test_router(TOKEN);
    let resp = app.clone().oneshot(get("/api/agent/threats?since=garbage", true)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(json(resp).await["error"].as_str().unwrap().contains("since"));

    let resp = app.oneshot(post("/api/agent/logs/query", serde_json::json!({"source": "missing"}))).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    let app = test_router_with(TOKEN, Arc::new(MockUiApi::without_agent()));
    let resp = app.clone().oneshot(get("/api/agent/overview", true)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    let resp = app.oneshot(get(&format!("/api/agent/stream?token={TOKEN}"), false)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn sse_stream_delivers_filtered_events() {
    let mock = Arc::new(MockUiApi::new());
    let app = test_router_with(TOKEN, mock.clone());

    // Bearer header auth, only `signal` events requested.
    let resp = app
        .oneshot(get("/api/agent/stream?types=signal", true))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let ct = resp.headers().get("content-type").unwrap().to_str().unwrap().to_string();
    assert!(ct.starts_with("text/event-stream"), "{ct}");

    // The handler subscribed during `oneshot`; events sent now are delivered.
    mock.agent_events.send(AgentEvent::BanRemoved { subject: "11.0.0.1/32".into() }).unwrap();
    mock.agent_events
        .send(AgentEvent::Signal(ThreatInfo {
            ip: "11.0.0.7".into(),
            severity: 90,
            confidence: 80,
            detector: "path_probe".into(),
            reason: "probe".into(),
            timestamp: "2026-10-09T06:00:00Z".into(),
        }))
        .unwrap();

    let mut body = resp.into_body();
    let frame = tokio::time::timeout(std::time::Duration::from_secs(5), body.frame())
        .await
        .expect("frame within 5s")
        .expect("stream open")
        .expect("ok frame");
    let text = String::from_utf8(frame.into_data().unwrap().to_vec()).unwrap();
    assert!(text.starts_with("event: signal\n"), "{text}");
    assert!(text.contains("\"ip\":\"11.0.0.7\""), "{text}");
    assert!(!text.contains("ban_removed"));
}

#[tokio::test]
async fn sse_stream_accepts_query_token_and_all_types() {
    let mock = Arc::new(MockUiApi::new());
    let app = test_router_with(TOKEN, mock.clone());
    let resp = app.oneshot(get(&format!("/api/agent/stream?token={TOKEN}"), false)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    mock.agent_events.send(AgentEvent::BanRemoved { subject: "11.0.0.1/32".into() }).unwrap();
    let mut body = resp.into_body();
    let frame = tokio::time::timeout(std::time::Duration::from_secs(5), body.frame())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let text = String::from_utf8(frame.into_data().unwrap().to_vec()).unwrap();
    assert!(text.starts_with("event: ban_removed\n"), "{text}");
    assert!(text.contains("\"subject\":\"11.0.0.1/32\""), "{text}");
}
