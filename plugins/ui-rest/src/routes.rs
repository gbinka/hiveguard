//! REST + WebSocket router assembly.

use std::path::{Path as StdPath, PathBuf};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, Path, Query, State},
    http::{header, HeaderMap, HeaderValue, Method, StatusCode},
    middleware,
    response::{IntoResponse, Json, Response},
    routing::{delete, get, post},
    Router,
};
use ipnet::IpNet;
use percent_encoding::percent_decode_str;
use serde::Deserialize;
use serde_json::{json, Value};
use tower_http::cors::CorsLayer;
use tower_http::services::{ServeDir, ServeFile};

use hiveguard_plugin_api::prelude::{BanRequest, PluginError};

use crate::auth::{ct_eq, require_auth};
use crate::state::AppState;
use crate::ws::ws_handler;

/// Prometheus / OpenMetrics exposition content type.
const METRICS_CONTENT_TYPE: &str = "application/openmetrics-text; version=1.0.0; charset=utf-8";

/// Build the complete Axum router with all routes wired up.
pub fn build_router(
    state: Arc<AppState>,
    static_dir: Option<PathBuf>,
    cors_origins: &[String],
) -> Router {
    // Authenticated API surface (everything except the public endpoints below).
    let api = Router::new()
        .route("/api/info", get(get_info))
        .route("/api/stats", get(get_stats))
        .route("/api/bans", get(get_bans).post(post_ban))
        .route("/api/bans/{cidr}", delete(delete_ban))
        .route("/api/whitelist", get(get_whitelist).post(post_whitelist))
        .route("/api/whitelist/{cidr}", delete(delete_whitelist))
        .route("/api/peers", get(get_peers))
        .route("/api/bots", get(get_bots))
        .route("/api/bots/{name}/policy", post(post_bot_policy))
        .route("/api/config", get(get_config).put(put_config))
        .route("/api/config/detectors", get(get_detectors).put(put_detectors))
        .route("/api/fail2ban/preview", get(get_fail2ban_preview))
        .route("/api/fail2ban/import", post(post_fail2ban_import))
        .route("/api/sigma/rules", get(get_sigma_rules).post(post_sigma_rule))
        .route("/api/sigma/rules/{id}", get(get_sigma_rule).delete(delete_sigma_rule))
        .route("/api/sigma/stats", get(get_sigma_stats))
        .route("/api/threats", get(get_threats))
        .route("/api/plugins", get(get_plugins))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            require_auth,
        ));

    // Public surface — no auth. `/metrics` matches the legacy unauthenticated
    // Prometheus scrape endpoint exactly.
    let public = Router::new()
        .route("/api/health", get(get_health))
        .route("/api/stream", get(ws_handler))
        .route("/metrics", get(get_metrics));

    let mut router = Router::new().merge(public).merge(api);

    // HTTP-push ingest — mounted only when enabled. Carries its own Bearer
    // token gate + per-second rate limit (in the handler) and a body-size cap
    // (the `DefaultBodyLimit` layer here).
    if state.ingest.enabled {
        let ingest = Router::new()
            .route("/api/ingest/logs", post(post_ingest_logs))
            .layer(DefaultBodyLimit::max(state.ingest.max_request_bytes));
        router = router.merge(ingest);
    }

    // Static file serving (optional).
    if let Some(dir) = static_dir {
        router = mount_static_files(router, &dir);
    }

    // CORS layer (optional).
    if !cors_origins.is_empty() {
        router = router.layer(build_cors_layer(cors_origins));
    }

    router.with_state(state)
}

fn build_cors_layer(origins: &[String]) -> CorsLayer {
    let allowed: Vec<HeaderValue> = origins
        .iter()
        .filter_map(|o| HeaderValue::from_str(o).ok())
        .collect();

    CorsLayer::new()
        .allow_origin(allowed)
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([
            axum::http::header::AUTHORIZATION,
            axum::http::header::CONTENT_TYPE,
        ])
}

/// Mount static SPA files at `/` with index.html fallback for client-side
/// routes (`/bans`, `/threats`, `/plugins`, `/config`, `/`).
fn mount_static_files(
    router: Router<Arc<AppState>>,
    dir: &StdPath,
) -> Router<Arc<AppState>> {
    let index = dir.join("index.html");
    let serve_dir = ServeDir::new(dir).fallback(ServeFile::new(&index));
    router.fallback_service(serve_dir)
}

// ---------------------------------------------------------------------------
// Request body / query types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct WhitelistAddRequest {
    cidr: String,
}

#[derive(Debug, Deserialize)]
struct SetBotPolicyRequest {
    policy: String,
}

#[derive(Debug, Deserialize)]
struct ConfigUpdateRequest {
    content: String,
}

#[derive(Debug, Deserialize)]
struct SigmaUploadRequest {
    yaml: String,
}

#[derive(Debug, Deserialize)]
struct Fail2banQuery {
    db: Option<String>,
    jail: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Fail2banImportRequest {
    db: Option<String>,
    jail: Option<String>,
}

// ---------------------------------------------------------------------------
// Read / WebSocket handlers (pre-existing)
// ---------------------------------------------------------------------------

async fn get_health(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let uptime = state.started_at.elapsed().as_secs();
    Json(json!({
        "status": "ok",
        "uptime_secs": uptime,
    }))
}

async fn get_info(State(state): State<Arc<AppState>>) -> Response {
    let info = state.api.node_info().await;
    Json(info).into_response()
}

async fn get_stats(State(state): State<Arc<AppState>>) -> Response {
    Json(state.api.stats().await).into_response()
}

async fn get_bans(State(state): State<Arc<AppState>>) -> Response {
    let bans = state.api.list_bans().await;
    Json(bans).into_response()
}

async fn get_threats(State(state): State<Arc<AppState>>) -> Response {
    let threats = state.api.list_threats().await;
    Json(threats).into_response()
}

async fn get_plugins(State(state): State<Arc<AppState>>) -> Response {
    let plugins = state.api.list_plugins().await;
    Json(plugins).into_response()
}

async fn post_ban(
    State(state): State<Arc<AppState>>,
    Json(req): Json<BanRequest>,
) -> Response {
    match state.api.add_ban(req).await {
        Ok(()) => (StatusCode::CREATED, Json(json!({ "status": "created" }))).into_response(),
        Err(e) => plugin_err_to_response(e),
    }
}

async fn delete_ban(
    State(state): State<Arc<AppState>>,
    Path(cidr): Path<String>,
) -> Response {
    let net = match decode_target(&cidr) {
        Ok(n) => n,
        Err(resp) => return resp,
    };
    match state.api.remove_ban(net).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => plugin_err_to_response(e),
    }
}

// ---------------------------------------------------------------------------
// Whitelist handlers
// ---------------------------------------------------------------------------

async fn get_whitelist(State(state): State<Arc<AppState>>) -> Response {
    let entries = state.api.list_whitelist().await;
    Json(json!({ "entries": entries })).into_response()
}

async fn post_whitelist(
    State(state): State<Arc<AppState>>,
    Json(body): Json<WhitelistAddRequest>,
) -> Response {
    let net = match parse_target(&body.cidr) {
        Ok(n) => n,
        Err(e) => return bad_request(e),
    };
    match state.api.add_whitelist(net).await {
        Ok(()) => (
            StatusCode::CREATED,
            Json(json!({ "message": format!("Whitelisted {net}") })),
        )
            .into_response(),
        Err(e) => mgmt_err_to_response(e),
    }
}

async fn delete_whitelist(
    State(state): State<Arc<AppState>>,
    Path(cidr): Path<String>,
) -> Response {
    let net = match decode_target(&cidr) {
        Ok(n) => n,
        Err(resp) => return resp,
    };
    match state.api.remove_whitelist(net).await {
        Ok(()) => (
            StatusCode::OK,
            Json(json!({ "message": format!("Removed {net} from whitelist") })),
        )
            .into_response(),
        Err(e) => mgmt_err_to_response(e),
    }
}

async fn get_peers(State(state): State<Arc<AppState>>) -> Response {
    Json(json!({ "peers": state.api.list_peers().await })).into_response()
}

// ---------------------------------------------------------------------------
// Bot management handlers
// ---------------------------------------------------------------------------

async fn get_bots(State(state): State<Arc<AppState>>) -> Response {
    match state.api.list_bots().await {
        Ok(v) => Json(v).into_response(),
        Err(e) => mgmt_err_to_response(e),
    }
}

async fn post_bot_policy(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
    Json(body): Json<SetBotPolicyRequest>,
) -> Response {
    match state.api.set_bot_policy(name.clone(), body.policy.clone()).await {
        Ok(()) => (
            StatusCode::OK,
            Json(json!({ "message": format!("Policy for '{name}' set to '{}'", body.policy.to_lowercase()) })),
        )
            .into_response(),
        Err(e) => mgmt_err_to_response(e),
    }
}

// ---------------------------------------------------------------------------
// Config management handlers
// ---------------------------------------------------------------------------

async fn get_config(State(state): State<Arc<AppState>>) -> Response {
    match state.api.get_config().await {
        Ok(content) => Json(json!({ "content": content })).into_response(),
        Err(e) => mgmt_err_to_response(e),
    }
}

async fn put_config(
    State(state): State<Arc<AppState>>,
    Json(body): Json<ConfigUpdateRequest>,
) -> Response {
    match state.api.put_config(body.content).await {
        Ok(()) => (
            StatusCode::OK,
            Json(json!({ "message": "Config saved. Restart daemon to apply changes." })),
        )
            .into_response(),
        Err(e) => mgmt_err_to_response(e),
    }
}

async fn get_detectors(State(state): State<Arc<AppState>>) -> Response {
    match state.api.get_detectors().await {
        Ok(v) => Json(v).into_response(),
        Err(e) => mgmt_err_to_response(e),
    }
}

async fn put_detectors(
    State(state): State<Arc<AppState>>,
    Json(body): Json<Value>,
) -> Response {
    match state.api.put_detectors(body).await {
        Ok(()) => (
            StatusCode::OK,
            Json(json!({ "message": "Detector rules saved. Restart daemon to apply changes." })),
        )
            .into_response(),
        Err(e) => mgmt_err_to_response(e),
    }
}

// ---------------------------------------------------------------------------
// Fail2ban handlers
// ---------------------------------------------------------------------------

async fn get_fail2ban_preview(
    State(state): State<Arc<AppState>>,
    Query(q): Query<Fail2banQuery>,
) -> Response {
    match state.api.fail2ban_preview(q.db, q.jail).await {
        Ok(bans) => {
            let total = bans.len();
            Json(json!({ "bans": bans, "total": total })).into_response()
        }
        Err(e) => mgmt_err_to_response(e),
    }
}

async fn post_fail2ban_import(
    State(state): State<Arc<AppState>>,
    Json(body): Json<Fail2banImportRequest>,
) -> Response {
    match state.api.fail2ban_import(body.db, body.jail).await {
        Ok(info) => Json(info).into_response(),
        Err(e) => mgmt_err_to_response(e),
    }
}

// ---------------------------------------------------------------------------
// Sigma rule management handlers
// ---------------------------------------------------------------------------

async fn get_sigma_rules(State(state): State<Arc<AppState>>) -> Response {
    match state.api.list_sigma_rules().await {
        Ok(rules) => {
            let total = rules.len();
            Json(json!({ "rules": rules, "total": total })).into_response()
        }
        Err(e) => mgmt_err_to_response(e),
    }
}

async fn post_sigma_rule(
    State(state): State<Arc<AppState>>,
    Json(body): Json<SigmaUploadRequest>,
) -> Response {
    match state.api.upsert_sigma_rule(body.yaml).await {
        Ok(id) => Json(json!({ "message": format!("Rule '{id}' saved") })).into_response(),
        Err(e) => mgmt_err_to_response(e),
    }
}

async fn get_sigma_rule(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Response {
    match state.api.get_sigma_rule(id.clone()).await {
        Ok(Some(detail)) => Json(detail).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": format!("Rule '{id}' not found") })),
        )
            .into_response(),
        Err(e) => mgmt_err_to_response(e),
    }
}

async fn delete_sigma_rule(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Response {
    match state.api.delete_sigma_rule(id.clone()).await {
        Ok(()) => Json(json!({ "message": format!("Rule '{id}' deleted") })).into_response(),
        Err(e) => mgmt_err_to_response(e),
    }
}

async fn get_sigma_stats(State(state): State<Arc<AppState>>) -> Response {
    match state.api.sigma_stats().await {
        Ok(s) => Json(s).into_response(),
        Err(e) => mgmt_err_to_response(e),
    }
}

// ---------------------------------------------------------------------------
// Metrics (public, no auth)
// ---------------------------------------------------------------------------

async fn get_metrics(State(state): State<Arc<AppState>>) -> Response {
    match state.api.render_metrics().await {
        Some(body) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, METRICS_CONTENT_TYPE)],
            body,
        )
            .into_response(),
        None => (
            StatusCode::SERVICE_UNAVAILABLE,
            [(header::CONTENT_TYPE, METRICS_CONTENT_TYPE)],
            "# Metrics not enabled\n".to_string(),
        )
            .into_response(),
    }
}

// ---------------------------------------------------------------------------
// HTTP-push ingest (own token gate + per-second rate limit)
// ---------------------------------------------------------------------------

async fn post_ingest_logs(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let ingest = &state.ingest;

    // Auth: dedicated ingest token (resolved to the main token at startup
    // when none was configured). Constant-time comparison.
    if let Some(ref expected) = ingest.token {
        let provided = headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .unwrap_or("");
        if !ct_eq(provided.as_bytes(), expected.as_bytes()) {
            return (StatusCode::UNAUTHORIZED, Json(json!({ "error": "Unauthorized" }))).into_response();
        }
    }

    // Per-second rate limit.
    if !push_rate_limit_ok(&ingest.rate_limiter, ingest.rate_limit_per_sec) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({ "error": "Rate limit exceeded" })),
        )
            .into_response();
    }

    let body_str = match std::str::from_utf8(&body) {
        Ok(s) => s.trim(),
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "Request body must be valid UTF-8" })),
            )
                .into_response();
        }
    };

    if body_str.is_empty() {
        return Json(json!({ "accepted": 0, "rejected": 0 })).into_response();
    }

    // Collect log lines: JSON array, single JSON object, or NDJSON fallback.
    let lines: Vec<String> = if let Ok(val) = serde_json::from_str::<Value>(body_str) {
        match val {
            Value::Array(arr) => arr.iter().filter_map(json_value_to_log_line).collect(),
            other => json_value_to_log_line(&other).into_iter().collect(),
        }
    } else {
        body_str
            .lines()
            .filter(|l| !l.trim().is_empty())
            .flat_map(|l| {
                if let Ok(val) = serde_json::from_str::<Value>(l) {
                    json_value_to_log_line(&val)
                } else {
                    Some(l.to_string())
                }
            })
            .collect()
    };

    match state.api.ingest_logs(lines, ingest.parser.clone()).await {
        Ok((accepted, rejected)) => {
            Json(json!({ "accepted": accepted, "rejected": rejected })).into_response()
        }
        Err(e) => mgmt_err_to_response(e),
    }
}

/// Extract a plain log line from a JSON value.
///
/// * String → used as-is.
/// * Object → first non-empty value under `message`, `log`, `msg`, `text`,
///   `line`, `event`.
/// * Anything else → `None`.
fn json_value_to_log_line(v: &Value) -> Option<String> {
    match v {
        Value::String(s) if !s.trim().is_empty() => Some(s.clone()),
        Value::Object(map) => {
            for key in &["message", "log", "msg", "text", "line", "event"] {
                if let Some(Value::String(s)) = map.get(*key) {
                    let trimmed = s.trim();
                    if !trimmed.is_empty() {
                        return Some(trimmed.to_string());
                    }
                }
            }
            None
        }
        _ => None,
    }
}

/// Per-second sliding-window check. Returns `true` if the request is allowed.
fn push_rate_limit_ok(limiter: &Mutex<(Instant, u32)>, max_per_sec: u32) -> bool {
    let mut guard = limiter.lock().unwrap_or_else(|e| e.into_inner());
    let (ref mut window_start, ref mut count) = *guard;
    let now = Instant::now();
    if now.duration_since(*window_start).as_secs() >= 1 {
        *window_start = now;
        *count = 0;
    }
    if *count >= max_per_sec {
        return false;
    }
    *count += 1;
    true
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Parse a bare IP or CIDR into an [`IpNet`] (bare IPs become `/32` or `/128`).
fn parse_target(target: &str) -> Result<IpNet, String> {
    if let Ok(net) = target.parse::<IpNet>() {
        return Ok(net);
    }
    if let Ok(ip) = target.parse::<std::net::IpAddr>() {
        return Ok(IpNet::from(ip));
    }
    Err(format!(
        "Invalid IP or CIDR: '{target}'. Use format like 10.0.0.1 or 10.0.0.0/24"
    ))
}

/// Percent-decode a path segment and parse it as an IP/CIDR target, returning
/// a ready `400` response on failure.
fn decode_target(raw: &str) -> Result<IpNet, Response> {
    let decoded = percent_decode_str(raw)
        .decode_utf8()
        .map_err(|_| bad_request("invalid percent-encoded CIDR".to_string()))?
        .into_owned();
    // Accept both strict CIDR and bare IPs.
    IpNet::from_str(&decoded)
        .map_err(|_| ())
        .or_else(|()| parse_target(&decoded).map_err(|_| ()))
        .map_err(|()| bad_request(format!("invalid CIDR: '{decoded}'")))
}

fn bad_request(msg: String) -> Response {
    (StatusCode::BAD_REQUEST, Json(json!({ "error": msg }))).into_response()
}

/// Error mapping for the ban endpoints (legacy semantics: generic failures →
/// 500, validation → 400).
fn plugin_err_to_response(err: PluginError) -> Response {
    let status = match &err {
        PluginError::ConfigValidation(_) | PluginError::MissingConfig(_) => StatusCode::BAD_REQUEST,
        PluginError::NotFound(_) => StatusCode::NOT_FOUND,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    (status, Json(json!({ "error": err.to_string() }))).into_response()
}

/// Error mapping for the management endpoints. Disabled subsystems surface as
/// `Runtime` and map to `503`, matching the legacy `/api/v1` behaviour.
fn mgmt_err_to_response(err: PluginError) -> Response {
    let status = match &err {
        PluginError::ConfigValidation(_) | PluginError::MissingConfig(_) => StatusCode::BAD_REQUEST,
        PluginError::NotFound(_) => StatusCode::NOT_FOUND,
        _ => StatusCode::SERVICE_UNAVAILABLE,
    };
    (status, Json(json!({ "error": err.to_string() }))).into_response()
}
