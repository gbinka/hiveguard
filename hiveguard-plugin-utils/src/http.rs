use std::time::Duration;

use hiveguard_plugin_api::error::{PluginError, PluginResult};

/// Build a `reqwest::Client` with HiveGuard's recommended defaults:
///
/// * `User-Agent: HiveGuard/<version>` (so endpoints can identify the source).
/// * TLS via `rustls` (no system OpenSSL).
/// * Configurable per-request timeout.
/// * No redirect chains beyond 5 hops.
/// * No HTTP/2 keep-alive for now (some webhook endpoints misbehave with
///   long-lived connections).
///
/// Plugins should call this once during `init` and stash the client on `self`.
pub fn build_client(timeout: Duration) -> PluginResult<reqwest::Client> {
    let user_agent = format!("HiveGuard/{}", env!("CARGO_PKG_VERSION"));
    reqwest::Client::builder()
        .user_agent(user_agent)
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()
        .map_err(|e| PluginError::Init(format!("failed to build HTTP client: {e}")))
}

/// Convenience: ensure response status is 2xx, mapping anything else to a
/// [`PluginError::Runtime`].
///
/// Use after `client.post(...).send().await` to convert HTTP-level
/// failures into plugin errors. The body is *not* read on success — the
/// caller decides whether they need it.
pub async fn check_status(resp: reqwest::Response) -> PluginResult<reqwest::Response> {
    if resp.status().is_success() {
        return Ok(resp);
    }
    let status = resp.status();
    let body = resp
        .text()
        .await
        .unwrap_or_else(|_| "<unable to read body>".to_owned());
    let body_preview = body.chars().take(256).collect::<String>();
    Err(PluginError::Runtime(format!(
        "HTTP {status}: {body_preview}"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_client_with_reasonable_timeout() {
        let client = build_client(Duration::from_secs(5)).unwrap();
        // Smoke test — client is constructed, we can't easily inspect its
        // internals without reqwest exposing them.
        drop(client);
    }
}
