//! Integration test: launch a mock HTTP server, instantiate the plugin against
//! it, send a real alert event, verify the POST arrived with the expected body.

use std::sync::Arc;

use hiveguard_plugin_api::prelude::*;
use hiveguard_plugin_api::context::parking_lot_compat::RegistryHandle;
use hiveguard_plugin_api::secrets::SecretResolver;
use hiveguard_plugin_notifier_webhook::WebhookNotifier;
use ipnet::IpNet;
use wiremock::matchers::{body_string_contains, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn test_ctx() -> PluginContext {
    PluginContext::new(
        "notifier.webhook".to_string(),
        std::env::temp_dir(),
        Arc::new(SecretResolver::new()),
        PluginMetrics {
            registry: Arc::new(RegistryHandle::default()),
            plugin_id: "notifier.webhook".to_string(),
        },
        CancellationToken::new(),
    )
}

#[tokio::test]
async fn delivers_json_payload_to_mock_server() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/hook"))
        .and(header("content-type", "application/json"))
        .and(body_string_contains("ip_banned"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;

    let cfg = serde_json::json!({
        "url": format!("{}/hook", server.uri()),
        "timeout_secs": 5,
    });
    let plugin = WebhookNotifier::create(test_ctx(), cfg).await.unwrap();

    let event = AlertEvent::IpBanned {
        ip: "1.2.3.4/32".parse::<IpNet>().unwrap(),
        severity: 100,
        reason: "integration test".into(),
        geo: None,
    };
    plugin.notify(&event).await.unwrap();
}

#[tokio::test]
async fn returns_error_on_non_2xx() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&server)
        .await;

    let cfg = serde_json::json!({
        "url": format!("{}/hook", server.uri()),
        "timeout_secs": 5,
    });
    let plugin = WebhookNotifier::create(test_ctx(), cfg).await.unwrap();

    let event = AlertEvent::HoneypotHit {
        ip: "10.0.0.1".into(),
        path: "/.env".into(),
    };
    let result = plugin.notify(&event).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn template_renders_into_body() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/slack"))
        .and(body_string_contains("Banned 1.2.3.4/32"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;

    let cfg = serde_json::json!({
        "url": format!("{}/slack", server.uri()),
        "template": "{\"text\": \"Banned {{ip}}: {{reason}}\"}",
        "timeout_secs": 5,
    });
    let plugin = WebhookNotifier::create(test_ctx(), cfg).await.unwrap();

    let event = AlertEvent::IpBanned {
        ip: "1.2.3.4/32".parse::<IpNet>().unwrap(),
        severity: 100,
        reason: "test".into(),
        geo: None,
    };
    plugin.notify(&event).await.unwrap();
}

#[tokio::test]
async fn event_filter_drops_unmatched_kinds() {
    let server = MockServer::start().await;
    // The mock expects zero calls — if the filter doesn't work, this fails.
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&server)
        .await;

    let cfg = serde_json::json!({
        "url": format!("{}/hook", server.uri()),
        "events": ["HoneypotHit"],
        "timeout_secs": 5,
    });
    let plugin = WebhookNotifier::create(test_ctx(), cfg).await.unwrap();

    // Send a non-honeypot event — should be filtered out.
    let event = AlertEvent::PeerDown {
        node_id: "node-1".into(),
        address: "127.0.0.1:7946".parse().unwrap(),
    };
    plugin.notify(&event).await.unwrap();
}
