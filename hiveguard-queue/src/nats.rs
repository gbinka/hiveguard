//! NATS / JetStream consumer log source — Phase 6.4.
//!
//! Implements [`LogSource`] on top of the `async-nats` 0.35 client.
//!
//! # Modes
//! * **Core NATS** — plain pub/sub (`client.subscribe` / `client.queue_subscribe`).
//!   At-most-once delivery; no explicit ACK required by the broker.
//! * **JetStream pull consumer** — durable, explicit ACK per message,
//!   at-least-once delivery with configurable backpressure.
//!
//! # Authentication
//! * NKey + JWT via a `.creds` file (`credentials_file` config key).
//! * TLS: CA certificate (`tls_ca`), optional mTLS client cert + key.
//!
//! # Subject routing
//! `subject_routes` maps NATS subject patterns (supporting `*` single-token
//! and `>` multi-token suffix wildcards) to log parsers.  Falls back to the
//! top-level `parser` field when no rule matches.

use std::time::Duration;

use async_trait::async_trait;
use futures::StreamExt;
use tokio::sync::{mpsc, watch};
use tracing::{debug, error, info, warn};

use hiveguard_core::config::{KafkaTopicParser, NatsJetStreamConfig, NatsSourceConfig};
use hiveguard_core::errors::HiveGuardError;
use hiveguard_core::models::NormalizedEvent;
use hiveguard_ingest::source::LogSource;

use crate::deserializer::MessageRouter;

// ---------------------------------------------------------------------------
// NatsSource
// ---------------------------------------------------------------------------

/// NATS / JetStream consumer implementing [`LogSource`].
pub struct NatsSource {
    config: NatsSourceConfig,
    stop_tx: Option<watch::Sender<bool>>,
}

impl NatsSource {
    /// Create a new NATS source from configuration.
    pub fn new(config: NatsSourceConfig) -> Self {
        Self {
            config,
            stop_tx: None,
        }
    }
}

#[async_trait]
impl LogSource for NatsSource {
    fn name(&self) -> &str {
        "nats"
    }

    async fn start(&mut self, sender: mpsc::Sender<NormalizedEvent>) -> Result<(), HiveGuardError> {
        let (stop_tx, stop_rx) = watch::channel(false);
        self.stop_tx = Some(stop_tx);

        let config = self.config.clone();
        tokio::spawn(async move {
            if let Err(e) = run_nats(config, sender, stop_rx).await {
                error!(error = %e, "NATS consumer exited with error");
            }
        });

        Ok(())
    }

    async fn stop(&mut self) -> Result<(), HiveGuardError> {
        if let Some(tx) = self.stop_tx.take() {
            let _ = tx.send(true);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Connection builder
// ---------------------------------------------------------------------------

async fn build_client(cfg: &NatsSourceConfig) -> Result<async_nats::Client, HiveGuardError> {
    let mut opts = async_nats::ConnectOptions::new()
        .name("hiveguard");

    // TLS CA certificate
    if let Some(ref ca) = cfg.tls_ca {
        opts = opts.add_root_certificates(ca.into());
    }

    // mTLS client certificate + key — both must be present together
    match (&cfg.tls_cert, &cfg.tls_key) {
        (Some(cert), Some(key)) => {
            opts = opts.add_client_certificate(cert.into(), key.into());
        }
        (Some(_), None) | (None, Some(_)) => {
            return Err(HiveGuardError::Config(
                "NATS: both tls_cert and tls_key must be set for mTLS".into(),
            ));
        }
        _ => {}
    }

    // NKey + JWT credentials file
    if let Some(ref creds) = cfg.credentials_file {
        opts = opts
            .credentials_file(creds)
            .await
            .map_err(|e| HiveGuardError::Config(format!("NATS credentials file: {e}")))?;
    }

    let connect_str = cfg.servers.join(",");
    let client = opts
        .connect(connect_str.as_str())
        .await
        .map_err(|e| HiveGuardError::Protocol(format!("NATS connect: {e}")))?;

    Ok(client)
}

// ---------------------------------------------------------------------------
// Top-level runner
// ---------------------------------------------------------------------------

async fn run_nats(
    cfg: NatsSourceConfig,
    sender: mpsc::Sender<NormalizedEvent>,
    stop_rx: watch::Receiver<bool>,
) -> Result<(), HiveGuardError> {
    info!(servers = ?cfg.servers, subject = %cfg.subject, "NATS connecting");

    let client = build_client(&cfg).await?;

    // Liveness probe — flush every 30 s to detect stale connections
    let probe_client = client.clone();
    let mut probe_stop = stop_rx.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        loop {
            tokio::select! {
                biased;
                _ = probe_stop.changed() => {
                    if *probe_stop.borrow() { break; }
                }
                _ = interval.tick() => {
                    if let Err(e) = probe_client.flush().await {
                        warn!(error = %e, "NATS liveness flush failed");
                    } else {
                        debug!("NATS liveness probe OK");
                    }
                }
            }
        }
    });

    let router = MessageRouter::new();

    if let Some(ref js_cfg) = cfg.jetstream.clone() {
        run_jetstream(&cfg, &client, js_cfg, sender, stop_rx, &router).await
    } else {
        run_core_nats(&cfg, &client, sender, stop_rx, &router).await
    }
}

// ---------------------------------------------------------------------------
// Core NATS consumer loop (at-most-once, no ACK)
// ---------------------------------------------------------------------------

async fn run_core_nats(
    cfg: &NatsSourceConfig,
    client: &async_nats::Client,
    sender: mpsc::Sender<NormalizedEvent>,
    mut stop_rx: watch::Receiver<bool>,
    router: &MessageRouter,
) -> Result<(), HiveGuardError> {
    let mut subscriber = if let Some(ref qg) = cfg.queue_group {
        client
            .queue_subscribe(cfg.subject.clone(), qg.clone())
            .await
            .map_err(|e| HiveGuardError::Protocol(format!("NATS queue_subscribe: {e}")))?
    } else {
        client
            .subscribe(cfg.subject.clone())
            .await
            .map_err(|e| HiveGuardError::Protocol(format!("NATS subscribe: {e}")))?
    };

    info!(subject = %cfg.subject, "NATS core subscriber ready");

    loop {
        tokio::select! {
            biased;
            _ = stop_rx.changed() => {
                if *stop_rx.borrow() {
                    info!("NATS core subscriber stopping");
                    break;
                }
            }
            msg = subscriber.next() => {
                match msg {
                    Some(msg) => {
                        process_message(&msg.payload, msg.subject.as_str(), cfg, &sender, router).await;
                    }
                    None => {
                        info!("NATS core subscriber stream ended");
                        break;
                    }
                }
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// JetStream pull consumer loop (at-least-once, explicit ACK)
// ---------------------------------------------------------------------------

async fn run_jetstream(
    cfg: &NatsSourceConfig,
    client: &async_nats::Client,
    js_cfg: &NatsJetStreamConfig,
    sender: mpsc::Sender<NormalizedEvent>,
    mut stop_rx: watch::Receiver<bool>,
    router: &MessageRouter,
) -> Result<(), HiveGuardError> {
    use async_nats::jetstream::consumer::pull;
    use async_nats::jetstream::consumer::{AckPolicy, DeliverPolicy};

    let deliver_policy = match js_cfg.deliver_policy.as_str() {
        "all" => DeliverPolicy::All,
        "new" => DeliverPolicy::New,
        _ => DeliverPolicy::Last,
    };

    let js = async_nats::jetstream::new(client.clone());

    let consumer: async_nats::jetstream::consumer::Consumer<pull::Config> = js
        .create_consumer_on_stream(
            pull::Config {
                durable_name: Some(js_cfg.consumer.clone()),
                name: Some(js_cfg.consumer.clone()),
                deliver_policy,
                max_ack_pending: js_cfg.max_ack_pending,
                ack_policy: AckPolicy::Explicit,
                filter_subject: cfg.subject.clone(),
                ..Default::default()
            },
            &js_cfg.stream,
        )
        .await
        .map_err(|e| HiveGuardError::Protocol(format!("JetStream consumer: {e}")))?;

    info!(
        stream = %js_cfg.stream,
        consumer = %js_cfg.consumer,
        "JetStream pull consumer ready"
    );

    let channel_cap = sender.max_capacity();

    loop {
        if *stop_rx.borrow() {
            info!("JetStream consumer stopping");
            break;
        }

        // Backpressure: throttle batch size when the pipeline channel is >80% full
        let free = sender.capacity();
        let batch = if channel_cap > 0 && free < channel_cap / 5 {
            1usize
        } else {
            js_cfg.batch_size
        };

        let messages_result = tokio::select! {
            biased;
            _ = stop_rx.changed() => {
                if *stop_rx.borrow() { break; }
                continue;
            }
            r = consumer.fetch().max_messages(batch).messages() => r,
        };

        let mut messages = match messages_result {
            Ok(m) => m,
            Err(e) => {
                warn!(error = %e, "JetStream fetch error, retrying in 1s");
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            }
        };

        loop {
            let next = tokio::select! {
                biased;
                _ = stop_rx.changed() => {
                    if *stop_rx.borrow() { return Ok(()); }
                    break;
                }
                v = messages.next() => v,
            };

            match next {
                Some(Ok(msg)) => {
                    let subject = msg.subject.as_str();
                    process_message(&msg.payload, subject, cfg, &sender, router).await;
                    if let Err(e) = msg.ack().await {
                        warn!(error = %e, "JetStream ACK failed");
                    }
                }
                Some(Err(e)) => {
                    warn!(error = %e, "JetStream message error");
                }
                None => break,
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Per-message processing
// ---------------------------------------------------------------------------

async fn process_message(
    payload: &[u8],
    subject: &str,
    cfg: &NatsSourceConfig,
    sender: &mpsc::Sender<NormalizedEvent>,
    router: &MessageRouter,
) {
    let raw = match std::str::from_utf8(payload) {
        Ok(s) => s.trim(),
        Err(_) => {
            warn!(subject = %subject, "NATS: non-UTF-8 payload, skipping");
            return;
        }
    };

    if raw.is_empty() {
        return;
    }

    debug!(subject = %subject, line = %raw, "NATS message");

    let parser = resolve_parser(subject, cfg);
    if let Some(event) = router.route_line(raw, parser, "nats") {
        if sender.send(event).await.is_err() {
            warn!("NATS: pipeline channel closed");
        }
    }
}

/// Select the parser for a message based on `subject_routes`, falling back to
/// the top-level `parser` when no pattern matches.
fn resolve_parser<'a>(subject: &str, cfg: &'a NatsSourceConfig) -> &'a KafkaTopicParser {
    for route in &cfg.subject_routes {
        if subject_matches(&route.pattern, subject) {
            return &route.parser;
        }
    }
    &cfg.parser
}

// ---------------------------------------------------------------------------
// NATS subject wildcard matching
// ---------------------------------------------------------------------------

/// Match a NATS *subject* against a *pattern*.
///
/// NATS wildcard semantics:
/// * `*` — matches exactly **one** subject token.
/// * `>` — matches **one or more** trailing subject tokens (must appear last).
fn subject_matches(pattern: &str, subject: &str) -> bool {
    let pp: Vec<&str> = pattern.split('.').collect();
    let sp: Vec<&str> = subject.split('.').collect();
    let mut pi = 0usize;
    let mut si = 0usize;

    loop {
        if pi == pp.len() && si == sp.len() {
            return true;
        }
        if pi == pp.len() {
            return false; // pattern exhausted, subject still has tokens
        }

        let tok = pp[pi];

        if tok == ">" {
            // ">" matches any number of remaining subject tokens (at least one)
            return si < sp.len();
        }

        if si == sp.len() {
            return false; // subject exhausted, pattern still has tokens
        }

        if tok == "*" || tok == sp[si] {
            pi += 1;
            si += 1;
        } else {
            return false;
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use hiveguard_core::config::{KafkaTopicParser, NatsSourceConfig, NatsSubjectRoute};

    fn make_config() -> NatsSourceConfig {
        NatsSourceConfig {
            servers: vec!["nats://localhost:4222".into()],
            subject: "logs.>".into(),
            queue_group: Some("hiveguard".into()),
            jetstream: None,
            credentials_file: None,
            tls_ca: None,
            tls_cert: None,
            tls_key: None,
            subject_routes: vec![
                NatsSubjectRoute {
                    pattern: "logs.nginx.*".into(),
                    parser: KafkaTopicParser::Nginx,
                },
                NatsSubjectRoute {
                    pattern: "logs.ssh.*".into(),
                    parser: KafkaTopicParser::Ssh,
                },
            ],
            parser: KafkaTopicParser::Auto,
            reconnect_buffer_size: 8 * 1024 * 1024,
        }
    }

    #[test]
    fn test_source_name() {
        assert_eq!(NatsSource::new(make_config()).name(), "nats");
    }

    #[test]
    fn test_subject_single_wildcard() {
        assert!(subject_matches("logs.nginx.*", "logs.nginx.access"));
        assert!(!subject_matches("logs.nginx.*", "logs.nginx.access.extra"));
        assert!(!subject_matches("logs.nginx.*", "logs.nginx"));
    }

    #[test]
    fn test_subject_multi_wildcard() {
        assert!(subject_matches("logs.>", "logs.nginx.access.2024"));
        assert!(subject_matches("logs.>", "logs.ssh.auth"));
        assert!(!subject_matches("logs.>", "metrics.nginx"));
        // ">" requires at least one token after the prefix
        assert!(!subject_matches("logs.>", "logs"));
    }

    #[test]
    fn test_subject_exact_match() {
        assert!(subject_matches("hiveguard.events", "hiveguard.events"));
        assert!(!subject_matches("hiveguard.events", "hiveguard.events.debug"));
        assert!(!subject_matches("hiveguard.events", "hiveguard"));
    }

    #[test]
    fn test_subject_mixed_wildcards() {
        assert!(subject_matches("logs.*.access", "logs.nginx.access"));
        assert!(!subject_matches("logs.*.access", "logs.nginx.error"));
        assert!(subject_matches("logs.*.*", "logs.nginx.access"));
        assert!(!subject_matches("logs.*.*", "logs.nginx.access.extra"));
    }

    #[test]
    fn test_resolve_parser_routes() {
        let cfg = make_config();
        assert!(matches!(
            resolve_parser("logs.nginx.access", &cfg),
            KafkaTopicParser::Nginx
        ));
        assert!(matches!(
            resolve_parser("logs.ssh.auth", &cfg),
            KafkaTopicParser::Ssh
        ));
        assert!(matches!(
            resolve_parser("logs.postfix.mail", &cfg),
            KafkaTopicParser::Auto
        ));
    }

    #[test]
    fn test_stop_before_start_is_noop() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut src = NatsSource::new(make_config());
            src.stop().await.unwrap();
        });
    }
}
