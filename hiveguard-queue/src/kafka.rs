//! Apache Kafka consumer log source — Phase 6.1.
//!
//! Implements [`LogSource`] on top of `rdkafka`'s async [`StreamConsumer`].
//!
//! # Features
//! * At-least-once delivery: offsets are committed **after** the event has
//!   been forwarded on the pipeline channel.
//! * Per-topic format/parser routing: `json` (raw log line, optionally wrapped
//!   in a JSON object) or `syslog` (RFC 5424 / RFC 3164 payload).
//! * SASL/PLAIN and SASL/SCRAM-SHA-512 authentication.
//! * TLS with optional mutual-TLS (client cert + key).
//! * Simple backpressure: if the pipeline channel free capacity drops below a
//!   configurable threshold, message processing pauses until it recovers.

use std::collections::HashMap;
use std::time::Duration;

use async_trait::async_trait;
use rdkafka::config::ClientConfig;
use rdkafka::consumer::{CommitMode, Consumer, StreamConsumer};
use rdkafka::message::Message;
use tokio::sync::{mpsc, watch};
use tracing::{debug, info, warn};

use hiveguard_core::config::{
    KafkaSaslMechanism, KafkaSourceConfig, KafkaTopicConfig, KafkaTopicFormat, KafkaTopicParser,
};
use hiveguard_core::errors::HiveGuardError;
use hiveguard_core::models::NormalizedEvent;
use hiveguard_ingest::nginx_parser::{nginx_event_to_normalized, parse_nginx_line, NginxPattern};
use hiveguard_ingest::postfix_parser::{
    parse_postfix_line, postfix_event_to_normalized, PostfixPatterns,
};
use hiveguard_ingest::source::LogSource;
use hiveguard_ingest::ssh_parser::{parse_ssh_line, ssh_event_to_normalized, SshPatterns};
use hiveguard_ingest::syslog_parser::parse_syslog;
use hiveguard_ingest::SyslogRouter;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// How long to wait between backpressure polls (channel-full situation).
const BACKPRESSURE_SLEEP_MS: u64 = 50;

/// Liveness-probe log interval.
const LIVENESS_CHECK_INTERVAL: Duration = Duration::from_secs(30);

// ---------------------------------------------------------------------------
// KafkaSource
// ---------------------------------------------------------------------------

/// Apache Kafka consumer implementing [`LogSource`].
///
/// Subscribe to one or more Kafka topics and forward parsed log lines as
/// [`NormalizedEvent`]s to the HiveGuard detection pipeline.
pub struct KafkaSource {
    config: KafkaSourceConfig,
    stop_tx: Option<watch::Sender<bool>>,
}

impl KafkaSource {
    /// Create a new Kafka source from configuration.
    pub fn new(config: KafkaSourceConfig) -> Self {
        Self {
            config,
            stop_tx: None,
        }
    }
}

#[async_trait]
impl LogSource for KafkaSource {
    fn name(&self) -> &str {
        "kafka"
    }

    async fn start(&mut self, sender: mpsc::Sender<NormalizedEvent>) -> Result<(), HiveGuardError> {
        if self.config.topics.is_empty() {
            return Err(HiveGuardError::Config(
                "Kafka source: no topics configured".to_string(),
            ));
        }

        let consumer: StreamConsumer = build_consumer(&self.config).map_err(|e| {
            HiveGuardError::Config(format!("Kafka consumer build error: {e}"))
        })?;

        let topic_names: Vec<&str> =
            self.config.topics.iter().map(|t| t.name.as_str()).collect();

        consumer.subscribe(&topic_names).map_err(|e| {
            HiveGuardError::Config(format!("Kafka subscribe error: {e}"))
        })?;

        info!(
            topics = ?topic_names,
            brokers = ?self.config.brokers,
            group_id = %self.config.group_id,
            "Kafka consumer subscribed"
        );

        let (stop_tx, stop_rx) = watch::channel(false);
        self.stop_tx = Some(stop_tx);

        // Build a per-topic lookup map for fast routing.
        let topic_configs: HashMap<String, KafkaTopicConfig> = self
            .config
            .topics
            .iter()
            .map(|t| (t.name.clone(), t.clone()))
            .collect();

        // Compute the backpressure watermark from channel capacity.
        let channel_capacity = sender.max_capacity();
        let backpressure_threshold = std::cmp::max(
            1,
            channel_capacity * usize::from(self.config.backpressure_threshold_pct) / 100,
        );

        tokio::spawn(run_kafka_consumer(
            consumer,
            sender,
            topic_configs,
            stop_rx,
            backpressure_threshold,
        ));

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
// Consumer task
// ---------------------------------------------------------------------------

async fn run_kafka_consumer(
    consumer: StreamConsumer,
    sender: mpsc::Sender<NormalizedEvent>,
    topic_configs: HashMap<String, KafkaTopicConfig>,
    mut stop_rx: watch::Receiver<bool>,
    backpressure_threshold: usize,
) {
    // Compile parsers once; reused for every message.
    let router = SyslogRouter::from_config(&[])
        .expect("SyslogRouter::from_config cannot fail with empty routes");
    let ssh_patterns = SshPatterns::new();
    let nginx_pattern = NginxPattern::new();
    let postfix_patterns = PostfixPatterns::new();

    let mut liveness_ticker = tokio::time::interval(LIVENESS_CHECK_INTERVAL);
    liveness_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = stop_rx.changed() => {
                if *stop_rx.borrow() {
                    info!("Kafka consumer stopping");
                    break;
                }
            }

            _ = liveness_ticker.tick() => {
                // rdkafka maintains broker connections automatically.
                // Emit a periodic heartbeat for observability.
                debug!("Kafka consumer heartbeat");
            }

            result = consumer.recv() => {
                match result {
                    Err(e) => {
                        warn!(error = %e, "Kafka recv error");
                    }
                    Ok(msg) => {
                        // ---------------------------------------------------
                        // Backpressure: hold the message (do NOT commit) until
                        // the pipeline channel has room again.
                        // ---------------------------------------------------
                        while sender.capacity() < backpressure_threshold {
                            debug!(
                                available = sender.capacity(),
                                threshold = backpressure_threshold,
                                "Kafka backpressure: channel near capacity"
                            );
                            tokio::time::sleep(Duration::from_millis(BACKPRESSURE_SLEEP_MS)).await;
                        }

                        // ---------------------------------------------------
                        // Deserialise and route.
                        // ---------------------------------------------------
                        let topic = msg.topic();
                        let topic_cfg = topic_configs.get(topic);

                        if let Some(event) = deserialize_message(
                            msg.payload(),
                            topic,
                            topic_cfg,
                            &router,
                            &ssh_patterns,
                            &nginx_pattern,
                            &postfix_patterns,
                        ) {
                            if sender.send(event).await.is_err() {
                                info!("Kafka consumer: pipeline channel closed, stopping");
                                break;
                            }
                        }

                        // ---------------------------------------------------
                        // Commit offset only after forwarding — at-least-once.
                        // ---------------------------------------------------
                        if let Err(e) = consumer.commit_message(&msg, CommitMode::Async) {
                            warn!(error = %e, topic, "Kafka offset commit error");
                        }
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Message deserialisation
// ---------------------------------------------------------------------------

fn deserialize_message(
    payload: Option<&[u8]>,
    topic: &str,
    config: Option<&KafkaTopicConfig>,
    router: &SyslogRouter,
    ssh_patterns: &SshPatterns,
    nginx_pattern: &NginxPattern,
    postfix_patterns: &PostfixPatterns,
) -> Option<NormalizedEvent> {
    let bytes = payload?;
    let raw = std::str::from_utf8(bytes).ok()?;

    let format = config
        .map(|c| &c.format)
        .unwrap_or(&KafkaTopicFormat::Json);
    let parser = config
        .map(|c| &c.parser)
        .unwrap_or(&KafkaTopicParser::Auto);

    match format {
        KafkaTopicFormat::Json => {
            // If the payload is a JSON object, try to extract the log line from
            // well-known keys (Filebeat: "message", Fluentd: "log", Logstash: "msg").
            let line: std::borrow::Cow<str> = match extract_json_log_line(raw) {
                Some(owned) => std::borrow::Cow::Owned(owned),
                None => std::borrow::Cow::Borrowed(raw),
            };
            apply_parser(&line, parser, topic, ssh_patterns, nginx_pattern, postfix_patterns)
        }
        KafkaTopicFormat::Syslog => {
            // Parse as RFC 5424 / RFC 3164 syslog, then route by app-name.
            let syslog_msg = parse_syslog(raw)?;
            router.route(syslog_msg, topic, None)
        }
    }
}

/// Extract a raw log line from a JSON-wrapped payload.
///
/// Supports the conventions used by popular log shippers:
/// * Filebeat: `{"message": "..."}`
/// * Fluentd / Docker logging driver: `{"log": "..."}`
/// * Logstash: `{"msg": "..."}`
/// * AWS: `{"@message": "..."}`
///
/// Returns `None` if the payload is not a JSON object or has none of the
/// known keys, so the caller can fall back to using the raw string.
fn extract_json_log_line(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if !trimmed.starts_with('{') {
        return None;
    }
    let v: serde_json::Value = serde_json::from_str(trimmed).ok()?;
    let obj = v.as_object()?;
    for key in &["message", "log", "msg", "@message"] {
        if let Some(serde_json::Value::String(s)) = obj.get(*key) {
            return Some(s.clone());
        }
    }
    None
}

/// Apply a named parser to a raw log line.
fn apply_parser(
    line: &str,
    parser: &KafkaTopicParser,
    _source_name: &str,
    ssh_patterns: &SshPatterns,
    nginx_pattern: &NginxPattern,
    postfix_patterns: &PostfixPatterns,
) -> Option<NormalizedEvent> {
    match parser {
        KafkaTopicParser::Ssh => {
            parse_ssh_line(line, ssh_patterns).map(ssh_event_to_normalized)
        }
        KafkaTopicParser::Nginx => {
            parse_nginx_line(line, nginx_pattern).map(nginx_event_to_normalized)
        }
        KafkaTopicParser::Postfix => {
            parse_postfix_line(line, postfix_patterns).map(postfix_event_to_normalized)
        }
        KafkaTopicParser::Auto => {
            // Try parsers in order of likelihood; first match wins.
            if let Some(ev) = parse_ssh_line(line, ssh_patterns) {
                return Some(ssh_event_to_normalized(ev));
            }
            if let Some(ev) = parse_nginx_line(line, nginx_pattern) {
                return Some(nginx_event_to_normalized(ev));
            }
            if let Some(ev) = parse_postfix_line(line, postfix_patterns) {
                return Some(postfix_event_to_normalized(ev));
            }
            // Try syslog as last resort (some shippers wrap lines in syslog).
            let syslog_msg = parse_syslog(line)?;
            // Reconstruct a minimal router for the auto case.
            let fallback_router = SyslogRouter::from_config(&[]).ok()?;
            fallback_router.route(syslog_msg, "kafka-auto", None)
        }
    }
}

// ---------------------------------------------------------------------------
// rdkafka ClientConfig builder
// ---------------------------------------------------------------------------

/// Build a [`StreamConsumer`] from [`KafkaSourceConfig`].
fn build_consumer(config: &KafkaSourceConfig) -> Result<StreamConsumer, rdkafka::error::KafkaError> {
    let brokers = config.brokers.join(",");
    let mut cc = ClientConfig::new();

    cc.set("bootstrap.servers", &brokers)
        .set("group.id", &config.group_id)
        // Manual offset commit for at-least-once delivery.
        .set("enable.auto.commit", "false")
        .set("session.timeout.ms", config.session_timeout_ms.to_string())
        .set("max.poll.interval.ms", config.max_poll_interval_ms.to_string())
        // Start from the earliest available offset on first join.
        .set("auto.offset.reset", "earliest");

    // --- TLS ---
    if let Some(ref tls) = config.tls {
        cc.set("security.protocol", "ssl");
        if let Some(ref ca) = tls.ca_cert {
            cc.set("ssl.ca.location", ca);
        }
        if let Some(ref cert) = tls.client_cert {
            cc.set("ssl.certificate.location", cert);
        }
        if let Some(ref key) = tls.client_key {
            cc.set("ssl.key.location", key);
        }
    }

    // --- SASL (overrides security.protocol set above) ---
    if let Some(ref sasl) = config.sasl {
        let protocol = if config.tls.is_some() {
            "sasl_ssl"
        } else {
            "sasl_plaintext"
        };
        let mechanism = match sasl.mechanism {
            KafkaSaslMechanism::Plain => "PLAIN",
            KafkaSaslMechanism::ScramSha512 => "SCRAM-SHA-512",
        };
        cc.set("security.protocol", protocol)
            .set("sasl.mechanism", mechanism)
            .set("sasl.username", &sasl.username)
            .set("sasl.password", &sasl.password);
    }

    cc.create()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_json_log_line_message_key() {
        let json = r#"{"message": "Failed password for root from 1.2.3.4 port 22 ssh2", "host": "web01"}"#;
        let result = extract_json_log_line(json);
        assert_eq!(
            result.as_deref(),
            Some("Failed password for root from 1.2.3.4 port 22 ssh2")
        );
    }

    #[test]
    fn test_extract_json_log_line_log_key() {
        let json = r#"{"log": "192.168.1.1 - - [01/Jan/2026:00:00:00 +0000] \"GET / HTTP/1.1\" 200 0"}"#;
        let result = extract_json_log_line(json);
        assert!(result.is_some());
    }

    #[test]
    fn test_extract_json_log_line_plain_text() {
        let plain = "Failed password for root from 1.2.3.4 port 22 ssh2";
        let result = extract_json_log_line(plain);
        assert!(result.is_none(), "plain text should fall through to raw");
    }

    #[test]
    fn test_extract_json_log_line_no_known_key() {
        let json = r#"{"timestamp": "2026-01-01T00:00:00Z", "level": "warn"}"#;
        let result = extract_json_log_line(json);
        assert!(result.is_none());
    }
}
