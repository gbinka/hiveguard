//! RabbitMQ AMQP 0-9-1 consumer log source — Phase 6.3.1.
//!
//! Implements [`LogSource`] on top of the `lapin` async AMQP client.
//!
//! # Features
//! * At-least-once delivery: `basic.ack` is sent **after** the event has been
//!   forwarded on the pipeline channel.
//! * TLS support: use an `amqps://` URL for encrypted connections.
//! * Configurable QoS (`prefetch_count`) to throttle unacknowledged messages.
//! * Optional exchange binding: if `exchange` is set the queue is bound to
//!   that exchange on startup using the configured `routing_key`.
//! * Clean shutdown via a `tokio::sync::watch` channel.

use async_trait::async_trait;
use lapin::options::{
    BasicAckOptions, BasicConsumeOptions, BasicNackOptions, BasicQosOptions, QueueBindOptions,
    QueueDeclareOptions,
};
use lapin::types::FieldTable;
use lapin::{Connection, ConnectionProperties};
use tokio::sync::{mpsc, watch};
use tracing::{debug, error, info, warn};

use hiveguard_core::config::RabbitMqSourceConfig;
use hiveguard_core::errors::HiveGuardError;
use hiveguard_core::models::NormalizedEvent;
use hiveguard_ingest::source::LogSource;

use crate::deserializer::MessageRouter;

// ---------------------------------------------------------------------------
// RabbitMqSource
// ---------------------------------------------------------------------------

/// RabbitMQ AMQP 0-9-1 consumer implementing [`LogSource`].
///
/// Consumes messages from a single queue, parses each payload as a log line,
/// and forwards the resulting [`NormalizedEvent`] to the HiveGuard pipeline.
pub struct RabbitMqSource {
    config: RabbitMqSourceConfig,
    stop_tx: Option<watch::Sender<bool>>,
}

impl RabbitMqSource {
    /// Create a new RabbitMQ source from configuration.
    pub fn new(config: RabbitMqSourceConfig) -> Self {
        Self {
            config,
            stop_tx: None,
        }
    }
}

#[async_trait]
impl LogSource for RabbitMqSource {
    fn name(&self) -> &str {
        "rabbitmq"
    }

    async fn start(&mut self, sender: mpsc::Sender<NormalizedEvent>) -> Result<(), HiveGuardError> {
        let (stop_tx, mut stop_rx) = watch::channel(false);
        self.stop_tx = Some(stop_tx);

        let config = self.config.clone();

        tokio::spawn(async move {
            if let Err(e) = run_consumer(config, sender, &mut stop_rx).await {
                error!(error = %e, "RabbitMQ consumer exited with error");
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
// Internal consumer loop
// ---------------------------------------------------------------------------

async fn run_consumer(
    config: RabbitMqSourceConfig,
    sender: mpsc::Sender<NormalizedEvent>,
    stop_rx: &mut watch::Receiver<bool>,
) -> Result<(), HiveGuardError> {
    info!(
        url = %config.amqp_url,
        queue = %config.queue,
        "RabbitMQ consumer connecting"
    );

    let conn = Connection::connect(&config.amqp_url, ConnectionProperties::default())
        .await
        .map_err(|e| HiveGuardError::Protocol(format!("AMQP connect: {e}")))?;

    let channel = conn
        .create_channel()
        .await
        .map_err(|e| HiveGuardError::Protocol(format!("AMQP create_channel: {e}")))?;

    // Apply QoS / prefetch
    channel
        .basic_qos(config.prefetch_count, BasicQosOptions::default())
        .await
        .map_err(|e| HiveGuardError::Protocol(format!("AMQP basic_qos: {e}")))?;

    // Ensure queue exists (passive = false → create if missing)
    channel
        .queue_declare(
            &config.queue,
            QueueDeclareOptions {
                durable: true,
                ..Default::default()
            },
            FieldTable::default(),
        )
        .await
        .map_err(|e| HiveGuardError::Protocol(format!("AMQP queue_declare: {e}")))?;

    // Optional exchange binding
    if let Some(ref exchange) = config.exchange {
        let routing_key = config.routing_key.as_deref().unwrap_or("");
        channel
            .queue_bind(
                &config.queue,
                exchange,
                routing_key,
                QueueBindOptions::default(),
                FieldTable::default(),
            )
            .await
            .map_err(|e| HiveGuardError::Protocol(format!("AMQP queue_bind: {e}")))?;
        info!(exchange = %exchange, routing_key = %routing_key, "RabbitMQ queue bound to exchange");
    }

    let consumer_tag = format!("hiveguard-{}", std::process::id());
    let mut consumer = channel
        .basic_consume(
            &config.queue,
            &consumer_tag,
            BasicConsumeOptions::default(),
            FieldTable::default(),
        )
        .await
        .map_err(|e| HiveGuardError::Protocol(format!("AMQP basic_consume: {e}")))?;

    info!(queue = %config.queue, "RabbitMQ consumer started");

    let router = MessageRouter::new();

    loop {
        // Check stop signal
        if *stop_rx.borrow() {
            info!("RabbitMQ consumer received stop signal, shutting down");
            break;
        }

        // Wait for the next delivery or stop signal
        tokio::select! {
            biased;

            _ = stop_rx.changed() => {
                if *stop_rx.borrow() {
                    info!("RabbitMQ consumer stopping");
                    break;
                }
            }

            delivery = next_delivery(&mut consumer) => {
                match delivery {
                    Some(Ok(delivery)) => {
                        let tag = delivery.delivery_tag;

                        // Decode payload as UTF-8 text
                        let raw = match std::str::from_utf8(&delivery.data) {
                            Ok(s) => s.trim().to_string(),
                            Err(e) => {
                                warn!(error = %e, "RabbitMQ: non-UTF-8 payload, nacking");
                                let _ = channel.basic_nack(tag, BasicNackOptions { requeue: false, ..Default::default() }).await;
                                continue;
                            }
                        };

                        if raw.is_empty() {
                            let _ = channel.basic_ack(tag, BasicAckOptions::default()).await;
                            continue;
                        }

                        debug!(line = %raw, "RabbitMQ message");

                        if let Some(event) = router.route_line(&raw, &config.parser, "rabbitmq") {
                            if sender.send(event).await.is_err() {
                                warn!("RabbitMQ: pipeline channel closed, stopping consumer");
                                let _ = channel.basic_nack(tag, BasicNackOptions { requeue: true, ..Default::default() }).await;
                                break;
                            }
                            let _ = channel.basic_ack(tag, BasicAckOptions::default()).await;
                        } else {
                            // Unparseable — ack to avoid requeue loop
                            debug!(line = %raw, "RabbitMQ: no parser matched, dropping message");
                            let _ = channel.basic_ack(tag, BasicAckOptions::default()).await;
                        }
                    }
                    Some(Err(e)) => {
                        error!(error = %e, "RabbitMQ delivery error");
                        break;
                    }
                    None => {
                        info!("RabbitMQ consumer stream ended");
                        break;
                    }
                }
            }
        }
    }

    Ok(())
}

/// Drive the `lapin` consumer's async iterator as a `Future` that resolves on
/// the next delivery so it can be used inside `tokio::select!`.
async fn next_delivery(
    consumer: &mut lapin::Consumer,
) -> Option<Result<lapin::message::Delivery, lapin::Error>> {
    use futures_lite::StreamExt;
    consumer.next().await
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use hiveguard_core::config::KafkaTopicParser;

    fn make_config() -> RabbitMqSourceConfig {
        RabbitMqSourceConfig {
            amqp_url: "amqp://guest:guest@localhost:5672/%2F".to_string(),
            queue: "hiveguard.test".to_string(),
            exchange: None,
            routing_key: None,
            prefetch_count: 10,
            parser: KafkaTopicParser::Auto,
        }
    }

    #[test]
    fn test_source_name() {
        let src = RabbitMqSource::new(make_config());
        assert_eq!(src.name(), "rabbitmq");
    }

    #[test]
    fn test_new_has_no_stop_tx() {
        let src = RabbitMqSource::new(make_config());
        assert!(src.stop_tx.is_none());
    }

    #[test]
    fn test_stop_without_start_is_noop() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut src = RabbitMqSource::new(make_config());
            // stop() before start() must not panic
            src.stop().await.unwrap();
        });
    }
}
