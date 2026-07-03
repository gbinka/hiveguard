//! `hiveguard-queue` — Message queue ingestion sources (Phase 6).
//!
//! Provides log sources backed by message queues:
//! * **Kafka** (Phase 6.1) — Apache Kafka consumer via `rdkafka`.
//! * **Kinesis** (Phase 6.2.1) — AWS Kinesis Data Streams consumer.
//! * **CloudWatch** (Phase 6.2.2) — AWS CloudWatch Logs ingestion.

pub mod checkpoint;
pub mod deserializer;

#[cfg(feature = "kafka")]
pub mod kafka;
#[cfg(feature = "kinesis")]
pub mod kinesis;
#[cfg(feature = "cloudwatch")]
pub mod cloudwatch;
#[cfg(feature = "rabbitmq")]
pub mod rabbitmq;
#[cfg(feature = "nats")]
pub mod nats;

#[cfg(feature = "kafka")]
pub use kafka::KafkaSource;
#[cfg(feature = "kinesis")]
pub use kinesis::KinesisSource;
#[cfg(feature = "cloudwatch")]
pub use cloudwatch::CloudWatchSource;
#[cfg(feature = "rabbitmq")]
pub use rabbitmq::RabbitMqSource;
#[cfg(feature = "nats")]
pub use nats::NatsSource;
