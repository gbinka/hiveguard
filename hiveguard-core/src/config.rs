use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use ipnet::IpNet;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

use crate::errors::HiveGuardError;

// ---------------------------------------------------------------------------
// Duration (de)serialization: accepts "30s", "5m", "24h", "7d", "permanent"
// ---------------------------------------------------------------------------

/// Wrapper around `Option<Duration>` – `None` means permanent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HumanDuration(pub Option<Duration>);

impl HumanDuration {
    /// Create a permanent (no-expiry) duration.
    pub fn permanent() -> Self {
        Self(None)
    }

    /// Create from seconds.
    pub fn from_secs(s: u64) -> Self {
        Self(Some(Duration::from_secs(s)))
    }

    /// Returns true if this duration is permanent (no expiry).
    pub fn is_permanent(&self) -> bool {
        self.0.is_none()
    }

    /// Returns the underlying `Duration`, or `None` if permanent.
    pub fn as_duration(&self) -> Option<Duration> {
        self.0
    }
}

/// Parse a human-readable duration string.
/// Supported formats: "30s", "5m", "2h", "7d", "permanent"
pub fn parse_duration_string(s: &str) -> Result<HumanDuration, String> {
    let s = s.trim();
    if s == "permanent" {
        return Ok(HumanDuration::permanent());
    }
    if s.is_empty() {
        return Err("empty duration string".to_string());
    }
    let (num_str, suffix) = s.split_at(s.len() - 1);
    let num: u64 = num_str
        .parse()
        .map_err(|_| format!("invalid duration number: {num_str}"))?;
    let secs = match suffix {
        "s" => num,
        "m" => num * 60,
        "h" => num * 3600,
        "d" => num * 86400,
        _ => return Err(format!("unknown duration suffix: {suffix}")),
    };
    Ok(HumanDuration::from_secs(secs))
}

impl<'de> Deserialize<'de> for HumanDuration {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        parse_duration_string(&s).map_err(de::Error::custom)
    }
}

impl Serialize for HumanDuration {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self.0 {
            None => serializer.serialize_str("permanent"),
            Some(d) => {
                let secs = d.as_secs();
                let s = if secs % 86400 == 0 && secs > 0 {
                    format!("{}d", secs / 86400)
                } else if secs % 3600 == 0 && secs > 0 {
                    format!("{}h", secs / 3600)
                } else if secs % 60 == 0 && secs > 0 {
                    format!("{}m", secs / 60)
                } else {
                    format!("{secs}s")
                };
                serializer.serialize_str(&s)
            }
        }
    }
}

impl fmt::Display for HumanDuration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            None => write!(f, "permanent"),
            Some(d) => {
                let secs = d.as_secs();
                if secs % 86400 == 0 && secs > 0 {
                    write!(f, "{}d", secs / 86400)
                } else if secs % 3600 == 0 && secs > 0 {
                    write!(f, "{}h", secs / 3600)
                } else if secs % 60 == 0 && secs > 0 {
                    write!(f, "{}m", secs / 60)
                } else {
                    write!(f, "{secs}s")
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Top-level config
// ---------------------------------------------------------------------------

/// Top-level HiveGuard configuration, deserialized from YAML.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HiveGuardConfig {
    pub node: NodeConfig,
    #[serde(default)]
    pub whitelist: Vec<String>,
    #[serde(default)]
    pub sources: SourcesConfig,
    #[serde(default)]
    pub detectors: DetectorsConfig,
    #[serde(default)]
    pub scoring: ScoringConfig,
    #[serde(default)]
    pub trust: TrustConfig,
    #[serde(default)]
    pub enforcement: EnforcementConfig,
    #[serde(default)]
    pub persistence: PersistenceConfig,
    #[serde(default)]
    pub bots: Vec<BotRuleConfig>,
    #[serde(default)]
    pub cti: CtiConfig,
    /// Alerting / webhook notification configuration (Phase 2.1).
    #[serde(default)]
    pub alerting: AlertingConfig,
    /// SIEM export configuration (Phase 3.1).
    #[serde(default)]
    pub siem: SiemConfig,
    /// Sigma rule engine configuration (Phase 4.2).
    #[serde(default)]
    pub sigma: SigmaConfig,

    /// Plugin instances to load (INT phase — new plugin architecture).
    ///
    /// Each entry references a registered `PluginDescriptor` by `id`. The
    /// daemon's `Loader` (from `hiveguard-host`) resolves these against
    /// the `inventory::iter::<PluginDescriptor>` registry, validates each
    /// config against the plugin's JSON Schema, and instantiates the
    /// plugin via its factory.
    ///
    /// Legacy fields above (`sources`, `detectors`, `enforcement`, …)
    /// remain functional for backwards compatibility; the daemon prefers
    /// plugins when present and falls back to legacy paths otherwise.
    /// `scripts/migrate-config.py` translates legacy → plugin entries.
    #[serde(default)]
    pub plugins: Vec<PluginConfigEntry>,
}

/// One entry from the `plugins:` list — mirror of
/// `hiveguard_config::PluginEntry`. Kept here as a separate type so that
/// `hiveguard-core` does not depend on `hiveguard-config`; the daemon
/// converts between the two when calling the loader.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginConfigEntry {
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default = "default_plugin_config")]
    pub config: serde_json::Value,
    #[serde(default)]
    pub optional: bool,
}

fn default_plugin_config() -> serde_json::Value {
    serde_json::Value::Object(serde_json::Map::new())
}

/// Configuration for a known bot rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BotRuleConfig {
    pub name: String,
    pub ua_contains: String,
    #[serde(default)]
    pub org: String,
    #[serde(default = "default_bot_policy_allow")]
    pub policy: String,
}

fn default_bot_policy_allow() -> String {
    "allow".to_string()
}

// ---------------------------------------------------------------------------
// NodeConfig
// ---------------------------------------------------------------------------

/// Seed peer specification with optional fingerprint for peer authentication.
///
/// Supports two YAML formats:
/// - Simple string: `"10.0.1.1:7946"` (auto-accept mode)
/// - Object: `{ address: "10.0.1.1:7946", fingerprint: "a3f2c8..." }`
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum SeedPeer {
    /// Address only — fingerprint will be learned on first connection (auto-accept).
    Address(String),
    /// Address with fingerprint for strict peer authentication.
    WithFingerprint {
        address: String,
        fingerprint: String,
    },
}

impl SeedPeer {
    /// Get the address string.
    pub fn address(&self) -> &str {
        match self {
            SeedPeer::Address(addr) => addr,
            SeedPeer::WithFingerprint { address, .. } => address,
        }
    }

    /// Get the fingerprint, if specified.
    pub fn fingerprint(&self) -> Option<&str> {
        match self {
            SeedPeer::Address(_) => None,
            SeedPeer::WithFingerprint { fingerprint, .. } => Some(fingerprint),
        }
    }
}

/// Cluster mode: strict (fingerprint allow-list) or auto-accept (development).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum ClusterMode {
    /// Only peers with known fingerprints are accepted (production default).
    #[default]
    Strict,
    /// New peers are automatically accepted and their fingerprints recorded.
    AutoAccept,
}

/// Node identity and network configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    pub name: String,
    #[serde(default = "default_listen_gossip")]
    pub listen_gossip: String,
    #[serde(default = "default_listen_api")]
    pub listen_api: String,
    #[serde(default = "default_data_dir")]
    pub data_dir: PathBuf,
    #[serde(default)]
    pub seeds: Vec<SeedPeer>,
    /// Cluster authentication mode.
    #[serde(default)]
    pub cluster_mode: ClusterMode,
    /// Node fingerprints (blake3 of Ed25519 public key) that start with
    /// maximum trust score (1.0).  Typically your own servers and partners
    /// — the "founder" nodes that constitute the initial trust core.
    #[serde(default)]
    pub founder_nodes: Vec<String>,
}

fn default_listen_gossip() -> String {
    "0.0.0.0:7946".to_string()
}
fn default_listen_api() -> String {
    "127.0.0.1:8443".to_string()
}
fn default_data_dir() -> PathBuf {
    PathBuf::from("/var/lib/hiveguard")
}

// ---------------------------------------------------------------------------
// SourcesConfig
// ---------------------------------------------------------------------------

/// Log source configuration (SSH, Nginx, Postfix, custom, syslog network).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SourcesConfig {
    #[serde(default)]
    pub ssh: SshSourceConfig,
    #[serde(default)]
    pub nginx: NginxSourceConfig,
    #[serde(default)]
    pub postfix: PostfixSourceConfig,
    #[serde(default)]
    pub custom: Vec<CustomSourceConfig>,
    /// Network syslog sources (UDP/TCP/TLS) — Phase 5.1.
    #[serde(default)]
    pub syslog: SyslogSourceConfig,
    /// Apache Kafka consumer source — Phase 6.1.
    #[serde(default)]
    pub kafka: Option<KafkaSourceConfig>,
    /// AWS Kinesis Data Streams consumer — Phase 6.2.1.
    #[serde(default)]
    pub kinesis: Option<KinesisSourceConfig>,
    /// AWS CloudWatch Logs ingestion — Phase 6.2.2.
    #[serde(default)]
    pub cloudwatch: Option<CloudWatchSourceConfig>,
    /// RabbitMQ AMQP consumer — Phase 6.3.1.
    #[serde(default)]
    pub rabbitmq: Option<RabbitMqSourceConfig>,
    /// NATS / JetStream consumer — Phase 6.4.
    #[serde(default)]
    pub nats: Option<NatsSourceConfig>,
}

// ---------------------------------------------------------------------------
// KafkaSourceConfig — Phase 6.1
// ---------------------------------------------------------------------------

/// Message format of Kafka topic payloads.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum KafkaTopicFormat {
    /// Each message payload is a raw log line (possibly wrapped as a JSON string
    /// with a `"message"` / `"log"` / `"msg"` key).  Parser is selected by
    /// the `parser` field.
    #[default]
    Json,
    /// Each message payload is a complete RFC 5424 / RFC 3164 syslog string.
    /// App-name–based routing is applied automatically (sshd, nginx, postfix).
    Syslog,
}

/// Which log parser to apply after format decoding.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum KafkaTopicParser {
    Ssh,
    Nginx,
    Postfix,
    /// Try each parser in order; use the first that succeeds.
    #[default]
    Auto,
}

/// Per-topic configuration for the Kafka consumer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KafkaTopicConfig {
    /// Kafka topic name.
    pub name: String,
    /// Payload encoding / wrapping format.
    #[serde(default)]
    pub format: KafkaTopicFormat,
    /// Log parser to apply after decoding.
    #[serde(default)]
    pub parser: KafkaTopicParser,
}

/// SASL authentication mechanism.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum KafkaSaslMechanism {
    Plain,
    ScramSha512,
}

/// SASL credentials for Kafka.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KafkaSaslConfig {
    pub mechanism: KafkaSaslMechanism,
    pub username: String,
    pub password: String,
}

/// TLS options for the Kafka client.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct KafkaTlsConfig {
    /// Path to PEM-encoded CA certificate (for broker certificate verification).
    #[serde(default)]
    pub ca_cert: Option<String>,
    /// Path to PEM-encoded client certificate (mutual TLS).
    #[serde(default)]
    pub client_cert: Option<String>,
    /// Path to PEM-encoded client private key (mutual TLS).
    #[serde(default)]
    pub client_key: Option<String>,
}

/// Apache Kafka consumer source configuration (Phase 6.1).
///
/// Example:
/// ```yaml
/// sources:
///   kafka:
///     brokers: ["kafka1:9092", "kafka2:9092"]
///     group_id: hiveguard
///     topics:
///       - name: nginx-access
///         format: json
///         parser: nginx
///       - name: syslog-all
///         format: syslog
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KafkaSourceConfig {
    /// Broker list (host:port pairs).
    pub brokers: Vec<String>,
    /// Consumer group ID.
    #[serde(default = "default_kafka_group_id")]
    pub group_id: String,
    /// Topics to subscribe to.
    #[serde(default)]
    pub topics: Vec<KafkaTopicConfig>,
    /// SASL authentication (PLAIN or SCRAM-SHA-512).
    #[serde(default)]
    pub sasl: Option<KafkaSaslConfig>,
    /// TLS configuration.
    #[serde(default)]
    pub tls: Option<KafkaTlsConfig>,
    /// Kafka `session.timeout.ms` (default 30 000 ms).
    #[serde(default = "default_kafka_session_timeout_ms")]
    pub session_timeout_ms: u32,
    /// Kafka `max.poll.interval.ms` (default 300 000 ms).
    #[serde(default = "default_kafka_max_poll_interval_ms")]
    pub max_poll_interval_ms: u32,
    /// Per-partition backpressure threshold: pause polling when the ingest
    /// channel free capacity drops below this percentage (0–100, default 20).
    #[serde(default = "default_kafka_backpressure_pct")]
    pub backpressure_threshold_pct: u8,
}

fn default_kafka_group_id() -> String {
    "hiveguard".to_string()
}
fn default_kafka_session_timeout_ms() -> u32 {
    30_000
}
fn default_kafka_max_poll_interval_ms() -> u32 {
    300_000
}
fn default_kafka_backpressure_pct() -> u8 {
    20
}

// ---------------------------------------------------------------------------
// AWS Shared — Phase 6.2
// ---------------------------------------------------------------------------

/// Explicit AWS credentials (optional; standard credential chain is used if absent).
///
/// The standard chain resolves in order: env vars (`AWS_ACCESS_KEY_ID` /
/// `AWS_SECRET_ACCESS_KEY`), shared credentials file (`~/.aws/credentials`),
/// ECS task role, EC2 instance metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AwsCredentialsConfig {
    pub access_key_id: String,
    pub secret_access_key: String,
    #[serde(default)]
    pub session_token: Option<String>,
}

// ---------------------------------------------------------------------------
// KinesisSourceConfig — Phase 6.2.1
// ---------------------------------------------------------------------------

/// Starting position when no checkpoint is found for a shard.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum KinesisStartPosition {
    /// Start from the oldest available record (TRIM_HORIZON).
    TrimHorizon,
    /// Start from the most recent record — skip historical data.
    #[default]
    Latest,
}

/// AWS Kinesis Data Streams consumer configuration (Phase 6.2.1).
///
/// Example:
/// ```yaml
/// sources:
///   kinesis:
///     stream_name: my-log-stream
///     region: us-east-1
///     batch_size: 100
///     parser: nginx
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KinesisSourceConfig {
    /// Kinesis stream name.
    pub stream_name: String,
    /// AWS region (e.g. `"us-east-1"`).
    pub region: String,
    /// Max records per `GetRecords` call (1–10 000, default 100).
    #[serde(default = "default_kinesis_batch_size")]
    pub batch_size: i32,
    /// Where to start reading when no checkpoint exists.
    #[serde(default)]
    pub start_position: KinesisStartPosition,
    /// Explicit AWS credentials (uses default chain if absent).
    #[serde(default)]
    pub credentials: Option<AwsCredentialsConfig>,
    /// Log parser applied to each record's payload.
    #[serde(default)]
    pub parser: KafkaTopicParser,
    /// Interval between `GetRecords` calls per shard in milliseconds.
    /// Kinesis allows max 5 calls/sec per shard; default 1 000 ms.
    #[serde(default = "default_kinesis_poll_interval_ms")]
    pub poll_interval_ms: u64,
}

fn default_kinesis_batch_size() -> i32 {
    100
}
fn default_kinesis_poll_interval_ms() -> u64 {
    1_000
}

// ---------------------------------------------------------------------------
// CloudWatchSourceConfig — Phase 6.2.2
// ---------------------------------------------------------------------------

/// AWS CloudWatch Logs ingestion configuration (Phase 6.2.2).
///
/// Example:
/// ```yaml
/// sources:
///   cloudwatch:
///     log_group_names:
///       - /aws/lambda/api
///       - /ecs/nginx
///     region: us-east-1
///     poll_interval_secs: 30
///     parser: nginx
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudWatchSourceConfig {
    /// CloudWatch Log Group names to subscribe to.
    pub log_group_names: Vec<String>,
    /// AWS region.
    pub region: String,
    /// How often to poll each log group in seconds (default 30).
    #[serde(default = "default_cloudwatch_poll_interval_secs")]
    pub poll_interval_secs: u64,
    /// Explicit AWS credentials (uses default chain if absent).
    #[serde(default)]
    pub credentials: Option<AwsCredentialsConfig>,
    /// Log parser applied to each log event's message.
    #[serde(default)]
    pub parser: KafkaTopicParser,
    /// Optional CloudWatch filter pattern (e.g. `"[host, ident, user, time, request]"`).
    #[serde(default)]
    pub filter_pattern: Option<String>,
    /// Max events returned per `FilterLogEvents` call (default 100).
    #[serde(default = "default_cloudwatch_batch_size")]
    pub batch_size: i32,
}

fn default_cloudwatch_poll_interval_secs() -> u64 {
    30
}
fn default_cloudwatch_batch_size() -> i32 {
    100
}

// ---------------------------------------------------------------------------
// RabbitMqSourceConfig — Phase 6.3.1
// ---------------------------------------------------------------------------

/// RabbitMQ AMQP 0-9-1 consumer configuration.
///
/// Example:
/// ```yaml
/// sources:
///   rabbitmq:
///     amqp_url: "amqp://guest:guest@localhost:5672/%2F"
///     queue: hiveguard.events
///     prefetch_count: 100
///     parser: ssh
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RabbitMqSourceConfig {
    /// AMQP URL, e.g. `amqp://user:pass@host:5672/vhost` or `amqps://…`.
    pub amqp_url: String,
    /// Queue name to consume from.
    pub queue: String,
    /// Exchange to bind the queue to (optional; uses default exchange when absent).
    #[serde(default)]
    pub exchange: Option<String>,
    /// Routing key for the binding (optional).
    #[serde(default)]
    pub routing_key: Option<String>,
    /// Pre-fetch / QoS count (default 100).
    #[serde(default = "default_rabbitmq_prefetch")]
    pub prefetch_count: u16,
    /// Log parser applied to each message payload.
    #[serde(default)]
    pub parser: KafkaTopicParser,
}

fn default_rabbitmq_prefetch() -> u16 {
    100
}

// ---------------------------------------------------------------------------
// NatsSourceConfig — Phase 6.4
// ---------------------------------------------------------------------------

/// Per-subject routing rule: if the message subject matches `pattern`, apply
/// the given parser.  Patterns support NATS wildcards (`*` single token,
/// `>` multi-token suffix).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NatsSubjectRoute {
    /// NATS subject pattern, e.g. `"logs.nginx.*"` or `"logs.>"`.
    pub pattern: String,
    /// Parser to apply when the subject matches.
    pub parser: KafkaTopicParser,
}

/// JetStream durable-consumer configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NatsJetStreamConfig {
    /// JetStream stream name (must exist or be created out-of-band).
    pub stream: String,
    /// Durable consumer name.
    pub consumer: String,
    /// Deliver policy: `all`, `last`, `new`, or `by_start_time`.
    #[serde(default = "default_nats_deliver_policy")]
    pub deliver_policy: String,
    /// Maximum number of unacknowledged messages in flight (backpressure, default 256).
    #[serde(default = "default_nats_max_ack_pending")]
    pub max_ack_pending: i64,
    /// How many messages to fetch per pull batch (default 64).
    #[serde(default = "default_nats_batch_size")]
    pub batch_size: usize,
}

/// NATS / JetStream consumer configuration (Phase 6.4).
///
/// Example:
/// ```yaml
/// sources:
///   nats:
///     servers:
///       - "nats://nats1:4222"
///       - "nats://nats2:4222"
///     subject: "hiveguard.logs.>"
///     queue_group: "hiveguard-consumers"
///     jetstream:
///       enabled: true
///       stream: HIVEGUARD_LOGS
///       consumer: hiveguard-ingest
///       deliver_policy: last
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NatsSourceConfig {
    /// One or more NATS server URLs, e.g. `["nats://host:4222"]`.
    pub servers: Vec<String>,
    /// Subject to subscribe to (supports wildcards `*` and `>`).
    pub subject: String,
    /// Optional queue group for load-balanced delivery across HiveGuard instances.
    #[serde(default)]
    pub queue_group: Option<String>,
    /// JetStream configuration (when absent, plain core-NATS subscribe is used).
    #[serde(default)]
    pub jetstream: Option<NatsJetStreamConfig>,
    /// Path to a NATS `.creds` credentials file (NKey+JWT auth).
    #[serde(default)]
    pub credentials_file: Option<String>,
    /// Path to a CA certificate file for TLS verification.
    #[serde(default)]
    pub tls_ca: Option<String>,
    /// Path to a client TLS certificate file (mTLS).
    #[serde(default)]
    pub tls_cert: Option<String>,
    /// Path to a client TLS key file (mTLS).
    #[serde(default)]
    pub tls_key: Option<String>,
    /// Subject-based parser routing rules.  Evaluated in order; first match wins.
    /// Falls back to `parser` when no rule matches.
    #[serde(default)]
    pub subject_routes: Vec<NatsSubjectRoute>,
    /// Fallback parser when no `subject_routes` entry matches (default `auto`).
    #[serde(default)]
    pub parser: KafkaTopicParser,
    /// Reconnect buffer size in bytes (default 8 MiB).
    #[serde(default = "default_nats_reconnect_buffer")]
    pub reconnect_buffer_size: usize,
}

fn default_nats_deliver_policy() -> String {
    "last".to_string()
}
fn default_nats_max_ack_pending() -> i64 {
    256
}
fn default_nats_batch_size() -> usize {
    64
}
fn default_nats_reconnect_buffer() -> usize {
    8 * 1024 * 1024
}

// ---------------------------------------------------------------------------
// SyslogSourceConfig — Phase 5.1
// ---------------------------------------------------------------------------

/// Network syslog source configuration (RFC 5424 / RFC 3164).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SyslogSourceConfig {
    /// UDP syslog listener (RFC 5426). Disabled unless this field is present.
    #[serde(default)]
    pub udp: Option<SyslogUdpConfig>,
    /// TCP syslog listener (RFC 6587). Disabled unless this field is present.
    #[serde(default)]
    pub tcp: Option<SyslogTcpConfig>,
    /// TLS syslog listener (RFC 5425). Disabled unless this field is present.
    #[serde(default)]
    pub tls: Option<SyslogTlsConfig>,
    /// Message routing rules — Phase 5.2. Evaluated in order; first match wins.
    /// Built-in defaults (sshd→ssh, nginx→nginx, postfix→postfix) apply if empty.
    #[serde(default)]
    pub routes: Vec<SyslogRouteConfig>,
}

// ---------------------------------------------------------------------------
// SyslogRouteConfig — Phase 5.2
// ---------------------------------------------------------------------------

/// One syslog routing rule: match conditions + parser selection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyslogRouteConfig {
    /// All conditions that must match simultaneously.
    pub r#match: SyslogRouteMatch,
    /// Parser to invoke when this route fires.
    pub parser: SyslogRouteParser,
    /// Regex with a named capture group `ip`; required for `parser: custom`.
    #[serde(default)]
    pub pattern: Option<String>,
}

/// Match conditions for a syslog routing rule (all specified conditions must match).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SyslogRouteMatch {
    /// Exact `app_name` to match (case-insensitive; subprocess suffix stripped,
    /// e.g. `"postfix/smtpd"` normalises to `"postfix"`).
    #[serde(default)]
    pub app_name: Option<String>,
    /// Glob pattern for the sending host's `hostname` field (`*` and `?` supported).
    #[serde(default)]
    pub hostname_pattern: Option<String>,
    /// Syslog facility name to match (`"kern"`, `"daemon"`, `"local0"`, …).
    #[serde(default)]
    pub facility: Option<String>,
}

/// Parser variant selected by a routing rule.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SyslogRouteParser {
    /// SSH auth.log parser.
    Ssh,
    /// Nginx / Apache access log parser.
    Nginx,
    /// Postfix mail log parser.
    Postfix,
    /// iptables / nftables kernel log lines.
    Iptables,
    /// Cisco ASA deny/permit messages (`%ASA-N-NNNNNN: …`).
    CiscoAsa,
    /// pfSense / OpenBSD pf filterlog.
    Pfsense,
    /// Custom regex with named capture group `ip` (requires `pattern` field).
    Custom,
    /// Explicitly drop matching messages (no event emitted).
    Drop,
}

/// UDP syslog listener configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyslogUdpConfig {
    /// Bind address (default `"0.0.0.0:514"`).
    #[serde(default = "default_syslog_udp_listen")]
    pub listen: String,
}

impl Default for SyslogUdpConfig {
    fn default() -> Self {
        Self {
            listen: default_syslog_udp_listen(),
        }
    }
}

fn default_syslog_udp_listen() -> String {
    "0.0.0.0:514".to_string()
}

/// TCP syslog listener configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyslogTcpConfig {
    /// Bind address (default `"0.0.0.0:601"`).
    #[serde(default = "default_syslog_tcp_listen")]
    pub listen: String,
}

impl Default for SyslogTcpConfig {
    fn default() -> Self {
        Self {
            listen: default_syslog_tcp_listen(),
        }
    }
}

fn default_syslog_tcp_listen() -> String {
    "0.0.0.0:601".to_string()
}

/// TLS syslog listener configuration (RFC 5425).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyslogTlsConfig {
    /// Bind address (default `"0.0.0.0:6514"`).
    #[serde(default = "default_syslog_tls_listen")]
    pub listen: String,
    /// Path to the PEM-encoded server certificate chain.
    pub cert: String,
    /// Path to the PEM-encoded server private key.
    pub key: String,
    /// Optional CA certificate for mutual TLS client verification.
    #[serde(default)]
    pub ca_cert: Option<String>,
}

fn default_syslog_tls_listen() -> String {
    "0.0.0.0:6514".to_string()
}

/// SSH log source configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshSourceConfig {
    #[serde(default = "default_true")]
    pub use_journald: bool,
    #[serde(default)]
    pub auth_log_path: Option<String>,
}

impl Default for SshSourceConfig {
    fn default() -> Self {
        Self {
            use_journald: true,
            auth_log_path: None,
        }
    }
}

/// Nginx log source configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NginxSourceConfig {
    #[serde(default)]
    pub access_log: Option<String>,
    #[serde(default)]
    pub error_log: Option<String>,
    #[serde(default)]
    pub non_wordpress: bool,
}

/// Postfix log source configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PostfixSourceConfig {
    #[serde(default)]
    pub log_path: Option<String>,
}

/// Custom log source configuration with user-defined regex pattern.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomSourceConfig {
    pub path: String,
    pub pattern: String,
    #[serde(default = "default_custom_detector")]
    pub detector: String,
    #[serde(default = "default_threshold_5")]
    pub threshold: u32,
    #[serde(default = "default_window_5m")]
    pub window: HumanDuration,
}

fn default_custom_detector() -> String {
    "brute_force".to_string()
}
fn default_threshold_5() -> u32 {
    5
}
fn default_window_5m() -> HumanDuration {
    HumanDuration::from_secs(300)
}

// ---------------------------------------------------------------------------
// DetectorsConfig
// ---------------------------------------------------------------------------

/// Configuration for all detectors (enabled flags, thresholds, windows).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DetectorsConfig {
    #[serde(default)]
    pub ssh_bruteforce: SshBruteforceConfig,
    #[serde(default)]
    pub ssh_user_enum: SshUserEnumConfig,
    #[serde(default)]
    pub path_probe: PathProbeConfig,
    #[serde(default)]
    pub http_4xx_flood: Http4xxFloodConfig,
    #[serde(default)]
    pub http_login_bruteforce: HttpLoginBruteforceConfig,
    #[serde(default)]
    pub scanner_fingerprint: ScannerFingerprintConfig,
    #[serde(default)]
    pub smtp_bruteforce: SmtpBruteforceConfig,
    #[serde(default)]
    pub port_scan: PortScanConfig,
    #[serde(default)]
    pub distributed_slow: DistributedSlowConfig,
    #[serde(default)]
    pub honeypot: HoneypotConfig,
    #[serde(default)]
    pub entropy: EntropyConfig,
    #[serde(default)]
    pub timing: TimingConfig,
}

// --- Individual detector configs ---

/// SSH brute-force detector configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshBruteforceConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_threshold_5")]
    pub threshold: u32,
    #[serde(default = "default_window_5m")]
    pub window: HumanDuration,
    #[serde(default = "default_ban_24h")]
    pub ban_duration: HumanDuration,
}

impl Default for SshBruteforceConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            threshold: 5,
            window: HumanDuration::from_secs(300),
            ban_duration: HumanDuration::from_secs(86400),
        }
    }
}

/// SSH user enumeration detector configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshUserEnumConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_threshold_3")]
    pub threshold: u32,
    #[serde(default = "default_window_2m")]
    pub window: HumanDuration,
    #[serde(default = "default_ban_48h")]
    pub ban_duration: HumanDuration,
}

impl Default for SshUserEnumConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            threshold: 3,
            window: HumanDuration::from_secs(120),
            ban_duration: HumanDuration::from_secs(172800),
        }
    }
}

/// Path probe detector configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathProbeConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_probe_paths")]
    pub paths: Vec<String>,
    #[serde(default = "default_ban_72h")]
    pub ban_duration: HumanDuration,
}

impl Default for PathProbeConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            paths: default_probe_paths(),
            ban_duration: HumanDuration::from_secs(259200),
        }
    }
}

fn default_probe_paths() -> Vec<String> {
    vec![
        "/wp-login.php".into(),
        "/xmlrpc.php".into(),
        "/.env".into(),
        "/phpmyadmin".into(),
        "/wp-admin".into(),
    ]
}

/// HTTP 4xx flood detector configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Http4xxFloodConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_threshold_50")]
    pub threshold: u32,
    #[serde(default = "default_window_1m")]
    pub window: HumanDuration,
    #[serde(default = "default_ban_1h")]
    pub ban_duration: HumanDuration,
}

impl Default for Http4xxFloodConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            threshold: 50,
            window: HumanDuration::from_secs(60),
            ban_duration: HumanDuration::from_secs(3600),
        }
    }
}

/// HTTP login brute-force detector configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpLoginBruteforceConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_login_paths")]
    pub paths: Vec<String>,
    #[serde(default = "default_threshold_5")]
    pub threshold: u32,
    #[serde(default = "default_window_10m")]
    pub window: HumanDuration,
    #[serde(default = "default_ban_24h")]
    pub ban_duration: HumanDuration,
}

impl Default for HttpLoginBruteforceConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            paths: default_login_paths(),
            threshold: 5,
            window: HumanDuration::from_secs(600),
            ban_duration: HumanDuration::from_secs(86400),
        }
    }
}

fn default_login_paths() -> Vec<String> {
    vec![
        "/wp-login.php".into(),
        "/xmlrpc.php".into(),
    ]
}

/// Scanner fingerprint detector configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannerFingerprintConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_ban_72h")]
    pub ban_duration: HumanDuration,
}

impl Default for ScannerFingerprintConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            ban_duration: HumanDuration::from_secs(259200),
        }
    }
}

/// SMTP brute-force detector configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmtpBruteforceConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_threshold_5")]
    pub threshold: u32,
    #[serde(default = "default_window_5m")]
    pub window: HumanDuration,
    #[serde(default = "default_ban_24h")]
    pub ban_duration: HumanDuration,
}

impl Default for SmtpBruteforceConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            threshold: 5,
            window: HumanDuration::from_secs(300),
            ban_duration: HumanDuration::from_secs(86400),
        }
    }
}

/// Port scan detector configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortScanConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_threshold_20")]
    pub threshold: u32,
    #[serde(default = "default_window_30s")]
    pub window: HumanDuration,
    #[serde(default = "default_ban_48h")]
    pub ban_duration: HumanDuration,
}

impl Default for PortScanConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            threshold: 20,
            window: HumanDuration::from_secs(30),
            ban_duration: HumanDuration::from_secs(172800),
        }
    }
}

/// Distributed slow-rate attack detector configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DistributedSlowConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_subnet_threshold")]
    pub subnet_threshold: u32,
    #[serde(default = "default_window_10m")]
    pub window: HumanDuration,
    #[serde(default = "default_ban_12h")]
    pub ban_duration: HumanDuration,
    #[serde(default = "default_ban_scope")]
    pub ban_scope: String,
}

impl Default for DistributedSlowConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            subnet_threshold: 5,
            window: HumanDuration::from_secs(600),
            ban_duration: HumanDuration::from_secs(43200),
            ban_scope: "/24".to_string(),
        }
    }
}

/// Honeypot detector configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HoneypotConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_honeypot_paths")]
    pub paths: Vec<String>,
    #[serde(default = "default_ban_permanent")]
    pub ban_duration: HumanDuration,
    #[serde(default = "default_severity_250")]
    pub severity: u8,
}

impl Default for HoneypotConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            paths: default_honeypot_paths(),
            ban_duration: HumanDuration::permanent(),
            severity: 250,
        }
    }
}

fn default_honeypot_paths() -> Vec<String> {
    vec![
        "/backup.sql".into(),
        "/db-dump.sql".into(),
        "/admin-panel-secret".into(),
        "/admin-backup-2024.zip".into(),
    ]
}

/// Multi-feature entropy-based payload detector configuration.
///
/// The detector combines compression ratio, bigram entropy, byte-class
/// profiling, structural URL analysis, and HTTP status correlation to
/// distinguish truly malicious payloads from benign high-entropy URLs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Minimum composite anomaly score (0–100) to emit a detection signal.
    #[serde(default = "default_entropy_score_threshold")]
    pub score_threshold: f64,
    /// Score reduction applied when a known-benign URL pattern is matched
    /// (WordPress assets, social-media click IDs, cache-buster hashes).
    #[serde(default = "default_entropy_benign_penalty")]
    pub benign_penalty: f64,
    /// Multiplier applied to the anomaly score when the HTTP response was
    /// 4xx or 5xx (amplifies suspicion for failed requests).
    #[serde(default = "default_entropy_error_multiplier")]
    pub error_response_multiplier: f64,

    // Legacy fields — accepted for backward-compatible config files but
    // no longer used by the multi-feature engine.
    #[serde(default = "default_entropy_min")]
    pub min_entropy: f64,
    #[serde(default = "default_entropy_max")]
    pub max_entropy: f64,
}

impl Default for EntropyConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            score_threshold: 25.0,
            benign_penalty: 30.0,
            error_response_multiplier: 1.5,
            min_entropy: 5.5,
            max_entropy: 6.5,
        }
    }
}

fn default_entropy_score_threshold() -> f64 {
    25.0
}
fn default_entropy_benign_penalty() -> f64 {
    30.0
}
fn default_entropy_error_multiplier() -> f64 {
    1.5
}
fn default_entropy_min() -> f64 {
    5.5
}
fn default_entropy_max() -> f64 {
    6.5
}

/// Timing-based bot detector configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimingConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_window_1m")]
    pub window: HumanDuration,
    #[serde(default = "default_min_samples")]
    pub min_samples: u32,
    #[serde(default = "default_stddev_threshold")]
    pub stddev_threshold_ms: f64,
}

impl Default for TimingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            window: HumanDuration::from_secs(60),
            min_samples: 10,
            stddev_threshold_ms: 50.0,
        }
    }
}

fn default_min_samples() -> u32 {
    10
}
fn default_stddev_threshold() -> f64 {
    50.0
}

// ---------------------------------------------------------------------------
// ScoringConfig
// ---------------------------------------------------------------------------

/// Scoring engine configuration (accumulation window, thresholds).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoringConfig {
    #[serde(default = "default_accumulation_window")]
    pub accumulation_window: HumanDuration,
    #[serde(default = "default_ban_severity_threshold")]
    pub ban_severity_threshold: u32,
    #[serde(default = "default_ban_24h")]
    pub default_ban_duration: HumanDuration,
}

impl Default for ScoringConfig {
    fn default() -> Self {
        Self {
            accumulation_window: HumanDuration::from_secs(1800),
            ban_severity_threshold: 100,
            default_ban_duration: HumanDuration::from_secs(86400),
        }
    }
}

// ---------------------------------------------------------------------------
// TrustConfig
// ---------------------------------------------------------------------------

/// Trust and anti-poisoning configuration for cluster peers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustConfig {
    #[serde(default = "default_ban_threshold")]
    pub ban_threshold: f64,
    #[serde(default = "default_grace_period")]
    pub new_node_grace_period: HumanDuration,
    #[serde(default = "default_new_node_multiplier")]
    pub new_node_threshold_multiplier: f64,
    #[serde(default = "default_max_bans_per_minute")]
    pub max_bans_per_minute: u32,
    #[serde(default = "default_auto_quarantine_multiplier")]
    pub auto_quarantine_multiplier: f64,
}

impl Default for TrustConfig {
    fn default() -> Self {
        Self {
            ban_threshold: 2.0,
            new_node_grace_period: HumanDuration::from_secs(86400),
            new_node_threshold_multiplier: 2.0,
            max_bans_per_minute: 100,
            auto_quarantine_multiplier: 10.0,
        }
    }
}

// ---------------------------------------------------------------------------
// EnforcementConfig
// ---------------------------------------------------------------------------

/// Firewall enforcement backend configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnforcementConfig {
    #[serde(default = "default_backend")]
    pub backend: String,
    #[serde(default = "default_nftables_set_name")]
    pub nftables_set_name: String,
    #[serde(default = "default_nftables_table")]
    pub nftables_table: String,
    #[serde(default = "default_batch_interval")]
    pub batch_interval: HumanDuration,
    #[serde(default)]
    pub ipset_name: Option<String>,
    /// Cloudflare edge enforcement configuration (phase 7.1).
    #[serde(default)]
    pub cloudflare: Option<CloudflareConfig>,
}

impl Default for EnforcementConfig {
    fn default() -> Self {
        Self {
            backend: "nftables".to_string(),
            nftables_set_name: "hiveguard_blocklist".to_string(),
            nftables_table: "hiveguard".to_string(),
            batch_interval: HumanDuration::from_secs(1),
            ipset_name: None,
            cloudflare: None,
        }
    }
}

// ---------------------------------------------------------------------------
// CloudflareConfig
// ---------------------------------------------------------------------------

/// Cloudflare edge enforcement configuration (phase 7.1).
///
/// Enables pushing ban lists to Cloudflare IP Lists so attacks are
/// blocked at the CDN/edge before reaching the origin server.
///
/// ```yaml
/// enforcement:
///   cloudflare:
///     enabled: true
///     api_token: "..."
///     zone_id: "..."
///     account_id: "..."
///     list_name: "hiveguard-blocklist"
///     min_severity: 60
///     zones:
///       - id: "abc123"
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudflareConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Cloudflare API token (scope: `Zone.Firewall Rules:Edit`, `Account.Lists:Edit`).
    pub api_token: String,
    /// Primary zone ID (for firewall rule creation).
    pub zone_id: String,
    /// Account ID (required for IP Lists API).
    pub account_id: String,
    /// Name of the IP list to create/manage in Cloudflare.
    #[serde(default = "default_cf_list_name")]
    pub list_name: String,
    /// Minimum ban severity to push to Cloudflare (0–255). Default: 60.
    #[serde(default = "default_cf_min_severity")]
    pub min_severity: u8,
    /// Additional zones to apply the same firewall rule to.
    #[serde(default)]
    pub zones: Vec<CloudflareZoneConfig>,
}

fn default_cf_list_name() -> String {
    "hiveguard-blocklist".to_string()
}

fn default_cf_min_severity() -> u8 {
    60
}

/// Per-zone configuration for multi-zone Cloudflare deployments.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudflareZoneConfig {
    /// Cloudflare Zone ID.
    pub id: String,
    /// Override the IP list ID for this zone (optional; auto-detected if not set).
    #[serde(default)]
    pub list_id: Option<String>,
}

// ---------------------------------------------------------------------------
// PersistenceConfig
// ---------------------------------------------------------------------------

/// WAL and snapshot persistence configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistenceConfig {
    #[serde(default = "default_snapshot_interval")]
    pub snapshot_interval: HumanDuration,
    #[serde(default = "default_wal_sync_mode")]
    pub wal_sync_mode: String,
    #[serde(default = "default_max_wal_size_mb")]
    pub max_wal_size_mb: u32,
}

impl Default for PersistenceConfig {
    fn default() -> Self {
        Self {
            snapshot_interval: HumanDuration::from_secs(300),
            wal_sync_mode: "fdatasync".to_string(),
            max_wal_size_mb: 100,
        }
    }
}

// ---------------------------------------------------------------------------
// Default value helpers
// ---------------------------------------------------------------------------

fn default_true() -> bool {
    true
}
fn default_threshold_3() -> u32 {
    3
}
fn default_threshold_20() -> u32 {
    20
}
fn default_threshold_50() -> u32 {
    50
}
fn default_subnet_threshold() -> u32 {
    5
}
fn default_severity_250() -> u8 {
    250
}

fn default_window_30s() -> HumanDuration {
    HumanDuration::from_secs(30)
}
fn default_window_1m() -> HumanDuration {
    HumanDuration::from_secs(60)
}
fn default_window_2m() -> HumanDuration {
    HumanDuration::from_secs(120)
}
fn default_window_10m() -> HumanDuration {
    HumanDuration::from_secs(600)
}

fn default_ban_1h() -> HumanDuration {
    HumanDuration::from_secs(3600)
}
fn default_ban_12h() -> HumanDuration {
    HumanDuration::from_secs(43200)
}
fn default_ban_24h() -> HumanDuration {
    HumanDuration::from_secs(86400)
}
fn default_ban_48h() -> HumanDuration {
    HumanDuration::from_secs(172800)
}
fn default_ban_72h() -> HumanDuration {
    HumanDuration::from_secs(259200)
}
fn default_ban_permanent() -> HumanDuration {
    HumanDuration::permanent()
}

fn default_accumulation_window() -> HumanDuration {
    HumanDuration::from_secs(1800)
}
fn default_ban_severity_threshold() -> u32 {
    100
}
fn default_ban_threshold() -> f64 {
    2.0
}
fn default_grace_period() -> HumanDuration {
    HumanDuration::from_secs(86400)
}
fn default_new_node_multiplier() -> f64 {
    2.0
}
fn default_max_bans_per_minute() -> u32 {
    100
}
fn default_auto_quarantine_multiplier() -> f64 {
    10.0
}
fn default_backend() -> String {
    "nftables".to_string()
}
fn default_nftables_set_name() -> String {
    "hiveguard_blocklist".to_string()
}
fn default_nftables_table() -> String {
    "hiveguard".to_string()
}
fn default_batch_interval() -> HumanDuration {
    HumanDuration::from_secs(1)
}
fn default_snapshot_interval() -> HumanDuration {
    HumanDuration::from_secs(300)
}
fn default_wal_sync_mode() -> String {
    "fdatasync".to_string()
}
fn default_max_wal_size_mb() -> u32 {
    100
}
fn default_ban_scope() -> String {
    "/24".to_string()
}

// ---------------------------------------------------------------------------
// AlertingConfig — Webhook & Alert Engine (Phase 2.1)
// ---------------------------------------------------------------------------

/// Top-level alerting / notification configuration.
///
/// ```yaml
/// alerting:
///   cooldown_secs: 600   # global per-IP alert cooldown (seconds)
///   destinations:
///     - name: "slack-security"
///       type: slack
///       url: "https://hooks.slack.com/..."
///       events: [IpBanned, HoneypotHit, SubnetBanned]
///       min_severity: 80
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AlertingConfig {
    /// Global default cooldown in seconds — the same alert (same type + same
    /// subject) is not delivered more than once per this window.
    #[serde(default = "default_cooldown_600")]
    pub cooldown_secs: u64,
    /// Maximum number of undelivered alerts to buffer before older entries
    /// are dropped.  Default: 1 000.
    #[serde(default = "default_alert_queue_depth")]
    pub queue_depth: usize,
    /// List of alert destinations (Slack, Teams, PagerDuty, generic webhook).
    #[serde(default)]
    pub destinations: Vec<AlertDestinationConfig>,
}

/// Configuration for a single alert destination.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertDestinationConfig {
    /// Unique human-readable name used in logs and metrics labels.
    pub name: String,
    /// Destination type: `slack` | `teams` | `pagerduty` | `webhook`.
    #[serde(rename = "type")]
    pub destination_type: String,
    /// Webhook / API endpoint URL.
    pub url: String,
    /// Which `AlertEvent` variants to forward.  If empty, all events are
    /// forwarded.  Variants are named by their Rust variant name, e.g.
    /// `["IpBanned", "HoneypotHit"]`.
    #[serde(default)]
    pub events: Vec<String>,
    /// Minimum ban severity (0–255) required to forward an `IpBanned` event.
    /// Events without an associated severity field are always forwarded.
    #[serde(default)]
    pub min_severity: u8,
    /// Per-destination cooldown override in seconds.  Overrides the global
    /// `alerting.cooldown_secs` for this destination.
    #[serde(default)]
    pub cooldown_secs: Option<u64>,
    /// Optional `Authorization` header value sent with every request.
    /// Example: `"Bearer my-token"` or `"Token abc123"`.
    #[serde(default)]
    pub auth_header: Option<String>,
    /// Optional payload template with `{{variable}}` placeholders.
    /// When set, the rendered template is used as the request body instead of
    /// the default JSON serialization of the alert event.
    ///
    /// Available variables: `{{type}}`, `{{ip}}`, `{{subnet}}`, `{{severity}}`,
    /// `{{reason}}`, `{{score}}`, `{{path}}`, `{{node_id}}`, `{{address}}`,
    /// `{{ip_count}}`, `{{bans_per_minute}}`, `{{threshold}}`, `{{country}}`,
    /// `{{asn}}`, `{{top_detectors}}`.
    #[serde(default)]
    pub payload_template: Option<String>,
    /// HTTP method to use for delivery.  Defaults to `"POST"`.  Accepted
    /// values: `"POST"`, `"PUT"`.
    #[serde(default)]
    pub http_method: Option<String>,
    /// `Content-Type` header value.  Defaults to `"application/json"`.
    /// Set to `"application/x-www-form-urlencoded"` when using a form-encoded
    /// template payload.
    #[serde(default)]
    pub content_type: Option<String>,
}

fn default_cooldown_600() -> u64 {
    600
}
fn default_alert_queue_depth() -> usize {
    1_000
}

// ---------------------------------------------------------------------------
// CtiConfig — Cyber Threat Intelligence
// ---------------------------------------------------------------------------

/// CTI enrichment configuration (GeoIP, AbuseIPDB, Spamhaus, Tor, OTX, …).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CtiConfig {
    #[serde(default)]
    pub geoip: GeoIpCtiConfig,
    #[serde(default)]
    pub abuseipdb: AbuseIpDbConfig,
    #[serde(default)]
    pub spamhaus: SpamhausConfig,
    #[serde(default)]
    pub tor: TorConfig,
    #[serde(default)]
    pub otx: OtxConfig,
}

/// GeoIP / ASN enrichment and ASN-based action configuration.
///
/// ```yaml
/// cti:
///   geoip:
///     enabled: true
///     license_key: "YOUR_KEY"
///     trusted_asns: [15169, 32934]     # Google, Facebook — never ban
///     datacenter_multiplier: 1.5       # severity multiplier for datacenter IPs
///     update_interval_days: 7
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoIpCtiConfig {
    /// Enable GeoIP enrichment.  Requires MaxMind GeoLite2 `.mmdb` files.
    #[serde(default)]
    pub enabled: bool,
    /// MaxMind account license key used to download GeoLite2 databases.
    #[serde(default)]
    pub license_key: Option<String>,
    /// ASNs whose traffic is **never** banned (treated as whitelist).
    ///
    /// Example: `[15169, 32934]` to trust Google and Facebook crawlers.
    #[serde(default)]
    pub trusted_asns: Vec<u32>,
    /// Severity multiplier applied to detection signals whose source IP
    /// belongs to a datacenter/cloud ASN.  Default: `1.5`.
    #[serde(default = "default_datacenter_multiplier")]
    pub datacenter_multiplier: f32,
    /// Interval (in days) between automatic GeoIP database updates.
    /// Default: `7`.
    #[serde(default = "default_geoip_update_interval_days")]
    pub update_interval_days: u32,
}

impl Default for GeoIpCtiConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            license_key: None,
            trusted_asns: vec![],
            datacenter_multiplier: default_datacenter_multiplier(),
            update_interval_days: default_geoip_update_interval_days(),
        }
    }
}

fn default_datacenter_multiplier() -> f32 {
    1.5
}
fn default_geoip_update_interval_days() -> u32 {
    7
}

// ---------------------------------------------------------------------------
// AbuseIpDbConfig — AbuseIPDB integration (Phase 1.2)
// ---------------------------------------------------------------------------

/// Configuration for the AbuseIPDB CTI provider.
///
/// ```yaml
/// cti:
///   abuseipdb:
///     enabled: true
///     api_key: "YOUR_KEY"
///     confidence_threshold: 75
///     ban_on_first_hit: false
///     cache_ttl_hours: 6
///     max_cache_entries: 100000
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbuseIpDbConfig {
    /// Enable AbuseIPDB enrichment.
    #[serde(default)]
    pub enabled: bool,
    /// AbuseIPDB v2 API key.
    #[serde(default)]
    pub api_key: Option<String>,
    /// Minimum confidence score (0–100) to emit a detection signal.
    #[serde(default = "default_abuseipdb_threshold")]
    pub confidence_threshold: u8,
    /// When `true`, signals from AbuseIPDB immediately trigger a ban
    /// (severity 200).  When `false`, they enter the scoring engine normally.
    #[serde(default)]
    pub ban_on_first_hit: bool,
    /// Time-to-live for cached AbuseIPDB results (hours).  Default: 6.
    #[serde(default = "default_abuseipdb_cache_ttl_hours")]
    pub cache_ttl_hours: u32,
    /// Maximum number of entries in the in-memory cache.  Default: 100 000.
    #[serde(default = "default_abuseipdb_max_cache_entries")]
    pub max_cache_entries: usize,
}

impl Default for AbuseIpDbConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            api_key: None,
            confidence_threshold: default_abuseipdb_threshold(),
            ban_on_first_hit: false,
            cache_ttl_hours: default_abuseipdb_cache_ttl_hours(),
            max_cache_entries: default_abuseipdb_max_cache_entries(),
        }
    }
}

fn default_abuseipdb_threshold() -> u8 {
    75
}
fn default_abuseipdb_cache_ttl_hours() -> u32 {
    6
}
fn default_abuseipdb_max_cache_entries() -> usize {
    100_000
}

// ---------------------------------------------------------------------------
// SpamhausConfig — Spamhaus DNSBL (Phase 1.3.1)
// ---------------------------------------------------------------------------

/// Configuration for the Spamhaus DNSBL CTI provider.
///
/// ```yaml
/// cti:
///   spamhaus:
///     enabled: true
///     # custom_resolver: "8.8.8.8:53"
///     confidence_threshold: 50
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpamhausConfig {
    /// Enable Spamhaus DNSBL enrichment.
    #[serde(default)]
    pub enabled: bool,
    /// Optional custom DNS resolver address (`host:port`).
    #[serde(default)]
    pub custom_resolver: Option<String>,
    /// Minimum Spamhaus severity (0–100) to emit a detection signal.
    #[serde(default = "default_spamhaus_threshold")]
    pub confidence_threshold: u8,
}

impl Default for SpamhausConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            custom_resolver: None,
            confidence_threshold: default_spamhaus_threshold(),
        }
    }
}

fn default_spamhaus_threshold() -> u8 {
    50
}

// ---------------------------------------------------------------------------
// TorConfig — Tor exit-node list (Phase 1.3.2)
// ---------------------------------------------------------------------------

/// Configuration for the Tor exit-node CTI provider.
///
/// ```yaml
/// cti:
///   tor:
///     enabled: true
///     refresh_interval_secs: 3600
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TorConfig {
    /// Enable Tor exit-node detection.
    #[serde(default)]
    pub enabled: bool,
    /// How often to re-download the exit-node list (seconds).  Default: 3600.
    #[serde(default = "default_tor_refresh_secs")]
    pub refresh_interval_secs: u64,
}

impl Default for TorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            refresh_interval_secs: default_tor_refresh_secs(),
        }
    }
}

fn default_tor_refresh_secs() -> u64 {
    3600
}

// ---------------------------------------------------------------------------
// OtxConfig — AlienVault OTX (Phase 1.3.3)
// ---------------------------------------------------------------------------

/// Configuration for the AlienVault OTX CTI provider.
///
/// ```yaml
/// cti:
///   otx:
///     enabled: true
///     api_key: "YOUR_OTX_KEY"
///     min_pulse_count: 3
///     cache_ttl_hours: 12
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtxConfig {
    /// Enable AlienVault OTX enrichment.
    #[serde(default)]
    pub enabled: bool,
    /// OTX API key (free at `https://otx.alienvault.com/`).
    #[serde(default)]
    pub api_key: Option<String>,
    /// Minimum number of OTX pulses to emit a signal.  Default: 3.
    #[serde(default = "default_otx_min_pulses")]
    pub min_pulse_count: u32,
    /// Cache TTL in hours.  Default: 12.
    #[serde(default = "default_otx_cache_ttl_hours")]
    pub cache_ttl_hours: u32,
}

impl Default for OtxConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            api_key: None,
            min_pulse_count: default_otx_min_pulses(),
            cache_ttl_hours: default_otx_cache_ttl_hours(),
        }
    }
}

fn default_otx_min_pulses() -> u32 {
    3
}
fn default_otx_cache_ttl_hours() -> u32 {
    12
}

// ---------------------------------------------------------------------------
// SiemConfig — SIEM Export (Phase 3.1)
// ---------------------------------------------------------------------------

/// SIEM export format.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "lowercase")]
pub enum SiemFormat {
    /// ArcSight Common Event Format (CEF v0.1).
    #[default]
    Cef,
    /// IBM QRadar Log Event Extended Format (LEEF 2.0).
    Leef,
}

/// Protocol used to deliver syslog messages.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "lowercase")]
pub enum SiemProtocol {
    /// TCP with octet-count framing (RFC 6587).
    #[default]
    Tcp,
    /// UDP (fire-and-forget).
    Udp,
}

/// SIEM export configuration (Phase 3.1 + 3.2).
///
/// ```yaml
/// siem:
///   syslog_exporter:
///     enabled: true
///     host: "splunk-hec.internal:514"
///     protocol: tcp     # tcp | udp
///     format: cef       # cef | leef
///     tls: false
///     leef_separator: "^"  # optional, only meaningful for leef format
///   elasticsearch:
///     enabled: true
///     host: "https://elastic.example.com:9200"
///     index_prefix: "hiveguard"
///     api_key: "VnVhQ2ZHY0JDZGJrUUhFemVGZTA6dWkybHAyYXhUTm1zeWFrdzl0dk5Fdw=="
///     bulk_size: 500
///     flush_interval_secs: 5
///     ilm_enabled: true
///     tls_verify: true
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SiemConfig {
    #[serde(default)]
    pub syslog_exporter: SiemSyslogConfig,
    #[serde(default)]
    pub elasticsearch: ElasticConfig,
    #[serde(default)]
    pub splunk: SplunkConfig,
    #[serde(default)]
    pub datadog: DatadogConfig,
}

/// Configuration for the Elasticsearch bulk indexer (Phase 3.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElasticConfig {
    /// Enable the Elasticsearch exporter.
    #[serde(default)]
    pub enabled: bool,
    /// Elasticsearch base URL (e.g. `https://elastic.example.com:9200`).
    #[serde(default = "default_elastic_host")]
    pub host: String,
    /// Index name prefix; documents land in `{prefix}-{YYYY.MM.dd}`.
    #[serde(default = "default_elastic_index_prefix")]
    pub index_prefix: String,
    /// Elasticsearch API key (`Authorization: ApiKey …`).  Mutually exclusive with username/password.
    #[serde(default)]
    pub api_key: Option<String>,
    /// HTTP Basic auth — username.
    #[serde(default)]
    pub username: Option<String>,
    /// HTTP Basic auth — password.
    #[serde(default)]
    pub password: Option<String>,
    /// Maximum documents per `_bulk` request.
    #[serde(default = "default_elastic_bulk_size")]
    pub bulk_size: usize,
    /// How often (seconds) to flush even when the buffer is not full.
    #[serde(default = "default_elastic_flush_secs")]
    pub flush_interval_secs: u64,
    /// Whether to install an ILM lifecycle policy + index template on startup.
    #[serde(default = "default_true")]
    pub ilm_enabled: bool,
    /// Verify TLS certificates.  Set to `false` only in development.
    #[serde(default = "default_true")]
    pub tls_verify: bool,
    /// Directory for the dead-letter queue (failed events).  Defaults to the
    /// daemon `data_dir`; relative paths are resolved against it.
    #[serde(default)]
    pub dlq_dir: Option<std::path::PathBuf>,
}

impl Default for ElasticConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            host: default_elastic_host(),
            index_prefix: default_elastic_index_prefix(),
            api_key: None,
            username: None,
            password: None,
            bulk_size: default_elastic_bulk_size(),
            flush_interval_secs: default_elastic_flush_secs(),
            ilm_enabled: true,
            tls_verify: true,
            dlq_dir: None,
        }
    }
}

/// Configuration for the Syslog SIEM exporter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiemSyslogConfig {
    /// Enable the syslog exporter.
    #[serde(default)]
    pub enabled: bool,
    /// Remote syslog host and port, e.g. `"splunk.example.com:514"`.
    #[serde(default = "default_siem_host")]
    pub host: String,
    /// Transport protocol: `tcp` (default) or `udp`.
    #[serde(default)]
    pub protocol: SiemProtocol,
    /// Event format: `cef` (default) or `leef`.
    #[serde(default)]
    pub format: SiemFormat,
    /// Enable TLS for TCP connections.  Default: `false`.
    #[serde(default)]
    pub tls: bool,
    /// Field separator used in LEEF format.  Default: `"^"`.
    /// Common choices: `"^"`, `"\t"`.
    #[serde(default = "default_leef_separator")]
    pub leef_separator: String,
}

impl Default for SiemSyslogConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            host: default_siem_host(),
            protocol: SiemProtocol::default(),
            format: SiemFormat::default(),
            tls: false,
            leef_separator: default_leef_separator(),
        }
    }
}

fn default_siem_host() -> String {
    "127.0.0.1:514".to_string()
}
fn default_leef_separator() -> String {
    "^".to_string()
}
fn default_elastic_host() -> String {
    "http://localhost:9200".to_string()
}
fn default_elastic_index_prefix() -> String {
    "hiveguard".to_string()
}
fn default_elastic_bulk_size() -> usize {
    500
}
fn default_elastic_flush_secs() -> u64 {
    5
}

// ---------------------------------------------------------------------------
// SplunkConfig — Splunk HEC exporter (Phase 3.3.1)
// ---------------------------------------------------------------------------

/// Configuration for the Splunk HTTP Event Collector exporter (Phase 3.3.1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SplunkConfig {
    /// Enable the Splunk HEC exporter.
    #[serde(default)]
    pub enabled: bool,
    /// Full HEC endpoint URL, e.g. `https://splunk.example.com:8088/services/collector/event`.
    #[serde(default = "default_splunk_url")]
    pub url: String,
    /// HEC authentication token.
    #[serde(default)]
    pub token: String,
    /// Target Splunk index name.  Omit to use the token's default index.
    #[serde(default)]
    pub index: Option<String>,
    /// Splunk `sourcetype` value.  Default: `hiveguard:ban`.
    #[serde(default = "default_splunk_sourcetype")]
    pub sourcetype: String,
    /// Verify TLS certificates.  Set to `false` only in development.
    #[serde(default = "default_true")]
    pub tls_verify: bool,
    /// Maximum events per HEC request (Splunk recommends ≤ 1000 events / 10 MB).
    #[serde(default = "default_splunk_batch_size")]
    pub batch_size: usize,
    /// How often (seconds) to flush even when the buffer is not full.
    #[serde(default = "default_splunk_flush_secs")]
    pub flush_interval_secs: u64,
    /// Directory for the dead-letter queue.  Defaults to daemon `data_dir`.
    #[serde(default)]
    pub dlq_dir: Option<std::path::PathBuf>,
}

impl Default for SplunkConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            url: default_splunk_url(),
            token: String::new(),
            index: None,
            sourcetype: default_splunk_sourcetype(),
            tls_verify: true,
            batch_size: default_splunk_batch_size(),
            flush_interval_secs: default_splunk_flush_secs(),
            dlq_dir: None,
        }
    }
}

fn default_splunk_url() -> String {
    "https://localhost:8088/services/collector/event".to_string()
}
fn default_splunk_sourcetype() -> String {
    "hiveguard:ban".to_string()
}
fn default_splunk_batch_size() -> usize {
    1000
}
fn default_splunk_flush_secs() -> u64 {
    5
}

// ---------------------------------------------------------------------------
// DatadogConfig — Datadog Logs API exporter (Phase 3.3.2)
// ---------------------------------------------------------------------------

/// Configuration for the Datadog Logs API exporter (Phase 3.3.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatadogConfig {
    /// Enable the Datadog exporter.
    #[serde(default)]
    pub enabled: bool,
    /// Datadog API key (`DD-API-KEY` header).
    #[serde(default)]
    pub api_key: String,
    /// Datadog site: `datadoghq.com` (US) or `datadoghq.eu` (EU).
    #[serde(default = "default_datadog_site")]
    pub site: String,
    /// `service` tag attached to every log entry.
    #[serde(default = "default_datadog_service")]
    pub service: String,
    /// Additional tags, e.g. `["env:prod", "node:gateway1"]`.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Maximum log entries per API request.
    #[serde(default = "default_datadog_batch_size")]
    pub batch_size: usize,
    /// How often (seconds) to flush even when the buffer is not full.
    #[serde(default = "default_datadog_flush_secs")]
    pub flush_interval_secs: u64,
    /// Directory for the dead-letter queue.  Defaults to daemon `data_dir`.
    #[serde(default)]
    pub dlq_dir: Option<std::path::PathBuf>,
}

impl Default for DatadogConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            api_key: String::new(),
            site: default_datadog_site(),
            service: default_datadog_service(),
            tags: Vec::new(),
            batch_size: default_datadog_batch_size(),
            flush_interval_secs: default_datadog_flush_secs(),
            dlq_dir: None,
        }
    }
}

fn default_datadog_site() -> String {
    "datadoghq.com".to_string()
}
fn default_datadog_service() -> String {
    "hiveguard-daemon".to_string()
}
fn default_datadog_batch_size() -> usize {
    500
}
fn default_datadog_flush_secs() -> u64 {
    5
}

// ---------------------------------------------------------------------------
// Load & validate
// ---------------------------------------------------------------------------

impl HiveGuardConfig {
    /// Load configuration from a YAML file.
    pub fn load(path: &Path) -> Result<Self, HiveGuardError> {
        let content = std::fs::read_to_string(path).map_err(|e| {
            HiveGuardError::Config(format!("failed to read config file {}: {}", path.display(), e))
        })?;
        let config: Self = serde_yaml::from_str(&content).map_err(|e| {
            HiveGuardError::Config(format!("failed to parse config YAML: {e}"))
        })?;
        config.validate()?;
        Ok(config)
    }

    /// Validate configuration values.
    pub fn validate(&self) -> Result<(), HiveGuardError> {
        // data_dir must be non-empty
        if self.node.data_dir.as_os_str().is_empty() {
            return Err(HiveGuardError::Config(
                "node.data_dir must not be empty".into(),
            ));
        }

        // Whitelist entries must parse as IpNet
        for entry in &self.whitelist {
            entry.parse::<IpNet>().map_err(|e| {
                HiveGuardError::Config(format!(
                    "invalid whitelist entry '{entry}': {e}"
                ))
            })?;
        }

        // Detector thresholds > 0
        Self::check_threshold("ssh_bruteforce.threshold", self.detectors.ssh_bruteforce.threshold)?;
        Self::check_threshold("ssh_user_enum.threshold", self.detectors.ssh_user_enum.threshold)?;
        Self::check_threshold("http_4xx_flood.threshold", self.detectors.http_4xx_flood.threshold)?;
        Self::check_threshold("smtp_bruteforce.threshold", self.detectors.smtp_bruteforce.threshold)?;
        Self::check_threshold("port_scan.threshold", self.detectors.port_scan.threshold)?;
        Self::check_threshold("distributed_slow.subnet_threshold", self.detectors.distributed_slow.subnet_threshold)?;

        // Ban durations > 0 unless permanent
        Self::check_ban_duration("ssh_bruteforce.ban_duration", &self.detectors.ssh_bruteforce.ban_duration)?;
        Self::check_ban_duration("ssh_user_enum.ban_duration", &self.detectors.ssh_user_enum.ban_duration)?;
        Self::check_ban_duration("path_probe.ban_duration", &self.detectors.path_probe.ban_duration)?;
        Self::check_ban_duration("http_4xx_flood.ban_duration", &self.detectors.http_4xx_flood.ban_duration)?;
        Self::check_ban_duration("scanner_fingerprint.ban_duration", &self.detectors.scanner_fingerprint.ban_duration)?;
        Self::check_ban_duration("smtp_bruteforce.ban_duration", &self.detectors.smtp_bruteforce.ban_duration)?;
        Self::check_ban_duration("port_scan.ban_duration", &self.detectors.port_scan.ban_duration)?;
        Self::check_ban_duration("distributed_slow.ban_duration", &self.detectors.distributed_slow.ban_duration)?;
        Self::check_ban_duration("honeypot.ban_duration", &self.detectors.honeypot.ban_duration)?;

        // enforcement.backend validation
        let valid_backends = ["nftables", "ipset", "observe_only"];
        if !valid_backends.contains(&self.enforcement.backend.as_str()) {
            return Err(HiveGuardError::Config(format!(
                "enforcement.backend must be one of {:?}, got '{}'",
                valid_backends, self.enforcement.backend
            )));
        }

        Ok(())
    }

    fn check_threshold(field: &str, value: u32) -> Result<(), HiveGuardError> {
        if value == 0 {
            return Err(HiveGuardError::Config(format!(
                "{field} must be > 0"
            )));
        }
        Ok(())
    }

    fn check_ban_duration(field: &str, dur: &HumanDuration) -> Result<(), HiveGuardError> {
        if let Some(d) = dur.0 {
            if d.is_zero() {
                return Err(HiveGuardError::Config(format!(
                    "{field} must be > 0 (or 'permanent')"
                )));
            }
        }
        Ok(())
    }

    /// Parse whitelist entries into `IpNet` values.
    pub fn parsed_whitelist(&self) -> Result<Vec<IpNet>, HiveGuardError> {
        self.whitelist
            .iter()
            .map(|s| {
                s.parse::<IpNet>().map_err(|e| {
                    HiveGuardError::Config(format!("invalid whitelist entry '{s}': {e}"))
                })
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// SigmaConfig
// ---------------------------------------------------------------------------

/// Sigma rule engine configuration (Phase 4.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigmaConfig {
    /// Enable the Sigma rule engine.
    #[serde(default)]
    pub enabled: bool,
    /// Directory containing `.yml` / `.yaml` Sigma rule files.
    #[serde(default = "default_sigma_rules_dir")]
    pub rules_dir: std::path::PathBuf,
    /// Automatically reload rules when files change in `rules_dir`.
    #[serde(default = "default_true_sigma")]
    pub hot_reload: bool,
}

fn default_sigma_rules_dir() -> std::path::PathBuf {
    std::path::PathBuf::from("/var/lib/hiveguard/sigma_rules")
}

fn default_true_sigma() -> bool {
    true
}

impl Default for SigmaConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            rules_dir: default_sigma_rules_dir(),
            hot_reload: true,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_duration_seconds() {
        let d = parse_duration_string("30s").unwrap();
        assert_eq!(d.0, Some(Duration::from_secs(30)));
    }

    #[test]
    fn test_parse_duration_minutes() {
        let d = parse_duration_string("5m").unwrap();
        assert_eq!(d.0, Some(Duration::from_secs(300)));
    }

    #[test]
    fn test_parse_duration_hours() {
        let d = parse_duration_string("24h").unwrap();
        assert_eq!(d.0, Some(Duration::from_secs(86400)));
    }

    #[test]
    fn test_parse_duration_days() {
        let d = parse_duration_string("7d").unwrap();
        assert_eq!(d.0, Some(Duration::from_secs(604800)));
    }

    #[test]
    fn test_parse_duration_permanent() {
        let d = parse_duration_string("permanent").unwrap();
        assert!(d.is_permanent());
        assert_eq!(d.0, None);
    }

    #[test]
    fn test_parse_duration_invalid() {
        assert!(parse_duration_string("").is_err());
        assert!(parse_duration_string("abc").is_err());
        assert!(parse_duration_string("5x").is_err());
    }

    #[test]
    fn test_deserialize_full_yaml() {
        let yaml = r#"
node:
  name: "test-node"
  data_dir: "/tmp/hiveguard-test"
  seeds:
    - "10.0.1.1:7946"

whitelist:
  - "127.0.0.0/8"
  - "10.0.0.0/8"

sources:
  ssh:
    use_journald: true
  nginx:
    access_log: "/var/log/nginx/access.log"

detectors:
  ssh_bruteforce:
    enabled: true
    threshold: 5
    window: "5m"
    ban_duration: "24h"
  honeypot:
    ban_duration: "permanent"
    severity: 250

scoring:
  accumulation_window: "30m"
  ban_severity_threshold: 100
  default_ban_duration: "24h"

trust:
  ban_threshold: 2.0
  max_bans_per_minute: 100

enforcement:
  backend: "nftables"
  batch_interval: "1s"

persistence:
  snapshot_interval: "5m"
  wal_sync_mode: "fdatasync"
  max_wal_size_mb: 100
"#;

        let config: HiveGuardConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.node.name, "test-node");
        assert_eq!(config.whitelist.len(), 2);
        assert_eq!(config.detectors.ssh_bruteforce.threshold, 5);
        assert_eq!(
            config.detectors.ssh_bruteforce.window.0,
            Some(Duration::from_secs(300))
        );
        assert!(config.detectors.honeypot.ban_duration.is_permanent());
        assert_eq!(config.detectors.honeypot.severity, 250);
        assert_eq!(config.enforcement.backend, "nftables");
        assert_eq!(config.scoring.ban_severity_threshold, 100);
    }

    #[test]
    fn test_valid_config_passes_validation() {
        let yaml = r#"
node:
  name: "test-node"
  data_dir: "/tmp/hiveguard"

whitelist:
  - "127.0.0.0/8"

api:
  auth_token: "test-secret"

enforcement:
  backend: "nftables"
"#;
        let config: HiveGuardConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validation_fails_missing_node_name() {
        // node.name is required (no default), so missing it should fail deserialization
        let yaml = r#"
node:
  data_dir: "/tmp/hiveguard"
"#;
        let result = serde_yaml::from_str::<HiveGuardConfig>(yaml);
        assert!(result.is_err());
    }

    #[test]
    fn test_validation_fails_invalid_whitelist() {
        let yaml = r#"
node:
  name: "test"
  data_dir: "/tmp/hiveguard"

whitelist:
  - "not-a-cidr"
"#;
        let config: HiveGuardConfig = serde_yaml::from_str(yaml).unwrap();
        let result = config.validate();
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("whitelist"));
    }

    #[test]
    fn test_validation_fails_invalid_backend() {
        let yaml = r#"
node:
  name: "test"
  data_dir: "/tmp/hiveguard"

enforcement:
  backend: "iptables"
"#;
        let config: HiveGuardConfig = serde_yaml::from_str(yaml).unwrap();
        let result = config.validate();
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("backend"));
    }

    #[test]
    fn test_validation_fails_zero_threshold() {
        let yaml = r#"
node:
  name: "test"
  data_dir: "/tmp/hiveguard"

detectors:
  ssh_bruteforce:
    threshold: 0
"#;
        let config: HiveGuardConfig = serde_yaml::from_str(yaml).unwrap();
        let result = config.validate();
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("threshold"));
    }

    #[test]
    fn test_defaults_applied_when_sections_omitted() {
        let yaml = r#"
node:
  name: "minimal"
"#;
        let config: HiveGuardConfig = serde_yaml::from_str(yaml).unwrap();

        // Node defaults
        assert_eq!(config.node.listen_gossip, "0.0.0.0:7946");
        assert_eq!(config.node.listen_api, "127.0.0.1:8443");
        assert_eq!(config.node.data_dir, PathBuf::from("/var/lib/hiveguard"));

        // Detector defaults
        assert!(config.detectors.ssh_bruteforce.enabled);
        assert_eq!(config.detectors.ssh_bruteforce.threshold, 5);
        assert_eq!(
            config.detectors.ssh_bruteforce.window.0,
            Some(Duration::from_secs(300))
        );
        assert_eq!(
            config.detectors.ssh_bruteforce.ban_duration.0,
            Some(Duration::from_secs(86400))
        );

        assert_eq!(config.detectors.http_4xx_flood.threshold, 50);
        assert_eq!(config.detectors.port_scan.threshold, 20);
        assert!(config.detectors.honeypot.ban_duration.is_permanent());
        assert_eq!(config.detectors.honeypot.severity, 250);

        // Scoring defaults
        assert_eq!(config.scoring.ban_severity_threshold, 100);

        // Trust defaults
        assert_eq!(config.trust.ban_threshold, 2.0);
        assert_eq!(config.trust.max_bans_per_minute, 100);

        // Enforcement defaults
        assert_eq!(config.enforcement.backend, "nftables");
        assert_eq!(
            config.enforcement.batch_interval.0,
            Some(Duration::from_secs(1))
        );

        // Persistence defaults
        assert_eq!(
            config.persistence.snapshot_interval.0,
            Some(Duration::from_secs(300))
        );
        assert_eq!(config.persistence.wal_sync_mode, "fdatasync");
        assert_eq!(config.persistence.max_wal_size_mb, 100);
    }

    #[test]
    fn test_load_from_file() {
        let dir = std::env::temp_dir().join("hiveguard_test_config");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.yaml");
        std::fs::write(
            &path,
            r#"
node:
  name: "file-test"
  data_dir: "/tmp/hiveguard"
api:
  auth_token: "test-secret"
"#,
        )
        .unwrap();

        let config = HiveGuardConfig::load(&path).unwrap();
        assert_eq!(config.node.name, "file-test");

        // Cleanup
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_load_nonexistent_file_fails() {
        let result = HiveGuardConfig::load(Path::new("/nonexistent/config.yaml"));
        assert!(result.is_err());
    }

    #[test]
    fn test_parsed_whitelist() {
        let yaml = r#"
node:
  name: "test"
whitelist:
  - "10.0.0.0/8"
  - "192.168.1.0/24"
  - "::1/128"
"#;
        let config: HiveGuardConfig = serde_yaml::from_str(yaml).unwrap();
        let nets = config.parsed_whitelist().unwrap();
        assert_eq!(nets.len(), 3);
    }

    #[test]
    fn test_observe_only_backend_valid() {
        let yaml = r#"
node:
  name: "test"
api:
  auth_token: "test-secret"
enforcement:
  backend: "observe_only"
"#;
        let config: HiveGuardConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_ipset_backend_valid() {
        let yaml = r#"
node:
  name: "test"
api:
  auth_token: "test-secret"
enforcement:
  backend: "ipset"
"#;
        let config: HiveGuardConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(config.validate().is_ok());
    }

    // --- Phase 10: comprehensive coverage ---

    #[test]
    fn test_empty_sections_use_defaults() {
        let yaml = r#"
node:
  name: "test"
api:
  auth_token: "test-secret"
sources: {}
detectors: {}
scoring: {}
trust: {}
enforcement: {}
persistence: {}
"#;
        let config: HiveGuardConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(config.validate().is_ok());
        assert_eq!(config.detectors.ssh_bruteforce.threshold, 5);
        assert_eq!(config.scoring.ban_severity_threshold, 100);
        assert_eq!(config.enforcement.backend, "nftables");
    }

    #[test]
    fn test_unknown_fields_ignored() {
        let yaml = r#"
node:
  name: "test"
  unknown_field: "value"
  another_unknown: 42
extra_section:
  something: true
"#;
        // serde_yaml ignores unknown fields by default with deny_unknown_fields not set
        let config: HiveGuardConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.node.name, "test");
    }

    #[test]
    fn test_empty_whitelist_valid() {
        let yaml = r#"
node:
  name: "test"
api:
  auth_token: "test-secret"
whitelist: []
"#;
        let config: HiveGuardConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(config.validate().is_ok());
        assert!(config.whitelist.is_empty());
        assert!(config.parsed_whitelist().unwrap().is_empty());
    }

    #[test]
    fn test_human_duration_display() {
        let d = HumanDuration::from_secs(30);
        assert_eq!(format!("{d}"), "30s");

        let d = HumanDuration::permanent();
        assert_eq!(format!("{d}"), "permanent");
    }

    #[test]
    fn test_parse_duration_with_whitespace() {
        let d = parse_duration_string("  30s  ").unwrap();
        assert_eq!(d.0, Some(Duration::from_secs(30)));
    }

    #[test]
    fn test_parse_duration_zero_seconds() {
        // "0s" is technically valid parsing, but 0-duration bans are caught in validate
        let d = parse_duration_string("0s").unwrap();
        assert_eq!(d.0, Some(Duration::from_secs(0)));
    }

    #[test]
    fn test_validation_zero_ban_duration() {
        let yaml = r#"
node:
  name: "test"
detectors:
  ssh_bruteforce:
    ban_duration: "0s"
"#;
        let config: HiveGuardConfig = serde_yaml::from_str(yaml).unwrap();
        let result = config.validate();
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("ban_duration"));
    }

    #[test]
    fn test_multiple_custom_sources() {
        let yaml = r#"
node:
  name: "test"
sources:
  custom:
    - path: "/var/log/app1.log"
      pattern: "ERROR"
      detector: "app1_errors"
      threshold: 10
      window: "5m"
    - path: "/var/log/app2.log"
      pattern: "WARN"
      detector: "app2_warnings"
      threshold: 20
      window: "10m"
"#;
        let config: HiveGuardConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.sources.custom.len(), 2);
        assert_eq!(config.sources.custom[0].path, "/var/log/app1.log");
        assert_eq!(config.sources.custom[1].threshold, 20);
    }

    #[test]
    fn test_seeds_list() {
        let yaml = r#"
node:
  name: "cluster-member"
  seeds:
    - "10.0.1.1:7946"
    - "10.0.1.2:7946"
    - "10.0.1.3:7946"
"#;
        let config: HiveGuardConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.node.seeds.len(), 3);
        assert_eq!(config.node.seeds[0].address(), "10.0.1.1:7946");
    }

    #[test]
    fn test_seeds_with_fingerprints() {
        let yaml = r#"
node:
  name: "cluster-member"
  cluster_mode: strict
  seeds:
    - address: "10.0.1.1:7946"
      fingerprint: "a3f2c8deadbeef0000000000000000000000000000000000000000000000abcd"
    - "10.0.1.2:7946"
"#;
        let config: HiveGuardConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.node.seeds.len(), 2);
        assert_eq!(config.node.seeds[0].address(), "10.0.1.1:7946");
        assert_eq!(
            config.node.seeds[0].fingerprint().unwrap(),
            "a3f2c8deadbeef0000000000000000000000000000000000000000000000abcd"
        );
        assert_eq!(config.node.seeds[1].address(), "10.0.1.2:7946");
        assert!(config.node.seeds[1].fingerprint().is_none());
        assert_eq!(config.node.cluster_mode, ClusterMode::Strict);
    }

    #[test]
    fn test_cluster_mode_auto_accept() {
        let yaml = r#"
node:
  name: "dev"
  cluster_mode: auto-accept
"#;
        let config: HiveGuardConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.node.cluster_mode, ClusterMode::AutoAccept);
    }

    #[test]
    fn test_ipv6_whitelist_entry_valid() {
        let yaml = r#"
node:
  name: "test"
api:
  auth_token: "test-secret"
whitelist:
  - "::1/128"
  - "2001:db8::/32"
  - "fe80::/10"
"#;
        let config: HiveGuardConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(config.validate().is_ok());
        let nets = config.parsed_whitelist().unwrap();
        assert_eq!(nets.len(), 3);
    }

    #[test]
    fn test_permanent_honeypot_duration_valid() {
        let yaml = r#"
node:
  name: "test"
api:
  auth_token: "test-secret"
detectors:
  honeypot:
    ban_duration: "permanent"
"#;
        let config: HiveGuardConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(config.validate().is_ok());
        assert!(config.detectors.honeypot.ban_duration.is_permanent());
    }

    #[test]
    fn test_human_duration_as_duration() {
        let d = HumanDuration::from_secs(3600);
        assert_eq!(d.as_duration(), Some(Duration::from_secs(3600)));
        assert!(!d.is_permanent());

        let p = HumanDuration::permanent();
        assert_eq!(p.as_duration(), None);
        assert!(p.is_permanent());
    }

    #[test]
    fn test_nginx_source_paths() {
        let yaml = r#"
node:
  name: "test"
sources:
  nginx:
    access_log: "/var/log/nginx/access.log"
    error_log: "/var/log/nginx/error.log"
"#;
        let config: HiveGuardConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.sources.nginx.access_log.as_deref(), Some("/var/log/nginx/access.log"));
        assert_eq!(config.sources.nginx.error_log.as_deref(), Some("/var/log/nginx/error.log"));
    }

    #[test]
    fn test_ssh_source_journald() {
        let yaml = r#"
node:
  name: "test"
sources:
  ssh:
    use_journald: false
    auth_log_path: "/var/log/auth.log"
"#;
        let config: HiveGuardConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(!config.sources.ssh.use_journald);
        assert_eq!(config.sources.ssh.auth_log_path.as_deref(), Some("/var/log/auth.log"));
    }
}
