//! Lenient deserialisation of the legacy HiveGuard YAML config.
//!
//! Every field is optional, so partial fixtures and migrated configs both
//! parse cleanly. Unknown keys are ignored — the migrator emits a warning for
//! ones it does not understand via [`crate::convert`].

use serde::Deserialize;
use serde_yaml::Value as YamlValue;

#[derive(Debug, Default, Deserialize)]
pub struct LegacyRoot {
    #[serde(default)]
    pub node: Option<YamlValue>,
    #[serde(default)]
    pub whitelist: Option<YamlValue>,
    #[serde(default)]
    pub trust: Option<YamlValue>,
    #[serde(default)]
    pub persistence: Option<YamlValue>,
    #[serde(default)]
    pub api: Option<YamlValue>,
    #[serde(default)]
    pub scoring: Option<YamlValue>,

    // ---- sections that become plugins ----
    #[serde(default)]
    pub sources: Option<SourcesSection>,
    #[serde(default)]
    pub detectors: Option<DetectorsSection>,
    #[serde(default)]
    pub enforcement: Option<EnforcementSection>,
    #[serde(default)]
    pub cti: Option<CtiSection>,
    #[serde(default)]
    pub alerting: Option<AlertingSection>,
    #[serde(default)]
    pub sigma: Option<SigmaSection>,
    #[serde(default)]
    pub siem: Option<SiemSection>,

    // Whatever is left — kept so we can surface unknown top-level keys.
    #[serde(flatten)]
    pub rest: std::collections::BTreeMap<String, YamlValue>,
}

// ---------------------------------------------------------------------------
// sources:
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Deserialize)]
pub struct SourcesSection {
    #[serde(default)]
    pub ssh: Option<SshSource>,
    #[serde(default)]
    pub nginx: Option<NginxSource>,
    #[serde(default)]
    pub postfix: Option<PostfixSource>,
    #[serde(default)]
    pub custom: Option<Vec<CustomSource>>,
    #[serde(flatten)]
    pub rest: std::collections::BTreeMap<String, YamlValue>,
}

#[derive(Debug, Default, Deserialize)]
pub struct SshSource {
    #[serde(default)]
    pub use_journald: Option<bool>,
    #[serde(default)]
    pub auth_log_path: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub struct NginxSource {
    #[serde(default)]
    pub access_log: Option<String>,
    #[serde(default)]
    pub error_log: Option<String>,
    #[serde(default)]
    pub non_wordpress: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
pub struct PostfixSource {
    #[serde(default)]
    pub log_path: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CustomSource {
    pub path: String,
    pub pattern: String,
    #[serde(default)]
    pub detector: Option<String>,
    #[serde(default)]
    pub threshold: Option<u32>,
    #[serde(default)]
    pub window: Option<String>,
}

// ---------------------------------------------------------------------------
// detectors:
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Deserialize)]
pub struct DetectorsSection {
    #[serde(default)]
    pub ssh_bruteforce: Option<DetectorSshBruteforce>,
    #[serde(default)]
    pub ssh_user_enum: Option<DetectorSshUserEnum>,
    #[serde(default)]
    pub path_probe: Option<DetectorPathProbe>,
    #[serde(default)]
    pub http_4xx_flood: Option<DetectorThresholdWindow>,
    #[serde(default)]
    pub http_login_bruteforce: Option<DetectorHttpLoginBruteforce>,
    #[serde(default)]
    pub scanner_fingerprint: Option<DetectorScannerFingerprint>,
    #[serde(default)]
    pub smtp_bruteforce: Option<DetectorThresholdWindow>,
    #[serde(default)]
    pub port_scan: Option<DetectorThresholdWindow>,
    #[serde(default)]
    pub distributed_slow: Option<DetectorDistributedSlow>,
    #[serde(default)]
    pub honeypot: Option<DetectorHoneypot>,
    #[serde(default)]
    pub entropy: Option<DetectorEntropy>,
    #[serde(default)]
    pub timing: Option<DetectorTiming>,
    #[serde(flatten)]
    pub rest: std::collections::BTreeMap<String, YamlValue>,
}

#[derive(Debug, Default, Deserialize)]
pub struct EnabledFlag {
    #[serde(default)]
    pub enabled: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
pub struct DetectorSshBruteforce {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub threshold: Option<u32>,
    #[serde(default)]
    pub window: Option<String>,
    #[serde(default)]
    pub ban_duration: Option<String>,
}

pub type DetectorSshUserEnum = DetectorSshBruteforce;

#[derive(Debug, Default, Deserialize)]
pub struct DetectorPathProbe {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub paths: Option<Vec<String>>,
    #[serde(default)]
    pub ban_duration: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub struct DetectorThresholdWindow {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub threshold: Option<u32>,
    #[serde(default)]
    pub window: Option<String>,
    #[serde(default)]
    pub ban_duration: Option<String>,
    #[serde(flatten)]
    pub rest: std::collections::BTreeMap<String, YamlValue>,
}

#[derive(Debug, Default, Deserialize)]
pub struct DetectorHttpLoginBruteforce {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub threshold: Option<u32>,
    #[serde(default)]
    pub window: Option<String>,
    #[serde(default)]
    pub ban_duration: Option<String>,
    #[serde(default)]
    pub paths: Option<Vec<String>>,
}

#[derive(Debug, Default, Deserialize)]
pub struct DetectorScannerFingerprint {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub scanners: Option<Vec<String>>,
    #[serde(default)]
    pub ban_duration: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub struct DetectorDistributedSlow {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub subnet_threshold: Option<u32>,
    #[serde(default)]
    pub window: Option<String>,
    #[serde(default)]
    pub ban_duration: Option<String>,
    #[serde(default)]
    pub ban_scope: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub struct DetectorHoneypot {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub paths: Option<Vec<String>>,
    #[serde(default)]
    pub ban_duration: Option<String>,
    #[serde(default)]
    pub severity: Option<u32>,
}

#[derive(Debug, Default, Deserialize)]
pub struct DetectorEntropy {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub score_threshold: Option<f64>,
    #[serde(default)]
    pub benign_penalty: Option<f64>,
    #[serde(default)]
    pub error_response_multiplier: Option<f64>,
    #[serde(default)]
    pub min_entropy: Option<f64>,
    #[serde(default)]
    pub max_entropy: Option<f64>,
}

#[derive(Debug, Default, Deserialize)]
pub struct DetectorTiming {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub window: Option<String>,
    #[serde(default)]
    pub min_samples: Option<u32>,
    #[serde(default)]
    pub stddev_threshold_ms: Option<f64>,
}

// ---------------------------------------------------------------------------
// enforcement:
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Deserialize)]
pub struct EnforcementSection {
    #[serde(default)]
    pub backend: Option<String>,
    #[serde(default)]
    pub nftables_set_name: Option<String>,
    #[serde(default)]
    pub nftables_table: Option<String>,
    #[serde(default)]
    pub ipset_name: Option<String>,
    #[serde(default)]
    pub batch_interval: Option<String>,
    #[serde(flatten)]
    pub rest: std::collections::BTreeMap<String, YamlValue>,
}

// ---------------------------------------------------------------------------
// cti:
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Deserialize)]
pub struct CtiSection {
    #[serde(default)]
    pub geoip: Option<CtiGeoIp>,
    #[serde(default)]
    pub abuseipdb: Option<CtiAbuseIpDb>,
    #[serde(default)]
    pub spamhaus: Option<CtiSpamhaus>,
    #[serde(default)]
    pub tor: Option<CtiTor>,
    #[serde(default)]
    pub otx: Option<CtiOtx>,
    #[serde(flatten)]
    pub rest: std::collections::BTreeMap<String, YamlValue>,
}

#[derive(Debug, Default, Deserialize)]
pub struct CtiGeoIp {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub license_key: Option<String>,
    #[serde(default)]
    pub trusted_asns: Option<Vec<u32>>,
    #[serde(default)]
    pub datacenter_multiplier: Option<f64>,
    #[serde(default)]
    pub update_interval_days: Option<u32>,
    #[serde(default)]
    pub database_path: Option<String>,
    #[serde(default)]
    pub data_dir: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub struct CtiAbuseIpDb {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub api_key: Option<String>,
    #[serde(default)]
    pub confidence_threshold: Option<u32>,
    #[serde(default)]
    pub ban_on_first_hit: Option<bool>,
    #[serde(default)]
    pub cache_ttl_hours: Option<u32>,
    #[serde(default)]
    pub max_cache_entries: Option<u32>,
}

#[derive(Debug, Default, Deserialize)]
pub struct CtiSpamhaus {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub custom_resolver: Option<String>,
    #[serde(default)]
    pub confidence_threshold: Option<u32>,
    #[serde(default)]
    pub ban_on_first_hit: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
pub struct CtiTor {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub refresh_interval_secs: Option<u32>,
    #[serde(default)]
    pub ban_on_first_hit: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
pub struct CtiOtx {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub api_key: Option<String>,
    #[serde(default)]
    pub min_pulse_count: Option<u32>,
    #[serde(default)]
    pub ban_on_first_hit: Option<bool>,
    #[serde(default)]
    pub cache_ttl_hours: Option<u32>,
}

// ---------------------------------------------------------------------------
// alerting:
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Deserialize)]
pub struct AlertingSection {
    #[serde(default)]
    pub cooldown_secs: Option<u64>,
    #[serde(default)]
    pub queue_depth: Option<u64>,
    #[serde(default)]
    pub destinations: Option<Vec<AlertDestination>>,
}

#[derive(Debug, Default, Deserialize)]
pub struct AlertDestination {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(rename = "type", default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub events: Option<Vec<String>>,
    #[serde(default)]
    pub min_severity: Option<u32>,
    #[serde(default)]
    pub cooldown_secs: Option<u64>,
    #[serde(default)]
    pub auth_header: Option<String>,
    #[serde(default)]
    pub payload_template: Option<String>,
    #[serde(default)]
    pub http_method: Option<String>,
    #[serde(default)]
    pub content_type: Option<String>,
    // Notifier-specific (slack/teams/discord)
    #[serde(default)]
    pub channel: Option<String>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub icon_emoji: Option<String>,
    // PagerDuty / Telegram extras
    #[serde(default)]
    pub routing_key: Option<String>,
    #[serde(default)]
    pub bot_token: Option<String>,
    #[serde(default)]
    pub chat_id: Option<String>,
}

// ---------------------------------------------------------------------------
// sigma:
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Deserialize)]
pub struct SigmaSection {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub rules_dir: Option<String>,
    #[serde(default)]
    pub hot_reload: Option<bool>,
}

// ---------------------------------------------------------------------------
// siem:
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Deserialize)]
pub struct SiemSection {
    #[serde(default)]
    pub syslog_exporter: Option<SiemSyslog>,
    #[serde(default)]
    pub elasticsearch: Option<SiemElastic>,
    #[serde(default)]
    pub splunk: Option<SiemSplunk>,
    #[serde(default)]
    pub datadog: Option<SiemDatadog>,
    #[serde(flatten)]
    pub rest: std::collections::BTreeMap<String, YamlValue>,
}

#[derive(Debug, Default, Deserialize)]
pub struct SiemSyslog {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub protocol: Option<String>,
    #[serde(default)]
    pub format: Option<String>,
    #[serde(default)]
    pub tls: Option<bool>,
    #[serde(default)]
    pub leef_separator: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub struct SiemElastic {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub index_prefix: Option<String>,
    #[serde(default)]
    pub api_key: Option<String>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub bulk_size: Option<u32>,
    #[serde(default)]
    pub flush_interval_secs: Option<u32>,
    #[serde(default)]
    pub ilm_enabled: Option<bool>,
    #[serde(default)]
    pub tls_verify: Option<bool>,
    #[serde(default)]
    pub dlq_dir: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub struct SiemSplunk {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub token: Option<String>,
    #[serde(default)]
    pub index: Option<String>,
    #[serde(default)]
    pub sourcetype: Option<String>,
    #[serde(default)]
    pub tls_verify: Option<bool>,
    #[serde(default)]
    pub batch_size: Option<u32>,
    #[serde(default)]
    pub flush_interval_secs: Option<u32>,
}

#[derive(Debug, Default, Deserialize)]
pub struct SiemDatadog {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub api_key: Option<String>,
    #[serde(default)]
    pub site: Option<String>,
    #[serde(default)]
    pub service: Option<String>,
    #[serde(default)]
    pub tags: Option<Vec<String>>,
    #[serde(default)]
    pub batch_size: Option<u32>,
    #[serde(default)]
    pub flush_interval_secs: Option<u32>,
}
