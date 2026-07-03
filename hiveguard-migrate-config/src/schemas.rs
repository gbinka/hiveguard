//! Per-plugin JSON Schemas, embedded at build time via `include_str!`.
//!
//! The migrator depends only on `hiveguard-plugin-api` + `hiveguard-config`,
//! not on the individual plugin crates (which would balloon the dependency
//! graph and prevent migration if a plugin fails to compile on the target
//! platform). To still validate generated plugin configs against the same
//! schemas the host uses at runtime, the JSON Schema files are pulled in
//! literally from `plugins/*/schema*.json`.

/// Look up a JSON Schema by plugin id, e.g. `"notifier.slack"`.
///
/// Returns `None` when no schema is bundled for the given id, in which case
/// validation is skipped (schema-less plugins like `notifier.email` accept
/// everything).
pub fn schema_for(id: &str) -> Option<&'static str> {
    Some(match id {
        // --- log sources ---
        "source.file.ssh" => include_str!("../../plugins/source-file/schema-ssh.json"),
        "source.file.nginx" => include_str!("../../plugins/source-file/schema-nginx.json"),
        "source.file.postfix" => include_str!("../../plugins/source-file/schema-postfix.json"),
        "source.file.custom" => include_str!("../../plugins/source-file/schema-custom.json"),
        "source.journald" => include_str!("../../plugins/source-journald/schema.json"),
        "source.kafka" => include_str!("../../plugins/source-kafka/schema.json"),
        "source.nats" => include_str!("../../plugins/source-nats/schema.json"),
        "source.rabbitmq" => include_str!("../../plugins/source-rabbitmq/schema.json"),
        "source.cloudwatch" => include_str!("../../plugins/source-cloudwatch/schema.json"),
        "source.kinesis" => include_str!("../../plugins/source-kinesis/schema.json"),

        // --- detectors ---
        "detector.ssh_bruteforce" => include_str!("../../plugins/detector-ssh-bruteforce/schema.json"),
        "detector.path_probe" => include_str!("../../plugins/detector-path-probe/schema.json"),
        "detector.http_4xx_flood" => include_str!("../../plugins/detector-http-4xx-flood/schema.json"),
        "detector.http_login_bruteforce" => {
            include_str!("../../plugins/detector-http-login-bruteforce/schema.json")
        }
        "detector.scanner_fingerprint" => {
            include_str!("../../plugins/detector-scanner-fingerprint/schema.json")
        }
        "detector.smtp_bruteforce" => include_str!("../../plugins/detector-smtp-bruteforce/schema.json"),
        "detector.port_scan" => include_str!("../../plugins/detector-port-scan/schema.json"),
        "detector.distributed_slow" => include_str!("../../plugins/detector-distributed-slow/schema.json"),
        "detector.honeypot" => include_str!("../../plugins/detector-honeypot/schema.json"),
        "detector.entropy" => include_str!("../../plugins/detector-entropy/schema.json"),
        "detector.timing" => include_str!("../../plugins/detector-timing/schema.json"),
        "detector.sigma" => include_str!("../../plugins/detector-sigma/schema.json"),

        // --- enforcers ---
        "enforcer.nftables" => include_str!("../../plugins/enforcer-nftables/schema.json"),
        "enforcer.ipset" => include_str!("../../plugins/enforcer-ipset/schema.json"),
        "enforcer.observe" => include_str!("../../plugins/enforcer-observe/schema.json"),
        "enforcer.cloudflare" => include_str!("../../plugins/enforcer-cloudflare/schema.json"),

        // --- notifiers ---
        "notifier.slack" => include_str!("../../plugins/notifier-slack/schema.json"),
        "notifier.teams" => include_str!("../../plugins/notifier-teams/schema.json"),
        "notifier.discord" => include_str!("../../plugins/notifier-discord/schema.json"),
        "notifier.telegram" => include_str!("../../plugins/notifier-telegram/schema.json"),
        "notifier.pagerduty" => include_str!("../../plugins/notifier-pagerduty/schema.json"),
        "notifier.email" => include_str!("../../plugins/notifier-email/schema.json"),
        "notifier.webhook" => include_str!("../../plugins/notifier-webhook/schema.json"),

        // --- CTI providers ---
        "cti.abuseipdb" => include_str!("../../plugins/cti-abuseipdb/schema.json"),
        "cti.spamhaus" => include_str!("../../plugins/cti-spamhaus/schema.json"),
        "cti.tor" => include_str!("../../plugins/cti-tor/schema.json"),
        "cti.otx" => include_str!("../../plugins/cti-otx/schema.json"),
        "cti.geoip" => include_str!("../../plugins/cti-geoip/schema.json"),

        // --- SIEM sinks ---
        "sink.syslog" => include_str!("../../plugins/sink-syslog/schema.json"),
        "sink.elastic" => include_str!("../../plugins/sink-elastic/schema.json"),
        "sink.splunk" => include_str!("../../plugins/sink-splunk/schema.json"),
        "sink.datadog" => include_str!("../../plugins/sink-datadog/schema.json"),

        _ => return None,
    })
}
