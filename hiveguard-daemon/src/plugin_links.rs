//! Force-link first-party plugin crates into the daemon binary.
//!
//! Plugins register themselves at startup through `inventory::submit!`
//! (collected by `hiveguard_plugin_api::registry`). Because nothing in the
//! daemon's own code references any symbol from these crates, the Rust linker
//! would otherwise drop their object files entirely — and with them the
//! `inventory::submit!` static initializers. The result is a binary that
//! compiles cleanly but fails at runtime with
//! `plugin \`<id>\` not linked into this binary`.
//!
//! An `extern crate … as _;` declaration creates a hard link dependency on the
//! crate purely for its side effects (the inventory registration), without
//! importing any name. Each is gated behind the same feature that pulls the
//! crate into the dependency graph, so this module stays in lock-step with the
//! `[features]` table in `Cargo.toml`. Keep the two in sync when adding or
//! removing a plugin.

// --- Sources -------------------------------------------------------------
#[cfg(feature = "source-file")]
extern crate hiveguard_plugin_source_file as _;
#[cfg(feature = "source-firewall")]
extern crate hiveguard_plugin_source_firewall as _;
#[cfg(feature = "source-syslog")]
extern crate hiveguard_plugin_source_syslog as _;
#[cfg(feature = "source-journald")]
extern crate hiveguard_plugin_source_journald as _;
#[cfg(feature = "source-kafka")]
extern crate hiveguard_plugin_source_kafka as _;
#[cfg(feature = "source-nats")]
extern crate hiveguard_plugin_source_nats as _;
#[cfg(feature = "source-rabbitmq")]
extern crate hiveguard_plugin_source_rabbitmq as _;
#[cfg(feature = "source-kinesis")]
extern crate hiveguard_plugin_source_kinesis as _;
#[cfg(feature = "source-cloudwatch")]
extern crate hiveguard_plugin_source_cloudwatch as _;

// --- Enforcers -----------------------------------------------------------
#[cfg(feature = "enforcer-nftables")]
extern crate hiveguard_plugin_enforcer_nftables as _;
#[cfg(feature = "enforcer-ipset")]
extern crate hiveguard_plugin_enforcer_ipset as _;
#[cfg(feature = "enforcer-cloudflare")]
extern crate hiveguard_plugin_enforcer_cloudflare as _;
#[cfg(feature = "enforcer-observe")]
extern crate hiveguard_plugin_enforcer_observe as _;

// --- Notifiers -----------------------------------------------------------
#[cfg(feature = "notifier-webhook")]
extern crate hiveguard_plugin_notifier_webhook as _;

// --- SIEM sinks ----------------------------------------------------------
#[cfg(feature = "sink-elastic")]
extern crate hiveguard_plugin_sink_elastic as _;
#[cfg(feature = "sink-splunk")]
extern crate hiveguard_plugin_sink_splunk as _;
#[cfg(feature = "sink-datadog")]
extern crate hiveguard_plugin_sink_datadog as _;
#[cfg(feature = "sink-syslog")]
extern crate hiveguard_plugin_sink_syslog as _;

// --- CTI providers -------------------------------------------------------
#[cfg(feature = "cti-abuseipdb")]
extern crate hiveguard_plugin_cti_abuseipdb as _;
#[cfg(feature = "cti-spamhaus")]
extern crate hiveguard_plugin_cti_spamhaus as _;
#[cfg(feature = "cti-tor")]
extern crate hiveguard_plugin_cti_tor as _;
#[cfg(feature = "cti-otx")]
extern crate hiveguard_plugin_cti_otx as _;
#[cfg(feature = "cti-geoip")]
extern crate hiveguard_plugin_cti_geoip as _;

// --- Detectors -----------------------------------------------------------
#[cfg(feature = "detector-ssh-bruteforce")]
extern crate hiveguard_plugin_detector_ssh_bruteforce as _;
#[cfg(feature = "detector-path-probe")]
extern crate hiveguard_plugin_detector_path_probe as _;
#[cfg(feature = "detector-http-4xx-flood")]
extern crate hiveguard_plugin_detector_http_4xx_flood as _;
#[cfg(feature = "detector-http-login-bruteforce")]
extern crate hiveguard_plugin_detector_http_login_bruteforce as _;
#[cfg(feature = "detector-scanner-fingerprint")]
extern crate hiveguard_plugin_detector_scanner_fingerprint as _;
#[cfg(feature = "detector-smtp-bruteforce")]
extern crate hiveguard_plugin_detector_smtp_bruteforce as _;
#[cfg(feature = "detector-honeypot")]
extern crate hiveguard_plugin_detector_honeypot as _;
#[cfg(feature = "detector-entropy")]
extern crate hiveguard_plugin_detector_entropy as _;
#[cfg(feature = "detector-timing")]
extern crate hiveguard_plugin_detector_timing as _;
#[cfg(feature = "detector-port-scan")]
extern crate hiveguard_plugin_detector_port_scan as _;
#[cfg(feature = "detector-distributed-slow")]
extern crate hiveguard_plugin_detector_distributed_slow as _;
#[cfg(feature = "detector-sigma")]
extern crate hiveguard_plugin_detector_sigma as _;

// --- Scoring engine ------------------------------------------------------
#[cfg(feature = "scoring-default")]
extern crate hiveguard_plugin_scoring_default as _;

// --- UI server plugins ---------------------------------------------------
#[cfg(feature = "ui-rest")]
extern crate hiveguard_plugin_ui_rest as _;
#[cfg(feature = "ui-tui")]
extern crate hiveguard_plugin_ui_tui as _;
#[cfg(feature = "ui-web")]
extern crate hiveguard_ui_web as _;
