//! Legacy → plugin-aware config conversion.
//!
//! Maps each legacy section to one or more [`PluginEntry`] values while
//! preserving the "core" sections (`node`, `whitelist`, `trust`,
//! `persistence`, `api`, `scoring`) verbatim. Conversion is best-effort:
//! unknown fields trigger warnings but never abort the run.

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use hiveguard_plugin_api::validate_against_schema;
use serde_yaml::Value as YamlValue;

use crate::legacy::*;
use crate::schemas::schema_for;

/// A single plugin entry as produced by the migrator. Intentionally separate
/// from `hiveguard_config::PluginEntry` so we control output field order
/// (clean diffs) and never strip unknown keys.
#[derive(Debug, Clone, serde::Serialize)]
pub struct GeneratedPluginEntry {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub config: serde_json::Value,
}

/// Aggregated migrator output.
#[derive(Debug, Clone)]
pub struct ConvertedConfig {
    pub yaml: String,
    pub report: ConversionReport,
}

#[derive(Debug, Clone, Default)]
pub struct ConversionReport {
    /// Sections we touched and translated into plugin entries.
    pub translated_sections: Vec<String>,
    /// Sections retained verbatim (e.g. `node`, `scoring`).
    pub preserved_sections: Vec<String>,
    /// Plugins we generated, in output order.
    pub generated_plugins: Vec<String>,
    /// Non-fatal warnings (unknown fields, conflicts, …).
    pub warnings: Vec<String>,
    /// Validation errors, one per plugin id that failed its schema check.
    pub validation_errors: Vec<String>,
}

/// Convert a legacy YAML string to the new plugin-aware YAML string.
pub fn convert(legacy_yaml: &str) -> Result<ConvertedConfig> {
    let legacy: LegacyRoot = serde_yaml::from_str(legacy_yaml)
        .context("failed to parse legacy YAML — top-level shape is not a map")?;

    let mut report = ConversionReport::default();
    let mut out_map: serde_yaml::Mapping = serde_yaml::Mapping::new();

    // ---- preserved sections ----
    for (key, value) in [
        ("node", &legacy.node),
        ("whitelist", &legacy.whitelist),
        ("trust", &legacy.trust),
        ("persistence", &legacy.persistence),
        ("api", &legacy.api),
        ("scoring", &legacy.scoring),
    ] {
        if let Some(v) = value {
            out_map.insert(YamlValue::String(key.into()), v.clone());
            report.preserved_sections.push(key.into());
        }
    }

    // ---- collect plugins ----
    let mut plugins: Vec<GeneratedPluginEntry> = Vec::new();

    if let Some(sources) = &legacy.sources {
        convert_sources(sources, &mut plugins, &mut report);
    }
    if let Some(detectors) = &legacy.detectors {
        convert_detectors(detectors, &mut plugins, &mut report);
    }
    if let Some(enforcement) = &legacy.enforcement {
        convert_enforcement(enforcement, &mut plugins, &mut report);
    }
    if let Some(cti) = &legacy.cti {
        convert_cti(cti, &mut plugins, &mut report);
    }
    if let Some(alerting) = &legacy.alerting {
        convert_alerting(alerting, &mut plugins, &mut report);
    }
    if let Some(sigma) = &legacy.sigma {
        convert_sigma(sigma, &mut plugins, &mut report);
    }
    if let Some(siem) = &legacy.siem {
        convert_siem(siem, &mut plugins, &mut report);
    }

    // ---- validate ----
    for entry in &plugins {
        if let Some(schema) = schema_for(&entry.id) {
            if let Err(err) = validate_against_schema(schema, &entry.config) {
                report
                    .validation_errors
                    .push(format!("{}: {err}", entry.id));
            }
        }
    }

    // ---- emit ----
    if !plugins.is_empty() {
        let serialized = serde_yaml::to_value(&plugins)
            .context("failed to serialize generated plugin list")?;
        out_map.insert(YamlValue::String("plugins".into()), serialized);
        report.generated_plugins = plugins.iter().map(|p| p.id.clone()).collect();
    }

    // ---- unknown top-level keys ----
    for (key, value) in &legacy.rest {
        report
            .warnings
            .push(format!("unknown top-level section `{key}` left as-is"));
        out_map.insert(YamlValue::String(key.clone()), value.clone());
    }

    let yaml = serde_yaml::to_string(&YamlValue::Mapping(out_map))
        .context("failed to serialize converted YAML")?;
    Ok(ConvertedConfig { yaml, report })
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn parse_duration_secs(raw: &str) -> Option<u64> {
    // Accept "30s", "5m", "1h", "24h", "permanent", or bare integer seconds.
    let s = raw.trim();
    if s.eq_ignore_ascii_case("permanent") {
        // No "permanent" mapping in schemas — pick a big value (10y) and warn.
        return Some(60 * 60 * 24 * 365 * 10);
    }
    if let Ok(v) = s.parse::<u64>() {
        return Some(v);
    }
    let (num_str, suffix) = s.split_at(
        s.find(|c: char| !c.is_ascii_digit() && c != '.')
            .unwrap_or(s.len()),
    );
    let n: f64 = num_str.parse().ok()?;
    let secs = match suffix.trim() {
        "s" | "" => n,
        "m" | "min" => n * 60.0,
        "h" => n * 3600.0,
        "d" => n * 86400.0,
        "w" => n * 7.0 * 86400.0,
        _ => return None,
    };
    Some(secs as u64)
}

fn insert_secs(obj: &mut serde_json::Map<String, serde_json::Value>, key: &str, raw: &Option<String>) {
    if let Some(s) = raw {
        if let Some(v) = parse_duration_secs(s) {
            obj.insert(key.into(), serde_json::Value::from(v));
        }
    }
}

fn warn_unknown(rest: &BTreeMap<String, YamlValue>, section: &str, report: &mut ConversionReport) {
    for k in rest.keys() {
        report
            .warnings
            .push(format!("ignored unknown field `{section}.{k}` (no plugin mapping)"));
    }
}

// ---------------------------------------------------------------------------
// sources:
// ---------------------------------------------------------------------------

fn convert_sources(
    sources: &SourcesSection,
    plugins: &mut Vec<GeneratedPluginEntry>,
    report: &mut ConversionReport,
) {
    report.translated_sections.push("sources".into());
    warn_unknown(&sources.rest, "sources", report);

    if let Some(ssh) = &sources.ssh {
        let mut cfg = serde_json::Map::new();
        if ssh.use_journald.unwrap_or(true) {
            cfg.insert(
                "units".into(),
                serde_json::json!(["sshd.service", "ssh.service"]),
            );
            cfg.insert("event_type".into(), serde_json::json!("AuthFailure"));
            plugins.push(GeneratedPluginEntry {
                id: "source.journald".into(),
                name: Some("ssh".into()),
                config: serde_json::Value::Object(cfg),
            });
        } else {
            let path = ssh.auth_log_path.clone().unwrap_or_else(|| "/var/log/auth.log".into());
            cfg.insert("path".into(), serde_json::json!(path));
            plugins.push(GeneratedPluginEntry {
                id: "source.file.ssh".into(),
                name: Some("ssh".into()),
                config: serde_json::Value::Object(cfg),
            });
        }
    }

    if let Some(nginx) = &sources.nginx {
        if let Some(path) = &nginx.access_log {
            let mut cfg = serde_json::Map::new();
            cfg.insert("path".into(), serde_json::json!(path));
            plugins.push(GeneratedPluginEntry {
                id: "source.file.nginx".into(),
                name: Some("nginx-access".into()),
                config: serde_json::Value::Object(cfg),
            });
        }
        if let Some(path) = &nginx.error_log {
            let mut cfg = serde_json::Map::new();
            cfg.insert("path".into(), serde_json::json!(path));
            plugins.push(GeneratedPluginEntry {
                id: "source.file.nginx".into(),
                name: Some("nginx-error".into()),
                config: serde_json::Value::Object(cfg),
            });
        }
        if nginx.non_wordpress.unwrap_or(false) {
            report.warnings.push(
                "nginx.non_wordpress is no longer a source flag — set detector.path_probe paths instead"
                    .into(),
            );
        }
    }

    if let Some(postfix) = &sources.postfix {
        let path = postfix.log_path.clone().unwrap_or_else(|| "/var/log/mail.log".into());
        let mut cfg = serde_json::Map::new();
        cfg.insert("path".into(), serde_json::json!(path));
        plugins.push(GeneratedPluginEntry {
            id: "source.file.postfix".into(),
            name: Some("postfix".into()),
            config: serde_json::Value::Object(cfg),
        });
    }

    if let Some(customs) = &sources.custom {
        for (idx, c) in customs.iter().enumerate() {
            let mut cfg = serde_json::Map::new();
            cfg.insert("path".into(), serde_json::json!(c.path));
            cfg.insert("pattern".into(), serde_json::json!(c.pattern));
            cfg.insert(
                "detector".into(),
                serde_json::json!(c.detector.clone().unwrap_or_else(|| "brute_force".into())),
            );
            // threshold/window legacy fields have no schema slot in source.file.custom
            // — they configured a detector. Warn so the user can move them.
            if c.threshold.is_some() || c.window.is_some() {
                report.warnings.push(format!(
                    "sources.custom[{idx}].threshold/window are detector settings; recreate them in a `detector.*` plugin"
                ));
            }
            plugins.push(GeneratedPluginEntry {
                id: "source.file.custom".into(),
                name: Some(format!("custom-{idx}")),
                config: serde_json::Value::Object(cfg),
            });
        }
    }
}

// ---------------------------------------------------------------------------
// detectors:
// ---------------------------------------------------------------------------

fn convert_detectors(
    d: &DetectorsSection,
    plugins: &mut Vec<GeneratedPluginEntry>,
    report: &mut ConversionReport,
) {
    report.translated_sections.push("detectors".into());
    warn_unknown(&d.rest, "detectors", report);

    if let Some(c) = &d.ssh_bruteforce {
        if c.enabled.unwrap_or(true) {
            let mut cfg = serde_json::Map::new();
            if let Some(t) = c.threshold {
                cfg.insert("threshold".into(), serde_json::json!(t));
            }
            insert_secs(&mut cfg, "window_secs", &c.window);
            insert_secs(&mut cfg, "ban_duration_secs", &c.ban_duration);
            // The plugin merges ssh_user_enum into the same crate, so we
            // fold ssh_user_enum below.
            if let Some(enu) = &d.ssh_user_enum {
                if enu.enabled.unwrap_or(true) {
                    if let Some(t) = enu.threshold {
                        cfg.insert("enum_threshold".into(), serde_json::json!(t));
                    }
                    insert_secs(&mut cfg, "enum_window_secs", &enu.window);
                    insert_secs(&mut cfg, "enum_ban_duration_secs", &enu.ban_duration);
                }
            }
            plugins.push(GeneratedPluginEntry {
                id: "detector.ssh_bruteforce".into(),
                name: None,
                config: serde_json::Value::Object(cfg),
            });
        }
    } else if let Some(enu) = &d.ssh_user_enum {
        // ssh_user_enum present without ssh_bruteforce — still surface settings.
        if enu.enabled.unwrap_or(true) {
            let mut cfg = serde_json::Map::new();
            if let Some(t) = enu.threshold {
                cfg.insert("enum_threshold".into(), serde_json::json!(t));
            }
            insert_secs(&mut cfg, "enum_window_secs", &enu.window);
            insert_secs(&mut cfg, "enum_ban_duration_secs", &enu.ban_duration);
            plugins.push(GeneratedPluginEntry {
                id: "detector.ssh_bruteforce".into(),
                name: None,
                config: serde_json::Value::Object(cfg),
            });
        }
    }

    if let Some(c) = &d.path_probe {
        if c.enabled.unwrap_or(true) {
            let mut cfg = serde_json::Map::new();
            if let Some(paths) = &c.paths {
                cfg.insert("paths".into(), serde_json::json!(paths));
            }
            insert_secs(&mut cfg, "ban_duration_secs", &c.ban_duration);
            plugins.push(GeneratedPluginEntry {
                id: "detector.path_probe".into(),
                name: None,
                config: serde_json::Value::Object(cfg),
            });
        }
    }

    if let Some(c) = &d.http_4xx_flood {
        if c.enabled.unwrap_or(true) {
            let mut cfg = serde_json::Map::new();
            if let Some(t) = c.threshold {
                cfg.insert("threshold".into(), serde_json::json!(t));
            }
            insert_secs(&mut cfg, "window_secs", &c.window);
            insert_secs(&mut cfg, "ban_duration_secs", &c.ban_duration);
            warn_unknown(&c.rest, "detectors.http_4xx_flood", report);
            plugins.push(GeneratedPluginEntry {
                id: "detector.http_4xx_flood".into(),
                name: None,
                config: serde_json::Value::Object(cfg),
            });
        }
    }

    if let Some(c) = &d.http_login_bruteforce {
        if c.enabled.unwrap_or(true) {
            let mut cfg = serde_json::Map::new();
            if let Some(t) = c.threshold {
                cfg.insert("threshold".into(), serde_json::json!(t));
            }
            if let Some(p) = &c.paths {
                cfg.insert("paths".into(), serde_json::json!(p));
            }
            insert_secs(&mut cfg, "window_secs", &c.window);
            insert_secs(&mut cfg, "ban_duration_secs", &c.ban_duration);
            plugins.push(GeneratedPluginEntry {
                id: "detector.http_login_bruteforce".into(),
                name: None,
                config: serde_json::Value::Object(cfg),
            });
        }
    }

    if let Some(c) = &d.scanner_fingerprint {
        if c.enabled.unwrap_or(true) {
            let mut cfg = serde_json::Map::new();
            if let Some(s) = &c.scanners {
                cfg.insert("scanners".into(), serde_json::json!(s));
            }
            insert_secs(&mut cfg, "ban_duration_secs", &c.ban_duration);
            plugins.push(GeneratedPluginEntry {
                id: "detector.scanner_fingerprint".into(),
                name: None,
                config: serde_json::Value::Object(cfg),
            });
        }
    }

    if let Some(c) = &d.smtp_bruteforce {
        if c.enabled.unwrap_or(true) {
            let mut cfg = serde_json::Map::new();
            if let Some(t) = c.threshold {
                cfg.insert("threshold".into(), serde_json::json!(t));
            }
            insert_secs(&mut cfg, "window_secs", &c.window);
            insert_secs(&mut cfg, "ban_duration_secs", &c.ban_duration);
            warn_unknown(&c.rest, "detectors.smtp_bruteforce", report);
            plugins.push(GeneratedPluginEntry {
                id: "detector.smtp_bruteforce".into(),
                name: None,
                config: serde_json::Value::Object(cfg),
            });
        }
    }

    if let Some(c) = &d.port_scan {
        if c.enabled.unwrap_or(true) {
            let mut cfg = serde_json::Map::new();
            if let Some(t) = c.threshold {
                cfg.insert("threshold".into(), serde_json::json!(t));
            }
            insert_secs(&mut cfg, "window_secs", &c.window);
            insert_secs(&mut cfg, "ban_duration_secs", &c.ban_duration);
            warn_unknown(&c.rest, "detectors.port_scan", report);
            plugins.push(GeneratedPluginEntry {
                id: "detector.port_scan".into(),
                name: None,
                config: serde_json::Value::Object(cfg),
            });
        }
    }

    if let Some(c) = &d.distributed_slow {
        if c.enabled.unwrap_or(true) {
            let mut cfg = serde_json::Map::new();
            if let Some(t) = c.subnet_threshold {
                cfg.insert("subnet_threshold".into(), serde_json::json!(t));
            }
            insert_secs(&mut cfg, "window_secs", &c.window);
            insert_secs(&mut cfg, "ban_duration_secs", &c.ban_duration);
            if let Some(s) = &c.ban_scope {
                cfg.insert("ban_scope".into(), serde_json::json!(s));
            }
            plugins.push(GeneratedPluginEntry {
                id: "detector.distributed_slow".into(),
                name: None,
                config: serde_json::Value::Object(cfg),
            });
        }
    }

    if let Some(c) = &d.honeypot {
        if c.enabled.unwrap_or(true) {
            let mut cfg = serde_json::Map::new();
            if let Some(p) = &c.paths {
                cfg.insert("paths".into(), serde_json::json!(p));
            }
            if let Some(s) = c.severity {
                // schema caps severity at 255
                cfg.insert("severity".into(), serde_json::json!(s.min(255)));
            }
            if let Some(bd) = &c.ban_duration {
                if bd.eq_ignore_ascii_case("permanent") {
                    report.warnings.push(
                        "detectors.honeypot.ban_duration=\"permanent\" mapped to 10 years (max accepted by schema)".into(),
                    );
                }
                if let Some(secs) = parse_duration_secs(bd) {
                    // schema max is 31_536_000 (1 year)
                    cfg.insert(
                        "ban_duration_secs".into(),
                        serde_json::json!(secs.min(31_536_000)),
                    );
                }
            }
            plugins.push(GeneratedPluginEntry {
                id: "detector.honeypot".into(),
                name: None,
                config: serde_json::Value::Object(cfg),
            });
        }
    }

    if let Some(c) = &d.entropy {
        if c.enabled.unwrap_or(true) {
            let mut cfg = serde_json::Map::new();
            if let Some(v) = c.score_threshold {
                cfg.insert("score_threshold".into(), serde_json::json!(v));
            }
            if let Some(v) = c.benign_penalty {
                cfg.insert("benign_penalty".into(), serde_json::json!(v));
            }
            if let Some(v) = c.error_response_multiplier {
                cfg.insert("error_response_multiplier".into(), serde_json::json!(v));
            }
            if let Some(v) = c.min_entropy {
                cfg.insert("min_entropy".into(), serde_json::json!(v));
            }
            if let Some(v) = c.max_entropy {
                cfg.insert("max_entropy".into(), serde_json::json!(v));
            }
            plugins.push(GeneratedPluginEntry {
                id: "detector.entropy".into(),
                name: None,
                config: serde_json::Value::Object(cfg),
            });
        }
    }

    if let Some(c) = &d.timing {
        if c.enabled.unwrap_or(true) {
            let mut cfg = serde_json::Map::new();
            insert_secs(&mut cfg, "window_secs", &c.window);
            if let Some(v) = c.min_samples {
                cfg.insert("min_samples".into(), serde_json::json!(v));
            }
            if let Some(v) = c.stddev_threshold_ms {
                cfg.insert("stddev_threshold_ms".into(), serde_json::json!(v));
            }
            plugins.push(GeneratedPluginEntry {
                id: "detector.timing".into(),
                name: None,
                config: serde_json::Value::Object(cfg),
            });
        }
    }
}

// ---------------------------------------------------------------------------
// enforcement:
// ---------------------------------------------------------------------------

fn convert_enforcement(
    e: &EnforcementSection,
    plugins: &mut Vec<GeneratedPluginEntry>,
    report: &mut ConversionReport,
) {
    report.translated_sections.push("enforcement".into());
    warn_unknown(&e.rest, "enforcement", report);

    let backend = e.backend.clone().unwrap_or_else(|| "nftables".into());
    let mut cfg = serde_json::Map::new();
    let id = match backend.as_str() {
        "nftables" => {
            cfg.insert(
                "table".into(),
                serde_json::json!(e.nftables_table.clone().unwrap_or_else(|| "hiveguard".into())),
            );
            cfg.insert(
                "set_name".into(),
                serde_json::json!(e.nftables_set_name.clone().unwrap_or_else(|| "hiveguard_blocklist".into())),
            );
            if let Some(iv) = &e.batch_interval {
                if let Some(secs) = parse_duration_secs(iv) {
                    cfg.insert(
                        "batch_interval_secs".into(),
                        serde_json::json!(secs.max(1)),
                    );
                }
            }
            "enforcer.nftables"
        }
        "ipset" => {
            cfg.insert(
                "set_name".into(),
                serde_json::json!(e.ipset_name.clone().unwrap_or_else(|| "hiveguard".into())),
            );
            "enforcer.ipset"
        }
        "observe" | "observe_only" => "enforcer.observe",
        other => {
            report.warnings.push(format!(
                "unknown enforcement.backend `{other}` — defaulting to enforcer.observe"
            ));
            "enforcer.observe"
        }
    };
    plugins.push(GeneratedPluginEntry {
        id: id.into(),
        name: Some("main".into()),
        config: serde_json::Value::Object(cfg),
    });
}

// ---------------------------------------------------------------------------
// cti:
// ---------------------------------------------------------------------------

fn convert_cti(c: &CtiSection, plugins: &mut Vec<GeneratedPluginEntry>, report: &mut ConversionReport) {
    report.translated_sections.push("cti".into());
    warn_unknown(&c.rest, "cti", report);

    if let Some(g) = &c.geoip {
        if g.enabled.unwrap_or(false) {
            let mut cfg = serde_json::Map::new();
            if let Some(p) = &g.database_path {
                cfg.insert("database_path".into(), serde_json::json!(p));
            }
            if let Some(p) = &g.data_dir {
                cfg.insert("data_dir".into(), serde_json::json!(p));
            }
            if let Some(asns) = &g.trusted_asns {
                cfg.insert("trusted_asns".into(), serde_json::json!(asns));
            }
            if g.license_key.is_some() {
                report.warnings.push(
                    "cti.geoip.license_key has no slot in cti.geoip schema — supply MaxMind DB via `database_path` or `data_dir`".into(),
                );
            }
            if g.datacenter_multiplier.is_some() || g.update_interval_days.is_some() {
                report.warnings.push(
                    "cti.geoip.datacenter_multiplier / update_interval_days no longer configurable — relevant scoring lives in scoring plugin".into(),
                );
            }
            plugins.push(GeneratedPluginEntry {
                id: "cti.geoip".into(),
                name: None,
                config: serde_json::Value::Object(cfg),
            });
        }
    }

    if let Some(a) = &c.abuseipdb {
        if a.enabled.unwrap_or(false) {
            let mut cfg = serde_json::Map::new();
            if let Some(k) = &a.api_key {
                cfg.insert("api_key".into(), serde_json::json!(k));
            }
            if let Some(v) = a.confidence_threshold {
                cfg.insert("confidence_threshold".into(), serde_json::json!(v));
            }
            if let Some(v) = a.ban_on_first_hit {
                cfg.insert("ban_on_first_hit".into(), serde_json::json!(v));
            }
            if let Some(v) = a.cache_ttl_hours {
                cfg.insert("cache_ttl_hours".into(), serde_json::json!(v));
            }
            if let Some(v) = a.max_cache_entries {
                cfg.insert("max_cache_entries".into(), serde_json::json!(v));
            }
            plugins.push(GeneratedPluginEntry {
                id: "cti.abuseipdb".into(),
                name: None,
                config: serde_json::Value::Object(cfg),
            });
        }
    }

    if let Some(s) = &c.spamhaus {
        if s.enabled.unwrap_or(false) {
            let mut cfg = serde_json::Map::new();
            if let Some(r) = &s.custom_resolver {
                cfg.insert("custom_resolver".into(), serde_json::json!(r));
            }
            if let Some(v) = s.confidence_threshold {
                cfg.insert("confidence_threshold".into(), serde_json::json!(v));
            }
            if let Some(v) = s.ban_on_first_hit {
                cfg.insert("ban_on_first_hit".into(), serde_json::json!(v));
            }
            plugins.push(GeneratedPluginEntry {
                id: "cti.spamhaus".into(),
                name: None,
                config: serde_json::Value::Object(cfg),
            });
        }
    }

    if let Some(t) = &c.tor {
        if t.enabled.unwrap_or(false) {
            let mut cfg = serde_json::Map::new();
            if let Some(v) = t.refresh_interval_secs {
                cfg.insert("refresh_interval_secs".into(), serde_json::json!(v));
            }
            if let Some(v) = t.ban_on_first_hit {
                cfg.insert("ban_on_first_hit".into(), serde_json::json!(v));
            }
            plugins.push(GeneratedPluginEntry {
                id: "cti.tor".into(),
                name: None,
                config: serde_json::Value::Object(cfg),
            });
        }
    }

    if let Some(o) = &c.otx {
        if o.enabled.unwrap_or(false) {
            let mut cfg = serde_json::Map::new();
            if let Some(k) = &o.api_key {
                cfg.insert("api_key".into(), serde_json::json!(k));
            }
            if let Some(v) = o.min_pulse_count {
                cfg.insert("min_pulse_count".into(), serde_json::json!(v));
            }
            if let Some(v) = o.ban_on_first_hit {
                cfg.insert("ban_on_first_hit".into(), serde_json::json!(v));
            }
            if o.cache_ttl_hours.is_some() {
                report.warnings.push(
                    "cti.otx.cache_ttl_hours has no slot in cti.otx schema (only api_key + min_pulse_count + ban_on_first_hit)".into(),
                );
            }
            plugins.push(GeneratedPluginEntry {
                id: "cti.otx".into(),
                name: None,
                config: serde_json::Value::Object(cfg),
            });
        }
    }
}

// ---------------------------------------------------------------------------
// alerting.destinations:
// ---------------------------------------------------------------------------

fn convert_alerting(
    a: &AlertingSection,
    plugins: &mut Vec<GeneratedPluginEntry>,
    report: &mut ConversionReport,
) {
    report.translated_sections.push("alerting".into());
    if a.cooldown_secs.is_some() || a.queue_depth.is_some() {
        report.warnings.push(
            "alerting.cooldown_secs / queue_depth have no per-plugin equivalent yet — drop them or move to scoring/notifier-specific config later".into(),
        );
    }
    let Some(dests) = &a.destinations else { return };

    for (idx, dest) in dests.iter().enumerate() {
        let kind = dest.kind.clone().unwrap_or_default().to_lowercase();
        let default_name = format!("dest-{idx}");
        let instance_name = dest.name.clone().unwrap_or(default_name.clone());

        match kind.as_str() {
            "slack" => {
                let mut cfg = serde_json::Map::new();
                if let Some(u) = &dest.url {
                    cfg.insert("webhook_url".into(), serde_json::json!(u));
                }
                if let Some(c) = &dest.channel {
                    cfg.insert("channel".into(), serde_json::json!(c));
                }
                if let Some(u) = &dest.username {
                    cfg.insert("username".into(), serde_json::json!(u));
                }
                if let Some(i) = &dest.icon_emoji {
                    cfg.insert("icon_emoji".into(), serde_json::json!(i));
                }
                plugins.push(GeneratedPluginEntry {
                    id: "notifier.slack".into(),
                    name: Some(instance_name),
                    config: serde_json::Value::Object(cfg),
                });
            }
            "teams" => {
                let mut cfg = serde_json::Map::new();
                if let Some(u) = &dest.url {
                    cfg.insert("webhook_url".into(), serde_json::json!(u));
                }
                plugins.push(GeneratedPluginEntry {
                    id: "notifier.teams".into(),
                    name: Some(instance_name),
                    config: serde_json::Value::Object(cfg),
                });
            }
            "discord" => {
                let mut cfg = serde_json::Map::new();
                if let Some(u) = &dest.url {
                    cfg.insert("webhook_url".into(), serde_json::json!(u));
                }
                plugins.push(GeneratedPluginEntry {
                    id: "notifier.discord".into(),
                    name: Some(instance_name),
                    config: serde_json::Value::Object(cfg),
                });
            }
            "pagerduty" => {
                let mut cfg = serde_json::Map::new();
                if let Some(k) = &dest.routing_key {
                    cfg.insert("routing_key".into(), serde_json::json!(k));
                } else if let Some(u) = &dest.url {
                    cfg.insert("url".into(), serde_json::json!(u));
                }
                plugins.push(GeneratedPluginEntry {
                    id: "notifier.pagerduty".into(),
                    name: Some(instance_name),
                    config: serde_json::Value::Object(cfg),
                });
            }
            "telegram" => {
                let mut cfg = serde_json::Map::new();
                if let Some(t) = &dest.bot_token {
                    cfg.insert("bot_token".into(), serde_json::json!(t));
                }
                if let Some(c) = &dest.chat_id {
                    cfg.insert("chat_id".into(), serde_json::json!(c));
                }
                plugins.push(GeneratedPluginEntry {
                    id: "notifier.telegram".into(),
                    name: Some(instance_name),
                    config: serde_json::Value::Object(cfg),
                });
            }
            "email" => {
                plugins.push(GeneratedPluginEntry {
                    id: "notifier.email".into(),
                    name: Some(instance_name),
                    config: serde_json::Value::Object(serde_json::Map::new()),
                });
            }
            "webhook" | "" => {
                let mut cfg = serde_json::Map::new();
                if let Some(u) = &dest.url {
                    cfg.insert("url".into(), serde_json::json!(u));
                }
                if let Some(m) = &dest.http_method {
                    cfg.insert("method".into(), serde_json::json!(m));
                }
                if let Some(c) = &dest.content_type {
                    cfg.insert("content_type".into(), serde_json::json!(c));
                }
                if let Some(h) = &dest.auth_header {
                    cfg.insert("auth_header".into(), serde_json::json!(h));
                }
                if let Some(e) = &dest.events {
                    cfg.insert("events".into(), serde_json::json!(e));
                }
                if let Some(t) = &dest.payload_template {
                    cfg.insert("template".into(), serde_json::json!(t));
                }
                if dest.min_severity.is_some() || dest.cooldown_secs.is_some() {
                    report.warnings.push(format!(
                        "alerting.destinations[{idx}].min_severity / cooldown_secs not yet supported by notifier.webhook schema"
                    ));
                }
                plugins.push(GeneratedPluginEntry {
                    id: "notifier.webhook".into(),
                    name: Some(instance_name),
                    config: serde_json::Value::Object(cfg),
                });
            }
            other => {
                report.warnings.push(format!(
                    "alerting.destinations[{idx}].type=`{other}` is not a known notifier — falling back to notifier.webhook"
                ));
                let mut cfg = serde_json::Map::new();
                if let Some(u) = &dest.url {
                    cfg.insert("url".into(), serde_json::json!(u));
                }
                plugins.push(GeneratedPluginEntry {
                    id: "notifier.webhook".into(),
                    name: Some(instance_name),
                    config: serde_json::Value::Object(cfg),
                });
            }
        }
    }
}

// ---------------------------------------------------------------------------
// sigma:
// ---------------------------------------------------------------------------

fn convert_sigma(
    s: &SigmaSection,
    plugins: &mut Vec<GeneratedPluginEntry>,
    report: &mut ConversionReport,
) {
    report.translated_sections.push("sigma".into());
    if !s.enabled.unwrap_or(false) {
        return;
    }
    let mut cfg = serde_json::Map::new();
    cfg.insert(
        "rules_dir".into(),
        serde_json::json!(s.rules_dir.clone().unwrap_or_else(|| "/var/lib/hiveguard/sigma_rules".into())),
    );
    if let Some(h) = s.hot_reload {
        cfg.insert("hot_reload".into(), serde_json::json!(h));
    }
    plugins.push(GeneratedPluginEntry {
        id: "detector.sigma".into(),
        name: None,
        config: serde_json::Value::Object(cfg),
    });
}

// ---------------------------------------------------------------------------
// siem:
// ---------------------------------------------------------------------------

fn convert_siem(
    s: &SiemSection,
    plugins: &mut Vec<GeneratedPluginEntry>,
    report: &mut ConversionReport,
) {
    report.translated_sections.push("siem".into());
    warn_unknown(&s.rest, "siem", report);

    if let Some(sy) = &s.syslog_exporter {
        if sy.enabled.unwrap_or(false) {
            let mut cfg = serde_json::Map::new();
            if let Some(h) = &sy.host {
                cfg.insert("host".into(), serde_json::json!(h));
            }
            if let Some(p) = &sy.protocol {
                cfg.insert("protocol".into(), serde_json::json!(p));
            }
            if sy.format.is_some() || sy.leef_separator.is_some() || sy.tls.is_some() {
                report.warnings.push(
                    "siem.syslog_exporter.format/leef_separator/tls have no slot in sink.syslog schema".into(),
                );
            }
            plugins.push(GeneratedPluginEntry {
                id: "sink.syslog".into(),
                name: None,
                config: serde_json::Value::Object(cfg),
            });
        }
    }
    if let Some(e) = &s.elasticsearch {
        if e.enabled.unwrap_or(false) {
            let mut cfg = serde_json::Map::new();
            if let Some(h) = &e.host {
                cfg.insert("host".into(), serde_json::json!(h));
            }
            if let Some(p) = &e.index_prefix {
                cfg.insert("index_prefix".into(), serde_json::json!(p));
            }
            if let Some(k) = &e.api_key {
                cfg.insert("api_key".into(), serde_json::json!(k));
            }
            if let Some(u) = &e.username {
                cfg.insert("username".into(), serde_json::json!(u));
            }
            if let Some(p) = &e.password {
                cfg.insert("password".into(), serde_json::json!(p));
            }
            if let Some(v) = e.bulk_size {
                cfg.insert("bulk_size".into(), serde_json::json!(v));
            }
            if let Some(v) = e.flush_interval_secs {
                cfg.insert("flush_interval_secs".into(), serde_json::json!(v));
            }
            plugins.push(GeneratedPluginEntry {
                id: "sink.elastic".into(),
                name: None,
                config: serde_json::Value::Object(cfg),
            });
        }
    }
    if let Some(sp) = &s.splunk {
        if sp.enabled.unwrap_or(false) {
            let mut cfg = serde_json::Map::new();
            // sink.splunk schema requires "host"; we map url→host fall-back.
            let host = sp.host.clone().or_else(|| sp.url.clone());
            if let Some(h) = host {
                cfg.insert("host".into(), serde_json::json!(h));
            }
            if let Some(t) = &sp.token {
                cfg.insert("token".into(), serde_json::json!(t));
            }
            if let Some(i) = &sp.index {
                cfg.insert("index".into(), serde_json::json!(i));
            }
            if let Some(st) = &sp.sourcetype {
                cfg.insert("sourcetype".into(), serde_json::json!(st));
            }
            plugins.push(GeneratedPluginEntry {
                id: "sink.splunk".into(),
                name: None,
                config: serde_json::Value::Object(cfg),
            });
        }
    }
    if let Some(d) = &s.datadog {
        if d.enabled.unwrap_or(false) {
            let mut cfg = serde_json::Map::new();
            // sink.datadog schema requires "host"; treat site as host.
            let host = d.site.clone().unwrap_or_else(|| "datadoghq.com".into());
            cfg.insert("host".into(), serde_json::json!(host));
            if let Some(k) = &d.api_key {
                cfg.insert("api_key".into(), serde_json::json!(k));
            }
            if let Some(s) = &d.service {
                cfg.insert("service".into(), serde_json::json!(s));
            }
            if let Some(t) = &d.tags {
                cfg.insert("tags".into(), serde_json::json!(t));
            }
            plugins.push(GeneratedPluginEntry {
                id: "sink.datadog".into(),
                name: None,
                config: serde_json::Value::Object(cfg),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_durations() {
        assert_eq!(parse_duration_secs("30s"), Some(30));
        assert_eq!(parse_duration_secs("5m"), Some(300));
        assert_eq!(parse_duration_secs("1h"), Some(3600));
        assert_eq!(parse_duration_secs("24h"), Some(86400));
        assert_eq!(parse_duration_secs("100"), Some(100));
        assert_eq!(parse_duration_secs("bogus"), None);
    }
}
