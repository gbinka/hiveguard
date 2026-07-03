//! fail2ban migration helper.
//!
//! Reads fail2ban's SQLite ban database and/or jail configuration, then
//! either forwards the active bans to a running HiveGuard daemon via the
//! Unix socket, or prints an equivalent HiveGuard `config.yaml` snippet.
//!
//! The SQLite database is read by shelling out to the `sqlite3` CLI so that
//! no native C library dependency is required.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};

// ---------------------------------------------------------------------------
// Fail2ban SQLite schema (read via `sqlite3` CLI)
// ---------------------------------------------------------------------------
// CREATE TABLE bans (
//     jail    TEXT    NOT NULL,
//     ip      TEXT    NOT NULL,
//     timeofban INTEGER NOT NULL,   -- Unix epoch seconds
//     bantime   INTEGER NOT NULL,   -- seconds, -1 = permanent
//     PRIMARY KEY (jail, ip)
// );

/// One active ban entry read from fail2ban's SQLite database.
#[derive(Debug)]
pub struct Fail2banBan {
    pub jail: String,
    pub ip: String,
    pub banned_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}

/// Locate the `sqlite3` binary.
fn find_sqlite3() -> Option<&'static str> {
    for candidate in &["/usr/bin/sqlite3", "sqlite3"] {
        if std::process::Command::new(candidate)
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
        {
            return Some(candidate);
        }
    }
    None
}

/// Read all **currently-active** bans from fail2ban's SQLite database by
/// shelling out to `sqlite3`.  Only bans that have not yet expired are returned.
pub fn read_active_bans(db_path: &Path) -> Result<Vec<Fail2banBan>, String> {
    let sqlite3 = find_sqlite3().ok_or_else(|| {
        "sqlite3 binary not found; install it with: apt-get install sqlite3".to_string()
    })?;

    let now_epoch = Utc::now().timestamp();

    let sql = format!(
        "SELECT jail,ip,timeofban,bantime FROM bans \
         WHERE bantime = -1 OR (timeofban + bantime) > {now_epoch};"
    );

    let output = std::process::Command::new(sqlite3)
        .args(["-separator", "|", db_path.to_str().unwrap_or(""), &sql])
        .output()
        .map_err(|e| format!("Failed to run sqlite3: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("sqlite3 error: {}", stderr.trim()));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut bans = Vec::new();

    for line in stdout.lines() {
        let parts: Vec<&str> = line.splitn(4, '|').collect();
        if parts.len() != 4 {
            continue;
        }
        let (jail, ip) = (parts[0].to_string(), parts[1].to_string());
        let timeofban: i64 = parts[2].parse().unwrap_or(0);
        let bantime: i64 = parts[3].parse().unwrap_or(3600);

        let banned_at = DateTime::from_timestamp(timeofban, 0).unwrap_or_else(Utc::now);
        let expires_at = if bantime < 0 {
            None
        } else {
            DateTime::from_timestamp(timeofban + bantime, 0)
        };

        bans.push(Fail2banBan { jail, ip, banned_at, expires_at });
    }

    Ok(bans)
}

// ---------------------------------------------------------------------------
// Jail config parsing
// ---------------------------------------------------------------------------

/// Thresholds extracted from a single fail2ban jail.
#[derive(Debug, Clone)]
pub struct JailConfig {
    pub name: String,
    pub enabled: bool,
    pub max_retry: u32,
    pub find_time_secs: u64,
    pub ban_time_secs: Option<u64>, // None = permanent
    pub log_paths: Vec<String>,
    pub filter: Option<String>,
}

impl Default for JailConfig {
    fn default() -> Self {
        Self {
            name: String::new(),
            enabled: true,
            max_retry: 5,
            find_time_secs: 600,
            ban_time_secs: Some(3600),
            log_paths: Vec::new(),
            filter: None,
        }
    }
}

/// Parse one or more fail2ban jail config files and return a map of jail
/// name to `JailConfig`.  Later files override earlier ones (same semantics
/// as fail2ban's own config merging).
pub fn parse_jail_configs(paths: &[PathBuf]) -> HashMap<String, JailConfig> {
    let mut defaults = JailConfig::default();
    let mut jails: HashMap<String, JailConfig> = HashMap::new();

    for path in paths {
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("Warning: cannot read {:?}: {}", path, e);
                continue;
            }
        };
        parse_ini_into(&text, &mut defaults, &mut jails);
    }

    jails
}

/// Minimal INI parser for fail2ban jail files.
fn parse_ini_into(text: &str, defaults: &mut JailConfig, jails: &mut HashMap<String, JailConfig>) {
    let mut current_section: Option<String> = None;
    let mut current_kv: Vec<(String, String)> = Vec::new();

    let mut flush = |section: &Option<String>,
                     kvs: &[(String, String)],
                     defaults: &mut JailConfig,
                     jails: &mut HashMap<String, JailConfig>| {
        if let Some(name) = section.as_deref() {
            if name.eq_ignore_ascii_case("DEFAULT") {
                apply_kvs(kvs, defaults);
            } else {
                let entry = jails.entry(name.to_lowercase()).or_insert_with(|| {
                    let mut j = defaults.clone();
                    j.name = name.to_lowercase();
                    j
                });
                apply_kvs(kvs, entry);
            }
        }
    };

    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            flush(&current_section, &current_kv, defaults, jails);
            current_section = Some(trimmed[1..trimmed.len() - 1].trim().to_string());
            current_kv.clear();
        } else if let Some(sep) = trimmed.find(['=', ':']) {
            let key = trimmed[..sep].trim().to_lowercase();
            let val = trimmed[sep + 1..].trim().to_string();
            current_kv.push((key, val));
        }
    }
    flush(&current_section, &current_kv, defaults, jails);
}

fn apply_kvs(kvs: &[(String, String)], jail: &mut JailConfig) {
    for (key, value) in kvs {
        match key.as_str() {
            "enabled" => jail.enabled = value.eq_ignore_ascii_case("true"),
            "maxretry" => {
                if let Ok(n) = value.parse() {
                    jail.max_retry = n;
                }
            }
            "findtime" => {
                if let Some(secs) = parse_f2b_time(value) {
                    jail.find_time_secs = secs;
                }
            }
            "bantime" => {
                if let Some(secs) = parse_f2b_time(value) {
                    jail.ban_time_secs = if secs == 0 { None } else { Some(secs) };
                } else if value.trim_start().starts_with('-') {
                    jail.ban_time_secs = None;
                }
            }
            "logpath" => {
                jail.log_paths = value.split_whitespace().map(str::to_string).collect();
            }
            "filter" => jail.filter = Some(value.clone()),
            _ => {}
        }
    }
}

/// Parse a fail2ban time value: plain seconds or suffixed (`10m`, `1h`, `1d`, `1w`).
fn parse_f2b_time(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Ok(n) = s.parse::<i64>() {
        return Some(n.unsigned_abs());
    }
    let (num, suffix) = s.split_at(s.len().saturating_sub(1));
    let n: u64 = num.parse().ok()?;
    let mult = match suffix {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86400,
        "w" => 604800,
        _ => return None,
    };
    Some(n * mult)
}

// ---------------------------------------------------------------------------
// Config snippet generation
// ---------------------------------------------------------------------------

const JAIL_DETECTOR_MAP: &[(&str, &str)] = &[
    ("sshd", "ssh_bruteforce"),
    ("ssh", "ssh_bruteforce"),
    ("ssh-ddos", "ssh_bruteforce"),
    ("nginx-http-auth", "http_4xx_flood"),
    ("nginx-botsearch", "path_probe"),
    ("nginx-noscript", "path_probe"),
    ("postfix", "smtp_bruteforce"),
    ("postfix-sasl", "smtp_bruteforce"),
    ("dovecot", "smtp_bruteforce"),
];

fn jail_to_detector(jail_name: &str) -> Option<&'static str> {
    JAIL_DETECTOR_MAP
        .iter()
        .find(|(j, _)| jail_name.starts_with(j))
        .map(|(_, d)| *d)
}

fn secs_to_hg(secs: u64) -> String {
    if secs % 86400 == 0 { return format!("{}d", secs / 86400); }
    if secs % 3600 == 0 { return format!("{}h", secs / 3600); }
    if secs % 60 == 0 { return format!("{}m", secs / 60); }
    format!("{}s", secs)
}

/// Generate a YAML snippet showing each imported jail as a HiveGuard detector
/// block.  Unrecognised jails are listed as comments.
pub fn generate_config_snippet(jails: &HashMap<String, JailConfig>) -> String {
    let mut out = String::new();
    out.push_str("# HiveGuard config snippet generated from fail2ban jails\n");
    out.push_str("# Add or merge these settings into your config.yaml\n\n");
    out.push_str("detectors:\n");

    let mut recognised: Vec<(&String, &JailConfig)> = jails
        .iter()
        .filter(|(_, j)| j.enabled)
        .filter(|(name, _)| jail_to_detector(name).is_some())
        .collect();
    recognised.sort_by_key(|(name, _)| name.as_str());

    for (jail_name, jail) in &recognised {
        let detector = jail_to_detector(jail_name).unwrap();
        let ban_dur = jail
            .ban_time_secs
            .map(secs_to_hg)
            .unwrap_or_else(|| "permanent".to_string());
        let window = secs_to_hg(jail.find_time_secs);
        out.push_str(&format!("  # imported from fail2ban jail '{jail_name}'\n"));
        out.push_str(&format!("  {detector}:\n"));
        out.push_str("    enabled: true\n");
        out.push_str(&format!("    threshold: {}\n", jail.max_retry));
        out.push_str(&format!("    window: {window}\n"));
        out.push_str(&format!("    ban_duration: {ban_dur}\n"));
        out.push('\n');
    }

    let mut unrecognised: Vec<_> = jails
        .iter()
        .filter(|(_, j)| j.enabled)
        .filter(|(name, _)| jail_to_detector(name).is_none())
        .map(|(name, _)| name.as_str())
        .collect();
    unrecognised.sort_unstable();

    if !unrecognised.is_empty() {
        out.push_str("# The following jails have no direct HiveGuard equivalent;\n");
        out.push_str("# consider using a custom log source for them:\n");
        for name in unrecognised {
            out.push_str(&format!("#   {name}\n"));
        }
    }

    out
}

// ---------------------------------------------------------------------------
// Top-level entry point called from main.rs
// ---------------------------------------------------------------------------

pub struct ImportResult {
    pub imported: usize,
    pub skipped: usize,
    pub errors: Vec<String>,
}

/// Import active fail2ban bans into HiveGuard.
/// If `dry_run` is true, bans are printed but not sent to the daemon.
pub async fn run_import(
    db_path: &Path,
    socket_path: &Path,
    dry_run: bool,
    jail_filter: Option<&str>,
) -> ImportResult {
    let bans = match read_active_bans(db_path) {
        Ok(b) => b,
        Err(e) => {
            return ImportResult { imported: 0, skipped: 0, errors: vec![e] };
        }
    };

    let bans: Vec<_> = if let Some(filter) = jail_filter {
        bans.into_iter().filter(|b| b.jail == filter).collect()
    } else {
        bans
    };

    if bans.is_empty() {
        println!("No active fail2ban bans found.");
        return ImportResult { imported: 0, skipped: 0, errors: vec![] };
    }

    println!("Found {} active fail2ban ban(s).", bans.len());

    if dry_run {
        println!("(dry run — not sending to daemon)\n");
        println!("{:<22} {:<20} {:<26} JAIL", "IP", "BANNED AT", "EXPIRES");
        for ban in &bans {
            let expires = ban
                .expires_at
                .map(|t| t.format("%Y-%m-%dT%H:%M:%SZ").to_string())
                .unwrap_or_else(|| "permanent".to_string());
            println!(
                "{:<22} {:<20} {:<26} {}",
                ban.ip,
                ban.banned_at.format("%Y-%m-%dT%H:%M:%SZ"),
                expires,
                ban.jail,
            );
        }
        return ImportResult { imported: 0, skipped: bans.len(), errors: vec![] };
    }

    let mut imported = 0usize;
    let mut skipped = 0usize;
    let mut errors: Vec<String> = Vec::new();

    for ban in &bans {
        let duration = ban.expires_at.map(|exp| {
            let remaining = exp.signed_duration_since(Utc::now());
            secs_to_hg(remaining.num_seconds().max(1) as u64)
        });

        let request = hiveguard_core::api::ApiRequest::Ban {
            target: ban.ip.clone(),
            duration,
            reason: Some(format!("imported from fail2ban jail '{}'", ban.jail)),
        };

        match crate::cli::send_request(&socket_path.to_path_buf(), &request).await {
            Ok(hiveguard_core::api::ApiResponse::Ok { .. }) => imported += 1,
            Ok(hiveguard_core::api::ApiResponse::Error { message }) => {
                skipped += 1;
                eprintln!("  skipped {}: {}", ban.ip, message);
            }
            Ok(_) => skipped += 1,
            Err(e) => errors.push(format!("{}: {}", ban.ip, e)),
        }
    }

    ImportResult { imported, skipped, errors }
}
