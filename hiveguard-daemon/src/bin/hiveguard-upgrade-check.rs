//! Offline, non-destructive state/config verification and explicit V3 export.
//! Never open a StateManager on the supplied data directory.

#[path = "../plugin_links.rs"]
mod plugin_links;

use std::collections::HashMap;
use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use bincode::Options;
use chrono::{DateTime, Utc};
use clap::Parser;
use hiveguard_core::ban_store::BanStore;
use hiveguard_core::config::HiveGuardConfig;
use hiveguard_core::crdt::CrdtBanRecord;
use hiveguard_core::persistence::snapshot::{load_snapshot_v2, SnapshotResult};
use hiveguard_core::persistence::state_manager::StateManager;
use hiveguard_core::persistence::wal::{WalEntry, WalReader, WalSyncMode};
use hiveguard_core::whitelist::WhitelistManager;
use hiveguard_core::BanRecord;
use hiveguard_host::Loader;
use hiveguard_plugin_api::secrets::SecretResolver;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

type Result<T> = std::result::Result<T, Box<dyn Error>>;
const MAX_STATE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_CONFIG_BYTES: u64 = 20 * 1024 * 1024;

#[derive(Parser)]
#[command(about = "Strict offline HiveGuard state/config check; source files are never changed")]
struct Args {
    #[arg(long)]
    data_dir: PathBuf,
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long)]
    ssh_ip: Option<IpAddr>,
    /// Write JSON to a NEW file. Without this option JSON goes to stdout.
    #[arg(long)]
    output: Option<PathBuf>,
    /// Export current effective state as V3 + empty WAL into a NEW directory.
    #[arg(long)]
    legacy_output_dir: Option<PathBuf>,
}

#[derive(Serialize, Deserialize)]
struct LegacySnapshot {
    bans: Vec<BanRecord>,
    whitelist: Vec<IpNet>,
    crdt_bans: Vec<CrdtBanRecord>,
}

#[derive(Deserialize)]
struct V1Snapshot {
    bans: Vec<BanRecord>,
    whitelist: Vec<IpNet>,
}

#[derive(Default)]
struct EffectiveState {
    bans: HashMap<IpNet, BanRecord>,
    whitelist: WhitelistManager,
    crdt: HashMap<IpNet, CrdtBanRecord>,
    revocations: HashMap<IpNet, DateTime<Utc>>,
}

fn bounded_read(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let file = fs::File::open(path)?;
    if !file.metadata()?.is_file() || file.metadata()?.len() > limit {
        return Err(format!(
            "{} is not a regular file within the {} byte limit",
            path.display(),
            limit
        )
        .into());
    }
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(format!("{} grew beyond the read limit", path.display()).into());
    }
    Ok(bytes)
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn strict_snapshot(path: &Path, bytes: &[u8]) -> Result<SnapshotResult> {
    // The core loader strictly handles postcard V3/V4. Legacy bincode needs
    // reject_trailing_bytes explicitly (the convenience decoder allows tails).
    match bytes.get(..8) {
        Some(b"HVGD0001") => {
            let parsed: V1Snapshot = bincode::DefaultOptions::new()
                .with_fixint_encoding()
                .with_limit(MAX_STATE_BYTES)
                .reject_trailing_bytes()
                .deserialize(&bytes[8..])?;
            Ok(SnapshotResult {
                bans: parsed.bans,
                whitelist: parsed.whitelist,
                crdt_bans: Vec::new(),
                revocations: Vec::new(),
            })
        }
        Some(b"HVGD0002") => {
            let parsed: LegacySnapshot = bincode::DefaultOptions::new()
                .with_fixint_encoding()
                .with_limit(MAX_STATE_BYTES)
                .reject_trailing_bytes()
                .deserialize(&bytes[8..])?;
            Ok(SnapshotResult {
                bans: parsed.bans,
                whitelist: parsed.whitelist,
                crdt_bans: parsed.crdt_bans,
                revocations: Vec::new(),
            })
        }
        _ => Ok(load_snapshot_v2(path)?),
    }
}

fn materialize(snapshot: SnapshotResult, entries: Vec<WalEntry>) -> EffectiveState {
    let mut state = EffectiveState::default();
    for ban in snapshot.bans {
        state.bans.insert(ban.subject, ban);
    }
    for net in snapshot.whitelist {
        state.whitelist.add(net);
    }
    for ban in snapshot.crdt_bans {
        state.crdt.insert(ban.subject, ban);
    }
    state.revocations.extend(snapshot.revocations);
    for entry in entries {
        match entry {
            WalEntry::AddBan(ban) => {
                state.bans.insert(ban.subject, ban);
            }
            WalEntry::RemoveBan(subject) => {
                state.bans.remove(&subject);
            }
            WalEntry::RevokeBan(subject, cutoff) => {
                state.bans.remove(&subject);
                state.revocations.insert(subject, cutoff);
            }
            WalEntry::AddWhitelist(net) => {
                state.whitelist.add(net);
            }
            WalEntry::RemoveWhitelist(net) => {
                state.whitelist.remove(&net);
            }
            WalEntry::AddCrdtBan(ban) => {
                let subject = ban.subject;
                let merged = state
                    .crdt
                    .get(&subject)
                    .and_then(|old| old.merge(&ban))
                    .unwrap_or(ban);
                state.crdt.insert(subject, merged);
            }
            WalEntry::TombstoneCrdtBan(subject) => {
                if let Some(ban) = state.crdt.get_mut(&subject) {
                    ban.tombstone = true;
                }
            }
        }
    }
    state
}

fn compare_manager(expected: &EffectiveState, actual: &StateManager) -> Result<()> {
    let bans: HashMap<_, _> = actual
        .ban_store()
        .get_all_bans()
        .into_iter()
        .map(|ban| (ban.subject, ban.clone()))
        .collect();
    if expected.bans != bans
        || expected.whitelist.entries() != actual.whitelist().entries()
        || &expected.crdt != actual.crdt_store()
    {
        return Err(
            "state recovery/roundtrip changed complete records, whitelist or CRDT state".into(),
        );
    }
    Ok(())
}

fn check_roundtrip(expected: &EffectiveState, copy_dir: &Path) -> Result<()> {
    for _ in 0..2 {
        let mut state = StateManager::new(copy_dir, WalSyncMode::Sync)?;
        compare_manager(expected, &state)?;
        state.take_snapshot()?;
        let persisted = load_snapshot_v2(&copy_dir.join("snapshot.bin"))?;
        let revocations: HashMap<_, _> = persisted.revocations.into_iter().collect();
        if revocations != expected.revocations {
            return Err("snapshot roundtrip changed durable revocations".into());
        }
        if !WalReader::replay_strict(&copy_dir.join("wal.bin"))?.is_empty() {
            return Err("snapshot left unexpected WAL entries".into());
        }
    }
    compare_manager(expected, &StateManager::new(copy_dir, WalSyncMode::Sync)?)
}

fn export_legacy(state: &EffectiveState, destination: &Path) -> Result<()> {
    // A fresh destination makes overwriting the live data or an existing
    // rollback bundle impossible, including through a pre-existing symlink.
    fs::create_dir(destination)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(destination, fs::Permissions::from_mode(0o700))?;
    }
    let mut bans: Vec<_> = state.bans.values().cloned().collect();
    bans.sort_by_key(|ban| ban.subject.to_string());
    let mut whitelist: Vec<_> = state.whitelist.entries().iter().copied().collect();
    whitelist.sort_by_key(ToString::to_string);
    let mut crdt_bans: Vec<_> = state.crdt.values().cloned().collect();
    crdt_bans.sort_by_key(|ban| ban.subject.to_string());
    let mut encoded = b"HVGD0003".to_vec();
    encoded.extend(postcard::to_allocvec(&LegacySnapshot {
        bans,
        whitelist,
        crdt_bans,
    })?);
    write_new(&destination.join("snapshot.bin"), &encoded)?;
    write_new(&destination.join("wal.bin"), &[])?;
    // Retain V4 semantics as a sidecar; the legacy daemon cannot enforce these
    // cutoffs. Export is deliberately explicit rather than silently downgrading.
    let mut revocations: Vec<_> = state
        .revocations
        .iter()
        .map(|(net, time)| (*net, *time))
        .collect();
    revocations.sort_by_key(|(net, _)| net.to_string());
    write_new(
        &destination.join("revocations.json"),
        &serde_json::to_vec_pretty(&revocations)?,
    )?;
    let decoded = materialize(
        load_snapshot_v2(&destination.join("snapshot.bin"))?,
        Vec::new(),
    );
    if decoded.bans != state.bans
        || decoded.crdt != state.crdt
        || decoded.whitelist.entries() != state.whitelist.entries()
    {
        return Err("legacy export changed bans, whitelist or CRDT records".into());
    }
    fs::File::open(destination)?.sync_all()?;
    Ok(())
}

fn inspect(args: &Args) -> Result<Value> {
    let checked_at = Utc::now();
    let snapshot_path = args.data_dir.join("snapshot.bin");
    let wal_path = args.data_dir.join("wal.bin");
    let snapshot_bytes = bounded_read(&snapshot_path, MAX_STATE_BYTES)?;
    let wal_bytes = bounded_read(&wal_path, MAX_STATE_BYTES)?;
    let temp = tempfile::tempdir()?;
    write_new(&temp.path().join("snapshot.bin"), &snapshot_bytes)?;
    write_new(&temp.path().join("wal.bin"), &wal_bytes)?;
    let snapshot = strict_snapshot(&temp.path().join("snapshot.bin"), &snapshot_bytes)?;
    let snapshot_ban_count = snapshot.bans.len();
    let entries = WalReader::replay_strict(&temp.path().join("wal.bin"))?;
    let wal_entry_count = entries.len();
    let expected = materialize(snapshot, entries);
    check_roundtrip(&expected, temp.path())?;

    let mut errors = Vec::new();
    let mut protected = expected.whitelist.clone();
    let mut config_report = Value::Null;
    if let Some(path) = &args.config {
        let config_bytes = bounded_read(path, MAX_CONFIG_BYTES)?;
        let config: HiveGuardConfig = serde_yaml::from_slice(&config_bytes)?;
        config.validate()?;
        for net in config.parsed_whitelist()? {
            protected.add(net);
        }
        let loader_config = hiveguard_daemon::plugin_bridge::to_loader_config(&config);
        let loader = Loader::resolve_only(Arc::new(SecretResolver::new()));
        let resolved = loader.resolve(&loader_config)?;
        let plugins: Vec<_> = resolved
            .iter()
            .map(|entry| entry.entry.id.clone())
            .collect();
        let requested: Vec<_> = config
            .plugins
            .iter()
            .map(|entry| entry.id.clone())
            .collect();
        let nft: Vec<_> = resolved
            .iter()
            .filter(|entry| entry.entry.id == "enforcer.nftables")
            .map(|entry| {
                json!({"table": entry.resolved_config.get("table"),
                "set_name": entry.resolved_config.get("set_name")})
            })
            .collect();
        let configured_dir = fs::canonicalize(&config.node.data_dir)
            .or_else(|_| std::path::absolute(&config.node.data_dir))?;
        let actual_dir = fs::canonicalize(&args.data_dir)?;
        config_report = json!({"path": path, "sha256": digest(&config_bytes),
            "configured_data_dir": config.node.data_dir,
            "data_dir_matches": configured_dir == actual_dir,
            "plugins": requested, "resolved_plugins": plugins, "nftables": nft});
    }
    let mut bans: Vec<_> = expected.bans.values().cloned().collect();
    bans.sort_by_key(|ban| ban.subject.to_string());
    let active: Vec<_> = bans
        .iter()
        .filter(|ban| ban.expires_at.is_none_or(|expiry| expiry > checked_at))
        .collect();
    let protected_active: Vec<_> = active
        .iter()
        .filter(|ban| protected.overlaps(&ban.subject))
        .map(|ban| ban.subject)
        .collect();
    let protected_all: Vec<_> = bans
        .iter()
        .filter(|ban| protected.overlaps(&ban.subject))
        .map(|ban| ban.subject)
        .collect();
    let ssh_subjects: Vec<_> = active
        .iter()
        .filter(|ban| args.ssh_ip.is_some_and(|ip| ban.subject.contains(&ip)))
        .map(|ban| ban.subject)
        .collect();
    if !protected_active.is_empty() {
        errors.push("active bans overlap immutable, persisted or configured whitelist".to_string());
    }
    if !ssh_subjects.is_empty() {
        errors.push("SSH source address is covered by an active ban".to_string());
    }
    let unchanged = snapshot_bytes == bounded_read(&snapshot_path, MAX_STATE_BYTES)?
        && wal_bytes == bounded_read(&wal_path, MAX_STATE_BYTES)?;
    if !unchanged {
        errors.push(
            "source state changed during inspection; repeat on a stopped daemon's consistent copy"
                .to_string(),
        );
    }
    let mut legacy_exported = false;
    if errors.is_empty() {
        if let Some(destination) = &args.legacy_output_dir {
            export_legacy(&expected, destination)?;
            legacy_exported = true;
        }
    }
    Ok(
        json!({"ok": errors.is_empty(), "errors": errors, "checked_at": checked_at,
        "data_dir": args.data_dir, "snapshot_magic": String::from_utf8_lossy(&snapshot_bytes[..8]),
        "snapshot_sha256": digest(&snapshot_bytes), "wal_sha256": digest(&wal_bytes),
        "snapshot_ban_count": snapshot_ban_count, "wal_entry_count": wal_entry_count,
        "total_count": bans.len(), "active_count": active.len(), "expired_count": bans.len() - active.len(),
        "bans": bans, "crdt_count": expected.crdt.len(), "revocations_count": expected.revocations.len(),
        "protected_active": protected_active, "protected_all": protected_all,
        "ssh_ip": args.ssh_ip, "ssh_whitelisted": args.ssh_ip.is_some_and(|ip| protected.is_whitelisted(&ip)), "ssh_banned": !ssh_subjects.is_empty(), "ssh_ban_subjects": ssh_subjects,
        "roundtrip_exact": true, "source_files_unchanged": unchanged, "config": config_report,
        "legacy_exported": legacy_exported, "legacy_output_dir": args.legacy_output_dir,
        "legacy_revocations_supported": false}),
    )
}

fn main() {
    let args = Args::parse();
    let report = inspect(&args).unwrap_or_else(
        |error| json!({"ok": false, "error": error.to_string(), "data_dir": args.data_dir}),
    );
    let encoded = serde_json::to_vec_pretty(&report).expect("JSON report serialization");
    let written = match &args.output {
        Some(path) => write_new(path, &encoded),
        None => std::io::stdout()
            .lock()
            .write_all(&encoded)
            .map_err(Into::into),
    };
    if let Err(error) = written {
        eprintln!("cannot write report: {error}");
        std::process::exit(2);
    }
    if report["ok"] != true {
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hiveguard_core::persistence::snapshot::save_snapshot_with_revocations;
    use hiveguard_core::persistence::wal::WalWriter;
    use hiveguard_core::BanSource;

    fn fixture(dir: &Path) -> BanRecord {
        let record = BanRecord {
            subject: "8.8.8.8/32".parse().unwrap(),
            created_at: Utc::now(),
            expires_at: Some(Utc::now() + chrono::Duration::hours(1)),
            severity: 120,
            reason: "migration test".into(),
            evidence_hash: [7; 32],
            source: BanSource::ManualAdmin,
            geo_info: None,
        };
        save_snapshot_with_revocations(&dir.join("snapshot.bin"), &[record.clone()], &[], &[], &[])
            .unwrap();
        write_new(&dir.join("wal.bin"), &[]).unwrap();
        record
    }

    fn args(dir: &Path) -> Args {
        Args {
            data_dir: dir.into(),
            config: None,
            ssh_ip: None,
            output: None,
            legacy_output_dir: None,
        }
    }

    #[test]
    fn full_record_and_revocation_roundtrip_preserves_sources() {
        let source = tempfile::tempdir().unwrap();
        let record = fixture(source.path());
        let mut writer = WalWriter::open(source.path(), WalSyncMode::Sync).unwrap();
        writer
            .append(&WalEntry::RevokeBan(
                "9.9.9.9/32".parse().unwrap(),
                Utc::now(),
            ))
            .unwrap();
        drop(writer);
        let before = fs::read(source.path().join("wal.bin")).unwrap();
        let report = inspect(&args(source.path())).unwrap();
        assert_eq!(report["ok"], true);
        assert_eq!(report["bans"], json!([record]));
        assert_eq!(report["revocations_count"], 1);
        assert_eq!(before, fs::read(source.path().join("wal.bin")).unwrap());
    }

    #[test]
    fn corruption_and_ssh_risk_fail_without_repairing_original() {
        let source = tempfile::tempdir().unwrap();
        fixture(source.path());
        let mut options = args(source.path());
        options.ssh_ip = Some("8.8.8.8".parse().unwrap());
        let report = inspect(&options).unwrap();
        assert_eq!(report["ok"], false);
        assert_eq!(report["ssh_banned"], true);
        fs::write(source.path().join("wal.bin"), [1, 2]).unwrap();
        assert!(inspect(&options).is_err());
        assert_eq!(fs::read(source.path().join("wal.bin")).unwrap(), [1, 2]);
    }

    #[test]
    fn legacy_export_preserves_expired_records_and_refuses_existing_destination() {
        let source = tempfile::tempdir().unwrap();
        let mut record = fixture(source.path());
        record.expires_at = Some(Utc::now() - chrono::Duration::hours(1));
        save_snapshot_with_revocations(
            &source.path().join("snapshot.bin"),
            &[record.clone()],
            &[],
            &[],
            &[],
        )
        .unwrap();
        let parent = tempfile::tempdir().unwrap();
        let mut options = args(source.path());
        options.legacy_output_dir = Some(parent.path().join("legacy"));
        let report = inspect(&options).unwrap();
        assert_eq!(report["ok"], true);
        assert_eq!(report["expired_count"], 1);
        let exported = load_snapshot_v2(
            &options
                .legacy_output_dir
                .as_ref()
                .unwrap()
                .join("snapshot.bin"),
        )
        .unwrap();
        assert_eq!(exported.bans, vec![record]);
        assert!(inspect(&options).is_err());
    }

    #[test]
    fn protected_bans_abort_and_roundtrip_comparison_detects_record_loss() {
        let source = tempfile::tempdir().unwrap();
        let mut record = fixture(source.path());
        record.subject = "127.0.0.7/32".parse().unwrap();
        // Simulate a legacy snapshot containing a now-protected ban without
        // using the guarded new-decision API.
        save_snapshot_with_revocations(
            &source.path().join("snapshot.bin"),
            &[record.clone()],
            &[],
            &[],
            &[],
        )
        .unwrap();
        let original = fs::read(source.path().join("snapshot.bin")).unwrap();
        let report = inspect(&args(source.path())).unwrap();
        assert_eq!(report["ok"], false);
        assert_eq!(report["protected_active"], json!(["127.0.0.7/32"]));
        assert_eq!(
            original,
            fs::read(source.path().join("snapshot.bin")).unwrap()
        );

        let temp = tempfile::tempdir().unwrap();
        write_new(&temp.path().join("snapshot.bin"), &original).unwrap();
        write_new(&temp.path().join("wal.bin"), &[]).unwrap();
        let expected = materialize(
            load_snapshot_v2(&temp.path().join("snapshot.bin")).unwrap(),
            vec![],
        );
        let mut state = StateManager::new(temp.path(), WalSyncMode::None).unwrap();
        state.remove_ban(&record.subject).unwrap();
        assert!(compare_manager(&expected, &state).is_err());
    }

    #[test]
    fn legacy_snapshot_trailing_data_is_rejected() {
        let source = tempfile::tempdir().unwrap();
        let record = fixture(source.path());
        let mut bytes = b"HVGD0002".to_vec();
        bytes.extend(
            bincode::serialize(&LegacySnapshot {
                bans: vec![record],
                whitelist: vec![],
                crdt_bans: vec![],
            })
            .unwrap(),
        );
        let path = source.path().join("legacy.bin");
        write_new(&path, &bytes).unwrap();
        assert!(strict_snapshot(&path, &bytes).is_ok());
        bytes.push(0);
        assert!(strict_snapshot(&path, &bytes).is_err());
    }
}
