//! Firewall log source plugin.
//!
//! Tails a firewall log file (UFW / iptables kernel `LOG` entries) and turns
//! each blocked-connection line into a [`NormalizedEvent`] of type
//! [`EventType::PortAccess`], with the destination port placed in
//! `metadata["port"]` — exactly what `detector.port_scan` consumes.
//!
//! ## Adapters
//!
//! The plugin is structured around an `adapter` enum so additional firewall
//! data sources (kernel journal, nftables `log prefix`, conntrack/netlink) can
//! be added without disturbing existing ones. Only the `ufw_file` adapter —
//! tailing a UFW/iptables log file — is implemented today; it is the only one
//! needed for the current deployment, where `/var/log/ufw.log` already carries
//! the `[UFW BLOCK]` entries.
//!
//! The file-tailing machinery (offset persistence, rotation handling, inotify
//! follow) mirrors the `source-file` plugin.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use chrono::{DateTime, NaiveDateTime, Utc};
use notify::{EventKind, RecursiveMode, Watcher};
use serde::Deserialize;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use hiveguard_core::models::{EventType, NormalizedEvent};
use hiveguard_plugin_api::prelude::*;

pub const PLUGIN_ID: &str = "source.firewall";
const PLUGIN_VERSION: &str = "0.1.0";

#[derive(Debug, Clone, Deserialize)]
struct Config {
    #[serde(default = "default_adapter")]
    adapter: String,
    #[serde(default = "default_path")]
    path: PathBuf,
    #[serde(default = "default_seek_to_end")]
    seek_to_end: bool,
    #[serde(default = "default_event_type")]
    event_type: String,
    #[serde(default = "default_block_marker")]
    block_marker: String,
    #[serde(default)]
    protocols: Vec<String>,
}

fn default_adapter() -> String { "ufw_file".to_string() }
fn default_path() -> PathBuf { PathBuf::from("/var/log/ufw.log") }
fn default_seek_to_end() -> bool { true }
fn default_event_type() -> String { "PortAccess".to_string() }
fn default_block_marker() -> String { "[UFW BLOCK]".to_string() }

pub struct FirewallSourcePlugin {
    manifest: PluginManifest,
    data_dir: PathBuf,
    config: Option<Config>,
}

impl FirewallSourcePlugin {
    pub fn manifest_fn() -> PluginManifest {
        PluginManifest {
            id: PLUGIN_ID,
            version: PLUGIN_VERSION,
            description: "Tails a firewall log (UFW/iptables) and emits PortAccess events.",
            kind: PluginKind::LogSource,
            author: "HiveGuard",
            docs_url: Some(
                "https://github.com/anthropics/hiveguard/blob/main/plugins/source-firewall/README.md",
            ),
        }
    }

    pub fn create(
        ctx: PluginContext,
        cfg: serde_json::Value,
    ) -> BoxFuture<'static, PluginResult<Box<dyn LogSourcePlugin>>> {
        Box::pin(async move {
            let mut plugin = FirewallSourcePlugin {
                manifest: Self::manifest_fn(),
                data_dir: ctx.data_dir,
                config: None,
            };
            <FirewallSourcePlugin as Plugin>::init(&mut plugin, cfg).await?;
            info!(plugin = PLUGIN_ID, "initialised");
            Ok(Box::new(plugin) as Box<dyn LogSourcePlugin>)
        })
    }
}

#[async_trait]
impl Plugin for FirewallSourcePlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    async fn init(&mut self, cfg: serde_json::Value) -> PluginResult<()> {
        let parsed: Config = serde_json::from_value(cfg)
            .map_err(|e| PluginError::ConfigValidation(e.to_string()))?;

        if parsed.adapter != "ufw_file" {
            return Err(PluginError::ConfigValidation(format!(
                "unsupported adapter '{}': only 'ufw_file' is implemented",
                parsed.adapter
            )));
        }
        if parsed.block_marker.is_empty() {
            return Err(PluginError::ConfigValidation(
                "block_marker must not be empty".into(),
            ));
        }

        self.config = Some(parsed);
        Ok(())
    }

    async fn shutdown(&mut self) -> PluginResult<()> {
        self.config = None;
        Ok(())
    }
}

#[async_trait]
impl LogSourcePlugin for FirewallSourcePlugin {
    async fn run(&mut self, sink: EventSink, shutdown: CancellationToken) -> PluginResult<()> {
        let cfg = self
            .config
            .as_ref()
            .ok_or_else(|| PluginError::Runtime("firewall source used before init".into()))?
            .clone();

        let event_type = parse_event_type(&cfg.event_type);
        let block_marker = cfg.block_marker.clone();
        let protocols: Vec<String> = cfg.protocols.iter().map(|p| p.to_uppercase()).collect();

        let parser = move |line: &str| {
            parse_ufw_line(line, &block_marker, &protocols, event_type.clone())
        };

        run_file_source(
            cfg.path.clone(),
            "firewall",
            cfg.seek_to_end,
            self.data_dir.clone(),
            sink,
            shutdown,
            parser,
        )
        .await
    }
}

fn parse_event_type(raw: &str) -> EventType {
    match raw {
        "PortAccess" => EventType::PortAccess,
        "ConnectionEvent" => EventType::ConnectionEvent,
        "AuthFailure" => EventType::AuthFailure,
        "AuthSuccess" => EventType::AuthSuccess,
        "HttpRequest" => EventType::HttpRequest,
        "Http4xx" => EventType::Http4xx,
        "Http5xx" => EventType::Http5xx,
        "SmtpAuthFailure" => EventType::SmtpAuthFailure,
        other => EventType::Custom(other.to_string()),
    }
}

/// Pull the value of a `KEY=VALUE` token out of a kernel firewall log line.
/// Tokens are whitespace-separated, so we look for `" KEY="` (or a leading
/// `KEY=`) and read up to the next whitespace.
fn field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let needle = format!("{key}=");
    let start = if line.starts_with(&needle) {
        0
    } else {
        line.find(&format!(" {needle}"))? + 1
    };
    let rest = &line[start + needle.len()..];
    let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
    Some(&rest[..end])
}

/// Parse the leading syslog timestamp (`Jun 15 12:34:56`) if present.
fn parse_syslog_timestamp(line: &str) -> Option<DateTime<Utc>> {
    // "Jun 15 12:34:56 host kernel: ..." — take the first three space groups.
    let mut it = line.splitn(4, ' ');
    let month = it.next()?;
    let day = it.next()?;
    let time = it.next()?;
    let current_year = Utc::now().format("%Y").to_string();
    let candidate = format!("{current_year} {month} {day} {time}");
    NaiveDateTime::parse_from_str(&candidate, "%Y %b %e %H:%M:%S")
        .ok()
        .map(|naive| naive.and_utc())
}

fn parse_ufw_line(
    line: &str,
    block_marker: &str,
    protocols: &[String],
    event_type: EventType,
) -> Option<NormalizedEvent> {
    if !line.contains(block_marker) {
        return None;
    }

    let source_ip: IpAddr = field(line, "SRC")?.parse().ok()?;
    let port_str = field(line, "DPT")?;
    // Validate it is a real port number; the detector parses it again from metadata.
    let port: u16 = port_str.parse().ok()?;

    let proto = field(line, "PROTO").map(|p| p.to_uppercase());
    if !protocols.is_empty() {
        match &proto {
            Some(p) if protocols.contains(p) => {}
            _ => return None,
        }
    }

    let mut metadata: HashMap<String, String> = HashMap::new();
    metadata.insert("port".to_string(), port.to_string());
    if let Some(p) = &proto {
        metadata.insert("proto".to_string(), p.clone());
    }
    if let Some(spt) = field(line, "SPT") {
        metadata.insert("spt".to_string(), spt.to_string());
    }
    if let Some(dst) = field(line, "DST") {
        metadata.insert("dst".to_string(), dst.to_string());
    }

    Some(NormalizedEvent {
        timestamp: parse_syslog_timestamp(line).unwrap_or_else(Utc::now),
        source_ip,
        event_type,
        source_name: "firewall".to_string(),
        raw_line: line.to_string(),
        metadata,
    })
}

// --- File tailing (mirrors source-file) ----------------------------------

async fn run_file_source<F>(
    path: PathBuf,
    offset_key: &str,
    seek_to_end: bool,
    data_dir: PathBuf,
    sink: EventSink,
    shutdown: CancellationToken,
    parser: F,
) -> PluginResult<()>
where
    F: Fn(&str) -> Option<NormalizedEvent> + Send + Sync + 'static,
{
    if !tokio::fs::try_exists(&path).await.map_err(PluginError::from)? {
        return Err(PluginError::Runtime(format!(
            "firewall log file not found: {}",
            path.display()
        )));
    }

    let saved_offset = load_offset(&data_dir, offset_key).await?;
    let mut watcher = if saved_offset > 0 {
        info!(source = offset_key, offset = saved_offset, "resuming firewall source from saved offset");
        FileWatcher::with_offset(path.clone(), saved_offset)
    } else {
        FileWatcher::new(path.clone(), seek_to_end).await.map_err(PluginError::from)?
    };

    let (notify_tx, mut notify_rx) = mpsc::channel::<()>(16);
    let notify_tx_clone = notify_tx.clone();
    let mut fs_watcher = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
        if let Ok(event) = res {
            if matches!(event.kind, EventKind::Modify(_)) {
                let _ = notify_tx_clone.blocking_send(());
            }
        }
    })
    .map_err(|e| PluginError::Runtime(format!("failed to create file watcher: {e}")))?;

    let watch_path = path.parent().unwrap_or(Path::new("."));
    fs_watcher
        .watch(watch_path, RecursiveMode::NonRecursive)
        .map_err(|e| PluginError::Runtime(format!("failed to watch {}: {e}", watch_path.display())))?;

    // Drain once on startup so `seek_to_end: false` replays existing content
    // and a saved offset picks up lines written while we were down.
    emit_new_lines(&mut watcher, &sink, &parser).await?;

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => {
                save_offset(&data_dir, offset_key, watcher.offset()).await.map_err(PluginError::from)?;
                info!(source = offset_key, path = %path.display(), "firewall source stopping");
                return Ok(());
            }
            Some(()) = notify_rx.recv() => {
                while notify_rx.try_recv().is_ok() {}
                emit_new_lines(&mut watcher, &sink, &parser).await?;
            }
        }
    }
}

async fn emit_new_lines<F>(
    watcher: &mut FileWatcher,
    sink: &EventSink,
    parser: &F,
) -> PluginResult<()>
where
    F: Fn(&str) -> Option<NormalizedEvent> + Send + Sync + 'static,
{
    let lines = watcher.read_new_lines().await.map_err(PluginError::from)?;
    for line in lines {
        if let Some(event) = parser(&line) {
            sink.send(event)
                .await
                .map_err(|_| PluginError::Runtime("event sink closed".into()))?;
        }
    }
    Ok(())
}

struct FileWatcher {
    path: PathBuf,
    offset: u64,
}

impl FileWatcher {
    async fn new(path: impl Into<PathBuf>, seek_to_end: bool) -> std::io::Result<Self> {
        let path = path.into();
        let offset = if seek_to_end {
            let path_for_metadata = path.clone();
            tokio::task::spawn_blocking(move || std::fs::metadata(path_for_metadata).map(|m| m.len()))
                .await
                .map_err(|e| std::io::Error::other(format!("blocking metadata task failed: {e}")))??
        } else {
            0
        };
        Ok(Self { path, offset })
    }

    fn with_offset(path: impl Into<PathBuf>, offset: u64) -> Self {
        Self { path: path.into(), offset }
    }

    async fn read_new_lines(&mut self) -> std::io::Result<Vec<String>> {
        let path = self.path.clone();
        let offset = self.offset;
        let read_outcome = tokio::task::spawn_blocking(move || read_new_lines_blocking(path, offset))
            .await
            .map_err(|e| std::io::Error::other(format!("blocking read task failed: {e}")))??;

        if read_outcome.rotated {
            info!(
                path = %self.path.display(),
                old_offset = offset,
                new_len = read_outcome.file_len,
                "firewall log truncated, resetting offset"
            );
        }

        self.offset = read_outcome.offset;
        debug!(path = %self.path.display(), lines = read_outcome.lines.len(), offset = self.offset, "read new firewall log lines");
        Ok(read_outcome.lines)
    }

    fn offset(&self) -> u64 {
        self.offset
    }
}

struct ReadOutcome {
    lines: Vec<String>,
    offset: u64,
    file_len: u64,
    rotated: bool,
}

fn read_new_lines_blocking(path: PathBuf, offset: u64) -> std::io::Result<ReadOutcome> {
    let mut file = std::fs::File::open(&path)?;
    let file_len = file.metadata()?.len();
    let start_offset = if file_len < offset { 0 } else { offset };

    if file_len == start_offset {
        return Ok(ReadOutcome {
            lines: Vec::new(),
            offset: start_offset,
            file_len,
            rotated: file_len < offset,
        });
    }

    file.seek(SeekFrom::Start(start_offset))?;
    let reader = BufReader::new(&file);
    let mut lines = Vec::new();
    let mut bytes_read = 0_u64;

    for line_result in reader.lines() {
        match line_result {
            Ok(line) => {
                bytes_read += line.len() as u64 + 1;
                lines.push(line);
            }
            Err(error) => {
                warn!(error = %error, "error reading line from firewall log");
                break;
            }
        }
    }

    Ok(ReadOutcome {
        lines,
        offset: start_offset + bytes_read,
        file_len,
        rotated: file_len < offset,
    })
}

async fn save_offset(data_dir: &Path, source_name: &str, offset: u64) -> std::io::Result<()> {
    let data_dir = data_dir.to_path_buf();
    let source_name = source_name.to_string();
    tokio::task::spawn_blocking(move || {
        let offsets_dir = data_dir.join("offsets");
        std::fs::create_dir_all(&offsets_dir)?;
        std::fs::write(offsets_dir.join(format!("{source_name}.offset")), offset.to_string())
    })
    .await
    .map_err(|e| std::io::Error::other(format!("blocking save task failed: {e}")))?
}

async fn load_offset(data_dir: &Path, source_name: &str) -> PluginResult<u64> {
    let data_dir = data_dir.to_path_buf();
    let source_name = source_name.to_string();
    tokio::task::spawn_blocking(move || {
        Ok::<u64, std::io::Error>(
            std::fs::read_to_string(data_dir.join("offsets").join(format!("{source_name}.offset")))
                .ok()
                .and_then(|value| value.trim().parse::<u64>().ok())
                .unwrap_or(0),
        )
    })
    .await
    .map_err(|e| PluginError::Runtime(format!("blocking load task failed: {e}")))?
    .map_err(PluginError::from)
}

inventory::submit! {
    PluginDescriptor {
        id: PLUGIN_ID,
        kind: PluginKind::LogSource,
        api_version: API_VERSION,
        manifest: FirewallSourcePlugin::manifest_fn,
        config_schema: include_str!("../schema.json"),
        factory: PluginFactory::LogSource(FirewallSourcePlugin::create),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::sync::Arc;

    use hiveguard_plugin_api::context::parking_lot_compat::RegistryHandle;
    use hiveguard_plugin_api::secrets::SecretResolver;

    const UFW_LINE: &str = "Jun 15 12:34:56 host kernel: [12345.678901] [UFW BLOCK] IN=eth0 OUT= MAC=00:11 SRC=203.0.113.5 DST=10.0.0.1 LEN=40 TOS=0x00 PREC=0x00 TTL=243 ID=54321 PROTO=TCP SPT=51000 DPT=23 WINDOW=1024 RES=0x00 SYN URGP=0";

    fn test_ctx(data_dir: PathBuf) -> PluginContext {
        PluginContext::new(
            PLUGIN_ID.to_string(),
            data_dir,
            Arc::new(SecretResolver::new()),
            PluginMetrics {
                registry: Arc::new(RegistryHandle::default()),
                plugin_id: PLUGIN_ID.to_string(),
            },
            CancellationToken::new(),
        )
    }

    #[test]
    fn manifest_has_correct_id_and_kind() {
        let m = FirewallSourcePlugin::manifest_fn();
        assert_eq!(m.id, PLUGIN_ID);
        assert_eq!(m.kind, PluginKind::LogSource);
    }

    #[test]
    fn field_extracts_tokens() {
        assert_eq!(field(UFW_LINE, "SRC"), Some("203.0.113.5"));
        assert_eq!(field(UFW_LINE, "DPT"), Some("23"));
        assert_eq!(field(UFW_LINE, "PROTO"), Some("TCP"));
        assert_eq!(field(UFW_LINE, "SPT"), Some("51000"));
        assert_eq!(field(UFW_LINE, "NOPE"), None);
    }

    #[test]
    fn field_not_confused_by_substring_keys() {
        // "DPT=" must not match the "SPT=" token or vice versa.
        let line = "x SPT=51000 DPT=23 y";
        assert_eq!(field(line, "DPT"), Some("23"));
        assert_eq!(field(line, "SPT"), Some("51000"));
    }

    #[test]
    fn parses_ufw_block_line() {
        let event =
            parse_ufw_line(UFW_LINE, "[UFW BLOCK]", &[], EventType::PortAccess).unwrap();
        assert_eq!(event.source_ip, "203.0.113.5".parse::<IpAddr>().unwrap());
        assert_eq!(event.event_type, EventType::PortAccess);
        assert_eq!(event.metadata.get("port").unwrap(), "23");
        assert_eq!(event.metadata.get("proto").unwrap(), "TCP");
        assert_eq!(event.metadata.get("spt").unwrap(), "51000");
        assert_eq!(event.source_name, "firewall");
    }

    #[test]
    fn skips_non_block_lines() {
        let line = "Jun 15 12:00:00 host kernel: [UFW ALLOW] SRC=1.2.3.4 DPT=80 PROTO=TCP";
        assert!(parse_ufw_line(line, "[UFW BLOCK]", &[], EventType::PortAccess).is_none());
    }

    #[test]
    fn skips_lines_missing_dpt() {
        let line = "Jun 15 12:00:00 host kernel: [UFW BLOCK] SRC=1.2.3.4 PROTO=ICMP TYPE=8";
        assert!(parse_ufw_line(line, "[UFW BLOCK]", &[], EventType::PortAccess).is_none());
    }

    #[test]
    fn protocol_filter_excludes_unlisted() {
        let only_udp = vec!["UDP".to_string()];
        assert!(parse_ufw_line(UFW_LINE, "[UFW BLOCK]", &only_udp, EventType::PortAccess).is_none());
        let only_tcp = vec!["TCP".to_string()];
        assert!(parse_ufw_line(UFW_LINE, "[UFW BLOCK]", &only_tcp, EventType::PortAccess).is_some());
    }

    #[tokio::test]
    async fn factory_rejects_unknown_adapter() {
        let tempdir = tempfile::tempdir().unwrap();
        let cfg = serde_json::json!({ "adapter": "conntrack" });
        match FirewallSourcePlugin::create(test_ctx(tempdir.path().into()), cfg).await {
            Err(PluginError::ConfigValidation(_)) => {}
            Err(other) => panic!("expected ConfigValidation, got {other:?}"),
            Ok(_) => panic!("expected ConfigValidation error for unknown adapter"),
        }
    }

    #[tokio::test]
    async fn factory_accepts_defaults_when_file_present() {
        let tempdir = tempfile::tempdir().unwrap();
        let log_path = tempdir.path().join("ufw.log");
        std::fs::write(&log_path, "").unwrap();
        let cfg = serde_json::json!({ "path": log_path });
        let plugin = FirewallSourcePlugin::create(test_ctx(tempdir.path().join("state")), cfg)
            .await
            .unwrap();
        assert_eq!(plugin.manifest().id, PLUGIN_ID);
    }

    #[tokio::test]
    async fn run_emits_port_access_for_appended_block() {
        let tempdir = tempfile::tempdir().unwrap();
        let log_path = tempdir.path().join("ufw.log");
        std::fs::write(&log_path, "").unwrap();

        let mut plugin = FirewallSourcePlugin {
            manifest: FirewallSourcePlugin::manifest_fn(),
            data_dir: tempdir.path().join("state"),
            config: Some(Config {
                adapter: "ufw_file".into(),
                path: log_path.clone(),
                seek_to_end: false,
                event_type: "PortAccess".into(),
                block_marker: "[UFW BLOCK]".into(),
                protocols: Vec::new(),
            }),
        };

        let (tx, mut rx) = mpsc::channel(4);
        let shutdown = CancellationToken::new();
        let shutdown_task = shutdown.clone();
        let handle = tokio::spawn(async move { plugin.run(tx, shutdown_task).await });

        let mut file = std::fs::OpenOptions::new().append(true).open(&log_path).unwrap();
        writeln!(file, "{UFW_LINE}").unwrap();
        file.flush().unwrap();

        let event = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(event.event_type, EventType::PortAccess);
        assert_eq!(event.metadata.get("port").unwrap(), "23");
        assert_eq!(event.source_ip, "203.0.113.5".parse::<IpAddr>().unwrap());

        shutdown.cancel();
        handle.await.unwrap().unwrap();
    }
}
