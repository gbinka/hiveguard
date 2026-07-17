//! File-backed log source plugins.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::Instant;

use chrono::{DateTime, FixedOffset, NaiveDateTime, Utc};
use notify::{EventKind, RecursiveMode, Watcher};
use prometheus_client::metrics::gauge::Gauge;
use regex::Regex;
use serde::Deserialize;
use tokio::sync::mpsc;
use tracing::{debug, info, trace, warn};

use hiveguard_core::models::{EventType, NormalizedEvent};
use hiveguard_plugin_api::prelude::*;

pub const SSH_PLUGIN_ID: &str = "source.file.ssh";
pub const NGINX_PLUGIN_ID: &str = "source.file.nginx";
pub const POSTFIX_PLUGIN_ID: &str = "source.file.postfix";
pub const CUSTOM_PLUGIN_ID: &str = "source.file.custom";
const PLUGIN_VERSION: &str = "0.1.0";

#[derive(Debug, Clone, Deserialize)]
struct FileConfig {
    path: PathBuf,
    #[serde(default = "default_seek_to_end")]
    seek_to_end: bool,
    #[serde(default = "default_max_chunk_bytes")]
    max_chunk_bytes: u64,
    #[serde(default = "default_max_lag_bytes")]
    max_lag_bytes: u64,
}

#[derive(Debug, Clone, Deserialize)]
struct CustomConfig {
    path: PathBuf,
    detector: String,
    pattern: String,
    #[serde(default = "default_seek_to_end")]
    seek_to_end: bool,
    #[serde(default = "default_max_chunk_bytes")]
    max_chunk_bytes: u64,
    #[serde(default = "default_max_lag_bytes")]
    max_lag_bytes: u64,
}

fn default_seek_to_end() -> bool { true }

/// Max bytes parsed per read batch. Bounds both memory use and the time the
/// source spends inside a single blocking read while the file keeps growing.
fn default_max_chunk_bytes() -> u64 { 8 * 1024 * 1024 }

/// If the unread backlog exceeds this, skip ahead to the tail of the file.
/// Losing history is preferable to being blind to live traffic (during the
/// 2026-07-11 bot flood the access log outgrew the reader by gigabytes and
/// no event reached the detectors for 17 hours).
fn default_max_lag_bytes() -> u64 { 128 * 1024 * 1024 }

/// How the per-source read limits travel together.
#[derive(Debug, Clone, Copy)]
struct ReadLimits {
    max_chunk_bytes: u64,
    max_lag_bytes: u64,
}

/// Offset-file key + metric suffix unique per watched path, so two instances
/// of the same plugin (e.g. nginx access + error logs) never share state.
fn source_key(kind: &str, path: &Path) -> String {
    let sanitized: String = path
        .to_string_lossy()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_lowercase() } else { '_' })
        .collect();
    format!("{kind}_{sanitized}")
}

#[derive(Debug)]
enum SourceConfig {
    Ssh(FileConfig),
    Nginx(FileConfig),
    Postfix(FileConfig),
    Custom(CustomConfig),
}

pub struct FileSourcePlugin {
    manifest: PluginManifest,
    data_dir: PathBuf,
    metrics: PluginMetrics,
    config: Option<SourceConfig>,
}

impl FileSourcePlugin {
    fn manifest_for(id: &'static str, description: &'static str) -> PluginManifest {
        PluginManifest {
            id,
            version: PLUGIN_VERSION,
            description,
            kind: PluginKind::LogSource,
            author: "HiveGuard",
            docs_url: Some("https://github.com/anthropics/hiveguard/blob/main/plugins/source-file/README.md"),
        }
    }

    fn create_with_manifest(
        ctx: PluginContext,
        cfg: serde_json::Value,
        manifest: PluginManifest,
    ) -> BoxFuture<'static, PluginResult<Box<dyn LogSourcePlugin>>> {
        Box::pin(async move {
            let mut plugin = FileSourcePlugin {
                manifest,
                data_dir: ctx.data_dir,
                metrics: ctx.metrics,
                config: None,
            };
            <FileSourcePlugin as Plugin>::init(&mut plugin, cfg).await?;
            info!(plugin = plugin.manifest.id, "initialised");
            Ok(Box::new(plugin) as Box<dyn LogSourcePlugin>)
        })
    }

    pub fn create_ssh(
        ctx: PluginContext,
        cfg: serde_json::Value,
    ) -> BoxFuture<'static, PluginResult<Box<dyn LogSourcePlugin>>> {
        Self::create_with_manifest(
            ctx,
            cfg,
            Self::manifest_for(SSH_PLUGIN_ID, "File-backed SSH auth.log source."),
        )
    }

    pub fn create_nginx(
        ctx: PluginContext,
        cfg: serde_json::Value,
    ) -> BoxFuture<'static, PluginResult<Box<dyn LogSourcePlugin>>> {
        Self::create_with_manifest(
            ctx,
            cfg,
            Self::manifest_for(NGINX_PLUGIN_ID, "File-backed Nginx access log source."),
        )
    }

    pub fn create_postfix(
        ctx: PluginContext,
        cfg: serde_json::Value,
    ) -> BoxFuture<'static, PluginResult<Box<dyn LogSourcePlugin>>> {
        Self::create_with_manifest(
            ctx,
            cfg,
            Self::manifest_for(POSTFIX_PLUGIN_ID, "File-backed Postfix mail log source."),
        )
    }

    pub fn create_custom(
        ctx: PluginContext,
        cfg: serde_json::Value,
    ) -> BoxFuture<'static, PluginResult<Box<dyn LogSourcePlugin>>> {
        Self::create_with_manifest(
            ctx,
            cfg,
            Self::manifest_for(CUSTOM_PLUGIN_ID, "File-backed custom regex log source."),
        )
    }

    fn parse_config(plugin_id: &str, cfg: serde_json::Value) -> PluginResult<SourceConfig> {
        match plugin_id {
            SSH_PLUGIN_ID => serde_json::from_value::<FileConfig>(cfg)
                .map(SourceConfig::Ssh)
                .map_err(|e| PluginError::ConfigValidation(e.to_string())),
            NGINX_PLUGIN_ID => serde_json::from_value::<FileConfig>(cfg)
                .map(SourceConfig::Nginx)
                .map_err(|e| PluginError::ConfigValidation(e.to_string())),
            POSTFIX_PLUGIN_ID => serde_json::from_value::<FileConfig>(cfg)
                .map(SourceConfig::Postfix)
                .map_err(|e| PluginError::ConfigValidation(e.to_string())),
            CUSTOM_PLUGIN_ID => {
                let parsed: CustomConfig = serde_json::from_value(cfg)
                    .map_err(|e| PluginError::ConfigValidation(e.to_string()))?;
                if parsed.pattern.len() > 1024 {
                    return Err(PluginError::ConfigValidation(
                        "custom regex pattern exceeds maximum length of 1024 characters".into(),
                    ));
                }
                let compiled = Regex::new(&parsed.pattern)
                    .map_err(|e| PluginError::ConfigValidation(format!("invalid custom regex pattern: {e}")))?;
                if !compiled.capture_names().any(|name| name == Some("ip")) {
                    return Err(PluginError::ConfigValidation(
                        "custom regex pattern must contain named group 'ip'".into(),
                    ));
                }
                Ok(SourceConfig::Custom(parsed))
            }
            other => Err(PluginError::Runtime(format!("unsupported plugin id: {other}"))),
        }
    }
}

#[async_trait]
impl Plugin for FileSourcePlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    async fn init(&mut self, cfg: serde_json::Value) -> PluginResult<()> {
        self.config = Some(Self::parse_config(self.manifest.id, cfg)?);
        Ok(())
    }

    async fn shutdown(&mut self) -> PluginResult<()> {
        self.config = None;
        Ok(())
    }
}

#[async_trait]
impl LogSourcePlugin for FileSourcePlugin {
    async fn run(&mut self, sink: EventSink, shutdown: CancellationToken) -> PluginResult<()> {
        let config = self
            .config
            .as_ref()
            .ok_or_else(|| PluginError::Runtime("log source used before init".into()))?;

        match config {
            SourceConfig::Ssh(cfg) => run_file_source(
                cfg.path.clone(),
                &source_key("ssh", &cfg.path),
                cfg.seek_to_end,
                ReadLimits { max_chunk_bytes: cfg.max_chunk_bytes, max_lag_bytes: cfg.max_lag_bytes },
                self.data_dir.clone(),
                self.metrics.clone(),
                sink,
                shutdown,
                parse_ssh_normalized,
            )
            .await,
            SourceConfig::Nginx(cfg) => run_file_source(
                cfg.path.clone(),
                &source_key("nginx", &cfg.path),
                cfg.seek_to_end,
                ReadLimits { max_chunk_bytes: cfg.max_chunk_bytes, max_lag_bytes: cfg.max_lag_bytes },
                self.data_dir.clone(),
                self.metrics.clone(),
                sink,
                shutdown,
                parse_nginx_normalized,
            )
            .await,
            SourceConfig::Postfix(cfg) => run_file_source(
                cfg.path.clone(),
                &source_key("postfix", &cfg.path),
                cfg.seek_to_end,
                ReadLimits { max_chunk_bytes: cfg.max_chunk_bytes, max_lag_bytes: cfg.max_lag_bytes },
                self.data_dir.clone(),
                self.metrics.clone(),
                sink,
                shutdown,
                parse_postfix_normalized,
            )
            .await,
            SourceConfig::Custom(cfg) => {
                let pattern = Arc::new(Regex::new(&cfg.pattern)
                    .map_err(|e| PluginError::ConfigValidation(format!("invalid custom regex pattern: {e}")))?);
                let detector = cfg.detector.clone();
                let offset_key = source_key(&format!("custom_{}", detector), &cfg.path);
                run_file_source(
                    cfg.path.clone(),
                    &offset_key,
                    cfg.seek_to_end,
                    ReadLimits { max_chunk_bytes: cfg.max_chunk_bytes, max_lag_bytes: cfg.max_lag_bytes },
                    self.data_dir.clone(),
                    self.metrics.clone(),
                    sink,
                    shutdown,
                    move |line| parse_custom_normalized(line, &pattern, &detector),
                )
                .await
            }
        }
    }
}

/// How often the current offset is persisted while the source is running, so
/// an ungraceful shutdown loses at most this much progress.
const OFFSET_SAVE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);

#[allow(clippy::too_many_arguments)]
async fn run_file_source<F>(
    path: PathBuf,
    offset_key: &str,
    seek_to_end: bool,
    limits: ReadLimits,
    data_dir: PathBuf,
    metrics: PluginMetrics,
    sink: EventSink,
    shutdown: CancellationToken,
    parser: F,
) -> PluginResult<()>
where
    F: Fn(&str) -> Option<NormalizedEvent> + Send + Sync + 'static,
{
    if !tokio::fs::try_exists(&path).await.map_err(PluginError::from)? {
        return Err(PluginError::Runtime(format!(
            "log file not found: {}",
            path.display()
        )));
    }

    let saved_offset = load_offset(&data_dir, offset_key).await?;
    let mut watcher = if saved_offset > 0 {
        info!(source = offset_key, offset = saved_offset, "resuming file source from saved offset");
        FileWatcher::with_offset(path.clone(), saved_offset)
    } else {
        FileWatcher::new(path.clone(), seek_to_end).await.map_err(PluginError::from)?
    };

    let lag_gauge = Gauge::<i64>::default();
    metrics.registry.with_registry(|registry| {
        registry.register(
            format!("source_lag_bytes_{offset_key}"),
            "Unread bytes between the watched file's end and the source's read offset",
            lag_gauge.clone(),
        );
    });

    let (notify_tx, mut notify_rx) = mpsc::channel::<()>(16);
    let notify_tx_clone = notify_tx.clone();
    let mut fs_watcher = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
        if let Ok(event) = res {
            // Modify = new data; Create = log file recreated after rotation.
            if matches!(event.kind, EventKind::Modify(_) | EventKind::Create(_)) {
                let _ = notify_tx_clone.try_send(());
            }
        }
    })
    .map_err(|e| PluginError::Runtime(format!("failed to create file watcher: {e}")))?;

    let watch_path = path.parent().unwrap_or(Path::new("."));
    fs_watcher
        .watch(watch_path, RecursiveMode::NonRecursive)
        .map_err(|e| PluginError::Runtime(format!("failed to watch {}: {e}", watch_path.display())))?;

    let mut last_save = Instant::now();

    // Drain once on startup so `seek_to_end: false` really replays existing content
    // and saved offsets pick up unread lines after restart.
    drain_to_eof(&mut watcher, limits, &sink, &shutdown, &parser, &lag_gauge).await?;

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => {
                save_offset(&data_dir, offset_key, watcher.offset()).await.map_err(PluginError::from)?;
                info!(source = offset_key, path = %path.display(), "file source stopping");
                return Ok(());
            }
            Some(()) = notify_rx.recv() => {
                while notify_rx.try_recv().is_ok() {}
                drain_to_eof(&mut watcher, limits, &sink, &shutdown, &parser, &lag_gauge).await?;
                if last_save.elapsed() >= OFFSET_SAVE_INTERVAL {
                    save_offset(&data_dir, offset_key, watcher.offset()).await.map_err(PluginError::from)?;
                    last_save = Instant::now();
                }
            }
        }
    }
}

/// Read and emit in bounded chunks until the reader has caught up with the
/// end of the file (or shutdown is requested). Keeping each chunk small means
/// steady event flow to the detectors even while the file is being flooded.
async fn drain_to_eof<F>(
    watcher: &mut FileWatcher,
    limits: ReadLimits,
    sink: &EventSink,
    shutdown: &CancellationToken,
    parser: &F,
    lag_gauge: &Gauge<i64>,
) -> PluginResult<()>
where
    F: Fn(&str) -> Option<NormalizedEvent> + Send + Sync + 'static,
{
    loop {
        let outcome = watcher.read_new_lines(limits).await.map_err(PluginError::from)?;
        lag_gauge.set(outcome.file_len.saturating_sub(outcome.offset) as i64);

        for line in &outcome.lines {
            if let Some(event) = parser(line) {
                sink.send(event)
                    .await
                    .map_err(|_| PluginError::Runtime("event sink closed".into()))?;
            }
        }

        if !outcome.more || shutdown.is_cancelled() {
            return Ok(());
        }
    }
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
            tokio::task::spawn_blocking(move || std::fs::metadata(path_for_metadata).map(|metadata| metadata.len()))
                .await
                .map_err(|error| std::io::Error::other(format!("blocking metadata task failed: {error}")))??
        } else {
            0
        };
        Ok(Self { path, offset })
    }

    fn with_offset(path: impl Into<PathBuf>, offset: u64) -> Self {
        Self { path: path.into(), offset }
    }

    async fn read_new_lines(&mut self, limits: ReadLimits) -> std::io::Result<ReadOutcome> {
        let path = self.path.clone();
        let offset = self.offset;
        let read_result =
            tokio::task::spawn_blocking(move || read_new_lines_blocking(path, offset, limits))
                .await
                .map_err(|error| std::io::Error::other(format!("blocking read task failed: {error}")))?;

        let read_outcome = read_result?;
        if read_outcome.rotated {
            info!(
                path = %self.path.display(),
                old_offset = offset,
                new_len = read_outcome.file_len,
                "file truncated, resetting offset"
            );
        }
        if read_outcome.skipped_bytes > 0 {
            warn!(
                path = %self.path.display(),
                skipped_bytes = read_outcome.skipped_bytes,
                max_lag_bytes = limits.max_lag_bytes,
                "file source lag exceeded limit — skipping ahead to file tail (backlog dropped)"
            );
        }

        self.offset = read_outcome.offset;
        debug!(path = %self.path.display(), lines = read_outcome.lines.len(), offset = self.offset, "read new log lines");
        Ok(read_outcome)
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
    /// Backlog bytes dropped because the lag limit was exceeded.
    skipped_bytes: u64,
    /// True when unread data remains past this chunk (caller should read again).
    more: bool,
}

fn read_new_lines_blocking(path: PathBuf, offset: u64, limits: ReadLimits) -> std::io::Result<ReadOutcome> {
    // During log rotation (mv + create) the file briefly doesn't exist. That
    // must not kill the source — report "nothing to read" and let the next
    // notification (or the recreated file's first write) resume tailing.
    let mut file = match std::fs::File::open(&path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(ReadOutcome {
                lines: Vec::new(),
                offset,
                file_len: offset,
                rotated: false,
                skipped_bytes: 0,
                more: false,
            });
        }
        Err(e) => return Err(e),
    };
    let file_len = file.metadata()?.len();
    let rotated = file_len < offset;
    let mut start_offset = if rotated { 0 } else { offset };

    // Backlog cap: when the file has outgrown the reader beyond the limit,
    // jump close to the tail instead of chewing through gigabytes of history.
    let mut skipped_bytes = 0_u64;
    let backlog = file_len.saturating_sub(start_offset);
    if limits.max_lag_bytes > 0 && backlog > limits.max_lag_bytes {
        let new_start = file_len.saturating_sub(limits.max_chunk_bytes.max(1));
        skipped_bytes = new_start - start_offset;
        start_offset = new_start;
    }

    if file_len == start_offset {
        return Ok(ReadOutcome {
            lines: Vec::new(),
            offset: start_offset,
            file_len,
            rotated,
            skipped_bytes,
            more: false,
        });
    }

    file.seek(SeekFrom::Start(start_offset))?;
    let mut reader = BufReader::new(&file);
    let mut lines = Vec::new();
    let mut bytes_read = 0_u64;
    let mut buf: Vec<u8> = Vec::new();

    // After a skip-ahead we usually land mid-line; drop the partial first line
    // so the parser only ever sees whole records.
    if skipped_bytes > 0 {
        buf.clear();
        let n = reader.read_until(b'\n', &mut buf)?;
        if n == 0 || buf.last() != Some(&b'\n') {
            // No complete line yet — retry from the same spot next round.
            return Ok(ReadOutcome {
                lines,
                offset: start_offset,
                file_len,
                rotated,
                skipped_bytes,
                more: false,
            });
        }
        bytes_read += n as u64;
    }

    let mut stopped_at_line_boundary = false;
    while bytes_read < limits.max_chunk_bytes {
        buf.clear();
        let n = match reader.read_until(b'\n', &mut buf) {
            Ok(n) => n,
            Err(error) => {
                warn!(error = %error, "error reading line from watched file");
                stopped_at_line_boundary = true;
                break;
            }
        };
        if n == 0 {
            stopped_at_line_boundary = true;
            break; // clean EOF
        }
        if buf.last() != Some(&b'\n') {
            // Partial line still being written — don't advance past it; it
            // will be re-read complete on the next notification.
            stopped_at_line_boundary = true;
            break;
        }
        bytes_read += n as u64;
        let mut end = buf.len() - 1; // strip '\n'
        if end > 0 && buf[end - 1] == b'\r' {
            end -= 1;
        }
        lines.push(String::from_utf8_lossy(&buf[..end]).into_owned());
    }

    let new_offset = start_offset + bytes_read;
    Ok(ReadOutcome {
        lines,
        offset: new_offset,
        file_len,
        rotated,
        skipped_bytes,
        // Only signal "read again immediately" when we stopped because of the
        // chunk limit — a partial trailing line or EOF means wait for notify.
        more: !stopped_at_line_boundary && new_offset < file_len,
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
    .map_err(|error| std::io::Error::other(format!("blocking save task failed: {error}")))?
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
    .map_err(|error| PluginError::Runtime(format!("blocking load task failed: {error}")))?
    .map_err(PluginError::from)
}

#[derive(Debug, Clone)]
struct SshEvent {
    timestamp_str: String,
    event_type: EventType,
    source_ip: IpAddr,
    user: String,
    invalid_user: bool,
    raw_line: String,
}

struct SshPatterns {
    failed_password: Regex,
    failed_password_invalid: Regex,
    invalid_user: Regex,
    accepted_password: Regex,
    accepted_publickey: Regex,
    syslog_timestamp: Regex,
}

impl SshPatterns {
    fn new() -> Self {
        Self {
            failed_password: Regex::new(r"Failed password for ([^\s]+) from ([0-9a-fA-F.:]+) port \d+").unwrap(),
            failed_password_invalid: Regex::new(r"Failed password for invalid user ([^\s]+) from ([0-9a-fA-F.:]+)").unwrap(),
            invalid_user: Regex::new(r"Invalid user ([^\s]+) from ([0-9a-fA-F.:]+)").unwrap(),
            accepted_password: Regex::new(r"Accepted password for ([^\s]+) from ([0-9a-fA-F.:]+)").unwrap(),
            accepted_publickey: Regex::new(r"Accepted publickey for ([^\s]+) from ([0-9a-fA-F.:]+)").unwrap(),
            syslog_timestamp: Regex::new(r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+").unwrap(),
        }
    }
}

fn parse_syslog_timestamp(ts: &str) -> Option<DateTime<Utc>> {
    let current_year = Utc::now().format("%Y").to_string();
    let with_year = format!("{current_year} {ts}");
    NaiveDateTime::parse_from_str(&with_year, "%Y %b %e %H:%M:%S")
        .ok()
        .map(|naive| naive.and_utc())
}

fn parse_ssh_line(line: &str, patterns: &SshPatterns) -> Option<SshEvent> {
    let timestamp_str = patterns
        .syslog_timestamp
        .captures(line)
        .map(|captures| captures[1].to_string())
        .unwrap_or_default();

    if let Some(captures) = patterns.failed_password_invalid.captures(line) {
        let user = captures[1].to_string();
        let source_ip = captures[2].parse().ok()?;
        return Some(SshEvent {
            timestamp_str,
            event_type: EventType::AuthFailure,
            source_ip,
            user,
            invalid_user: true,
            raw_line: line.to_string(),
        });
    }
    if let Some(captures) = patterns.failed_password.captures(line) {
        let user = captures[1].to_string();
        let source_ip = captures[2].parse().ok()?;
        return Some(SshEvent {
            timestamp_str,
            event_type: EventType::AuthFailure,
            source_ip,
            user,
            invalid_user: false,
            raw_line: line.to_string(),
        });
    }
    if let Some(captures) = patterns.invalid_user.captures(line) {
        let user = captures[1].to_string();
        let source_ip = captures[2].parse().ok()?;
        return Some(SshEvent {
            timestamp_str,
            event_type: EventType::AuthFailure,
            source_ip,
            user,
            invalid_user: true,
            raw_line: line.to_string(),
        });
    }
    if let Some(captures) = patterns.accepted_password.captures(line) {
        let user = captures[1].to_string();
        let source_ip = captures[2].parse().ok()?;
        return Some(SshEvent {
            timestamp_str,
            event_type: EventType::AuthSuccess,
            source_ip,
            user,
            invalid_user: false,
            raw_line: line.to_string(),
        });
    }
    if let Some(captures) = patterns.accepted_publickey.captures(line) {
        let user = captures[1].to_string();
        let source_ip = captures[2].parse().ok()?;
        return Some(SshEvent {
            timestamp_str,
            event_type: EventType::AuthSuccess,
            source_ip,
            user,
            invalid_user: false,
            raw_line: line.to_string(),
        });
    }

    trace!(line = line, "ssh line did not match any known pattern");
    None
}

fn ssh_patterns() -> &'static SshPatterns {
    static PATTERNS: OnceLock<SshPatterns> = OnceLock::new();
    PATTERNS.get_or_init(SshPatterns::new)
}

fn parse_ssh_normalized(line: &str) -> Option<NormalizedEvent> {
    let event = parse_ssh_line(line, ssh_patterns())?;
    let mut metadata = HashMap::new();
    metadata.insert("user".to_string(), event.user);
    if event.invalid_user {
        metadata.insert("invalid_user".to_string(), "true".to_string());
    }

    Some(NormalizedEvent {
        timestamp: parse_syslog_timestamp(&event.timestamp_str).unwrap_or_else(Utc::now),
        source_ip: event.source_ip,
        event_type: event.event_type,
        source_name: "ssh".to_string(),
        raw_line: event.raw_line,
        metadata,
    })
}

#[derive(Debug, Clone)]
struct NginxEvent {
    source_ip: IpAddr,
    timestamp: DateTime<Utc>,
    method: String,
    path: String,
    status_code: u16,
    user_agent: String,
    raw_line: String,
}

struct NginxPattern {
    combined: Regex,
}

impl NginxPattern {
    fn new() -> Self {
        Self {
            combined: Regex::new(r#"^([0-9a-fA-F.:]+) - [^\s]+ \[([^\]]+)\] "([^"]*)" (\d{3}) (\d+) "[^"]*" "([^"]*)""#).unwrap(),
        }
    }
}

fn parse_nginx_timestamp(ts: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_str(ts, "%d/%b/%Y:%H:%M:%S %z")
        .ok()
        .map(|dt: DateTime<FixedOffset>| dt.with_timezone(&Utc))
}

fn parse_request_line(request: &str) -> Option<(String, String)> {
    let parts: Vec<&str> = request.splitn(3, ' ').collect();
    if parts.len() < 2 {
        return None;
    }
    Some((parts[0].to_string(), parts[1].to_string()))
}

fn parse_nginx_line(line: &str, pattern: &NginxPattern) -> Option<NginxEvent> {
    let captures = pattern.combined.captures(line)?;
    let source_ip = captures[1].parse().ok()?;
    let timestamp = parse_nginx_timestamp(&captures[2]).unwrap_or_else(Utc::now);
    let (method, path) = parse_request_line(&captures[3])?;
    let status_code = captures[4].parse().ok()?;
    let user_agent = captures[6].to_string();

    Some(NginxEvent {
        source_ip,
        timestamp,
        method,
        path,
        status_code,
        user_agent,
        raw_line: line.to_string(),
    })
}

fn nginx_pattern() -> &'static NginxPattern {
    static PATTERN: OnceLock<NginxPattern> = OnceLock::new();
    PATTERN.get_or_init(NginxPattern::new)
}

fn parse_nginx_normalized(line: &str) -> Option<NormalizedEvent> {
    let event = parse_nginx_line(line, nginx_pattern())?;
    let event_type = match event.status_code {
        400..=499 => EventType::Http4xx,
        500..=599 => EventType::Http5xx,
        _ => EventType::HttpRequest,
    };

    let mut metadata = HashMap::new();
    metadata.insert("path".to_string(), event.path);
    metadata.insert("method".to_string(), event.method);
    metadata.insert("user_agent".to_string(), event.user_agent);
    metadata.insert("status_code".to_string(), event.status_code.to_string());

    Some(NormalizedEvent {
        timestamp: event.timestamp,
        source_ip: event.source_ip,
        event_type,
        source_name: "nginx".to_string(),
        raw_line: event.raw_line,
        metadata,
    })
}

#[derive(Debug, Clone)]
struct PostfixEvent {
    timestamp_str: String,
    source_ip: IpAddr,
    mechanism: String,
    raw_line: String,
}

struct PostfixPatterns {
    sasl_warning: Regex,
    sasl_login_failed: Regex,
    syslog_timestamp: Regex,
}

impl PostfixPatterns {
    fn new() -> Self {
        Self {
            sasl_warning: Regex::new(r"warning:\s+\S+\[(?P<ip>[^\]]+)\]:\s+SASL\s+(?P<mech>\S+)\s+authentication\s+failed").unwrap(),
            sasl_login_failed: Regex::new(r"SASL\s+LOGIN\s+authentication\s+failed.*client=\S+\[(?P<ip>[^\]]+)\]").unwrap(),
            syslog_timestamp: Regex::new(r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+").unwrap(),
        }
    }
}

fn parse_postfix_line(line: &str, patterns: &PostfixPatterns) -> Option<PostfixEvent> {
    let timestamp_str = patterns
        .syslog_timestamp
        .captures(line)
        .and_then(|captures| captures.name("ts"))
        .map(|ts| ts.as_str().to_string())
        .unwrap_or_default();

    if let Some(captures) = patterns.sasl_warning.captures(line) {
        return Some(PostfixEvent {
            timestamp_str,
            source_ip: captures.name("ip")?.as_str().parse().ok()?,
            mechanism: captures.name("mech").map(|mech| mech.as_str().to_string()).unwrap_or_default(),
            raw_line: line.to_string(),
        });
    }
    if let Some(captures) = patterns.sasl_login_failed.captures(line) {
        return Some(PostfixEvent {
            timestamp_str,
            source_ip: captures.name("ip")?.as_str().parse().ok()?,
            mechanism: "LOGIN".to_string(),
            raw_line: line.to_string(),
        });
    }

    trace!(line = line, "postfix line did not match any known pattern");
    None
}

fn postfix_patterns() -> &'static PostfixPatterns {
    static PATTERNS: OnceLock<PostfixPatterns> = OnceLock::new();
    PATTERNS.get_or_init(PostfixPatterns::new)
}

fn parse_postfix_normalized(line: &str) -> Option<NormalizedEvent> {
    let event = parse_postfix_line(line, postfix_patterns())?;
    let mut metadata = HashMap::new();
    metadata.insert("mechanism".to_string(), event.mechanism);

    Some(NormalizedEvent {
        timestamp: parse_syslog_timestamp(&event.timestamp_str).unwrap_or_else(Utc::now),
        source_ip: event.source_ip,
        event_type: EventType::SmtpAuthFailure,
        source_name: "postfix".to_string(),
        raw_line: event.raw_line,
        metadata,
    })
}

fn parse_custom_normalized(line: &str, pattern: &Regex, detector_name: &str) -> Option<NormalizedEvent> {
    let captures = pattern.captures(line)?;
    let source_ip: IpAddr = captures.name("ip")?.as_str().parse().ok()?;

    let mut metadata = HashMap::new();
    if let Some(user) = captures.name("user") {
        metadata.insert("user".to_string(), user.as_str().to_string());
    }
    if let Some(path) = captures.name("path") {
        metadata.insert("path".to_string(), path.as_str().to_string());
    }
    if let Some(status) = captures.name("status") {
        metadata.insert("status".to_string(), status.as_str().to_string());
    }

    Some(NormalizedEvent {
        timestamp: Utc::now(),
        source_ip,
        event_type: EventType::Custom(detector_name.to_string()),
        source_name: format!("custom_{detector_name}"),
        raw_line: line.to_string(),
        metadata,
    })
}

inventory::submit! {
    PluginDescriptor {
        id: SSH_PLUGIN_ID,
        kind: PluginKind::LogSource,
        api_version: API_VERSION,
        manifest: || FileSourcePlugin::manifest_for(SSH_PLUGIN_ID, "File-backed SSH auth.log source."),
        config_schema: include_str!("../schema-ssh.json"),
        factory: PluginFactory::LogSource(FileSourcePlugin::create_ssh),
    }
}

inventory::submit! {
    PluginDescriptor {
        id: NGINX_PLUGIN_ID,
        kind: PluginKind::LogSource,
        api_version: API_VERSION,
        manifest: || FileSourcePlugin::manifest_for(NGINX_PLUGIN_ID, "File-backed Nginx access log source."),
        config_schema: include_str!("../schema-nginx.json"),
        factory: PluginFactory::LogSource(FileSourcePlugin::create_nginx),
    }
}

inventory::submit! {
    PluginDescriptor {
        id: POSTFIX_PLUGIN_ID,
        kind: PluginKind::LogSource,
        api_version: API_VERSION,
        manifest: || FileSourcePlugin::manifest_for(POSTFIX_PLUGIN_ID, "File-backed Postfix mail log source."),
        config_schema: include_str!("../schema-postfix.json"),
        factory: PluginFactory::LogSource(FileSourcePlugin::create_postfix),
    }
}

inventory::submit! {
    PluginDescriptor {
        id: CUSTOM_PLUGIN_ID,
        kind: PluginKind::LogSource,
        api_version: API_VERSION,
        manifest: || FileSourcePlugin::manifest_for(CUSTOM_PLUGIN_ID, "File-backed custom regex log source."),
        config_schema: include_str!("../schema-custom.json"),
        factory: PluginFactory::LogSource(FileSourcePlugin::create_custom),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    use hiveguard_plugin_api::context::parking_lot_compat::RegistryHandle;
    use hiveguard_plugin_api::secrets::SecretResolver;

    fn test_context(plugin_id: &str, data_dir: PathBuf) -> PluginContext {
        PluginContext::new(
            plugin_id.to_string(),
            data_dir,
            Arc::new(SecretResolver::new()),
            PluginMetrics {
                registry: Arc::new(RegistryHandle::default()),
                plugin_id: plugin_id.to_string(),
            },
            CancellationToken::new(),
        )
    }

    #[tokio::test]
    async fn init_accepts_ssh_config() {
        let tempdir = tempfile::tempdir().unwrap();
        let log_path = tempdir.path().join("auth.log");
        std::fs::write(&log_path, "").unwrap();

        let plugin = FileSourcePlugin::create_ssh(
            test_context(SSH_PLUGIN_ID, tempdir.path().join("state")),
            serde_json::json!({ "path": log_path, "seek_to_end": false }),
        )
        .await
        .unwrap();

        assert_eq!(plugin.manifest().id, SSH_PLUGIN_ID);
    }

    #[tokio::test]
    async fn run_emits_ssh_event_for_appended_line() {
        let tempdir = tempfile::tempdir().unwrap();
        let log_path = tempdir.path().join("auth.log");
        std::fs::write(&log_path, "").unwrap();

        let mut plugin = FileSourcePlugin {
            manifest: FileSourcePlugin::manifest_for(SSH_PLUGIN_ID, "File-backed SSH auth.log source."),
            data_dir: tempdir.path().join("state"),
            metrics: PluginMetrics {
                registry: Arc::new(RegistryHandle::default()),
                plugin_id: SSH_PLUGIN_ID.to_string(),
            },
            config: Some(SourceConfig::Ssh(FileConfig {
                path: log_path.clone(),
                seek_to_end: false,
                max_chunk_bytes: default_max_chunk_bytes(),
                max_lag_bytes: default_max_lag_bytes(),
            })),
        };

        let (tx, mut rx) = mpsc::channel(4);
        let shutdown = CancellationToken::new();
        let shutdown_task = shutdown.clone();

        let handle = tokio::spawn(async move { plugin.run(tx, shutdown_task).await });

        let mut file = std::fs::OpenOptions::new().append(true).open(&log_path).unwrap();
        writeln!(
            file,
            "Apr  8 14:30:22 host sshd[123]: Failed password for invalid user admin from 203.0.113.10 port 34567 ssh2"
        )
        .unwrap();
        file.flush().unwrap();

        let event = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(event.source_name, "ssh");
        assert_eq!(event.source_ip, "203.0.113.10".parse::<IpAddr>().unwrap());
        assert_eq!(event.event_type, EventType::AuthFailure);
        assert_eq!(event.metadata.get("user").unwrap(), "admin");

        shutdown.cancel();
        handle.await.unwrap().unwrap();
    }

    #[test]
    fn custom_config_requires_ip_capture() {
        let err = FileSourcePlugin::parse_config(
            CUSTOM_PLUGIN_ID,
            serde_json::json!({
                "path": "/tmp/app.log",
                "detector": "app_abuse",
                "pattern": "user=(?P<user>\\S+)"
            }),
        )
        .unwrap_err();

        assert!(matches!(err, PluginError::ConfigValidation(_)));
    }

    #[test]
    fn chunked_read_respects_limit_and_reports_more() {
        let tempdir = tempfile::tempdir().unwrap();
        let log_path = tempdir.path().join("big.log");
        let mut content = String::new();
        for i in 0..1000 {
            content.push_str(&format!("line number {i}\n"));
        }
        std::fs::write(&log_path, &content).unwrap();

        let limits = ReadLimits { max_chunk_bytes: 1024, max_lag_bytes: 0 };
        let first = read_new_lines_blocking(log_path.clone(), 0, limits).unwrap();
        assert!(first.more, "large file should require another read");
        assert!(!first.lines.is_empty());
        assert!(first.offset < content.len() as u64);

        // Continue until fully drained; total must equal the original file.
        let mut offset = first.offset;
        let mut total = first.lines.len();
        loop {
            let out = read_new_lines_blocking(log_path.clone(), offset, limits).unwrap();
            total += out.lines.len();
            offset = out.offset;
            if !out.more {
                break;
            }
        }
        assert_eq!(total, 1000);
        assert_eq!(offset, content.len() as u64);
    }

    #[test]
    fn lag_cap_skips_to_tail_on_whole_lines() {
        let tempdir = tempfile::tempdir().unwrap();
        let log_path = tempdir.path().join("lagged.log");
        let mut content = String::new();
        for i in 0..2000 {
            content.push_str(&format!("old backlog line {i}\n"));
        }
        content.push_str("freshest line\n");
        std::fs::write(&log_path, &content).unwrap();

        let limits = ReadLimits { max_chunk_bytes: 512, max_lag_bytes: 4096 };
        let out = read_new_lines_blocking(log_path.clone(), 0, limits).unwrap();
        assert!(out.skipped_bytes > 0, "backlog beyond limit must be skipped");
        // Partial first line after the jump is dropped; remaining are intact.
        assert!(out.lines.iter().all(|l| l.starts_with("old backlog line") || l == "freshest line"));
        assert_eq!(out.lines.last().unwrap(), "freshest line");
    }

    #[test]
    fn partial_trailing_line_is_not_consumed() {
        let tempdir = tempfile::tempdir().unwrap();
        let log_path = tempdir.path().join("partial.log");
        std::fs::write(&log_path, "complete line\nincomplete without newline").unwrap();

        let limits = ReadLimits { max_chunk_bytes: 1 << 20, max_lag_bytes: 0 };
        let out = read_new_lines_blocking(log_path.clone(), 0, limits).unwrap();
        assert_eq!(out.lines, vec!["complete line".to_string()]);
        assert_eq!(out.offset, "complete line\n".len() as u64);
        assert!(!out.more, "waiting for the rest of a partial line must not busy-loop");

        // Once the newline arrives the line is picked up from the same offset.
        std::fs::OpenOptions::new()
            .append(true)
            .open(&log_path)
            .unwrap();
        std::fs::write(&log_path, "complete line\nincomplete without newline\n").unwrap();
        let out2 = read_new_lines_blocking(log_path, out.offset, limits).unwrap();
        assert_eq!(out2.lines, vec!["incomplete without newline".to_string()]);
    }

    #[test]
    fn missing_file_returns_empty_instead_of_error() {
        let limits = ReadLimits { max_chunk_bytes: 1 << 20, max_lag_bytes: 0 };
        let out = read_new_lines_blocking(PathBuf::from("/nonexistent/rotating.log"), 42, limits).unwrap();
        assert!(out.lines.is_empty());
        assert_eq!(out.offset, 42, "offset must survive the rotation gap");
        assert!(!out.more);
    }

    #[test]
    fn rotation_sequence_resumes_on_recreated_file() {
        let tempdir = tempfile::tempdir().unwrap();
        let log_path = tempdir.path().join("rotating.log");
        let limits = ReadLimits { max_chunk_bytes: 1 << 20, max_lag_bytes: 0 };

        std::fs::write(&log_path, "before rotation\n").unwrap();
        let out = read_new_lines_blocking(log_path.clone(), 0, limits).unwrap();
        assert_eq!(out.lines, vec!["before rotation".to_string()]);

        // logrotate: mv + brief gap
        let rotated_path = tempdir.path().join("rotating.log.1");
        std::fs::rename(&log_path, &rotated_path).unwrap();
        let gap = read_new_lines_blocking(log_path.clone(), out.offset, limits).unwrap();
        assert!(gap.lines.is_empty());
        assert_eq!(gap.offset, out.offset);

        // new file created — smaller than the old offset → offset resets
        std::fs::write(&log_path, "after rotation\n").unwrap();
        let resumed = read_new_lines_blocking(log_path, gap.offset, limits).unwrap();
        assert!(resumed.rotated);
        assert_eq!(resumed.lines, vec!["after rotation".to_string()]);
    }

    #[test]
    fn source_keys_are_unique_per_path() {
        let a = source_key("nginx", Path::new("/var/log/nginx/access.log"));
        let b = source_key("nginx", Path::new("/var/log/nginx/error.log"));
        assert_ne!(a, b);
        assert!(a.starts_with("nginx_"));
    }

    #[test]
    fn parses_nginx_line_to_http4xx_event() {
        let line = r#"203.0.113.9 - - [08/Apr/2026:14:31:11 +0000] "GET /wp-login.php HTTP/1.1" 404 153 "-" "scanner""#;
        let event = parse_nginx_normalized(line).unwrap();
        assert_eq!(event.source_name, "nginx");
        assert_eq!(event.event_type, EventType::Http4xx);
        assert_eq!(event.metadata.get("path").unwrap(), "/wp-login.php");
    }
}