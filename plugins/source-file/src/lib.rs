//! File-backed log source plugins.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use chrono::{DateTime, FixedOffset, NaiveDateTime, Utc};
use notify::{EventKind, RecursiveMode, Watcher};
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
}

#[derive(Debug, Clone, Deserialize)]
struct CustomConfig {
    path: PathBuf,
    detector: String,
    pattern: String,
    #[serde(default = "default_seek_to_end")]
    seek_to_end: bool,
}

fn default_seek_to_end() -> bool { true }

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
                "ssh",
                cfg.seek_to_end,
                self.data_dir.clone(),
                sink,
                shutdown,
                parse_ssh_normalized,
            )
            .await,
            SourceConfig::Nginx(cfg) => run_file_source(
                cfg.path.clone(),
                "nginx",
                cfg.seek_to_end,
                self.data_dir.clone(),
                sink,
                shutdown,
                parse_nginx_normalized,
            )
            .await,
            SourceConfig::Postfix(cfg) => run_file_source(
                cfg.path.clone(),
                "postfix",
                cfg.seek_to_end,
                self.data_dir.clone(),
                sink,
                shutdown,
                parse_postfix_normalized,
            )
            .await,
            SourceConfig::Custom(cfg) => {
                let pattern = Arc::new(Regex::new(&cfg.pattern)
                    .map_err(|e| PluginError::ConfigValidation(format!("invalid custom regex pattern: {e}")))?);
                let detector = cfg.detector.clone();
                let offset_key = format!("custom_{}", detector);
                run_file_source(
                    cfg.path.clone(),
                    &offset_key,
                    cfg.seek_to_end,
                    self.data_dir.clone(),
                    sink,
                    shutdown,
                    move |line| parse_custom_normalized(line, &pattern, &detector),
                )
                .await
            }
        }
    }
}

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

    // Drain once on startup so `seek_to_end: false` really replays existing content
    // and saved offsets pick up unread lines after restart.
    emit_new_lines(&mut watcher, &sink, &parser).await?;

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => {
                save_offset(&data_dir, offset_key, watcher.offset()).await.map_err(PluginError::from)?;
                info!(source = offset_key, path = %path.display(), "file source stopping");
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

    async fn read_new_lines(&mut self) -> std::io::Result<Vec<String>> {
        let path = self.path.clone();
        let offset = self.offset;
        let read_result = tokio::task::spawn_blocking(move || read_new_lines_blocking(path, offset))
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

        self.offset = read_outcome.offset;
        debug!(path = %self.path.display(), lines = read_outcome.lines.len(), offset = self.offset, "read new log lines");
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
                warn!(error = %error, "error reading line from watched file");
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

fn parse_ssh_normalized(line: &str) -> Option<NormalizedEvent> {
    let event = parse_ssh_line(line, &SshPatterns::new())?;
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

fn parse_nginx_normalized(line: &str) -> Option<NormalizedEvent> {
    let event = parse_nginx_line(line, &NginxPattern::new())?;
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

fn parse_postfix_normalized(line: &str) -> Option<NormalizedEvent> {
    let event = parse_postfix_line(line, &PostfixPatterns::new())?;
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
            config: Some(SourceConfig::Ssh(FileConfig {
                path: log_path.clone(),
                seek_to_end: false,
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
    fn parses_nginx_line_to_http4xx_event() {
        let line = r#"203.0.113.9 - - [08/Apr/2026:14:31:11 +0000] "GET /wp-login.php HTTP/1.1" 404 153 "-" "scanner""#;
        let event = parse_nginx_normalized(line).unwrap();
        assert_eq!(event.source_name, "nginx");
        assert_eq!(event.event_type, EventType::Http4xx);
        assert_eq!(event.metadata.get("path").unwrap(), "/wp-login.php");
    }
}