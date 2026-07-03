use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tokio::sync::Mutex;
use tracing::{error, info, warn};

use hiveguard_core::api::{ApiRequest, ApiResponse, BanInfo, ExportFormat};
use hiveguard_core::ban_store::BanStore;
use hiveguard_core::config::parse_duration_string;
use hiveguard_core::models::{BanRecord, BanSource};
use hiveguard_core::persistence::StateManager;
use hiveguard_enforce::Enforcer;

/// Hook invoked with a freshly-issued manual ban so it can be replicated to
/// cluster peers (wired to `ClusterHandle::announce_local_ban` in `main.rs`;
/// `None` in non-cluster builds).
pub type BanHook = Arc<dyn Fn(&BanRecord) + Send + Sync>;

/// Unix socket server handling CLI commands.
pub struct SocketServer {
    socket_path: PathBuf,
    state: Arc<Mutex<StateManager>>,
    start_time: Instant,
    enforcer: Option<Arc<Mutex<Box<dyn Enforcer>>>>,
    on_ban: Option<BanHook>,
}

impl SocketServer {
    pub fn new(socket_path: PathBuf, state: Arc<Mutex<StateManager>>) -> Self {
        Self {
            socket_path,
            state,
            start_time: Instant::now(),
            enforcer: None,
            on_ban: None,
        }
    }

    /// Apply manual bans/unbans to the firewall enforcer so they take effect
    /// immediately (previously manual bans only reached nftables at next restart).
    pub fn with_enforcer(mut self, enforcer: Arc<Mutex<Box<dyn Enforcer>>>) -> Self {
        self.enforcer = Some(enforcer);
        self
    }

    /// Replicate manual bans to cluster peers (live propagation).
    pub fn with_ban_hook(mut self, hook: BanHook) -> Self {
        self.on_ban = Some(hook);
        self
    }

    /// Start listening on the Unix socket. Runs until the shutdown signal fires.
    pub async fn run(&self, mut shutdown: tokio::sync::watch::Receiver<bool>) {
        // Ensure parent directory exists
        if let Some(parent) = self.socket_path.parent() {
            if !parent.exists() {
                if let Err(e) = std::fs::create_dir_all(parent) {
                    error!("Failed to create socket directory {:?}: {}", parent, e);
                    return;
                }
            }
        }

        // Remove stale socket file
        if self.socket_path.exists() {
            let _ = std::fs::remove_file(&self.socket_path);
        }

        let listener = match UnixListener::bind(&self.socket_path) {
            Ok(l) => l,
            Err(e) => {
                error!("Failed to bind Unix socket {:?}: {}", self.socket_path, e);
                return;
            }
        };

        // Set restrictive permissions on socket file (F-14: owner + group only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Err(e) = std::fs::set_permissions(
                &self.socket_path,
                std::fs::Permissions::from_mode(0o660),
            ) {
                warn!("Failed to set socket permissions: {}", e);
            }
        }

        info!("Socket server listening on {:?}", self.socket_path);

        loop {
            tokio::select! {
                accept_result = listener.accept() => {
                    match accept_result {
                        Ok((stream, _addr)) => {
                            let state = Arc::clone(&self.state);
                            let start_time = self.start_time;
                            let enforcer = self.enforcer.clone();
                            let on_ban = self.on_ban.clone();
                            tokio::spawn(async move {
                                Self::handle_connection(stream, state, start_time, enforcer, on_ban)
                                    .await;
                            });
                        }
                        Err(e) => {
                            warn!("Failed to accept connection: {}", e);
                        }
                    }
                }
                _ = shutdown.changed() => {
                    info!("Socket server shutting down");
                    break;
                }
            }
        }

        // Cleanup socket file
        let _ = std::fs::remove_file(&self.socket_path);
    }

    async fn handle_connection(
        stream: tokio::net::UnixStream,
        state: Arc<Mutex<StateManager>>,
        start_time: Instant,
        enforcer: Option<Arc<Mutex<Box<dyn Enforcer>>>>,
        on_ban: Option<BanHook>,
    ) {
        let (reader, mut writer) = stream.into_split();
        let mut buf_reader = BufReader::new(reader);
        let mut line = String::new();

        match buf_reader.read_line(&mut line).await {
            Ok(0) => return, // EOF
            Ok(_) => {}
            Err(e) => {
                warn!("Failed to read from socket: {}", e);
                return;
            }
        }

        let request: ApiRequest = match serde_json::from_str(line.trim()) {
            Ok(r) => r,
            Err(e) => {
                let resp = ApiResponse::Error {
                    message: format!("Invalid request: {}", e),
                };
                let _ = Self::send_response(&mut writer, &resp).await;
                return;
            }
        };

        let response =
            Self::process_request(request, &state, start_time, &enforcer, &on_ban).await;
        let _ = Self::send_response(&mut writer, &response).await;
    }

    async fn send_response(
        writer: &mut tokio::net::unix::OwnedWriteHalf,
        response: &ApiResponse,
    ) -> std::io::Result<()> {
        let mut json = match serde_json::to_string(response) {
            Ok(j) => j,
            Err(e) => format!("{{\"error\":\"serialization failed: {}\"}}", e),
        };
        json.push('\n');
        writer.write_all(json.as_bytes()).await?;
        writer.flush().await?;
        Ok(())
    }

    async fn process_request(
        request: ApiRequest,
        state: &Arc<Mutex<StateManager>>,
        start_time: Instant,
        enforcer: &Option<Arc<Mutex<Box<dyn Enforcer>>>>,
        on_ban: &Option<BanHook>,
    ) -> ApiResponse {
        match request {
            ApiRequest::Status => {
                let st = state.lock().await;
                let total_bans = st.ban_store().get_all_bans().len();
                let total_whitelisted = st.whitelist().entries().len();
                ApiResponse::StatusInfo {
                    uptime_secs: start_time.elapsed().as_secs(),
                    total_bans,
                    total_whitelisted,
                    version: env!("CARGO_PKG_VERSION").to_string(),
                }
            }
            ApiRequest::Ban {
                target,
                duration,
                reason,
            } => {
                let net = match parse_target(&target) {
                    Ok(n) => n,
                    Err(e) => {
                        return ApiResponse::Error { message: e };
                    }
                };

                let ban_duration = match duration {
                    Some(ref d) => match parse_duration_string(d) {
                        Ok(hd) => hd.as_duration(),
                        Err(e) => {
                            return ApiResponse::Error {
                                message: format!("Invalid duration: {}", e),
                            };
                        }
                    },
                    None => Some(std::time::Duration::from_secs(86400)), // default 24h
                };

                let expires_at = ban_duration.and_then(|d| {
                    chrono::Duration::from_std(d)
                        .ok()
                        .map(|cd| chrono::Utc::now() + cd)
                });

                let reason_str = reason.unwrap_or_else(|| "manual admin ban".to_string());

                let record = BanRecord {
                    subject: net,
                    created_at: chrono::Utc::now(),
                    expires_at,
                    severity: 200,
                    reason: reason_str,
                    evidence_hash: [0u8; 32],
                    source: BanSource::ManualAdmin,
                    geo_info: None,
                };

                // 1) Persist to state.
                {
                    let mut st = state.lock().await;
                    if let Err(e) = st.add_ban(record.clone()) {
                        return ApiResponse::Error {
                            message: format!("Failed to ban: {}", e),
                        };
                    }
                }
                // 2) Replicate to cluster peers (live propagation), matching the
                //    detector-issued ban path. No-op in non-cluster builds.
                if let Some(hook) = on_ban {
                    hook(&record);
                }
                // 3) Apply to the firewall enforcer so the ban takes effect now
                //    (manual bans previously only reached nftables at next restart).
                if let Some(enf) = enforcer {
                    if let Err(e) = enf.lock().await.apply_ban(&net).await {
                        warn!(subject = %net, "manual ban: enforcer apply failed: {}", e);
                    }
                }
                ApiResponse::Ok {
                    message: format!("Banned {}", net),
                }
            }
            ApiRequest::Unban { target } => {
                let net = match parse_target(&target) {
                    Ok(n) => n,
                    Err(e) => {
                        return ApiResponse::Error { message: e };
                    }
                };

                let removed = {
                    let mut st = state.lock().await;
                    match st.remove_ban(&net) {
                        Ok(b) => b,
                        Err(e) => {
                            return ApiResponse::Error {
                                message: format!("Failed to unban: {}", e),
                            };
                        }
                    }
                };
                // Remove from the enforcer too (manual unban previously left the
                // nftables entry until next restart). Cluster peers are not
                // notified of manual unbans — no tombstone-announce hook exists.
                if removed {
                    if let Some(enf) = enforcer {
                        if let Err(e) = enf.lock().await.remove_ban(&net).await {
                            warn!(subject = %net, "manual unban: enforcer remove failed: {}", e);
                        }
                    }
                }
                if removed {
                    ApiResponse::Ok {
                        message: format!("Unbanned {}", net),
                    }
                } else {
                    ApiResponse::Ok {
                        message: format!("{} was not banned", net),
                    }
                }
            }
            ApiRequest::WhitelistAdd { target } => {
                let net = match parse_target(&target) {
                    Ok(n) => n,
                    Err(e) => {
                        return ApiResponse::Error { message: e };
                    }
                };

                let mut st = state.lock().await;
                match st.add_whitelist(net) {
                    Ok(()) => ApiResponse::Ok {
                        message: format!("Added {} to whitelist", net),
                    },
                    Err(e) => ApiResponse::Error {
                        message: format!("Failed to add whitelist: {}", e),
                    },
                }
            }
            ApiRequest::WhitelistRemove { target } => {
                let net = match parse_target(&target) {
                    Ok(n) => n,
                    Err(e) => {
                        return ApiResponse::Error { message: e };
                    }
                };

                let mut st = state.lock().await;
                match st.remove_whitelist(&net) {
                    Ok(()) => ApiResponse::Ok {
                        message: format!("Removed {} from whitelist", net),
                    },
                    Err(e) => ApiResponse::Error {
                        message: format!("Failed to remove whitelist: {}", e),
                    },
                }
            }
            ApiRequest::ListBans { limit } => {
                let st = state.lock().await;
                let all_bans = st.ban_store().get_all_bans();
                let bans: Vec<BanInfo> = all_bans
                    .iter()
                    .take(limit.unwrap_or(usize::MAX))
                    .map(|b| ban_record_to_info(b))
                    .collect();
                ApiResponse::BanList { bans }
            }
            ApiRequest::ListWhitelist => {
                let st = state.lock().await;
                let entries: Vec<String> =
                    st.whitelist().entries().iter().map(|n| n.to_string()).collect();
                ApiResponse::WhitelistEntries { entries }
            }
            ApiRequest::TopThreats { limit } => {
                // Return top banned IPs sorted by severity
                let st = state.lock().await;
                let mut bans: Vec<&BanRecord> = st.ban_store().get_all_bans();
                bans.sort_by(|a, b| b.severity.cmp(&a.severity));
                let threats: Vec<hiveguard_core::api::ThreatInfo> = bans
                    .iter()
                    .take(limit)
                    .map(|b| hiveguard_core::api::ThreatInfo {
                        ip: b.subject.to_string(),
                        total_severity: b.severity as u32,
                        ban_count: 1,
                        last_seen: b.created_at.to_rfc3339(),
                    })
                    .collect();
                ApiResponse::ThreatList { threats }
            }
            ApiRequest::ExportBans { format } => {
                let st = state.lock().await;
                let all_bans = st.ban_store().get_all_bans();
                let ban_infos: Vec<BanInfo> = all_bans
                    .iter()
                    .map(|b| ban_record_to_info(b))
                    .collect();

                match format {
                    ExportFormat::Json => {
                        let data = serde_json::to_string_pretty(&ban_infos)
                            .unwrap_or_else(|e| format!("{{\"error\": \"{}\"}}", e));
                        ApiResponse::ExportData {
                            data,
                            format: ExportFormat::Json,
                        }
                    }
                    ExportFormat::Csv => {
                        let mut csv = String::new();
                        csv.push_str("subject,created_at,expires_at,severity,reason,source\n");
                        for ban in &ban_infos {
                            let expires = ban.expires_at.as_deref().unwrap_or("permanent");
                            // Escape CSV fields that may contain commas or quotes
                            csv.push_str(&format!(
                                "{},{},{},{},\"{}\",\"{}\"\n",
                                ban.subject,
                                ban.created_at,
                                expires,
                                ban.severity,
                                ban.reason.replace('"', "\"\""),
                                ban.source.replace('"', "\"\""),
                            ));
                        }
                        ApiResponse::ExportData {
                            data: csv,
                            format: ExportFormat::Csv,
                        }
                    }
                }
            }
            ApiRequest::Replay { duration } => {
                // Stub: replay is not yet implemented — requires an event journal
                ApiResponse::Error {
                    message: format!(
                        "Replay not yet implemented. Requested duration: {}. \
                         Future implementation requires persisted event journal.",
                        duration
                    ),
                }
            }
        }
    }
}

/// Parse a target string as an IP or CIDR network.
fn parse_target(target: &str) -> Result<ipnet::IpNet, String> {
    // Try CIDR first
    if let Ok(net) = target.parse::<ipnet::IpNet>() {
        return Ok(net);
    }
    // Try bare IP → /32 or /128
    if let Ok(ip) = target.parse::<std::net::IpAddr>() {
        return Ok(ipnet::IpNet::from(ip));
    }
    Err(format!(
        "Invalid IP or CIDR: '{}'. Use format like 10.0.0.1 or 10.0.0.0/24",
        target
    ))
}

/// Convert a BanRecord to a BanInfo for API serialization.
fn ban_record_to_info(record: &BanRecord) -> BanInfo {
    BanInfo {
        subject: record.subject.to_string(),
        created_at: record.created_at.to_rfc3339(),
        expires_at: record.expires_at.map(|e| e.to_rfc3339()),
        severity: record.severity,
        reason: record.reason.clone(),
        source: format!("{:?}", record.source),
    }
}

/// Get the default socket path.
pub fn default_socket_path() -> PathBuf {
    PathBuf::from("/var/run/hiveguard/hiveguard.sock")
}
