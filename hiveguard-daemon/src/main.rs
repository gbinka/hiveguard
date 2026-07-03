mod cli;
// Cluster gossip runtime — wires `hiveguard-net` into the daemon so bans
// replicate across nodes. Only compiled with the `cluster` feature.
#[cfg(feature = "cluster")]
mod cluster;
// Stage 3 of INT: `mod alert_manager` removed — dispatcher logic moved into
// `hiveguard_host::AlertDispatcher`. Legacy source archived under
// `obsolete/daemon-src/alert_manager.rs`.
mod fail2ban_import;
mod metrics;
mod pipeline;
mod plugin_bridge;
// Force-links first-party plugin crates so their `inventory::submit!`
// registrations survive linking. See the module docs for the why.
mod plugin_links;
mod plugin_supervisor;
mod siem_buffer;
mod siem_exporter;
mod socket_server;
mod ui_api;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use clap::{Parser, Subcommand};
use tokio::sync::{mpsc, Mutex};

use hiveguard_core::api::{ApiRequest, ExportFormat};
use hiveguard_core::ban_store::BanStore;
use hiveguard_core::bot_registry::{BotPolicy, BotRegistry, BotRule};
use hiveguard_core::config::HiveGuardConfig;
use hiveguard_core::detectors::create_detectors as create_detectors_from_config;
use hiveguard_core::persistence::state_manager::StateManager;
use hiveguard_core::persistence::wal::WalSyncMode;

use hiveguard_cti::{AbuseIpDbProvider, CtiEnricher, CtiProvider, GeoIpDb, GeoIpUpdater, SharedGeoIpDb};
use hiveguard_cti::abuseipdb::AbuseIpDbClient;
use hiveguard_cti::spamhaus::SpamhausProvider;
use hiveguard_cti::tor::TorProvider;
use hiveguard_cti::otx::OtxProvider;
use hiveguard_core::config::CtiConfig;
use hiveguard_enforce::{create_enforcer, Enforcer};
// Stage 2 of INT: legacy log-source crates (`hiveguard-ingest`,
// `hiveguard-queue`) are no longer consumed by the daemon. The corresponding
// log sources now come from `plugins/source-file/`, `source-syslog/`,
// `source-journald/`, `source-kafka/`, `source-nats/`, `source-rabbitmq/`,
// `source-kinesis/`, `source-cloudwatch/`.
use hiveguard_sigma::{load_rules_from_dir, spawn_hot_reload_watcher, FieldMapper, SigmaDetector};

use hiveguard_host::{Loader, LoadedPlugins};
use hiveguard_plugin_api::context::parking_lot_compat::RegistryHandle;
use hiveguard_plugin_api::secrets::SecretResolver;
use tokio_util::sync::CancellationToken;

use crate::cli::{print_response, send_request};
use crate::metrics::create_metrics;
use crate::pipeline::{ban_expiry_task, snapshot_task, watchdog_task, Pipeline};
use crate::socket_server::SocketServer;

/// HiveGuard — distributed intrusion detection & auto-ban daemon
#[derive(Parser, Debug)]
#[command(name = "hiveguard", version, about)]
struct Cli {
    /// Path to the YAML configuration file
    #[arg(short, long, global = true)]
    config: Option<PathBuf>,

    /// Path to the Unix socket
    #[arg(short, long, global = true)]
    socket: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Run the daemon (default if no subcommand given)
    Run,

    /// Show daemon status
    Status,

    /// Ban an IP or CIDR
    Ban {
        /// IP address or CIDR to ban
        target: String,
        /// Ban duration (e.g. "24h", "7d", "permanent")
        #[arg(short = 't', long)]
        duration: Option<String>,
        /// Reason for the ban
        #[arg(short, long)]
        reason: Option<String>,
    },

    /// Unban an IP or CIDR
    Unban {
        /// IP address or CIDR to unban
        target: String,
    },

    /// Manage whitelist
    Whitelist {
        #[command(subcommand)]
        action: WhitelistAction,
    },

    /// List active bans
    ListBans {
        /// Maximum number of bans to show
        #[arg(long)]
        limit: Option<usize>,
    },

    /// Show top threats
    Top {
        /// Number of threats to show
        #[arg(long, default_value = "10")]
        threats: usize,
    },

    /// Export bans in JSON or CSV format
    Export {
        /// Output format: json or csv
        #[arg(long, default_value = "json")]
        format: String,
    },

    /// Replay detection from recorded events (stub)
    Replay {
        /// Duration to replay (e.g. "1h", "24h")
        duration: String,
    },

    /// Import active bans and/or configuration from fail2ban
    ImportFail2ban {
        /// Path to fail2ban SQLite database
        #[arg(long, default_value = "/var/lib/fail2ban/fail2ban.sqlite3")]
        db: PathBuf,

        /// Only import bans from this jail (default: all jails)
        #[arg(long)]
        jail: Option<String>,

        /// Print what would be imported without actually sending bans to the daemon
        #[arg(long)]
        dry_run: bool,

        /// Instead of importing bans, print an equivalent HiveGuard config snippet.
        /// Pass one or more jail.conf / jail.local / jail.d/*.conf paths.
        #[arg(long, num_args = 0..)]
        config_from: Vec<PathBuf>,
    },

    /// GeoIP database management
    GeoIp {
        #[command(subcommand)]
        action: GeoIpAction,
    },

    /// Sigma rule management
    Sigma {
        #[command(subcommand)]
        action: SigmaAction,
    },
}

#[derive(Subcommand, Debug)]
enum GeoIpAction {
    /// Download or update GeoLite2-Country and GeoLite2-ASN databases from MaxMind.
    Update {
        /// MaxMind license key (overrides config value).
        #[arg(long)]
        license_key: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
enum SigmaAction {
    /// Import all Sigma rules from a directory
    Import {
        /// Path to directory containing .yml / .yaml Sigma rule files
        path: std::path::PathBuf,
        /// Only validate rules, do not import
        #[arg(long)]
        dry_run: bool,
    },
    /// Test a single Sigma rule against a JSON-lines log file
    Test {
        /// Path to the Sigma rule file (.yml)
        rule: std::path::PathBuf,
        /// Path to a JSON-lines file with NormalizedEvent objects
        sample: std::path::PathBuf,
    },
    /// List all loaded Sigma rules (queries the running daemon)
    List,
    /// Show statistics for loaded rules (queries the running daemon)
    Stats,
}

#[derive(Subcommand, Debug)]
enum WhitelistAction {
    /// Add an IP or CIDR to whitelist
    Add {
        /// IP address or CIDR to whitelist
        target: String,
    },
    /// Remove an IP or CIDR from whitelist
    Remove {
        /// IP address or CIDR to remove
        target: String,
    },
    /// List all whitelisted entries
    List,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    let socket_path = cli
        .socket
        .clone()
        .unwrap_or_else(socket_server::default_socket_path);

    match cli.command {
        None | Some(Command::Run) => {
            run_daemon(cli.config, socket_path).await;
        }
        Some(cmd) => {
            run_cli_command(cmd, &socket_path, cli.config).await;
        }
    }
}

async fn run_daemon(config_path: Option<PathBuf>, socket_path: PathBuf) {
    let config_path = match config_path {
        Some(p) => p,
        None => {
            eprintln!("Error: --config is required when running the daemon");
            std::process::exit(1);
        }
    };

    tracing::info!("Loading configuration from {:?}", config_path);

    let config = match HiveGuardConfig::load(&config_path) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Failed to load config: {e}");
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
    };

    tracing::info!(node_name = %config.node.name, "Config loaded successfully");

    // --- Step 1: Load snapshot + replay WAL (StateManager recovery) ---
    let sync_mode = config.persistence.wal_sync_mode.parse::<WalSyncMode>().unwrap_or(WalSyncMode::Fdatasync);
    let state = match StateManager::new(&config.node.data_dir, sync_mode) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("Failed to initialize state: {e}");
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
    };

    let state = Arc::new(Mutex::new(state));
    tracing::info!("State recovered from snapshot + WAL");

    // --- Step 1b: Plugin loading (INT phase) ---
    //
    // Resolves the `plugins:` section in config against the static `inventory`
    // registry, validates each plugin's JSON Schema, and instantiates them via
    // their factory. The resulting `LoadedPlugins` is then merged into the
    // legacy code paths below (detectors/enforcer/log_sources extend with
    // plugin instances via the adapter layer in `plugin_bridge`).
    let plugin_shutdown_token = CancellationToken::new();
    let loader = Loader::new(
        Arc::new(SecretResolver::new()),
        config.node.data_dir.clone(),
        Arc::new(RegistryHandle::default()),
        plugin_shutdown_token.clone(),
    );
    let loader_cfg = plugin_bridge::to_loader_config(&config);
    let mut loaded: LoadedPlugins = match loader.load_categorized(&loader_cfg).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!("plugin load failed: {e}");
            eprintln!("Error: plugin load failed: {e}");
            std::process::exit(1);
        }
    };
    tracing::info!(
        sources = loaded.log_sources.len(),
        detectors = loaded.detectors.len(),
        enforcers = loaded.enforcers.len(),
        cti = loaded.cti_providers.len(),
        notifiers = loaded.notifiers.len(),
        scoring = loaded.scoring_engines.len(),
        sinks = loaded.siem_sinks.len(),
        ui = loaded.ui_servers.len(),
        "plugins loaded"
    );

    // Materialise the plugin snapshot now, before any plugins are drained
    // by the wiring stages below. UI clients query this via `list_plugins()`.
    let plugin_infos = ui_api::plugin_infos_from_loaded(&loaded);

    // --- Step 2: Initialize Enforcer and sync existing bans ---
    //
    // Stage 2 of INT: enforcer is supplied exclusively by the plugin
    // registry. Legacy `config.enforcement.backend = "nftables" | "ipset" |
    // "cloudflare" | "observe_only"` is no longer consulted — declare
    // `id: enforcer.nftables` (or one of the alternatives) under `plugins:`.
    //
    // If multiple enforcers are configured the first one wins; subsequent
    // entries are warned and dropped. Multi-enforcer fan-out is not on the
    // roadmap.
    if loaded.enforcers.len() > 1 {
        tracing::warn!(
            count = loaded.enforcers.len(),
            "multiple enforcer plugins configured — using the first, dropping the rest"
        );
    }
    let mut enforcer: Box<dyn Enforcer> = match loaded.enforcers.into_iter().next() {
        Some(plugin) => {
            tracing::info!(plugin = plugin.manifest().id, "using plugin enforcer");
            Box::new(plugin_bridge::EnforcerPluginAdapter(plugin))
        }
        None => {
            tracing::error!(
                "no enforcer plugin configured — daemon cannot apply bans. \
                 Add `id: enforcer.nftables` (or `enforcer.observe`) under \
                 `plugins:` and restart."
            );
            eprintln!(
                "Error: no enforcer plugin configured. \
                 See `scripts/migrate-config.py` or docs/plugins/enforcer.md."
            );
            std::process::exit(1);
        }
    };

    // Set up nftables table/sets/chains (idempotent)
    if let Err(e) = enforcer.setup().await {
        tracing::error!("Failed to set up enforcer: {e}");
        std::process::exit(1);
    }

    {
        let st = state.lock().await;
        let current_bans: Vec<ipnet::IpNet> =
            st.ban_store().get_all_bans().iter().map(|b| b.subject).collect();
        if !current_bans.is_empty() {
            tracing::info!(count = current_bans.len(), "Syncing existing bans to enforcer");
            if let Err(e) = enforcer.sync_full(&current_bans).await {
                tracing::error!("Failed to sync bans to enforcer: {e}");
            }
        }
    }

    let enforcer: Arc<Mutex<Box<dyn Enforcer>>> = Arc::new(Mutex::new(enforcer));

    // --- Step 3: Initialize whitelist from config ---
    {
        let mut st = state.lock().await;
        if let Ok(parsed_wl) = config.parsed_whitelist() {
            for net in parsed_wl {
                if !st.whitelist().is_whitelisted(&net.addr()) {
                    if let Err(e) = st.add_whitelist(net) {
                        tracing::warn!("Failed to add whitelist entry {}: {}", net, e);
                    }
                }
            }
        }
    }

    // --- Step 4: Initialize detectors and scoring ---
    //
    // Stage 2 of INT: detectors come exclusively from the plugin registry.
    // Legacy `config.detectors.*` is no longer consulted — to keep the SSH
    // brute-force detector active, declare `id: detector.ssh_bruteforce` in
    // the `plugins:` list with the equivalent config.
    let mut detectors: Vec<Box<dyn hiveguard_core::Detector>> = Vec::new();
    for plugin in loaded.detectors.drain(..) {
        tracing::info!(plugin = plugin.manifest().id, "adding plugin detector");
        detectors.push(Box::new(plugin_bridge::DetectorPluginAdapter(plugin)));
    }
    if detectors.is_empty() && !config.sigma.enabled {
        tracing::warn!(
            "no detector plugins loaded — daemon will not produce detection \
             signals. Configure detectors in your YAML (`plugins:` list)."
        );
    }

    // Phase 4.2 — SigmaDetector (watcher deferred until shutdown_rx is available)
    let sigma_rules_handle;
    let sigma_stats_handle;
    let sigma_hot_reload_needed;
    if config.sigma.enabled {
        let mapper = FieldMapper::new();
        let initial_rules = load_rules_from_dir(&config.sigma.rules_dir);
        tracing::info!(count = initial_rules.len(), rules_dir = ?config.sigma.rules_dir, "Sigma rules loaded");
        let stats = std::sync::Arc::new(tokio::sync::Mutex::new(
            std::collections::HashMap::<String, u64>::new()
        ));
        let sigma_det = SigmaDetector::new(initial_rules, mapper).with_stats(stats.clone());
        let handle = sigma_det.rules_handle();
        let stats_arc = sigma_det.stats_handle().unwrap();
        sigma_rules_handle = Some(handle);
        sigma_stats_handle = Some(stats_arc);
        sigma_hot_reload_needed = config.sigma.hot_reload;
        detectors.push(Box::new(sigma_det));
    } else {
        sigma_rules_handle = None;
        sigma_stats_handle = None;
        sigma_hot_reload_needed = false;
    }

    tracing::info!(count = detectors.len(), "Detectors initialized");

    // Stage 3 of INT: scoring engine is now a plugin. The loader instantiates
    // it from the `plugins:` section of the config. Fail loud if none is
    // configured — running without a scoring engine would silently drop every
    // detection signal, which is the worst possible failure mode for a
    // security tool.
    let scoring = loaded.scoring_engines.pop().unwrap_or_else(|| {
        tracing::error!(
            "No scoring engine plugin configured. Add an entry like \
             `- id: scoring.default` to the `plugins:` section."
        );
        std::process::exit(1);
    });
    if !loaded.scoring_engines.is_empty() {
        tracing::warn!(
            extra = loaded.scoring_engines.len(),
            "Multiple scoring engine plugins loaded — only the last one is active"
        );
    }

    // --- Step 4b: Initialize bot registry from config ---
    let bot_rules: Vec<BotRule> = config.bots.iter().map(|rc| {
        let policy = match rc.policy.to_lowercase().as_str() {
            "block" => BotPolicy::Block,
            "monitor" => BotPolicy::Monitor,
            _ => BotPolicy::Allow,
        };
        BotRule {
            name: rc.name.clone(),
            ua_contains: rc.ua_contains.clone(),
            org: rc.org.clone(),
            policy,
        }
    }).collect();
    let bot_registry = Arc::new(Mutex::new(BotRegistry::new(bot_rules.clone())));
    tracing::info!(rules = bot_rules.len(), "Bot registry initialized");

    // Create event channel
    let (event_tx, event_rx) = mpsc::channel::<hiveguard_core::models::NormalizedEvent>(4096);

    // Shutdown signal
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    // Bridge the legacy watch-channel shutdown to the plugin CancellationToken
    // so plugins respect Ctrl+C / SIGTERM without bringing in a new signal API.
    {
        let mut sd_rx = shutdown_rx.clone();
        let token = plugin_shutdown_token.clone();
        tokio::spawn(async move {
            let _ = sd_rx.changed().await;
            token.cancel();
        });
    }

    // Spawn plugin log sources via the supervisor — they emit into the same
    // `event_tx` as legacy sources and shut down when `plugin_shutdown_token`
    // fires (bridged above).
    let mut plugin_source_handles = Vec::new();
    for plugin in loaded.log_sources.drain(..) {
        let h = plugin_supervisor::spawn_log_source(
            plugin,
            event_tx.clone(),
            plugin_shutdown_token.clone(),
        );
        plugin_source_handles.push(h);
    }
    if !plugin_source_handles.is_empty() {
        tracing::info!(
            count = plugin_source_handles.len(),
            "plugin log sources spawned"
        );
    }

    // Phase 4.2 — start Sigma hot-reload watcher now that shutdown_rx exists
    if sigma_hot_reload_needed {
        if let Some(ref handle) = sigma_rules_handle {
            spawn_hot_reload_watcher(
                config.sigma.rules_dir.clone(),
                handle.clone(),
                shutdown_rx.clone(),
            );
            tracing::info!("Sigma hot-reload watcher started");
        }
    }

    // --- Create Prometheus metrics ---
    let metrics = create_metrics();
    {
        let st = state.lock().await;
        metrics.active_bans.set(st.ban_store().get_all_bans().len() as i64);
        metrics.whitelisted_count.set(st.whitelist().entries().len() as i64);
    }

    // --- Step 5: Build socket server ---
    // Spawned later (Step 9c) once the enforcer and the optional cluster hook
    // are available, so manual (CLI/socket) bans are enforced + replicated to
    // peers exactly like detector-issued bans.
    let mut socket_server =
        SocketServer::new(socket_path, state.clone()).with_enforcer(enforcer.clone());

    // --- Step 5b: REST API ---
    // NOTE (REFACTOR 2.5): the legacy `api:` REST server has been removed. The
    // full management surface now lives in the `ui.rest` plugin, which consumes
    // the `DaemonUiApi` built below. `config_path` is forwarded to that handle
    // so `GET/PUT /api/config` can read and rewrite the config file.
    let ui_config_path = config_path.clone();

    // --- Step 6: Log sources ---
    //
    // Stage 2 of INT: legacy `build_log_sources` removed. All log sources
    // come exclusively from the plugin loader (see "Step 1b" above). The
    // `plugin_source_handles` Vec tracks their JoinHandles for shutdown.
    if plugin_source_handles.is_empty() {
        tracing::warn!(
            "no log sources configured — daemon will run with no event input. \
             Configure plugins in your YAML; run `scripts/migrate-config.py` \
             to convert legacy `sources:` sections."
        );
    }

    // --- Step 7: Start background tasks ---
    // Snapshot timer
    let snapshot_interval = config
        .persistence
        .snapshot_interval
        .as_duration()
        .unwrap_or(Duration::from_secs(300));
    let snapshot_state = state.clone();
    let snapshot_shutdown = shutdown_rx.clone();
    let snapshot_handle = tokio::spawn(async move {
        snapshot_task(snapshot_state, snapshot_interval, snapshot_shutdown).await;
    });

    // Ban expiry timer (every 60 seconds)
    let expiry_state = state.clone();
    let expiry_enforcer = enforcer.clone();
    let expiry_shutdown = shutdown_rx.clone();
    let expiry_metrics = Some(metrics.clone());
    let expiry_handle = tokio::spawn(async move {
        ban_expiry_task(
            expiry_state,
            expiry_enforcer,
            Duration::from_secs(60),
            expiry_shutdown,
            expiry_metrics,
        )
        .await;
    });

    // sd-notify watchdog timer (every 15 seconds)
    let watchdog_shutdown = shutdown_rx.clone();
    let watchdog_handle = tokio::spawn(async move {
        watchdog_task(watchdog_shutdown).await;
    });

    // --- Step 8: Notify systemd that we are ready ---
    let _ = sd_notify::notify(&[sd_notify::NotifyState::Ready]);
    tracing::info!("HiveGuard daemon started (sd-notify: ready)");

    // --- Step 9: Handle Ctrl+C / SIGTERM ---
    let shutdown_tx_clone = shutdown_tx.clone();
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        tracing::info!("Received shutdown signal");
        let _ = shutdown_tx_clone.send(true);
    });

    // --- UI API setup (Stage 3 INT) ---
    // Build the daemon-side UiApiHandle implementation. UI plugins (ui-rest,
    // ui-tui, ui-web) all consume `Arc<dyn UiApiHandle>`. The pipeline gets a
    // `UiSniffer` clone that observes detection signals + ban changes.
    let daemon_ui_api = std::sync::Arc::new(ui_api::DaemonUiApi::new(
        config.node.name.clone(),
        env!("CARGO_PKG_VERSION").to_string(),
        state.clone(),
        enforcer.clone(),
        plugin_infos,
        Some(ui_config_path),
        sigma_rules_handle.clone(),
        sigma_stats_handle.clone(),
        Some(metrics.clone()),
        Some(bot_registry.clone()),
        Some(event_tx.clone()),
    ));
    let ui_sniffer = ui_api::UiSniffer::from_arc(daemon_ui_api.clone());

    // --- Step 9b: Cluster gossip runtime ---
    // Brings up QUIC/SWIM/CRDT ban replication when `node.listen_gossip` is set.
    // Returns a handle the pipeline uses to announce locally-issued bans; remote
    // bans are applied straight to the state + enforcer inside the runtime.
    #[cfg(feature = "cluster")]
    let cluster_handle = cluster::spawn_cluster(
        &config,
        state.clone(),
        enforcer.clone(),
        Some(metrics.clone()),
        shutdown_rx.clone(),
    )
    .await;

    // --- Step 10: Run pipeline (main event loop) ---
    let mut pipeline = Pipeline::new(event_rx, detectors, scoring, state.clone(), enforcer.clone())
        .with_bot_registry(bot_registry.clone())
        .with_metrics(metrics.clone())
        .with_ui_sniffer(ui_sniffer);

    #[cfg(feature = "cluster")]
    if let Some(handle) = cluster_handle {
        // Replicate manual (socket/CLI) bans to peers too, matching the detector
        // path. `ClusterHandle` is cheap to clone.
        let hook_handle = handle.clone();
        socket_server = socket_server.with_ban_hook(std::sync::Arc::new(
            move |rec: &hiveguard_core::models::BanRecord| hook_handle.announce_local_ban(rec),
        ));
        pipeline = pipeline.with_cluster(handle);
    }

    // --- Step 9c: Start socket server (enforcer + optional cluster hook wired) ---
    {
        let socket_shutdown_rx = shutdown_rx.clone();
        tokio::spawn(async move {
            socket_server.run(socket_shutdown_rx).await;
        });
    }

    // --- Alert dispatcher setup (Stage 3 INT) ---
    // Replaces the legacy `alert_manager` module. Notifier plugins handle
    // their own transport (Slack, Teams, webhook, ...); the host-side
    // `AlertDispatcher` provides fan-out + cooldown + retry on top of them.
    if !loaded.notifiers.is_empty() {
        use std::sync::Arc as StdArc;
        let notifier_count = loaded.notifiers.len();
        let notifier_arcs: Vec<StdArc<dyn hiveguard_plugin_api::NotifierPlugin>> =
            loaded.notifiers.drain(..).map(StdArc::from).collect();

        let dispatcher = hiveguard_host::AlertDispatcher::new(notifier_arcs)
            .with_config(hiveguard_host::AlertDispatcherConfig {
                cooldown_secs: config.alerting.cooldown_secs,
                queue_depth: config.alerting.queue_depth,
                channel_capacity: 1024,
            });

        // Bridge the legacy `watch::Receiver<bool>` shutdown signal directly
        // into the dispatcher.
        let (handle, _join) = dispatcher.spawn(shutdown_rx.clone());
        pipeline = pipeline.with_alert_dispatcher(handle);

        tracing::info!(
            notifiers = notifier_count,
            cooldown_secs = config.alerting.cooldown_secs,
            queue_depth = config.alerting.queue_depth,
            "Alert dispatcher started"
        );
    } else if !config.alerting.destinations.is_empty() {
        tracing::warn!(
            destinations = config.alerting.destinations.len(),
            "Legacy `alerting.destinations` configured but no notifier \
             plugins loaded — alerts will not be delivered. Migrate the \
             destinations to `plugins:` entries (notifier.slack, \
             notifier.webhook, ...) using `hiveguard-migrate-config`."
        );
    }

    // --- SIEM syslog exporter setup (Phase 3.1) ---
    if config.siem.syslog_exporter.enabled {
        let exporter = siem_exporter::SiemSyslogExporter::new(
            config.siem.syslog_exporter.clone(),
        )
        .with_metrics(metrics.clone());
        pipeline = pipeline.with_siem_exporter(exporter);
        tracing::info!(
            host = %config.siem.syslog_exporter.host,
            protocol = ?config.siem.syslog_exporter.protocol,
            format = ?config.siem.syslog_exporter.format,
            "SIEM syslog exporter enabled"
        );
    }

    // --- SIEM sink plugins (sink-elastic, sink-splunk, sink-datadog, sink-syslog) ---
    //
    // The legacy `siem.elasticsearch.*` / `siem.splunk.*` / `siem.datadog.*`
    // exporters were migrated to the plugin API. Sinks now come from the
    // plugin registry (`plugins:` section in the config).
    if !loaded.siem_sinks.is_empty() {
        let count = loaded.siem_sinks.len();
        let sinks: Vec<Arc<dyn hiveguard_plugin_api::SiemSinkPlugin>> = loaded
            .siem_sinks
            .drain(..)
            .map(Arc::from)
            .collect();
        pipeline = pipeline.with_siem_sinks(sinks);
        tracing::info!(count, "SIEM sink plugins enabled");
    }

    // --- GeoIP enrichment setup ---
    if config.cti.geoip.enabled {
        let shared_geoip = init_geoip(&config.node.data_dir, &config.cti.geoip).await;
        pipeline = pipeline.with_geoip(
            shared_geoip,
            config.cti.geoip.trusted_asns.clone(),
            config.cti.geoip.datacenter_multiplier,
        );
        tracing::info!("GeoIP enrichment enabled");
    }

    // --- CTI enrichment setup (Stage 2 of INT) ---
    //
    // CTI providers come from the plugin registry. Plugins are wrapped via
    // `CtiPluginAdapter` so the existing `CtiEnricher` consumed by the
    // pipeline can aggregate them.
    if !loaded.cti_providers.is_empty() {
        let count = loaded.cti_providers.len();
        let providers: Vec<Box<dyn CtiProvider>> = loaded
            .cti_providers
            .drain(..)
            .map(|p| Box::new(plugin_bridge::CtiPluginAdapter(p)) as Box<dyn CtiProvider>)
            .collect();
        let cti_enricher = CtiEnricher::new(providers);
        pipeline = pipeline.with_cti_enricher(Arc::new(cti_enricher));
        tracing::info!(count, "CTI enrichment enabled (from plugins)");
    }

    // --- UI server plugins (ui-rest / ui-tui / ui-web native side) ---
    // Each UI plugin gets a clone of the Arc<dyn UiApiHandle>. A bridge
    // task converts the legacy `watch::Receiver<bool>` shutdown signal
    // into the CancellationToken plugins expect.
    if !loaded.ui_servers.is_empty() {
        use tokio_util::sync::CancellationToken;
        let ui_shutdown = CancellationToken::new();
        {
            let token = ui_shutdown.clone();
            let mut rx = shutdown_rx.clone();
            tokio::spawn(async move {
                let _ = rx.changed().await;
                token.cancel();
            });
        }

        for mut plugin in loaded.ui_servers.drain(..) {
            let api: std::sync::Arc<dyn hiveguard_plugin_api::UiApiHandle> = daemon_ui_api.clone();
            let token = ui_shutdown.clone();
            let plugin_id = plugin.manifest().id.to_string();
            tracing::info!(plugin = %plugin_id, "Starting UI server plugin");
            tokio::spawn(async move {
                if let Err(e) = plugin.run(api, token).await {
                    tracing::error!(plugin = %plugin_id, error = %e, "UI server plugin exited");
                }
            });
        }
    }

    let pipeline_shutdown = shutdown_rx.clone();
    let pipeline_event_tx = event_tx.clone();
    tokio::spawn(async move {
        let mut rx = pipeline_shutdown;
        let _ = rx.changed().await;
        drop(pipeline_event_tx);
    });

    drop(event_tx);

    pipeline.run().await;

    // ===== GRACEFUL SHUTDOWN SEQUENCE =====
    tracing::info!("Beginning graceful shutdown");
    let _ = shutdown_tx.send(true);

    // 1. Stop ingest sources — plugin shutdown token already fired via
    //    the legacy watch-channel bridge in Step 1b; we just wait for each
    //    plugin task to finish (bounded by Tokio task drop timeout).
    for handle in plugin_source_handles {
        let _ = tokio::time::timeout(Duration::from_secs(5), handle).await;
    }

    // 2. Wait for background tasks to finish (with timeout)
    let _ = tokio::time::timeout(Duration::from_secs(5), snapshot_handle).await;
    let _ = tokio::time::timeout(Duration::from_secs(5), expiry_handle).await;
    let _ = tokio::time::timeout(Duration::from_secs(2), watchdog_handle).await;

    // 3. Final snapshot + WAL flush
    {
        let mut st = state.lock().await;
        if let Err(e) = st.take_snapshot() {
            tracing::error!("Failed to take final snapshot: {}", e);
        }
        if let Err(e) = st.flush_wal() {
            tracing::error!("Failed to flush WAL: {}", e);
        }
    }

    // 4. Notify systemd we're stopping
    let _ = sd_notify::notify(&[sd_notify::NotifyState::Stopping]);

    tracing::info!("HiveGuard daemon stopped");
}

// Stage 3 of INT: `build_scoring_engine` removed — the scoring engine is
// now sourced from the plugin registry. Configuration moved from the legacy
// `scoring:` YAML section to a `- id: scoring.default` entry under `plugins:`,
// where the plugin reads its own `accumulation_window_secs`,
// `ban_severity_threshold`, and `default_ban_duration_secs` fields directly.

// Stage 2 of INT: `init_cti_enricher` removed — CTI providers now come from
// the plugin registry and are wrapped via `plugin_bridge::CtiPluginAdapter`.
// The `cti.abuseipdb`, `cti.spamhaus`, `cti.tor`, `cti.otx`, `cti.geoip`
// plugins (all in `plugins/cti-*/`) handle their own configuration.

/// Initialise the shared GeoIP database and, if configured, spawn the auto-update task.
async fn init_geoip(
    data_dir: &std::path::Path,
    geoip_cfg: &hiveguard_core::config::GeoIpCtiConfig,
) -> SharedGeoIpDb {
    let db = GeoIpDb::try_load(data_dir);
    let shared: SharedGeoIpDb = Arc::new(ArcSwap::new(Arc::new(db)));

    if let Some(ref key) = geoip_cfg.license_key {
        let interval = Duration::from_secs(geoip_cfg.update_interval_days as u64 * 86400);
        let updater = GeoIpUpdater::new(data_dir.to_path_buf(), key.clone(), shared.clone());
        updater.spawn_auto_update(interval);
        tracing::info!(
            interval_days = geoip_cfg.update_interval_days,
            "GeoIP auto-update task spawned"
        );
    }

    shared
}

/// Run `hiveguard geoip update` — download fresh GeoLite2 databases.
async fn run_geoip_update(config_path: Option<PathBuf>, license_key_arg: Option<String>) {
    // Resolve license key: CLI arg takes precedence over config
    let (data_dir, license_key) = match config_path {
        Some(ref cp) => match HiveGuardConfig::load(cp) {
            Ok(cfg) => {
                let key = license_key_arg
                    .or_else(|| cfg.cti.geoip.license_key.clone())
                    .unwrap_or_default();
                (cfg.node.data_dir.clone(), key)
            }
            Err(e) => {
                eprintln!("Failed to load config: {}", e);
                std::process::exit(1);
            }
        },
        None => {
            let key = license_key_arg.unwrap_or_default();
            (std::path::PathBuf::from("/var/lib/hiveguard"), key)
        }
    };

    if license_key.is_empty() {
        eprintln!(
            "Error: MaxMind license key is required.\n\
             Provide it with --license-key KEY or set cti.geoip.license_key in config."
        );
        std::process::exit(1);
    }

    println!("Updating GeoIP databases in {:?} …", data_dir.join("geoip"));

    let shared: SharedGeoIpDb = Arc::new(ArcSwap::new(Arc::new(None)));
    let updater = GeoIpUpdater::new(data_dir, license_key, shared);

    match updater.update().await {
        Ok(()) => println!("GeoIP databases updated successfully."),
        Err(e) => {
            eprintln!("GeoIP update failed: {}", e);
            std::process::exit(1);
        }
    }
}

// Stage 2 of INT: `build_log_sources` removed — all log sources come from
// the plugin registry now. Legacy `config.sources.*` sections are still
// parsed for backwards compatibility but are no longer honoured. Use
// `scripts/migrate-config.py` to convert.

async fn run_cli_command(cmd: Command, socket_path: &PathBuf, config_path: Option<PathBuf>) {
    let request = match cmd {
        Command::Status => ApiRequest::Status,
        Command::Ban {
            target,
            duration,
            reason,
        } => ApiRequest::Ban {
            target,
            duration,
            reason,
        },
        Command::Unban { target } => ApiRequest::Unban { target },
        Command::Whitelist { action } => match action {
            WhitelistAction::Add { target } => ApiRequest::WhitelistAdd { target },
            WhitelistAction::Remove { target } => ApiRequest::WhitelistRemove { target },
            WhitelistAction::List => ApiRequest::ListWhitelist,
        },
        Command::ListBans { limit } => ApiRequest::ListBans { limit },
        Command::Top { threats } => ApiRequest::TopThreats { limit: threats },
        Command::Export { format } => {
            let fmt = match format.to_lowercase().as_str() {
                "csv" => ExportFormat::Csv,
                _ => ExportFormat::Json,
            };
            ApiRequest::ExportBans { format: fmt }
        }
        Command::Replay { duration } => ApiRequest::Replay { duration },

        Command::ImportFail2ban { db, jail, dry_run, config_from } => {
            // --config-from: parse jail configs and print a HiveGuard snippet
            if !config_from.is_empty() {
                let jails = fail2ban_import::parse_jail_configs(&config_from);
                print!("{}", fail2ban_import::generate_config_snippet(&jails));
                return;
            }

            // Default: import active bans from the SQLite database
            let result = fail2ban_import::run_import(
                &db,
                socket_path,
                dry_run,
                jail.as_deref(),
            )
            .await;

            for err in &result.errors {
                eprintln!("Error: {}", err);
            }

            if !dry_run {
                println!(
                    "Import complete: {} imported, {} skipped, {} errors",
                    result.imported,
                    result.skipped,
                    result.errors.len()
                );
            }

            if !result.errors.is_empty() {
                std::process::exit(1);
            }
            return;
        }

        Command::GeoIp { action } => {
            match action {
                GeoIpAction::Update { license_key } => {
                    run_geoip_update(config_path, license_key).await;
                    return;
                }
            }
        }

        Command::Sigma { action } => {
            run_sigma_command(action).await;
            return;
        }

        Command::Run => unreachable!(),
    };

    match send_request(socket_path, &request).await {
        Ok(response) => {
            print_response(&response);
        }
        Err(e) => {
            eprintln!("{}", e);
            std::process::exit(1);
        }
    }
}

// ---------------------------------------------------------------------------
// Sigma CLI (Phase 4.2.4)
// ---------------------------------------------------------------------------

async fn run_sigma_command(action: SigmaAction) {
    match action {
        SigmaAction::Import { path, dry_run } => {
            use hiveguard_sigma::SigmaRule;

            if !path.is_dir() {
                eprintln!("Error: '{}' is not a directory", path.display());
                std::process::exit(1);
            }

            let mut imported = 0usize;
            let mut rejected = 0usize;
            let mut errors: Vec<String> = Vec::new();

            let read_dir = match std::fs::read_dir(&path) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("Error reading directory: {}", e);
                    std::process::exit(1);
                }
            };

            for entry in read_dir.flatten() {
                let file_path = entry.path();
                let ext = file_path.extension().and_then(|e| e.to_str()).unwrap_or("");
                if ext != "yml" && ext != "yaml" {
                    continue;
                }
                let text = match std::fs::read_to_string(&file_path) {
                    Ok(t) => t,
                    Err(e) => {
                        let msg = format!("{}: {}", file_path.display(), e);
                        errors.push(msg);
                        rejected += 1;
                        continue;
                    }
                };
                match SigmaRule::from_yaml(&text) {
                    Ok(rule) => {
                        if dry_run {
                            println!("  [OK] {} ({})", rule.title, file_path.display());
                        }
                        imported += 1;
                    }
                    Err(e) => {
                        let msg = format!("{}: {}", file_path.display(), e);
                        if dry_run {
                            println!("  [FAIL] {}", msg);
                        }
                        errors.push(msg);
                        rejected += 1;
                    }
                }
            }

            if dry_run {
                println!("\nDry-run complete: {} valid, {} invalid", imported, rejected);
            } else {
                println!("Validated {} rules, {} errors", imported, rejected);
                if !errors.is_empty() {
                    eprintln!("\nErrors:");
                    for e in &errors {
                        eprintln!("  {}", e);
                    }
                }
            }

            if rejected > 0 {
                std::process::exit(1);
            }
        }

        SigmaAction::Test { rule, sample } => {
            use hiveguard_core::models::NormalizedEvent;
            use hiveguard_sigma::SigmaRule;

            let rule_text = match std::fs::read_to_string(&rule) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("Error reading rule file: {}", e);
                    std::process::exit(1);
                }
            };
            let sigma_rule = match SigmaRule::from_yaml(&rule_text) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("Error parsing rule: {}", e);
                    std::process::exit(1);
                }
            };

            let sample_text = match std::fs::read_to_string(&sample) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("Error reading sample file: {}", e);
                    std::process::exit(1);
                }
            };

            let mapper = FieldMapper::new();
            let mut matches = 0usize;
            let mut total = 0usize;

            for (line_no, line) in sample_text.lines().enumerate() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                total += 1;
                let event: NormalizedEvent = match serde_json::from_str(line) {
                    Ok(e) => e,
                    Err(e) => {
                        eprintln!("Line {}: JSON parse error: {}", line_no + 1, e);
                        continue;
                    }
                };
                if sigma_rule.matches(&event, &mapper) {
                    matches += 1;
                    println!("  MATCH line {}: {}", line_no + 1, &line[..line.len().min(120)]);
                }
            }

            println!(
                "\nRule '{}': {}/{} events matched",
                sigma_rule.title, matches, total
            );
        }

        SigmaAction::List | SigmaAction::Stats => {
            eprintln!("This command requires a running daemon. Use the REST API instead:");
            eprintln!("  GET /api/v1/sigma/rules");
            eprintln!("  GET /api/v1/sigma/stats");
            std::process::exit(1);
        }
    }
}

