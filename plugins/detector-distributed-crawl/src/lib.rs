//! `detector.distributed_crawl` — distributed (residential-proxy) crawl
//! detector. **Never bans**: it flips an "under attack" state that the web
//! server can act on (flag file → challenge), exported as a gauge and logged
//! as WARN on every change. Logic: `hiveguard_core::detectors::distributed_crawl`.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use hiveguard_core::detectors::attack_state::{self, AttackState};
use hiveguard_core::detectors::distributed_crawl::{
    CrawlStatus, CrawlTransition, DistributedCrawlConfig, DistributedCrawlDetector,
};
use hiveguard_core::detectors::netkey::validate_ipv6_prefix;
use hiveguard_core::models::NormalizedEvent;
use hiveguard_plugin_api::prelude::*;
use serde::Deserialize;
use tracing::{error, info, warn};

pub const PLUGIN_ID: &str = "detector.distributed_crawl";
pub const PLUGIN_VERSION: &str = "0.1.0";
/// Name under which the state is published (gauge label `detector`).
pub const STATE_NAME: &str = "distributed_crawl";
pub const DEFAULT_FLAG_FILE: &str = "/run/hiveguard/under_attack";

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct Config {
    #[serde(default)]
    path_prefixes: Vec<String>,
    window_secs: Option<u64>,
    fresh_ip_memory_secs: Option<u64>,
    fresh_ip_threshold: Option<usize>,
    off_threshold: Option<usize>,
    cooldown_secs: Option<u64>,
    max_tracked_ips: Option<usize>,
    exclude_static_fetchers: Option<bool>,
    static_extensions: Option<Vec<String>>,
    require_no_referer: Option<bool>,
    ipv6_prefix: Option<u8>,
    flag_file: Option<String>,
    eval_interval_secs: Option<u64>,
}

struct Settings {
    detector: DistributedCrawlConfig,
    flag_file: Option<PathBuf>,
    eval_interval: Duration,
}

fn settings(cfg: Config) -> PluginResult<Settings> {
    let bad = |m: String| PluginError::ConfigValidation(m);
    if cfg.path_prefixes.is_empty() {
        return Err(bad("path_prefixes must list at least one path".into()));
    }
    let d = DistributedCrawlConfig::default();
    let threshold = cfg.fresh_ip_threshold.unwrap_or(d.fresh_ip_threshold);
    let off = cfg.off_threshold.unwrap_or(threshold / 3);
    if off > threshold {
        return Err(bad(format!(
            "off_threshold ({off}) must be <= fresh_ip_threshold ({threshold})"
        )));
    }
    let ipv6_prefix = cfg.ipv6_prefix.unwrap_or(d.ipv6_prefix);
    validate_ipv6_prefix("ipv6_prefix", ipv6_prefix).map_err(bad)?;
    let flag_file = match cfg.flag_file {
        None => Some(PathBuf::from(DEFAULT_FLAG_FILE)),
        Some(s) if s.trim().is_empty() => None,
        Some(s) => {
            let p = PathBuf::from(s);
            if !p.is_absolute() || p.file_name().is_none() {
                return Err(bad("flag_file must be an absolute file path".into()));
            }
            Some(p)
        }
    };
    Ok(Settings {
        detector: DistributedCrawlConfig {
            window: cfg.window_secs.map(Duration::from_secs).unwrap_or(d.window),
            path_prefixes: cfg.path_prefixes,
            fresh_ip_memory: cfg
                .fresh_ip_memory_secs
                .map(Duration::from_secs)
                .unwrap_or(d.fresh_ip_memory),
            fresh_ip_threshold: threshold,
            off_threshold: off,
            cooldown: cfg.cooldown_secs.map(Duration::from_secs).unwrap_or(d.cooldown),
            max_tracked_ips: cfg.max_tracked_ips.unwrap_or(d.max_tracked_ips),
            exclude_static_fetchers: cfg.exclude_static_fetchers.unwrap_or(d.exclude_static_fetchers),
            static_extensions: cfg.static_extensions.unwrap_or(d.static_extensions),
            require_no_referer: cfg.require_no_referer.unwrap_or(d.require_no_referer),
            ipv6_prefix,
        },
        flag_file,
        eval_interval: Duration::from_secs(cfg.eval_interval_secs.unwrap_or(5).max(1)),
    })
}

/// Atomically create `path` (write a temp file in the same directory, chmod
/// 0644, rename) so a reader never sees a half-written flag.
fn write_flag(path: &Path, content: &str) -> std::io::Result<()> {
    use std::io::Write;
    let dir = path.parent().unwrap_or_else(|| Path::new("/"));
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let tmp = dir.join(format!(".{name}.tmp.{}", std::process::id()));
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(content.as_bytes())?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644))?;
    }
    std::fs::rename(&tmp, path).inspect_err(|_| {
        let _ = std::fs::remove_file(&tmp);
    })
}

fn remove_flag(path: &Path) -> std::io::Result<bool> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}

/// Owns the side effects of the state machine (flag file, gauge, log).
struct StateSink {
    flag_file: Option<PathBuf>,
    window_secs: u64,
    threshold: usize,
}

impl StateSink {
    fn startup(&self) {
        if let Some(ref p) = self.flag_file {
            match remove_flag(p) {
                Ok(true) => info!(flag = %p.display(), "distributed_crawl: removed stale under-attack flag (starting in normal state)"),
                Ok(false) => {}
                Err(e) => warn!(flag = %p.display(), error = %e, "distributed_crawl: cannot remove stale flag file"),
            }
        }
        attack_state::publish(STATE_NAME, AttackState { on: false, value: 0, since: Utc::now() });
    }

    fn flag_content(&self, fresh_ips: usize) -> String {
        format!(
            "under_attack since={} fresh_ips={} window_secs={} threshold={}\n",
            Utc::now().to_rfc3339(),
            fresh_ips,
            self.window_secs,
            self.threshold
        )
    }

    fn apply(&self, status: CrawlStatus) {
        match status.transition {
            Some(CrawlTransition::On { fresh_ips }) => {
                warn!(
                    fresh_ips,
                    threshold = self.threshold,
                    window_secs = self.window_secs,
                    flag = ?self.flag_file,
                    "distributed_crawl: UNDER ATTACK — many first-time IPs hitting watched paths (no bans issued)"
                );
                attack_state::publish(STATE_NAME, AttackState { on: true, value: fresh_ips as u64, since: Utc::now() });
                if let Some(ref p) = self.flag_file {
                    if let Err(e) = write_flag(p, &self.flag_content(fresh_ips)) {
                        error!(flag = %p.display(), error = %e, "distributed_crawl: cannot write under-attack flag file");
                    }
                }
            }
            Some(CrawlTransition::Off { fresh_ips }) => {
                warn!(fresh_ips, "distributed_crawl: attack over — back to normal state");
                attack_state::publish(STATE_NAME, AttackState { on: false, value: fresh_ips as u64, since: Utc::now() });
                if let Some(ref p) = self.flag_file {
                    if let Err(e) = remove_flag(p) {
                        error!(flag = %p.display(), error = %e, "distributed_crawl: cannot remove under-attack flag file");
                    }
                }
            }
            None => {
                attack_state::update_value(STATE_NAME, status.fresh_ips as u64);
                // Re-assert the flag if something removed it while on.
                if status.under_attack {
                    if let Some(ref p) = self.flag_file {
                        if !p.exists() {
                            let _ = write_flag(p, &self.flag_content(status.fresh_ips));
                        }
                    }
                }
            }
        }
    }

    fn shutdown(&self) {
        if let Some(ref p) = self.flag_file {
            let _ = remove_flag(p);
        }
        attack_state::clear(STATE_NAME);
    }
}

pub struct DistributedCrawlPlugin {
    manifest: PluginManifest,
    detector: Arc<DistributedCrawlDetector>,
    sink: Arc<StateSink>,
    eval_interval: Duration,
}

impl DistributedCrawlPlugin {
    pub fn manifest_fn() -> PluginManifest {
        PluginManifest {
            id: PLUGIN_ID,
            version: PLUGIN_VERSION,
            description: "Distributed residential-proxy crawl detector: under-attack flag file + gauge, never bans.",
            kind: PluginKind::Detector,
            author: "HiveGuard",
            docs_url: Some("https://github.com/anthropics/hiveguard/blob/main/plugins/detector-distributed-crawl/README.md"),
        }
    }

    pub fn create(
        ctx: PluginContext,
        cfg: serde_json::Value,
    ) -> BoxFuture<'static, PluginResult<Box<dyn DetectorPlugin>>> {
        Box::pin(async move {
            let mut plugin = DistributedCrawlPlugin {
                manifest: Self::manifest_fn(),
                detector: Arc::new(DistributedCrawlDetector::with_config(DistributedCrawlConfig::default())),
                sink: Arc::new(StateSink { flag_file: None, window_secs: 0, threshold: 0 }),
                eval_interval: Duration::from_secs(5),
            };
            <DistributedCrawlPlugin as Plugin>::init(&mut plugin, cfg).await?;
            plugin.sink.startup();
            plugin.spawn_ticker(ctx.shutdown.clone());
            Ok(Box::new(plugin) as Box<dyn DetectorPlugin>)
        })
    }

    fn spawn_ticker(&self, shutdown: CancellationToken) {
        let detector = self.detector.clone();
        let sink = self.sink.clone();
        let every = self.eval_interval;
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(every);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    _ = shutdown.cancelled() => {
                        sink.shutdown();
                        break;
                    }
                    _ = tick.tick() => {
                        sink.apply(detector.evaluate(Utc::now()));
                    }
                }
            }
        });
    }
}

#[async_trait]
impl Plugin for DistributedCrawlPlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    async fn init(&mut self, cfg: serde_json::Value) -> PluginResult<()> {
        let cfg: Config = serde_json::from_value(cfg)
            .map_err(|e| PluginError::ConfigValidation(e.to_string()))?;
        let s = settings(cfg)?;
        self.sink = Arc::new(StateSink {
            flag_file: s.flag_file,
            window_secs: s.detector.window.as_secs(),
            threshold: s.detector.fresh_ip_threshold,
        });
        self.detector = Arc::new(DistributedCrawlDetector::with_config(s.detector));
        self.eval_interval = s.eval_interval;
        Ok(())
    }

    async fn shutdown(&mut self) -> PluginResult<()> {
        self.sink.shutdown();
        Ok(())
    }
}

impl DetectorPlugin for DistributedCrawlPlugin {
    fn process(&self, event: &NormalizedEvent) -> Option<DetectionSignal> {
        // Recording only; state changes are evaluated by the ticker so the
        // pipeline never does file I/O. This detector never returns a signal.
        self.detector.record(event);
        None
    }
}

inventory::submit! {
    PluginDescriptor {
        id: PLUGIN_ID,
        kind: PluginKind::Detector,
        api_version: API_VERSION,
        manifest: DistributedCrawlPlugin::manifest_fn,
        config_schema: include_str!("../schema.json"),
        factory: PluginFactory::Detector(DistributedCrawlPlugin::create),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    use hiveguard_core::models::EventType;
    use hiveguard_plugin_api::context::parking_lot_compat::RegistryHandle;
    use hiveguard_plugin_api::secrets::SecretResolver;

    fn test_ctx(token: CancellationToken) -> PluginContext {
        PluginContext::new(
            PLUGIN_ID.to_string(),
            std::env::temp_dir(),
            Arc::new(SecretResolver::new()),
            PluginMetrics {
                registry: Arc::new(RegistryHandle::default()),
                plugin_id: PLUGIN_ID.to_string(),
            },
            token,
        )
    }

    fn search(ip: &str) -> NormalizedEvent {
        let mut metadata = HashMap::new();
        metadata.insert("path".to_string(), "/catalogsearch/result/?q=buty".to_string());
        metadata.insert("method".to_string(), "GET".to_string());
        metadata.insert("status_code".to_string(), "200".to_string());
        NormalizedEvent {
            timestamp: Utc::now(),
            source_ip: ip.parse().unwrap(),
            event_type: EventType::HttpRequest,
            source_name: "nginx".into(),
            raw_line: String::new(),
            metadata,
        }
    }

    #[test]
    fn manifest_has_correct_id_and_kind() {
        let m = DistributedCrawlPlugin::manifest_fn();
        assert_eq!(m.id, PLUGIN_ID);
        assert_eq!(m.kind, PluginKind::Detector);
    }

    #[test]
    fn schema_is_valid_json_and_requires_prefixes() {
        let v: serde_json::Value = serde_json::from_str(include_str!("../schema.json")).unwrap();
        assert_eq!(v["required"][0], "path_prefixes");
    }

    #[tokio::test]
    async fn factory_rejects_missing_prefixes() {
        let p = DistributedCrawlPlugin::create(test_ctx(CancellationToken::new()), serde_json::json!({})).await;
        assert!(p.is_err());
    }

    #[tokio::test]
    async fn factory_rejects_bad_values() {
        for cfg in [
            serde_json::json!({"path_prefixes": ["/s"], "fresh_ip_threshold": 5, "off_threshold": 6}),
            serde_json::json!({"path_prefixes": ["/s"], "ipv6_prefix": 32}),
            serde_json::json!({"path_prefixes": ["/s"], "flag_file": "relative/flag"}),
            serde_json::json!({"path_prefixes": ["/s"], "window_secs": "abc"}),
            serde_json::json!({"path_prefixes": ["/s"], "unknown_key": 1}),
        ] {
            let p = DistributedCrawlPlugin::create(test_ctx(CancellationToken::new()), cfg.clone()).await;
            assert!(p.is_err(), "must reject {cfg}");
        }
    }

    #[tokio::test]
    async fn full_config_never_emits_signals() {
        let dir = tempfile::tempdir().unwrap();
        let token = CancellationToken::new();
        let p = DistributedCrawlPlugin::create(
            test_ctx(token.clone()),
            serde_json::json!({
                "path_prefixes": ["/catalogsearch/", "/cgi-bin/koha/opac-search.pl"],
                "window_secs": 300,
                "fresh_ip_memory_secs": 86400,
                "fresh_ip_threshold": 2,
                "off_threshold": 1,
                "cooldown_secs": 600,
                "max_tracked_ips": 1000,
                "exclude_static_fetchers": true,
                "static_extensions": [".css", ".js"],
                "require_no_referer": false,
                "ipv6_prefix": 64,
                "flag_file": dir.path().join("under_attack").to_string_lossy(),
                "eval_interval_secs": 1
            }),
        )
        .await
        .unwrap();
        for i in 0..10 {
            assert!(p.process(&search(&format!("100.64.7.{i}"))).is_none());
        }
        token.cancel();
    }

    #[test]
    fn sink_writes_and_removes_flag_atomically() {
        let dir = tempfile::tempdir().unwrap();
        let flag = dir.path().join("under_attack");
        std::fs::write(&flag, "stale").unwrap();
        let sink = StateSink { flag_file: Some(flag.clone()), window_secs: 300, threshold: 2 };

        sink.startup();
        assert!(!flag.exists(), "stale flag removed on startup");

        sink.apply(CrawlStatus {
            under_attack: true,
            fresh_ips: 3,
            transition: Some(CrawlTransition::On { fresh_ips: 3 }),
        });
        assert!(flag.exists());
        let body = std::fs::read_to_string(&flag).unwrap();
        assert!(body.contains("fresh_ips=3"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&flag).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o644);
        }
        // No temp files left behind.
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);

        // Re-asserted while on if removed externally.
        std::fs::remove_file(&flag).unwrap();
        sink.apply(CrawlStatus { under_attack: true, fresh_ips: 3, transition: None });
        assert!(flag.exists());

        sink.apply(CrawlStatus {
            under_attack: false,
            fresh_ips: 0,
            transition: Some(CrawlTransition::Off { fresh_ips: 0 }),
        });
        assert!(!flag.exists());
        sink.shutdown();
    }

    #[tokio::test]
    async fn ticker_turns_flag_on_and_shutdown_removes_it() {
        let dir = tempfile::tempdir().unwrap();
        let flag = dir.path().join("ua");
        let token = CancellationToken::new();
        let p = DistributedCrawlPlugin::create(
            test_ctx(token.clone()),
            serde_json::json!({
                "path_prefixes": ["/catalogsearch/"],
                "fresh_ip_threshold": 3,
                "flag_file": flag.to_string_lossy(),
                "eval_interval_secs": 1
            }),
        )
        .await
        .unwrap();
        for i in 0..5 {
            p.process(&search(&format!("100.64.9.{i}")));
        }
        // The first interval tick fires immediately; allow a few to pass.
        for _ in 0..30 {
            if flag.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(flag.exists(), "flag written by the ticker");

        token.cancel();
        for _ in 0..30 {
            if !flag.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(!flag.exists(), "flag removed on shutdown");
    }
}
