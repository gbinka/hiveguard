//! AWS CloudWatch Logs ingestion — Phase 6.2.2.
//!
//! Implements [`LogSource`] for CloudWatch Logs.
//!
//! # Design
//!
//! * One polling task is spawned **per log group** for independent pacing.
//! * Each task calls `FilterLogEvents` with a `start_time` derived from the
//!   persisted checkpoint (last processed event's timestamp + 1 ms) so events
//!   are not re-processed across restarts.
//! * The checkpoint is saved atomically after each successful poll batch.
//! * The `filter_pattern` field is optional; when absent all events are
//!   returned.
//! * A `watch::Receiver<bool>` is used for cooperative stop signalling.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use aws_config::BehaviorVersion;
use aws_credential_types::Credentials as AwsCredentials;
use aws_sdk_cloudwatchlogs::{config::Region, Client};
use hiveguard_core::config::{AwsCredentialsConfig, CloudWatchSourceConfig};
use hiveguard_core::errors::HiveGuardError;
use hiveguard_core::models::NormalizedEvent;
use hiveguard_ingest::LogSource;
use tokio::sync::{mpsc, watch};
use tokio::time::sleep;
use tracing::{debug, info, warn};

use crate::checkpoint::CloudWatchCheckpoints;
use crate::deserializer::MessageRouter;

// ---------------------------------------------------------------------------
// Public struct
// ---------------------------------------------------------------------------

/// CloudWatch Logs log source.
pub struct CloudWatchSource {
    config: CloudWatchSourceConfig,
    /// Root directory used to persist per-group checkpoints.
    data_dir: PathBuf,
    stop_tx: Option<watch::Sender<bool>>,
}

impl CloudWatchSource {
    pub fn new(config: CloudWatchSourceConfig, data_dir: impl AsRef<Path>) -> Self {
        Self {
            config,
            data_dir: data_dir.as_ref().to_path_buf(),
            stop_tx: None,
        }
    }
}

// ---------------------------------------------------------------------------
// LogSource implementation
// ---------------------------------------------------------------------------

#[async_trait]
impl LogSource for CloudWatchSource {
    fn name(&self) -> &str {
        "cloudwatch"
    }

    async fn start(&mut self, sender: mpsc::Sender<NormalizedEvent>) -> Result<(), HiveGuardError> {
        let client = build_aws_client(&self.config.region, self.config.credentials.as_ref())
            .await
            .map_err(|e| HiveGuardError::Config(format!("CloudWatch AWS client build failed: {e}")))?;

        let checkpoints = Arc::new(tokio::sync::Mutex::new(CloudWatchCheckpoints::load(
            &self.data_dir,
        )));

        info!(
            log_groups = ?self.config.log_group_names,
            "CloudWatch: starting ingestion"
        );

        let (stop_tx, stop_rx) = watch::channel(false);
        self.stop_tx = Some(stop_tx);

        let router = Arc::new(MessageRouter::new());
        let config = Arc::new(self.config.clone());
        let data_dir = Arc::new(self.data_dir.clone());

        for log_group in &self.config.log_group_names {
            let log_group = log_group.clone();
            let client = client.clone();
            let sender = sender.clone();
            let stop_rx = stop_rx.clone();
            let router = Arc::clone(&router);
            let config = Arc::clone(&config);
            let data_dir = Arc::clone(&data_dir);
            let checkpoints = Arc::clone(&checkpoints);

            tokio::spawn(async move {
                run_log_group_consumer(
                    client,
                    sender,
                    config,
                    data_dir,
                    checkpoints,
                    router,
                    log_group,
                    stop_rx,
                )
                .await;
            });
        }

        Ok(())
    }

    async fn stop(&mut self) -> Result<(), HiveGuardError> {
        if let Some(tx) = self.stop_tx.take() {
            let _ = tx.send(true);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Per-log-group consumer task
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
async fn run_log_group_consumer(
    client: Client,
    sender: mpsc::Sender<NormalizedEvent>,
    config: Arc<CloudWatchSourceConfig>,
    data_dir: Arc<PathBuf>,
    checkpoints: Arc<tokio::sync::Mutex<CloudWatchCheckpoints>>,
    router: Arc<MessageRouter>,
    log_group: String,
    mut stop_rx: watch::Receiver<bool>,
) {
    let source_name = format!("cloudwatch/{}", log_group);
    let poll_duration = Duration::from_secs(config.poll_interval_secs);

    info!(log_group = %log_group, "CloudWatch: log group consumer started");

    loop {
        if *stop_rx.borrow() {
            debug!(log_group = %log_group, "CloudWatch: stop signal received");
            break;
        }

        // Determine start_time from checkpoint (add 1 ms to avoid re-reading
        // the last event, CloudWatch timestamps are inclusive).
        let start_time: Option<i64> = {
            let cp = checkpoints.lock().await;
            cp.get(&log_group).map(|t| t + 1)
        };

        match poll_log_group(
            &client,
            &config,
            &log_group,
            start_time,
            &sender,
            &source_name,
            &router,
        )
        .await
        {
            Ok(Some(max_ts)) => {
                let mut cp = checkpoints.lock().await;
                cp.set(&log_group, max_ts);
                cp.save(&data_dir);
            }
            Ok(None) => {
                // No new events.
            }
            Err(e) => {
                warn!(log_group = %log_group, error = %e, "CloudWatch: poll error");
            }
        }

        sleep(poll_duration).await;
    }

    info!(log_group = %log_group, "CloudWatch: log group consumer stopped");
}

/// Poll a single log group and return the maximum event timestamp seen (ms),
/// or `None` if no events were returned.
async fn poll_log_group(
    client: &Client,
    config: &CloudWatchSourceConfig,
    log_group: &str,
    start_time: Option<i64>,
    sender: &mpsc::Sender<NormalizedEvent>,
    source_name: &str,
    router: &MessageRouter,
) -> Result<Option<i64>, Box<dyn std::error::Error + Send + Sync>> {
    let mut next_token: Option<String> = None;
    let mut max_timestamp: Option<i64> = None;

    loop {
        let mut req = client
            .filter_log_events()
            .log_group_name(log_group)
            .limit(config.batch_size);

        if let Some(t) = start_time {
            req = req.start_time(t);
        }
        if let Some(ref pattern) = config.filter_pattern {
            req = req.filter_pattern(pattern);
        }
        if let Some(ref token) = next_token {
            req = req.next_token(token);
        }

        let resp = req.send().await?;
        let events = resp.events();

        for event in events {
            let message = match event.message() {
                Some(m) => m,
                None => continue,
            };

            let ts = event.timestamp();
            if let Some(t) = ts {
                max_timestamp = Some(max_timestamp.map_or(t, |prev: i64| prev.max(t)));
            }

            let trimmed = message.trim();
            if trimmed.is_empty() {
                continue;
            }

            if let Some(normalized) = router.route_line(trimmed, &config.parser, source_name) {
                if sender.send(normalized).await.is_err() {
                    debug!(log_group = %log_group, "CloudWatch: channel closed");
                    return Ok(max_timestamp);
                }
            }
        }

        match resp.next_token() {
            Some(token) => next_token = Some(token.to_string()),
            None => break,
        }
    }

    Ok(max_timestamp)
}

// ---------------------------------------------------------------------------
// AWS helpers (shared pattern with kinesis.rs)
// ---------------------------------------------------------------------------

async fn build_aws_client(
    region: &str,
    credentials: Option<&AwsCredentialsConfig>,
) -> Result<Client, Box<dyn std::error::Error + Send + Sync>> {
    let region = Region::new(region.to_string());

    let sdk_config = if let Some(creds) = credentials {
        let static_creds = AwsCredentials::new(
            &creds.access_key_id,
            &creds.secret_access_key,
            creds.session_token.clone(),
            None,
            "hiveguard-config",
        );
        aws_config::defaults(BehaviorVersion::latest())
            .credentials_provider(static_creds)
            .region(region)
            .load()
            .await
    } else {
        aws_config::defaults(BehaviorVersion::latest())
            .region(region)
            .load()
            .await
    };

    Ok(Client::new(&sdk_config))
}
