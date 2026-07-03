//! AWS Kinesis Data Streams consumer — Phase 6.2.1.
//!
//! Implements [`LogSource`] for Kinesis Data Streams.
//!
//! # Design
//!
//! * One polling task is spawned **per shard** so that multiple shards are read
//!   concurrently.
//! * Shard iterators are obtained using the cheapest approach: if a checkpoint
//!   exists for the shard, `AT_SEQUENCE_NUMBER` is used; otherwise the
//!   configured [`KinesisStartPosition`] is applied.
//! * After each successful `GetRecords` batch the checkpoint is saved to disk
//!   atomically so a daemon restart picks up from roughly the last processed
//!   position.
//! * Kinesis allows at most 5 `GetRecords` calls per shard per second.  The
//!   configurable `poll_interval_ms` (default 1 000 ms) stays safely below that
//!   limit.
//! * A `watch::Receiver<bool>` is used for cooperative stop signalling.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use aws_config::BehaviorVersion;
use aws_credential_types::Credentials as AwsCredentials;
use aws_sdk_kinesis::{
    config::Region,
    types::{Shard, ShardIteratorType},
    Client,
};
use hiveguard_core::config::{AwsCredentialsConfig, KinesisSourceConfig, KinesisStartPosition};
use hiveguard_core::errors::HiveGuardError;
use hiveguard_core::models::NormalizedEvent;
use hiveguard_ingest::LogSource;
use tokio::sync::{mpsc, watch};
use tokio::time::sleep;
use tracing::{debug, error, info, warn};

use crate::checkpoint::KinesisCheckpoints;
use crate::deserializer::MessageRouter;

// ---------------------------------------------------------------------------
// Public struct
// ---------------------------------------------------------------------------

/// Kinesis Data Streams log source.
pub struct KinesisSource {
    config: KinesisSourceConfig,
    /// Root directory used to persist shard checkpoints.
    data_dir: PathBuf,
    stop_tx: Option<watch::Sender<bool>>,
}

impl KinesisSource {
    pub fn new(config: KinesisSourceConfig, data_dir: impl AsRef<Path>) -> Self {
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
impl LogSource for KinesisSource {
    fn name(&self) -> &str {
        &self.config.stream_name
    }

    async fn start(
        &mut self,
        sender: mpsc::Sender<NormalizedEvent>,
    ) -> Result<(), HiveGuardError> {
        let client = build_aws_client(&self.config.region, self.config.credentials.as_ref())
            .await
            .map_err(|e| HiveGuardError::Config(format!("Kinesis AWS client build failed: {e}")))?;

        let checkpoints = Arc::new(tokio::sync::Mutex::new(KinesisCheckpoints::load(
            &self.data_dir,
        )));

        let shards = list_shards(&client, &self.config.stream_name)
            .await
            .map_err(|e| HiveGuardError::Storage(format!("Kinesis list_shards failed: {e}")))?;

        info!(
            stream = %self.config.stream_name,
            shard_count = shards.len(),
            "Kinesis: starting consumer"
        );

        let (stop_tx, stop_rx) = watch::channel(false);
        self.stop_tx = Some(stop_tx);

        let router = Arc::new(MessageRouter::new());
        let config = Arc::new(self.config.clone());
        let data_dir = Arc::new(self.data_dir.clone());

        for shard in shards {
            let shard_id = shard.shard_id().to_string();

            let client = client.clone();
            let sender = sender.clone();
            let stop_rx = stop_rx.clone();
            let router = Arc::clone(&router);
            let config = Arc::clone(&config);
            let data_dir = Arc::clone(&data_dir);
            let checkpoints = Arc::clone(&checkpoints);

            tokio::spawn(async move {
                run_shard_consumer(
                    client, sender, config, data_dir, checkpoints, router, shard_id, stop_rx,
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
// Per-shard consumer task
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
async fn run_shard_consumer(
    client: Client,
    sender: mpsc::Sender<NormalizedEvent>,
    config: Arc<KinesisSourceConfig>,
    data_dir: Arc<PathBuf>,
    checkpoints: Arc<tokio::sync::Mutex<KinesisCheckpoints>>,
    router: Arc<MessageRouter>,
    shard_id: String,
    mut stop_rx: watch::Receiver<bool>,
) {
    let source_name = format!("kinesis/{}/{}", config.stream_name, shard_id);
    let poll_duration = Duration::from_millis(config.poll_interval_ms);

    // Determine starting iterator type.
    let (iterator_type, start_seq) = {
        let cp = checkpoints.lock().await;
        match cp.get(&config.stream_name, &shard_id) {
            Some(seq) => (ShardIteratorType::AfterSequenceNumber, Some(seq.to_string())),
            None => match config.start_position {
                KinesisStartPosition::TrimHorizon => (ShardIteratorType::TrimHorizon, None),
                KinesisStartPosition::Latest => (ShardIteratorType::Latest, None),
            },
        }
    };

    let mut shard_iterator = match get_shard_iterator(
        &client,
        &config.stream_name,
        &shard_id,
        iterator_type,
        start_seq,
    )
    .await
    {
        Ok(it) => it,
        Err(e) => {
            error!(shard = %shard_id, error = %e, "Kinesis: failed to get shard iterator");
            return;
        }
    };

    info!(shard = %shard_id, "Kinesis: shard consumer started");

    loop {
        if *stop_rx.borrow() {
            debug!(shard = %shard_id, "Kinesis: stop signal received");
            break;
        }

        let current_iter = match shard_iterator.take() {
            Some(it) => it,
            None => {
                debug!(shard = %shard_id, "Kinesis: shard iterator exhausted (shard sealed)");
                break;
            }
        };

        let resp = match client
            .get_records()
            .shard_iterator(&current_iter)
            .limit(config.batch_size)
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                warn!(shard = %shard_id, error = %e, "Kinesis: GetRecords error, retrying");
                sleep(poll_duration).await;
                shard_iterator =
                    re_acquire_iterator(&client, &config, &checkpoints, &shard_id).await;
                continue;
            }
        };

        let next_iterator = resp.next_shard_iterator().map(String::from);
        let records = resp.records();

        let mut last_seq: Option<String> = None;
        for record in records {
            let data = record.data().as_ref();
            let raw = match std::str::from_utf8(data) {
                Ok(s) => s,
                Err(_) => {
                    warn!(shard = %shard_id, "Kinesis: non-UTF-8 record, skipping");
                    continue;
                }
            };
            for line in raw.lines() {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                if let Some(event) = router.route_line(trimmed, &config.parser, &source_name) {
                    if sender.send(event).await.is_err() {
                        debug!(shard = %shard_id, "Kinesis: channel closed, stopping");
                        return;
                    }
                }
            }
            // sequence_number() returns &str (non-optional) in SDK 1.92+
            last_seq = Some(record.sequence_number().to_string());
        }

        // Persist checkpoint after successful batch.
        if let Some(seq) = last_seq {
            let mut cp = checkpoints.lock().await;
            cp.set(&config.stream_name, &shard_id, seq);
            cp.save(&data_dir);
        }

        shard_iterator = next_iterator;

        // Respect Kinesis rate limit: max 5 GetRecords/sec per shard.
        sleep(poll_duration).await;
    }

    info!(shard = %shard_id, "Kinesis: shard consumer stopped");
}

// ---------------------------------------------------------------------------
// AWS helpers
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

async fn list_shards(
    client: &Client,
    stream_name: &str,
) -> Result<Vec<Shard>, Box<dyn std::error::Error + Send + Sync>> {
    let mut shards = Vec::new();
    let mut next_token: Option<String> = None;

    loop {
        let mut req = client.list_shards();

        if let Some(ref token) = next_token {
            // Use next_token for pagination (cannot combine with stream_name).
            req = req.next_token(token);
        } else {
            req = req.stream_name(stream_name);
        }

        let resp = req.send().await?;
        shards.extend(resp.shards().to_vec());

        match resp.next_token() {
            Some(token) => next_token = Some(token.to_string()),
            None => break,
        }
    }

    Ok(shards)
}

async fn get_shard_iterator(
    client: &Client,
    stream_name: &str,
    shard_id: &str,
    iterator_type: ShardIteratorType,
    sequence_number: Option<String>,
) -> Result<Option<String>, Box<dyn std::error::Error + Send + Sync>> {
    let mut req = client
        .get_shard_iterator()
        .stream_name(stream_name)
        .shard_id(shard_id)
        .shard_iterator_type(iterator_type);

    if let Some(seq) = sequence_number {
        req = req.starting_sequence_number(seq);
    }

    let resp = req.send().await?;
    Ok(resp.shard_iterator().map(String::from))
}

/// Re-acquire a fresh shard iterator from the last saved checkpoint after a
/// transient `GetRecords` error.
async fn re_acquire_iterator(
    client: &Client,
    config: &KinesisSourceConfig,
    checkpoints: &tokio::sync::Mutex<KinesisCheckpoints>,
    shard_id: &str,
) -> Option<String> {
    let (iter_type, seq) = {
        let cp = checkpoints.lock().await;
        match cp.get(&config.stream_name, shard_id) {
            Some(s) => (ShardIteratorType::AfterSequenceNumber, Some(s.to_string())),
            None => (ShardIteratorType::TrimHorizon, None),
        }
    };
    match get_shard_iterator(client, &config.stream_name, shard_id, iter_type, seq).await {
        Ok(it) => it,
        Err(e) => {
            error!(shard = %shard_id, error = %e, "Kinesis: failed to re-acquire iterator");
            None
        }
    }
}
