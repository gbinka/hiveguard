//! File-based checkpointing for queue sources (Phase 6.2).
//!
//! Both Kinesis and CloudWatch need to persist their reading position so
//! that a daemon restart does not re-process already-seen records.
//!
//! Checkpoints are written atomically: a temporary file is created first,
//! then renamed to the final path, which is an atomic operation on POSIX
//! file systems.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

// ---------------------------------------------------------------------------
// Kinesis checkpoint
// ---------------------------------------------------------------------------

/// Per-stream, per-shard sequence number checkpoints.
///
/// Stored as `<data_dir>/kinesis_checkpoints.json`:
/// ```json
/// {
///   "my-stream": {
///     "shardId-000000000000": "49590338...",
///     "shardId-000000000001": "49590338..."
///   }
/// }
/// ```
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct KinesisCheckpoints {
    /// outer key: stream_name, inner key: shard_id, value: sequence_number
    #[serde(flatten)]
    pub streams: HashMap<String, HashMap<String, String>>,
}

impl KinesisCheckpoints {
    /// Load from disk, returning an empty checkpoint on any error.
    pub fn load(data_dir: &Path) -> Self {
        let path = kinesis_checkpoint_path(data_dir);
        match std::fs::read_to_string(&path) {
            Ok(text) => serde_json::from_str(&text).unwrap_or_else(|e| {
                warn!(path = %path.display(), error = %e, "Kinesis checkpoint parse error, starting fresh");
                Self::default()
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                debug!(path = %path.display(), "No Kinesis checkpoint found, starting fresh");
                Self::default()
            }
            Err(e) => {
                warn!(path = %path.display(), error = %e, "Failed to read Kinesis checkpoint");
                Self::default()
            }
        }
    }

    /// Atomically save to disk.
    pub fn save(&self, data_dir: &Path) {
        let path = kinesis_checkpoint_path(data_dir);
        atomic_write_json(&path, self);
    }

    /// Get the last known sequence number for a shard.
    pub fn get(&self, stream: &str, shard_id: &str) -> Option<&str> {
        self.streams.get(stream)?.get(shard_id).map(String::as_str)
    }

    /// Update the sequence number for a shard.
    pub fn set(&mut self, stream: &str, shard_id: &str, sequence: String) {
        self.streams
            .entry(stream.to_string())
            .or_default()
            .insert(shard_id.to_string(), sequence);
    }
}

fn kinesis_checkpoint_path(data_dir: &Path) -> PathBuf {
    data_dir.join("kinesis_checkpoints.json")
}

// ---------------------------------------------------------------------------
// CloudWatch checkpoint
// ---------------------------------------------------------------------------

/// Per-log-group timestamp checkpoints (milliseconds since Unix epoch).
///
/// Stored as `<data_dir>/cloudwatch_checkpoints.json`:
/// ```json
/// {
///   "/aws/lambda/api": 1716230400000,
///   "/ecs/nginx": 1716230350000
/// }
/// ```
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct CloudWatchCheckpoints {
    /// log_group_name → last processed event timestamp (ms)
    #[serde(flatten)]
    pub groups: HashMap<String, i64>,
}

impl CloudWatchCheckpoints {
    /// Load from disk, returning an empty checkpoint on any error.
    pub fn load(data_dir: &Path) -> Self {
        let path = cloudwatch_checkpoint_path(data_dir);
        match std::fs::read_to_string(&path) {
            Ok(text) => serde_json::from_str(&text).unwrap_or_else(|e| {
                warn!(path = %path.display(), error = %e, "CloudWatch checkpoint parse error");
                Self::default()
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                debug!(path = %path.display(), "No CloudWatch checkpoint found, starting fresh");
                Self::default()
            }
            Err(e) => {
                warn!(path = %path.display(), error = %e, "Failed to read CloudWatch checkpoint");
                Self::default()
            }
        }
    }

    /// Atomically save to disk.
    pub fn save(&self, data_dir: &Path) {
        let path = cloudwatch_checkpoint_path(data_dir);
        atomic_write_json(&path, self);
    }

    /// Get the last seen timestamp for a log group (ms).
    pub fn get(&self, group: &str) -> Option<i64> {
        self.groups.get(group).copied()
    }

    /// Update the timestamp for a log group.
    pub fn set(&mut self, group: &str, timestamp_ms: i64) {
        self.groups.insert(group.to_string(), timestamp_ms);
    }
}

fn cloudwatch_checkpoint_path(data_dir: &Path) -> PathBuf {
    data_dir.join("cloudwatch_checkpoints.json")
}

// ---------------------------------------------------------------------------
// Atomic write helper
// ---------------------------------------------------------------------------

fn atomic_write_json<T: Serialize>(path: &Path, value: &T) {
    let text = match serde_json::to_string_pretty(value) {
        Ok(t) => t,
        Err(e) => {
            warn!(path = %path.display(), error = %e, "Checkpoint serialisation error");
            return;
        }
    };

    // Write to a temporary file next to the destination, then rename.
    let tmp = path.with_extension("json.tmp");
    if let Err(e) = std::fs::write(&tmp, &text) {
        warn!(path = %tmp.display(), error = %e, "Failed to write checkpoint tmp file");
        return;
    }
    if let Err(e) = std::fs::rename(&tmp, path) {
        warn!(
            src = %tmp.display(), dst = %path.display(),
            error = %e, "Failed to rename checkpoint file"
        );
    }
}
