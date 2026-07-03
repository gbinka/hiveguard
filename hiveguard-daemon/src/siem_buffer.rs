//! Persistent SIEM Retry Buffer — Phase 3.3.3
//!
//! Provides a file-backed queue for SIEM events that could not be delivered
//! immediately.  Events are serialized as JSON lines (NDJSON) and stored under
//! `<dir>/<name>_retry.ndjson`.
//!
//! # Usage by exporters
//!
//! ```rust,ignore
//! let buf = PersistentBuffer::new(data_dir.join("siem_buffer"), "splunk", 50 * 1024 * 1024);
//! // On delivery failure:
//! buf.push(&failed_events).await;
//! // On next startup or retry cycle:
//! let retry = buf.drain().await;
//! ```
//!
//! # Design
//!
//! - **Format**: NDJSON — one `SiemEvent` JSON object per line.
//! - **Limit**: configurable `max_bytes`.  When exceeded, the oldest lines
//!   are pruned to bring the file back under the limit.
//! - **Atomicity**: file writes use `append` mode; partial writes are
//!   tolerated (malformed lines are skipped silently on drain).
//! - **Thread-safety**: `PersistentBuffer` is `Clone + Send + Sync`; it
//!   holds only a `PathBuf` and the size limit.

use std::path::PathBuf;

use tracing::{error, warn};

use crate::siem_exporter::SiemEvent;

/// Default maximum buffer size: 50 MiB.
pub const DEFAULT_MAX_BYTES: u64 = 50 * 1024 * 1024;

/// File-backed NDJSON retry buffer for a single SIEM exporter.
#[derive(Clone, Debug)]
pub struct PersistentBuffer {
    /// Full path to the NDJSON buffer file.
    path: PathBuf,
    /// Maximum allowed file size in bytes.  Oldest lines are pruned when
    /// exceeded after a write.
    max_bytes: u64,
}

impl PersistentBuffer {
    /// Create a new buffer backed by `<dir>/<name>_retry.ndjson`.
    ///
    /// The directory is created on first write; missing files are fine.
    pub fn new(dir: PathBuf, name: &str, max_bytes: u64) -> Self {
        let path = dir.join(format!("{name}_retry.ndjson"));
        Self { path, max_bytes }
    }

    /// Append `events` to the buffer file.  Prunes the file to `max_bytes`
    /// afterwards if necessary.
    pub async fn push(&self, events: &[SiemEvent]) {
        use tokio::io::AsyncWriteExt;

        if events.is_empty() {
            return;
        }

        // Ensure parent directory exists.
        if let Some(parent) = self.path.parent() {
            if let Err(e) = tokio::fs::create_dir_all(parent).await {
                error!(error = %e, "PersistentBuffer: failed to create directory");
                return;
            }
        }

        // Serialize events as NDJSON.
        let mut blob = String::new();
        for ev in events {
            match serde_json::to_string(ev) {
                Ok(line) => {
                    blob.push_str(&line);
                    blob.push('\n');
                }
                Err(e) => warn!(error = %e, "PersistentBuffer: failed to serialize event"),
            }
        }

        // Append to file. Determine the post-write size from the open handle
        // (fstat after flush) rather than a separate path stat — the latter can
        // race the just-written append under load and miss it, leaving the
        // buffer over the limit until the next push.
        let written_len = match tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .await
        {
            Ok(mut f) => {
                if let Err(e) = f.write_all(blob.as_bytes()).await {
                    error!(error = %e, "PersistentBuffer: write failed");
                    return;
                }
                if let Err(e) = f.flush().await {
                    error!(error = %e, "PersistentBuffer: flush failed");
                    return;
                }
                f.metadata().await.map(|m| m.len()).ok()
            }
            Err(e) => {
                error!(error = %e, path = %self.path.display(), "PersistentBuffer: open failed");
                return;
            }
        };

        // Prune if over the size limit.
        if let Some(len) = written_len {
            if len > self.max_bytes {
                self.prune_to_limit().await;
            }
        }
    }

    /// Read all events from the buffer file and truncate it on success.
    ///
    /// Malformed lines are silently skipped so a single corrupt entry does
    /// not prevent draining the rest.
    pub async fn drain(&self) -> Vec<SiemEvent> {
        let content = match tokio::fs::read_to_string(&self.path).await {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Vec::new(),
            Err(e) => {
                error!(error = %e, "PersistentBuffer: drain read failed");
                return Vec::new();
            }
        };

        let events: Vec<SiemEvent> = content
            .lines()
            .filter_map(|line| {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    return None;
                }
                serde_json::from_str(trimmed)
                    .map_err(|e| warn!(error = %e, "PersistentBuffer: skipping malformed line"))
                    .ok()
            })
            .collect();

        // Truncate after successful read.
        if let Err(e) = tokio::fs::remove_file(&self.path).await {
            if e.kind() != std::io::ErrorKind::NotFound {
                warn!(error = %e, "PersistentBuffer: could not remove after drain");
            }
        }

        events
    }

    /// Return the current on-disk size in bytes (0 if the file does not exist).
    pub async fn size_bytes(&self) -> u64 {
        tokio::fs::metadata(&self.path)
            .await
            .map(|m| m.len())
            .unwrap_or(0)
    }

    /// Remove the oldest lines until the file is under `max_bytes`.
    ///
    /// Called automatically after each `push` that overshoots the limit.
    pub async fn prune_to_limit(&self) {
        let content = match tokio::fs::read_to_string(&self.path).await {
            Ok(s) => s,
            Err(_) => return,
        };

        let lines: Vec<&str> = content.lines().collect();
        let total_lines = lines.len();
        if total_lines == 0 {
            return;
        }

        // Drop the front of the file until we're under the limit.
        let mut keep_from = 0usize;
        let mut current_size = content.len() as u64;
        for (i, line) in lines.iter().enumerate() {
            if current_size <= self.max_bytes {
                break;
            }
            current_size -= (line.len() as u64) + 1; // +1 for '\n'
            keep_from = i + 1;
        }

        if keep_from >= total_lines {
            // Everything would be pruned — clear the file.
            let _ = tokio::fs::write(&self.path, b"").await;
            warn!(
                path = %self.path.display(),
                "PersistentBuffer: entire buffer pruned (over size limit)"
            );
            return;
        }

        let kept = lines[keep_from..].join("\n") + "\n";
        let pruned_count = keep_from;
        if let Err(e) = tokio::fs::write(&self.path, kept.as_bytes()).await {
            error!(error = %e, "PersistentBuffer: prune write failed");
        } else {
            warn!(
                pruned = pruned_count,
                path = %self.path.display(),
                "PersistentBuffer: pruned oldest events to stay under size limit"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn make_event(src_ip: &str) -> SiemEvent {
        SiemEvent {
            src_ip: src_ip.to_string(),
            reason: "test".to_string(),
            severity: 100,
            detector: "test_detector".to_string(),
            ban_duration: "1h".to_string(),
            country: None,
            asn: None,
            event_class: "BanTriggered".to_string(),
            timestamp: "2026-05-21T00:00:00Z".to_string(),
        }
    }

    #[tokio::test]
    async fn push_and_drain_roundtrip() {
        let dir = TempDir::new().unwrap();
        let buf = PersistentBuffer::new(dir.path().to_path_buf(), "test", DEFAULT_MAX_BYTES);

        let events = vec![make_event("1.2.3.4"), make_event("5.6.7.8")];
        buf.push(&events).await;
        let drained = buf.drain().await;

        assert_eq!(drained.len(), 2);
        assert_eq!(drained[0].src_ip, "1.2.3.4");
        assert_eq!(drained[1].src_ip, "5.6.7.8");
    }

    #[tokio::test]
    async fn drain_empty_returns_empty() {
        let dir = TempDir::new().unwrap();
        let buf = PersistentBuffer::new(dir.path().to_path_buf(), "empty", DEFAULT_MAX_BYTES);
        let events = buf.drain().await;
        assert!(events.is_empty());
    }

    #[tokio::test]
    async fn drain_clears_file() {
        let dir = TempDir::new().unwrap();
        let buf = PersistentBuffer::new(dir.path().to_path_buf(), "clear", DEFAULT_MAX_BYTES);
        buf.push(&[make_event("1.1.1.1")]).await;
        assert!(buf.size_bytes().await > 0);
        buf.drain().await;
        assert_eq!(buf.size_bytes().await, 0);
    }

    #[tokio::test]
    async fn multiple_pushes_accumulate() {
        let dir = TempDir::new().unwrap();
        let buf = PersistentBuffer::new(dir.path().to_path_buf(), "acc", DEFAULT_MAX_BYTES);
        buf.push(&[make_event("1.1.1.1")]).await;
        buf.push(&[make_event("2.2.2.2")]).await;
        buf.push(&[make_event("3.3.3.3")]).await;
        let events = buf.drain().await;
        assert_eq!(events.len(), 3);
    }

    #[tokio::test]
    async fn prune_removes_oldest_events() {
        let dir = TempDir::new().unwrap();
        // Very small max: ~60 bytes — forces pruning after a few events
        let buf = PersistentBuffer::new(dir.path().to_path_buf(), "prune", 60);
        // Push enough events to overflow the limit
        for i in 0..10u8 {
            buf.push(&[make_event(&format!("{i}.{i}.{i}.{i}"))]).await;
        }
        // After pruning the buffer must be ≤ 60 bytes
        let size = buf.size_bytes().await;
        assert!(
            size <= 60,
            "expected buffer ≤ 60 bytes after pruning, got {size}"
        );
    }

    #[tokio::test]
    async fn push_empty_slice_is_noop() {
        let dir = TempDir::new().unwrap();
        let buf = PersistentBuffer::new(dir.path().to_path_buf(), "noop", DEFAULT_MAX_BYTES);
        buf.push(&[]).await;
        assert_eq!(buf.size_bytes().await, 0);
        // Buffer file must not exist
        assert!(!buf.path.exists());
    }
}
