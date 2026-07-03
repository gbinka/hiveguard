//! Sigma rule directory loader and hot-reload watcher.
//!
//! # Loading
//!
//! [`load_rules_from_dir`] scans a directory for `.yml`/`.yaml` files,
//! parses each as a Sigma rule, and returns the successfully parsed rules.
//! Parse errors are logged as warnings; the faulty file is skipped.
//!
//! # Hot-reload
//!
//! [`spawn_hot_reload_watcher`] starts a Tokio task that uses the `notify`
//! crate to watch for file-system changes. On any create/modify/remove event
//! in the watched directory the rule set is re-parsed and atomically swapped
//! into the shared `SharedSigmaRules` handle.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use notify::{EventKind, RecursiveMode, Watcher};
use tokio::sync::{mpsc, watch};
use tracing::{info, warn};

use crate::detector::SharedSigmaRules;
use crate::rule::SigmaRule;

// ---------------------------------------------------------------------------
// Directory loader
// ---------------------------------------------------------------------------

/// Load all `.yml` / `.yaml` Sigma rules from `dir`.
///
/// Returns only successfully parsed rules. Parse errors are logged and
/// the offending file is skipped.
pub fn load_rules_from_dir(dir: &Path) -> Vec<SigmaRule> {
    let mut rules = Vec::new();

    let read_dir = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) => {
            warn!("Cannot read sigma rules directory {:?}: {}", dir, e);
            return rules;
        }
    };

    for entry in read_dir.flatten() {
        let path = entry.path();
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        if ext != "yml" && ext != "yaml" {
            continue;
        }

        let text = match std::fs::read_to_string(&path) {
            Ok(t) => t,
            Err(e) => {
                warn!("Failed to read sigma rule {:?}: {}", path, e);
                continue;
            }
        };

        match SigmaRule::from_yaml(&text) {
            Ok(rule) => {
                info!(title = %rule.title, path = ?path, "Loaded Sigma rule");
                rules.push(rule);
            }
            Err(e) => {
                warn!("Failed to parse sigma rule {:?}: {}", path, e);
            }
        }
    }

    info!(count = rules.len(), dir = ?dir, "Sigma rules loaded from directory");
    rules
}

// ---------------------------------------------------------------------------
// Hot-reload watcher
// ---------------------------------------------------------------------------

/// Spawn a background Tokio task that watches `dir` for file changes and
/// hot-reloads the Sigma rule set into `rules_handle`.
///
/// The task exits when `shutdown` fires.
///
/// Returns the `JoinHandle` of the watcher task.
pub fn spawn_hot_reload_watcher(
    dir: PathBuf,
    rules_handle: SharedSigmaRules,
    mut shutdown: watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let (notify_tx, mut notify_rx) = mpsc::channel::<()>(16);
        let notify_tx_clone = notify_tx.clone();

        // Build the notify watcher synchronously.
        let mut watcher = match notify::recommended_watcher(
            move |res: notify::Result<notify::Event>| {
                if let Ok(event) = res {
                    let relevant = matches!(
                        event.kind,
                        EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_)
                    );
                    if relevant {
                        let _ = notify_tx_clone.blocking_send(());
                    }
                }
            },
        ) {
            Ok(w) => w,
            Err(e) => {
                warn!("Failed to create Sigma rules file watcher: {}", e);
                return;
            }
        };

        if let Err(e) = watcher.watch(&dir, RecursiveMode::NonRecursive) {
            warn!("Failed to watch Sigma rules directory {:?}: {}", dir, e);
            return;
        }

        info!(dir = ?dir, "Sigma rules hot-reload watcher started");

        loop {
            tokio::select! {
                Some(()) = notify_rx.recv() => {
                    // Drain any buffered change notifications (debounce).
                    while notify_rx.try_recv().is_ok() {}
                    // Small delay to let the OS finish writing files.
                    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

                    let new_rules = load_rules_from_dir(&dir);
                    let count = new_rules.len();
                    rules_handle.store(Arc::new(new_rules));
                    info!(count = count, "Sigma rules hot-reloaded");
                }
                _ = shutdown.changed() => {
                    info!("Sigma rules hot-reload watcher stopping");
                    break;
                }
            }
        }
    })
}
