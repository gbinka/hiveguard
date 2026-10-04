//! Supervision for log source tasks: restart after errors, early returns and
//! panics, with cancellable bounded backoff and per-instance runtime status.

use std::panic::AssertUnwindSafe;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use futures::FutureExt;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

use hiveguard_core::models::NormalizedEvent;
use hiveguard_plugin_api::{LogSourcePlugin, NotifierPlugin};

/// One entry per source instance, including multiple files using the same plugin.
/// Running describes the task, not a guarantee that its external source is ready.
pub type SourceStatus = Arc<RwLock<Vec<(String, String)>>>;

pub fn spawn_log_source(
    plugin: Box<dyn LogSourcePlugin>,
    sink: tokio::sync::mpsc::Sender<NormalizedEvent>,
    shutdown: CancellationToken,
) -> JoinHandle<()> {
    spawn_log_source_monitored(plugin, sink, shutdown, SourceStatus::default())
}

pub fn spawn_log_source_monitored(
    mut plugin: Box<dyn LogSourcePlugin>,
    sink: tokio::sync::mpsc::Sender<NormalizedEvent>,
    shutdown: CancellationToken,
    status: SourceStatus,
) -> JoinHandle<()> {
    let plugin_id = plugin.manifest().id.to_owned();
    let index = {
        let mut entries = status.write().unwrap_or_else(|e| e.into_inner());
        let index = entries.len();
        entries.push((plugin_id.clone(), "Starting".into()));
        index
    };
    tokio::spawn(async move {
        let update = |value: String| {
            status.write().unwrap_or_else(|e| e.into_inner())[index].1 = value;
        };
        let mut delay = Duration::from_secs(1);
        while !shutdown.is_cancelled() && !sink.is_closed() {
            update("Running".into());
            info!(plugin = %plugin_id, "log source starting");
            let started = tokio::time::Instant::now();
            // Keep the same instance so journal cursors and other recovery
            // state survive. Panics are contained in the supervised future.
            let result =
                AssertUnwindSafe(async { plugin.run(sink.clone(), shutdown.clone()).await })
                    .catch_unwind()
                    .await;
            if shutdown.is_cancelled() || sink.is_closed() {
                break;
            }
            let reason = match result {
                Ok(Ok(())) => "unexpected successful return".to_string(),
                Ok(Err(error)) => error.to_string(),
                Err(_) => "task panicked".to_string(),
            };
            if started.elapsed() >= Duration::from_secs(60) {
                delay = Duration::from_secs(1);
            }
            error!(plugin = %plugin_id, error = %reason, retry_seconds = delay.as_secs(), "log source exited; restarting");
            update(format!("Restarting: {reason}"));
            tokio::select! {
                _ = shutdown.cancelled() => break,
                _ = sink.closed() => break,
                _ = tokio::time::sleep(delay) => {}
            }
            delay = (delay * 2).min(Duration::from_secs(30));
        }
        update("Stopped".into());
        info!(plugin = %plugin_id, "log source stopped");
    })
}

/// Wrap a vector of notifier plugins behind an `Arc<Mutex<...>>` so the
/// daemon's existing alert dispatcher (legacy `alert_manager.rs`) can pull
/// from it without taking ownership.
///
/// Returns `None` when the input is empty so callers can short-circuit
/// alert plumbing.
pub fn share_notifiers(
    notifiers: Vec<Box<dyn NotifierPlugin>>,
) -> Option<Arc<Mutex<Vec<Box<dyn NotifierPlugin>>>>> {
    if notifiers.is_empty() {
        None
    } else {
        Some(Arc::new(Mutex::new(notifiers)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hiveguard_plugin_api::prelude::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Clone, Copy)]
    enum Exit {
        Error,
        Success,
        Panic,
    }

    struct TestSource {
        manifest: PluginManifest,
        calls: Arc<AtomicUsize>,
        exit: Exit,
        always_exit: bool,
    }

    #[async_trait]
    impl Plugin for TestSource {
        fn manifest(&self) -> &PluginManifest {
            &self.manifest
        }
        async fn init(&mut self, _: serde_json::Value) -> PluginResult<()> {
            Ok(())
        }
    }

    #[async_trait]
    impl LogSourcePlugin for TestSource {
        async fn run(&mut self, _: EventSink, shutdown: CancellationToken) -> PluginResult<()> {
            let attempt = self.calls.fetch_add(1, Ordering::SeqCst);
            if attempt > 0 && !self.always_exit {
                shutdown.cancelled().await;
                return Ok(());
            }
            match self.exit {
                Exit::Error => Err(PluginError::Runtime("test source EOF".into())),
                Exit::Success => Ok(()),
                Exit::Panic => panic!("test source panic"),
            }
        }
    }

    fn source(exit: Exit, always_exit: bool) -> (Box<dyn LogSourcePlugin>, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let source = TestSource {
            manifest: PluginManifest {
                id: "source.test",
                version: "0.1.0",
                description: "test",
                kind: PluginKind::LogSource,
                author: "test",
                docs_url: None,
            },
            calls: calls.clone(),
            exit,
            always_exit,
        };
        (Box::new(source), calls)
    }

    async fn assert_restarts(exit: Exit) {
        let (source, calls) = source(exit, false);
        let (sink, _receiver) = tokio::sync::mpsc::channel(1);
        let shutdown = CancellationToken::new();
        let status = SourceStatus::default();
        let task = spawn_log_source_monitored(source, sink, shutdown.clone(), status.clone());
        tokio::task::yield_now().await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(status.read().unwrap()[0].1.starts_with("Restarting:"));
        tokio::time::advance(Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(status.read().unwrap()[0].1, "Running");
        shutdown.cancel();
        task.await.unwrap();
        assert_eq!(status.read().unwrap()[0].1, "Stopped");
    }

    #[tokio::test(start_paused = true)]
    async fn restarts_after_error() {
        assert_restarts(Exit::Error).await;
    }

    #[tokio::test(start_paused = true)]
    async fn restarts_after_early_ok() {
        assert_restarts(Exit::Success).await;
    }

    #[tokio::test(start_paused = true)]
    async fn restarts_after_panic() {
        assert_restarts(Exit::Panic).await;
    }

    #[tokio::test(start_paused = true)]
    async fn retry_backoff_increases_and_is_cancellable() {
        let (source, calls) = source(Exit::Error, true);
        let (sink, _receiver) = tokio::sync::mpsc::channel(1);
        let shutdown = CancellationToken::new();
        let task = spawn_log_source(source, sink, shutdown.clone());
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        tokio::time::advance(Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        shutdown.cancel();
        task.await.unwrap();
        tokio::time::advance(Duration::from_secs(60)).await;
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn closed_sink_stops_retrying() {
        let (source, calls) = source(Exit::Error, true);
        let (sink, receiver) = tokio::sync::mpsc::channel(1);
        let task = spawn_log_source(source, sink, CancellationToken::new());
        tokio::task::yield_now().await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        drop(receiver);
        task.await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}
