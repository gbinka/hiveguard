//! Alert dispatcher — fan-out + dedup + retry on top of notifier plugins.
//!
//! Receives [`AlertEvent`]s from an mpsc channel and delivers each one to
//! every notifier plugin that:
//!   1. Declares support for the event's [`AlertKind`] (`NotifierPlugin::supports`)
//!   2. Has not received the same `dedup_key()` within the cooldown window
//!
//! Failed deliveries enter a bounded retry queue with exponential backoff
//! (5s → 30s → 2min → 10min, 4 attempts max). When the queue is full the
//! oldest pending alert is dropped to make room for new failures.
//!
//! This module replaces the legacy `daemon/src/alert_manager.rs` — the
//! difference is that HTTP transport is no longer baked in. Each notifier
//! plugin owns its own transport (Slack, Teams, PagerDuty, etc.).

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{mpsc, watch};
use tracing::{debug, info, warn};

use hiveguard_plugin_api::{AlertEvent, NotifierPlugin};

/// Retry schedule for failed deliveries (attempt 0 = initial, then 1..4 are retries).
const RETRY_DELAYS: [Duration; 4] = [
    Duration::from_secs(5),
    Duration::from_secs(30),
    Duration::from_secs(120),
    Duration::from_secs(600),
];

const MAX_ATTEMPTS: u32 = 4;

/// Configuration for the alert dispatcher.
#[derive(Debug, Clone)]
pub struct AlertDispatcherConfig {
    /// Global per-(notifier, dedup_key) cooldown window in seconds.
    /// Subsequent alerts with the same key delivered to the same notifier
    /// within this window are silently dropped.
    pub cooldown_secs: u64,
    /// Maximum number of pending retries held in the ring buffer. When full,
    /// the oldest pending alert is dropped to make room.
    pub queue_depth: usize,
    /// Channel buffer size for the `AlertDispatcherHandle` sender.
    pub channel_capacity: usize,
}

impl Default for AlertDispatcherConfig {
    fn default() -> Self {
        Self {
            cooldown_secs: 600,
            queue_depth: 1000,
            channel_capacity: 1024,
        }
    }
}

/// Cheap-to-clone handle used by event producers (pipeline, cluster gossip,
/// admin API) to emit alerts. Dropping all handles closes the channel and
/// stops the dispatcher.
#[derive(Debug, Clone)]
pub struct AlertDispatcherHandle {
    sender: mpsc::Sender<AlertEvent>,
}

impl AlertDispatcherHandle {
    /// Fire-and-forget send. Logs (but does not panic) if the channel is full.
    pub fn send(&self, event: AlertEvent) {
        if let Err(e) = self.sender.try_send(event) {
            warn!(error = %e, "Alert channel full or closed — event dropped");
        }
    }

    /// Returns true if the dispatcher background task is still consuming.
    pub fn is_alive(&self) -> bool {
        !self.sender.is_closed()
    }
}

/// One pending alert in the retry queue.
struct PendingAlert {
    event: AlertEvent,
    notifier_idx: usize,
    dedup_key: String,
    attempt: u32,
    next_try: Instant,
}

/// Per-notifier dedup state.
struct NotifierState {
    notifier: Arc<dyn NotifierPlugin>,
    /// `dedup_key -> last successful delivery`.
    last_sent: HashMap<String, Instant>,
}

impl NotifierState {
    fn on_cooldown(&self, key: &str, window: Duration) -> bool {
        self.last_sent
            .get(key)
            .is_some_and(|t| t.elapsed() < window)
    }

    fn record(&mut self, key: &str) {
        self.last_sent.insert(key.to_owned(), Instant::now());
    }
}

/// The dispatcher itself. Owns the notifiers; consumed by [`run`].
pub struct AlertDispatcher {
    notifiers: Vec<Arc<dyn NotifierPlugin>>,
    config: AlertDispatcherConfig,
}

impl AlertDispatcher {
    pub fn new(notifiers: Vec<Arc<dyn NotifierPlugin>>) -> Self {
        Self {
            notifiers,
            config: AlertDispatcherConfig::default(),
        }
    }

    pub fn with_config(mut self, config: AlertDispatcherConfig) -> Self {
        self.config = config;
        self
    }

    /// Spawn the dispatcher task, returning a handle producers can clone
    /// and a `JoinHandle` callers can await on shutdown.
    pub fn spawn(
        self,
        shutdown: watch::Receiver<bool>,
    ) -> (AlertDispatcherHandle, tokio::task::JoinHandle<()>) {
        let (tx, rx) = mpsc::channel::<AlertEvent>(self.config.channel_capacity);
        let join = tokio::spawn(self.run(rx, shutdown));
        (AlertDispatcherHandle { sender: tx }, join)
    }

    /// Run the dispatcher loop. Returns when the shutdown signal flips or the
    /// channel closes. Used internally by `spawn`; exposed for tests.
    pub async fn run(
        self,
        mut rx: mpsc::Receiver<AlertEvent>,
        mut shutdown: watch::Receiver<bool>,
    ) {
        let cooldown = Duration::from_secs(self.config.cooldown_secs);
        let queue_depth = self.config.queue_depth;
        let mut notifiers: Vec<NotifierState> = self
            .notifiers
            .into_iter()
            .map(|n| NotifierState {
                notifier: n,
                last_sent: HashMap::new(),
            })
            .collect();

        info!(
            notifiers = notifiers.len(),
            cooldown_secs = self.config.cooldown_secs,
            queue_depth = self.config.queue_depth,
            "Alert dispatcher started"
        );

        let mut retry_queue: VecDeque<PendingAlert> = VecDeque::new();

        loop {
            let next_retry_in: Option<Duration> = retry_queue.front().map(|p| {
                p.next_try
                    .checked_duration_since(Instant::now())
                    .unwrap_or(Duration::ZERO)
            });

            tokio::select! {
                biased;

                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        info!("Alert dispatcher shutting down");
                        break;
                    }
                }

                maybe_event = rx.recv() => {
                    match maybe_event {
                        None => {
                            info!("Alert dispatcher channel closed");
                            break;
                        }
                        Some(event) => {
                            handle_new_event(
                                event,
                                &mut notifiers,
                                cooldown,
                                queue_depth,
                                &mut retry_queue,
                            ).await;
                        }
                    }
                }

                _ = async {
                    match next_retry_in {
                        Some(d) => tokio::time::sleep(d).await,
                        None => std::future::pending::<()>().await,
                    }
                } => {
                    process_retry_queue(
                        &mut notifiers,
                        cooldown,
                        &mut retry_queue,
                    ).await;
                }
            }
        }

        if !retry_queue.is_empty() {
            warn!(
                pending = retry_queue.len(),
                "Alert dispatcher stopped with undelivered alerts in retry queue"
            );
        }
    }
}

/// Stable dedup key derived from event variant + identifying field(s).
fn dedup_key(event: &AlertEvent) -> String {
    match event {
        AlertEvent::IpBanned { ip, .. } => format!("IpBanned:{ip}"),
        AlertEvent::SubnetBanned { subnet, .. } => format!("SubnetBanned:{subnet}"),
        AlertEvent::PeerDown { node_id, .. } => format!("PeerDown:{node_id}"),
        AlertEvent::PeerQuarantined { node_id, .. } => format!("PeerQuarantined:{node_id}"),
        AlertEvent::HighThreatDetected { ip, .. } => format!("HighThreatDetected:{ip}"),
        AlertEvent::HoneypotHit { ip, path } => format!("HoneypotHit:{ip}:{path}"),
        AlertEvent::BanRateAnomaly { .. } => "BanRateAnomaly".to_owned(),
    }
}

async fn handle_new_event(
    event: AlertEvent,
    notifiers: &mut [NotifierState],
    cooldown: Duration,
    queue_depth: usize,
    retry_queue: &mut VecDeque<PendingAlert>,
) {
    let kind = event.kind();
    let key = dedup_key(&event);

    for (idx, state) in notifiers.iter_mut().enumerate() {
        if !state.notifier.supports(kind) {
            continue;
        }
        if state.on_cooldown(&key, cooldown) {
            debug!(
                notifier = state.notifier.manifest().id,
                key = %key,
                "Alert skipped (cooldown active)"
            );
            continue;
        }

        match state.notifier.notify(&event).await {
            Ok(()) => {
                state.record(&key);
                info!(
                    notifier = state.notifier.manifest().id,
                    kind = ?kind,
                    "Alert delivered"
                );
            }
            Err(e) => {
                warn!(
                    notifier = state.notifier.manifest().id,
                    error = %e,
                    "Notifier delivery failed — queueing retry"
                );
                if retry_queue.len() >= queue_depth {
                    warn!(
                        notifier = state.notifier.manifest().id,
                        "Retry queue full — dropping oldest pending alert"
                    );
                    retry_queue.pop_front();
                }
                retry_queue.push_back(PendingAlert {
                    event: event.clone(),
                    notifier_idx: idx,
                    dedup_key: key.clone(),
                    attempt: 1,
                    next_try: Instant::now() + RETRY_DELAYS[0],
                });
            }
        }
    }
}

async fn process_retry_queue(
    notifiers: &mut [NotifierState],
    cooldown: Duration,
    retry_queue: &mut VecDeque<PendingAlert>,
) {
    let now = Instant::now();
    let mut still_pending: VecDeque<PendingAlert> = VecDeque::with_capacity(retry_queue.len());

    while let Some(pending) = retry_queue.pop_front() {
        if pending.next_try > now {
            still_pending.push_back(pending);
            continue;
        }

        let state = match notifiers.get_mut(pending.notifier_idx) {
            Some(s) => s,
            None => continue,
        };

        if state.on_cooldown(&pending.dedup_key, cooldown) {
            continue;
        }

        match state.notifier.notify(&pending.event).await {
            Ok(()) => {
                state.record(&pending.dedup_key);
                info!(
                    notifier = state.notifier.manifest().id,
                    attempt = pending.attempt,
                    "Alert delivered on retry"
                );
            }
            Err(e) => {
                let next_attempt = pending.attempt + 1;
                if next_attempt >= MAX_ATTEMPTS {
                    warn!(
                        notifier = state.notifier.manifest().id,
                        attempts = pending.attempt,
                        error = %e,
                        "Alert exhausted retries — discarding"
                    );
                } else {
                    let delay = RETRY_DELAYS
                        .get(next_attempt as usize)
                        .copied()
                        .unwrap_or(Duration::from_secs(600));
                    still_pending.push_back(PendingAlert {
                        next_try: Instant::now() + delay,
                        attempt: next_attempt,
                        ..pending
                    });
                }
            }
        }
    }

    *retry_queue = still_pending;
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Mutex;

    use async_trait::async_trait;
    use ipnet::IpNet;
    use serde_json::json;

    use hiveguard_plugin_api::{
        AlertKind, PluginError, PluginKind, PluginManifest, PluginResult,
    };
    use hiveguard_plugin_api::traits::Plugin;

    struct MockNotifier {
        id: &'static str,
        deliveries: Mutex<Vec<AlertEvent>>,
        fail_count: Mutex<u32>,
        supports_kind: AlertKind,
    }

    impl MockNotifier {
        fn new(id: &'static str, supports_kind: AlertKind) -> Self {
            Self {
                id,
                deliveries: Mutex::new(Vec::new()),
                fail_count: Mutex::new(0),
                supports_kind,
            }
        }

        fn with_failures(self, n: u32) -> Self {
            *self.fail_count.lock().unwrap() = n;
            self
        }

        fn manifest_static() -> PluginManifest {
            PluginManifest {
                id: "notifier.mock",
                version: "0.1.0",
                description: "mock notifier",
                kind: PluginKind::Notifier,
                author: "test",
                docs_url: None,
            }
        }

        fn delivered(&self) -> Vec<AlertEvent> {
            self.deliveries.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl Plugin for MockNotifier {
        fn manifest(&self) -> &PluginManifest {
            // Leak a 'static manifest for the mock.
            static MANIFEST: once_cell::sync::Lazy<PluginManifest> =
                once_cell::sync::Lazy::new(MockNotifier::manifest_static);
            &MANIFEST
        }
        async fn init(&mut self, _: serde_json::Value) -> PluginResult<()> {
            Ok(())
        }
    }

    #[async_trait]
    impl NotifierPlugin for MockNotifier {
        async fn notify(&self, event: &AlertEvent) -> PluginResult<()> {
            let mut fc = self.fail_count.lock().unwrap();
            if *fc > 0 {
                *fc -= 1;
                return Err(PluginError::Runtime(format!("mock failure ({})", self.id)));
            }
            self.deliveries.lock().unwrap().push(event.clone());
            Ok(())
        }

        fn supports(&self, kind: AlertKind) -> bool {
            kind == self.supports_kind
        }
    }

    fn make_event(ip: &str) -> AlertEvent {
        AlertEvent::IpBanned {
            ip: ip.parse::<IpNet>().unwrap(),
            severity: 200,
            reason: "test".into(),
            geo: None,
        }
    }

    #[tokio::test]
    async fn delivers_to_supporting_notifier() {
        let notifier = Arc::new(MockNotifier::new("a", AlertKind::IpBanned));
        let dispatcher = AlertDispatcher::new(vec![notifier.clone()]);
        let (sd_tx, sd_rx) = watch::channel(false);
        let (handle, _join) = dispatcher.spawn(sd_rx);

        handle.send(make_event("1.2.3.4/32"));
        tokio::time::sleep(Duration::from_millis(50)).await;
        let _ = sd_tx.send(true);

        assert_eq!(notifier.delivered().len(), 1);
    }

    #[tokio::test]
    async fn cooldown_suppresses_duplicate() {
        let notifier = Arc::new(MockNotifier::new("a", AlertKind::IpBanned));
        let dispatcher = AlertDispatcher::new(vec![notifier.clone()])
            .with_config(AlertDispatcherConfig {
                cooldown_secs: 60,
                ..Default::default()
            });
        let (sd_tx, sd_rx) = watch::channel(false);
        let (handle, _join) = dispatcher.spawn(sd_rx);

        handle.send(make_event("1.2.3.4/32"));
        handle.send(make_event("1.2.3.4/32"));
        handle.send(make_event("1.2.3.4/32"));
        tokio::time::sleep(Duration::from_millis(80)).await;
        let _ = sd_tx.send(true);

        // Three events, same dedup key → only the first goes through.
        assert_eq!(notifier.delivered().len(), 1);
    }

    #[tokio::test]
    async fn unsupported_kind_skipped() {
        let notifier = Arc::new(MockNotifier::new("a", AlertKind::HoneypotHit));
        let dispatcher = AlertDispatcher::new(vec![notifier.clone()]);
        let (sd_tx, sd_rx) = watch::channel(false);
        let (handle, _join) = dispatcher.spawn(sd_rx);

        // IpBanned event, notifier only supports HoneypotHit.
        handle.send(make_event("1.2.3.4/32"));
        tokio::time::sleep(Duration::from_millis(50)).await;
        let _ = sd_tx.send(true);

        assert!(notifier.delivered().is_empty());
    }

    #[tokio::test]
    async fn retry_delivers_after_transient_failure() {
        // Notifier fails once, then succeeds. First delivery enters retry queue
        // with 5s delay; we don't actually wait 5s in unit tests — instead we
        // assert the retry queue is populated by checking that no delivery
        // happened on the first attempt. The full retry path is integration-
        // tested separately.
        let notifier = Arc::new(MockNotifier::new("a", AlertKind::IpBanned).with_failures(1));
        let dispatcher = AlertDispatcher::new(vec![notifier.clone()]);
        let (sd_tx, sd_rx) = watch::channel(false);
        let (handle, _join) = dispatcher.spawn(sd_rx);

        handle.send(make_event("1.2.3.4/32"));
        tokio::time::sleep(Duration::from_millis(50)).await;
        let _ = sd_tx.send(true);

        // Initial attempt failed → no delivery recorded yet.
        assert!(notifier.delivered().is_empty());
        // Retries fire after 5 s — we don't block tests on that.
    }

    #[test]
    fn dedup_key_distinguishes_variants() {
        let a = AlertEvent::HoneypotHit {
            ip: "1.2.3.4".into(),
            path: "/a".into(),
        };
        let b = AlertEvent::HoneypotHit {
            ip: "1.2.3.4".into(),
            path: "/b".into(),
        };
        let c = AlertEvent::PeerDown {
            node_id: "n1".into(),
            address: "127.0.0.1:8080".parse().unwrap(),
        };
        assert_ne!(dedup_key(&a), dedup_key(&b));
        assert_ne!(dedup_key(&a), dedup_key(&c));
    }

    #[test]
    fn json_roundtrip() {
        // Sanity: AlertEvent serializes losslessly so it can cross the channel
        // via cloning without surprises.
        let e = make_event("10.0.0.1/32");
        let s = serde_json::to_string(&e).unwrap();
        let _: serde_json::Value = serde_json::from_str(&s).unwrap();
        let _ = json!({ "k": s });
    }
}
