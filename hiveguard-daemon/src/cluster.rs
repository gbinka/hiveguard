//! Cluster runtime — wires the `hiveguard-net` gossip/SWIM/CRDT primitives into
//! the running daemon so that bans issued on one node are replicated to its
//! peers (and vice-versa).
//!
//! Until this module existed, `hiveguard-net` was a fully-implemented but
//! *unwired* library: `node.listen_gossip` / `node.seeds` were parsed and then
//! dropped on the floor. [`spawn_cluster`] is the missing integration layer.
//!
//! # Architecture
//!
//! A single Tokio task (the **actor**) owns the [`SyncCoordinator`],
//! [`TrustManager`], [`RateLimiter`] and the live `node_id → quinn::Connection`
//! map. All mutable cluster state lives in that one task, so nothing needs to be
//! `Sync`. Peripheral tasks feed it events over an mpsc channel:
//!
//! * **acceptor** — `endpoint.accept()` loop; hands new inbound connections to
//!   the actor.
//! * **dialer** — periodically (re)connects to configured seed peers that are
//!   not currently connected.
//! * **reader** (one per connection) — reads length-prefixed [`ClusterMessage`]s
//!   off QUIC uni-streams and forwards them to the actor.
//! * **probe / maintenance timers** — drive SWIM liveness pings and periodic
//!   anti-entropy digest exchange.
//!
//! Outbound sends open a fresh uni-stream per message (`open_uni → send_message
//! → finish`), matching the reader's one-message-per-stream model.
//!
//! # Security model
//!
//! * mTLS (QUIC/TLS 1.3) with the node's persisted Ed25519 identity. The peer's
//!   blake3 fingerprint *is* its `node_id`.
//! * In `strict` mode only fingerprints listed in `node.seeds` are accepted.
//! * Inbound ban records are passed through
//!   [`SyncCoordinator::handle_ban_sync_filtered`] which enforces Ed25519
//!   signature + PoW verification, per-sender rate limiting, anti-poison
//!   quarantine and trust-threshold corroboration before anything is applied.
//!
//! Locally-issued bans are propagated via [`ClusterHandle::announce_local_ban`];
//! remotely-received bans are written straight to the [`StateManager`] +
//! enforcer and are **not** re-announced, so there is no propagation echo.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;

use ipnet::IpNet;
use tokio::sync::{mpsc, watch, Mutex, Semaphore};
use tokio::time::{interval, Duration};
use tracing::{debug, info, warn};

use hiveguard_core::anti_poison::RateLimiter;
use hiveguard_core::ban_store::BanStore;
use hiveguard_core::config::{ClusterMode, HiveGuardConfig, TrustConfig};
use hiveguard_core::persistence::state_manager::StateManager;
use hiveguard_core::trust::TrustManager;
use hiveguard_core::{BanRecord, BanSource};
use hiveguard_enforce::Enforcer;
use hiveguard_net::{
    decode_message, extract_peer_fingerprint_and_key, read_bounded_message, send_message,
    signed_pages, ClusterMessage, GossipAction, GossipConfig, GossipEngine, NodeIdentity, PeerInfo,
    PeerState, QuicTransport, SignedBanRecord, SigningCache, SwimAction, SwimConfig,
    SyncCoordinator,
};

use crate::metrics::SharedMetrics;

/// PoW difficulty (leading zero bits) mined into every outbound signed ban.
/// Matches `GossipConfig` default / `SignedBanRecord` minimum.
const POW_DIFFICULTY: u8 = 16;

/// How often the dialer reconnects to missing seeds and the actor emits an
/// anti-entropy digest exchange.
const MAINTENANCE_INTERVAL: Duration = Duration::from_secs(5);

/// Persistent digest mismatches are expected (records one side can never
/// accept: permanent, too wide, whitelisted, independently detected, …).
/// Report them at INFO at most this often, with a count; every round is DEBUG.
const DIGEST_MISMATCH_REPORT_INTERVAL: Duration = Duration::from_secs(30 * 60);

/// A pinned seed unreachable for this long gets one WARN (then one per
/// [`SEED_UNREACHABLE_REPEAT`]) so a retired host left in `node.seeds` is
/// visible in a daily journal review.
const SEED_UNREACHABLE_WARN_AFTER: Duration = Duration::from_secs(60 * 60);
const SEED_UNREACHABLE_REPEAT: Duration = Duration::from_secs(24 * 60 * 60);

/// Cheap-to-clone handle the pipeline uses to announce locally-issued bans to
/// the cluster. Dropping all clones does not stop the cluster (the actor task
/// owns its own lifecycle and shuts down on the watch channel).
#[derive(Clone)]
pub struct ClusterHandle {
    local_ban_tx: mpsc::Sender<BanRecord>,
}

impl ClusterHandle {
    /// Best-effort announce a ban that was just issued locally. Non-blocking:
    /// if the cluster channel is full the ban is dropped from *propagation*
    /// only (it is still enforced + persisted locally, and anti-entropy will
    /// reconcile it later).
    pub fn announce_local_ban(&self, record: &BanRecord) {
        if let Err(e) = self.local_ban_tx.try_send(record.clone()) {
            debug!(error = %e, "cluster: dropped local-ban announcement (channel full/closed)");
        }
    }
}

/// Events delivered to the actor's single inbox.
enum ActorEvent {
    /// A connection (inbound or outbound) completed its TLS handshake.
    PeerConnected {
        node_id: String,
        public_key: Vec<u8>,
        addr: SocketAddr,
        conn: quinn::Connection,
    },
    /// A decoded protocol message arrived from `from`.
    Inbound { from: String, msg: ClusterMessage },
    /// A locally-issued ban to sign + gossip.
    LocalBan(BanRecord),
    /// SWIM probe tick.
    Probe,
    /// Reconnect-to-seeds + anti-entropy tick.
    Maintenance,
}

/// A resolved seed: socket address plus (in strict mode) the pinned fingerprint
/// = expected `node_id`.
#[derive(Clone)]
struct Seed {
    raw_addr: String,
    fingerprint: Option<String>,
}

/// Start the cluster runtime. Returns `None` (standalone, no-op) when gossip is
/// not configured or cannot be initialised — the daemon keeps running.
pub async fn spawn_cluster(
    config: &HiveGuardConfig,
    state: Arc<Mutex<StateManager>>,
    enforcer: Arc<Mutex<Box<dyn Enforcer>>>,
    metrics: Option<SharedMetrics>,
    shutdown_rx: watch::Receiver<bool>,
) -> Option<ClusterHandle> {
    let listen = config.node.listen_gossip.trim();
    if listen.is_empty() {
        info!("cluster: listen_gossip empty — running standalone (no ban replication)");
        return None;
    }
    let listen_addr: SocketAddr = match listen.parse() {
        Ok(a) => a,
        Err(e) => {
            warn!(listen, error = %e, "cluster: invalid listen_gossip address — cluster disabled");
            return None;
        }
    };

    // Persisted Ed25519 identity (data_dir/identity/{node.key,node.crt}).
    let identity = match NodeIdentity::load_or_generate(&config.node.data_dir) {
        Ok(id) => id,
        Err(e) => {
            warn!(error = %e, "cluster: failed to load/generate node identity — cluster disabled");
            return None;
        }
    };
    let node_id = identity.node_id().to_string();
    let pkcs8 = identity.private_key_der();

    // QUIC transport with mutual TLS. Peers are authenticated at the
    // application layer by fingerprint (see `accept_peer`), so the permissive
    // TLS verifier is the intended configuration here.
    let transport = match QuicTransport::new(listen_addr, &identity) {
        Ok(t) => Arc::new(t),
        Err(e) => {
            warn!(error = %e, "cluster: QUIC transport init failed — cluster disabled");
            return None;
        }
    };
    let endpoint = match transport.start_server().await {
        Ok(ep) => ep,
        Err(e) => {
            warn!(error = %e, "cluster: QUIC server bind failed — cluster disabled");
            return None;
        }
    };

    let strict = matches!(config.node.cluster_mode, ClusterMode::Strict);

    // Allowed fingerprints (strict mode) and founder set (full-trust nodes).
    let mut allowed: HashSet<String> = HashSet::new();
    let mut seeds: Vec<Seed> = Vec::new();
    for s in &config.node.seeds {
        if let Some(fp) = s.fingerprint() {
            allowed.insert(fp.to_string());
        }
        seeds.push(Seed {
            raw_addr: s.address().to_string(),
            fingerprint: s.fingerprint().map(str::to_string),
        });
    }
    let founders: HashSet<String> = config.node.founder_nodes.iter().cloned().collect();

    if strict && seeds.iter().any(|s| s.fingerprint.is_none()) {
        warn!(
            "cluster: strict mode but some seeds have no fingerprint — those peers \
             will be rejected. Add `fingerprint:` to every seed or use cluster_mode: auto-accept."
        );
    }

    // Trust + anti-poison, seeded from config.
    let mut trust = TrustManager::new(config.trust.ban_threshold);
    for fp in &founders {
        trust.register_founder_node(fp.clone());
    }
    let rate_limiter = RateLimiter::new(
        config.trust.max_bans_per_minute as usize,
        chrono::Duration::minutes(1),
    );

    let coordinator = SyncCoordinator::new(
        node_id.clone(),
        SwimConfig::default(),
        GossipConfig {
            fanout: 8,
            pow_difficulty: POW_DIFFICULTY,
        },
    );

    let (tx, rx) = mpsc::channel::<ActorEvent>(1024);
    let (local_ban_tx, local_ban_rx) = mpsc::channel::<BanRecord>(1024);

    info!(
        %node_id,
        listen = %listen_addr,
        mode = if strict { "strict" } else { "auto-accept" },
        seeds = seeds.len(),
        founders = founders.len(),
        "cluster: gossip runtime starting"
    );

    // --- acceptor task ---
    {
        let tx = tx.clone();
        let mut shutdown = shutdown_rx.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = shutdown.changed() => break,
                    incoming = endpoint.accept() => {
                        let Some(incoming) = incoming else { break };
                        let tx = tx.clone();
                        tokio::spawn(async move {
                            match incoming.await {
                                Ok(conn) => forward_connected(conn, &tx).await,
                                Err(e) => debug!(error = %e, "cluster: inbound handshake failed"),
                            }
                        });
                    }
                }
            }
            debug!("cluster: acceptor task stopped");
        });
    }

    // --- dialer task: feed Maintenance ticks (actor drives the actual dialing) ---
    {
        let tx = tx.clone();
        let mut shutdown = shutdown_rx.clone();
        tokio::spawn(async move {
            let mut tick = interval(MAINTENANCE_INTERVAL);
            loop {
                tokio::select! {
                    _ = shutdown.changed() => break,
                    _ = tick.tick() => {
                        if tx.send(ActorEvent::Maintenance).await.is_err() { break; }
                    }
                }
            }
        });
    }

    // --- probe timer (SWIM ping interval) ---
    {
        let tx = tx.clone();
        let mut shutdown = shutdown_rx.clone();
        let ping_interval = SwimConfig::default().ping_interval;
        tokio::spawn(async move {
            let mut tick = interval(ping_interval);
            loop {
                tokio::select! {
                    _ = shutdown.changed() => break,
                    _ = tick.tick() => {
                        if tx.send(ActorEvent::Probe).await.is_err() { break; }
                    }
                }
            }
        });
    }

    // --- local-ban forwarder: pipeline → actor ---
    {
        let tx = tx.clone();
        let mut local_ban_rx = local_ban_rx;
        tokio::spawn(async move {
            while let Some(rec) = local_ban_rx.recv().await {
                if tx.send(ActorEvent::LocalBan(rec)).await.is_err() {
                    break;
                }
            }
        });
    }

    // --- the actor ---
    let actor = ClusterActor {
        node_id,
        pkcs8,
        strict,
        allowed,
        founders,
        seeds,
        transport,
        coordinator,
        trust,
        rate_limiter,
        sign_cache: Arc::new(std::sync::Mutex::new(SigningCache::default())),
        signing_slot: Arc::new(Semaphore::new(1)),
        diff_offsets: HashMap::new(),
        diff_requests: HashMap::new(),
        raw_limiter: RateLimiter::new(10_000, chrono::Duration::minutes(1)),
        remote_policy: config.trust.clone(),
        count_window: std::time::Instant::now(),
        ban_counts: HashMap::new(),
        digest_mismatches: HashMap::new(),
        seed_outages: HashMap::new(),
        connections: HashMap::new(),
        dialing: Arc::new(std::sync::Mutex::new(HashSet::new())),
        state,
        enforcer,
        metrics,
        tx: tx.clone(),
    };
    tokio::spawn(actor.run(rx, shutdown_rx));

    Some(ClusterHandle { local_ban_tx })
}

/// Extract the peer's fingerprint/pubkey from a freshly-handshaked connection
/// and forward a `PeerConnected` event to the actor.
async fn forward_connected(conn: quinn::Connection, tx: &mpsc::Sender<ActorEvent>) {
    match extract_peer_fingerprint_and_key(&conn) {
        Some((fp, pubkey)) => {
            let addr = conn.remote_address();
            let _ = tx
                .send(ActorEvent::PeerConnected {
                    node_id: fp,
                    public_key: pubkey,
                    addr,
                    conn,
                })
                .await;
        }
        None => debug!("cluster: peer presented no usable certificate — dropping connection"),
    }
}

struct ClusterActor {
    node_id: String,
    pkcs8: Vec<u8>,
    strict: bool,
    allowed: HashSet<String>,
    founders: HashSet<String>,
    seeds: Vec<Seed>,
    transport: Arc<QuicTransport>,
    coordinator: SyncCoordinator,
    trust: TrustManager,
    rate_limiter: RateLimiter,
    /// Memoised PoW stamps — anti-entropy re-sends the same records every round
    /// and mining each one costs ~65 k blake3 hashes.
    sign_cache: Arc<std::sync::Mutex<SigningCache>>,
    signing_slot: Arc<Semaphore>,
    diff_offsets: HashMap<String, usize>,
    diff_requests: HashMap<String, std::time::Instant>,
    raw_limiter: RateLimiter,
    remote_policy: TrustConfig,
    count_window: std::time::Instant,
    /// node_id → number of ban records received (anti-poison quarantine input).
    ban_counts: HashMap<String, usize>,
    /// peer → (mismatching rounds since last INFO report, time of that report).
    digest_mismatches: HashMap<String, (u64, Option<std::time::Instant>)>,
    /// seed address → (unreachable since, last WARN).
    seed_outages: HashMap<String, (std::time::Instant, Option<std::time::Instant>)>,
    connections: HashMap<String, quinn::Connection>,
    /// Addresses with an in-flight dial, to avoid pile-ups.
    dialing: Arc<std::sync::Mutex<HashSet<String>>>,
    state: Arc<Mutex<StateManager>>,
    enforcer: Arc<Mutex<Box<dyn Enforcer>>>,
    metrics: Option<SharedMetrics>,
    tx: mpsc::Sender<ActorEvent>,
}

impl ClusterActor {
    async fn run(
        mut self,
        mut rx: mpsc::Receiver<ActorEvent>,
        mut shutdown: watch::Receiver<bool>,
    ) {
        loop {
            tokio::select! {
                _ = shutdown.changed() => break,
                ev = rx.recv() => {
                    let Some(ev) = ev else { break };
                    match ev {
                        ActorEvent::PeerConnected { node_id, public_key, addr, conn } => {
                            self.on_peer_connected(node_id, public_key, addr, conn);
                        }
                        ActorEvent::Inbound { from, msg } => self.on_inbound(from, msg).await,
                        ActorEvent::LocalBan(rec) => self.on_local_ban(rec),
                        ActorEvent::Probe => self.on_probe(),
                        ActorEvent::Maintenance => self.on_maintenance(),
                    }
                }
            }
        }
        info!("cluster: gossip runtime stopped");
    }

    /// Accept (or reject) a newly handshaked peer connection.
    fn on_peer_connected(
        &mut self,
        node_id: String,
        public_key: Vec<u8>,
        addr: SocketAddr,
        conn: quinn::Connection,
    ) {
        if node_id == self.node_id {
            // Self-connection (e.g. seed points at our own address). Ignore.
            conn.close(0u32.into(), b"self");
            return;
        }
        if self.strict && !self.allowed.contains(&node_id) {
            warn!(%node_id, %addr, "cluster: rejecting unknown peer (strict mode)");
            conn.close(0u32.into(), b"unknown peer");
            return;
        }

        // Keep an existing healthy connection rather than churning.
        if let Some(existing) = self.connections.get(&node_id) {
            if existing.close_reason().is_none() {
                // Refresh the peer's public key but drop the duplicate conn.
                self.register_peer(&node_id, &public_key, addr);
                conn.close(0u32.into(), b"duplicate");
                return;
            }
        }

        info!(%node_id, %addr, "cluster: peer connected");
        self.register_peer(&node_id, &public_key, addr);
        self.connections.insert(node_id.clone(), conn.clone());
        self.update_peer_metric();

        // Spawn the per-connection reader.
        let tx = self.tx.clone();
        let nid = node_id.clone();
        tokio::spawn(async move {
            reader_loop(nid, conn, tx).await;
        });
    }

    /// Register/refresh a peer in the SWIM peer manager + trust manager.
    fn register_peer(&mut self, node_id: &str, public_key: &[u8], addr: SocketAddr) {
        let pm = self.coordinator.peer_manager_mut();
        match pm.get_peer(node_id) {
            Some(_) => {
                pm.update_peer_state(node_id, PeerState::Alive);
            }
            None => {
                let mut info = PeerInfo::new(node_id.to_string(), addr, node_id.to_string());
                info.public_key_bytes = public_key.to_vec();
                pm.add_peer(info);
            }
        }
        // Ensure pubkey is current (needed to verify signed ban records).
        if let Some(p) = self.coordinator.peer_manager_mut().get_peer(node_id) {
            if p.public_key_bytes != public_key {
                let mut info = p.clone();
                info.public_key_bytes = public_key.to_vec();
                self.coordinator.peer_manager_mut().add_peer(info);
            }
        }

        if self.founders.contains(node_id) {
            self.trust.register_founder_node(node_id.to_string());
        } else {
            self.trust.register_node(node_id.to_string());
        }
    }

    async fn on_inbound(&mut self, from: String, msg: ClusterMessage) {
        self.coordinator
            .peer_manager_mut()
            .update_peer_state(&from, PeerState::Alive);

        match msg {
            ClusterMessage::Ping { .. } => {
                let digest = self.local_digest().await;
                self.send_to(
                    &from,
                    ClusterMessage::Pong {
                        sender_id: self.node_id.clone(),
                        digest,
                    },
                );
            }
            ClusterMessage::Pong { .. } => {
                self.coordinator.handle_pong(&from);
            }
            ClusterMessage::PingReq { target_id, .. } => {
                let digest = self.local_digest().await;
                self.send_to(
                    &target_id,
                    ClusterMessage::Ping {
                        sender_id: self.node_id.clone(),
                        digest,
                    },
                );
            }
            ClusterMessage::BanSync { records, .. } => {
                self.ingest_remote_bans(&from, records).await;
            }
            ClusterMessage::DiffResponse { records } => {
                self.ingest_remote_bans(&from, records).await;
            }
            ClusterMessage::DigestExchange { merkle_root } => {
                let local_bans = self.snapshot_bans().await;
                if let Some(GossipAction::SendDiffRequest { missing_keys, .. }) = self
                    .coordinator
                    .handle_digest_exchange(&merkle_root, &local_bans, &from)
                {
                    self.note_digest_mismatch(&from, std::time::Instant::now());
                    self.send_to(&from, ClusterMessage::DiffRequest { missing_keys });
                } else if let Some((count, _)) = self.digest_mismatches.get_mut(&from) {
                    if *count > 0 {
                        info!(peer = %from, rounds = *count, "cluster: ban digests converged with peer");
                    }
                    *count = 0;
                }
            }
            ClusterMessage::DiffRequest { missing_keys } => {
                let now = std::time::Instant::now();
                if self
                    .diff_requests
                    .get(&from)
                    .is_some_and(|last| now.duration_since(*last) < MAINTENANCE_INTERVAL)
                {
                    return;
                }
                self.diff_requests.insert(from.clone(), now);
                let local_bans = self.snapshot_bans().await;
                let missing = self
                    .coordinator
                    .handle_diff_request(&missing_keys, &local_bans);
                // Bound each signing job and rotate over rejected/nonmatching
                // subjects, so one unapplicable prefix cannot starve the tail.
                let mut missing: Vec<_> = missing
                    .into_iter()
                    .filter(|r| !matches!(r.source, BanSource::ClusterPeer(_)))
                    .filter(|r| r.expires_at.is_some())
                    .collect();
                missing.sort_by_key(|r| r.subject.to_string());
                let offset = self.diff_offsets.entry(from.clone()).or_default();
                if !missing.is_empty() {
                    let len = missing.len();
                    missing.rotate_left(*offset % len);
                    missing.truncate(256);
                    *offset = (*offset + missing.len()) % len;
                    let now = chrono::Utc::now();
                    let max_secs = self.announce_max_secs();
                    let missing = missing
                        .iter()
                        .filter_map(|r| announced_form(r, max_secs, now))
                        .collect();
                    self.send_signed_bans(vec![from.clone()], missing);
                }
            }
            ClusterMessage::MembershipUpdate { .. } => {
                // Not needed for the static-seed topology; ignored.
            }
        }
    }

    /// Run incoming signed records through the full security filter, then apply
    /// whatever survives.
    async fn ingest_remote_bans(&mut self, from: &str, records: Vec<SignedBanRecord>) {
        if records.is_empty() {
            return;
        }
        if self.count_window.elapsed() >= Duration::from_secs(60) {
            self.ban_counts.clear();
            self.count_window = std::time::Instant::now();
        }
        // Cheap applicability checks precede expensive crypto and the decision
        // quota. A separate budget still bounds hostile raw verification work.
        let mut batch = HashSet::new();
        let records = {
            let st = self.state.lock().await;
            records
                .into_iter()
                .filter(|signed| {
                    let rec = &signed.record;
                    remote_policy_allows(&self.remote_policy, rec, chrono::Utc::now())
                        && st.accepts_remote_ban(rec)
                        && !st.whitelist().overlaps(&rec.subject)
                        && remote_changes_state(&st, rec)
                        && batch.insert((signed.signer_id.clone(), GossipEngine::record_key(rec)))
                        && self.raw_limiter.check_and_record(from)
                })
                .collect()
        };
        let peer_keys = self.peer_public_keys();
        let st = self.state.lock().await;
        let action = self.coordinator.handle_ban_sync_filtered_with_policy(
            records,
            from,
            &self.trust,
            &mut self.rate_limiter,
            &self.ban_counts,
            &peer_keys,
            |rec| {
                remote_policy_allows(&self.remote_policy, rec, chrono::Utc::now())
                    && st.accepts_remote_ban(rec)
                    && !st.whitelist().overlaps(&rec.subject)
                    && remote_changes_state(&st, rec)
            },
        );
        drop(st);
        if let Some(GossipAction::ApplyBans { records }) = action {
            *self.ban_counts.entry(from.to_string()).or_insert(0) += records.len();
            self.apply_bans(from, records).await;
        }
    }

    fn on_local_ban(&mut self, rec: BanRecord) {
        if matches!(rec.source, BanSource::ClusterPeer(_)) {
            return;
        }
        // Long local bans are announced as a bounded window (the local ban
        // itself keeps its full lifetime); permanent ones never replicate.
        let Some(rec) = announced_form(&rec, self.announce_max_secs(), chrono::Utc::now()) else {
            debug!(subject = %rec.subject, "cluster: local ban not announceable (permanent/expired)");
            return;
        };
        let targets = self.connections.keys().cloned().collect();
        self.send_signed_bans(targets, vec![rec]);
    }

    /// Longest lifetime a peer accepts (`trust.remote_max_ttl_secs`, default
    /// 24 h — also the hard-coded default of older builds).
    fn announce_max_secs(&self) -> i64 {
        i64::try_from(self.remote_policy.remote_max_ttl_secs).unwrap_or(i64::MAX)
    }

    fn note_digest_mismatch(&mut self, peer: &str, now: std::time::Instant) {
        let entry = self
            .digest_mismatches
            .entry(peer.to_string())
            .or_insert((0, None));
        entry.0 += 1;
        let due = entry
            .1
            .is_none_or(|last| now.duration_since(last) >= DIGEST_MISMATCH_REPORT_INTERVAL);
        if due {
            info!(
                peer = %peer,
                rounds = entry.0,
                "cluster: ban digest differs from peer — anti-entropy exchanging diffs \
                 (expected while either side holds records the other does not accept; \
                 reported at most every 30 min)"
            );
            *entry = (0, Some(now));
        } else {
            debug!(peer = %peer, "cluster: digest mismatch — requesting diff");
        }
    }

    /// Track pinned seeds that stay unreachable and WARN once they exceed
    /// [`SEED_UNREACHABLE_WARN_AFTER`] (repeated every 24 h).
    fn track_seed_outage(&mut self, seed: &Seed, connected: bool, now: std::time::Instant) {
        // Unpinned seeds cannot be mapped to a node id before the handshake.
        let Some(fp) = &seed.fingerprint else { return };
        if *fp == self.node_id {
            return;
        }
        if connected {
            if let Some((since, warned)) = self.seed_outages.remove(&seed.raw_addr) {
                if warned.is_some() {
                    info!(
                        seed = %seed.raw_addr,
                        hours = now.duration_since(since).as_secs() / 3600,
                        "cluster: seed reachable again"
                    );
                }
            }
            return;
        }
        let (since, last_warn) = self
            .seed_outages
            .entry(seed.raw_addr.clone())
            .or_insert((now, None));
        let down = now.duration_since(*since);
        let due = down >= SEED_UNREACHABLE_WARN_AFTER
            && last_warn.is_none_or(|last| now.duration_since(last) >= SEED_UNREACHABLE_REPEAT);
        if due {
            warn!(
                seed = %seed.raw_addr,
                fingerprint = %fp,
                hours = down.as_secs() / 3600,
                "cluster: seed unreachable for {} h — if the host was retired, remove it from \
                 node.seeds and node.founder_nodes",
                down.as_secs() / 3600
            );
            *last_warn = Some(now);
        }
    }

    fn on_probe(&mut self) {
        // SWIM digest is informational; an empty vec is fine for liveness.
        let actions = self.coordinator.run_probe_cycle(Vec::new());
        for action in actions {
            match action {
                SwimAction::SendPing { target_id, digest } => {
                    self.send_to(
                        &target_id,
                        ClusterMessage::Ping {
                            sender_id: self.node_id.clone(),
                            digest,
                        },
                    );
                }
                SwimAction::SendPingReq {
                    target_id,
                    via_peers,
                } => {
                    for via in via_peers {
                        self.send_to(
                            &via,
                            ClusterMessage::PingReq {
                                sender_id: self.node_id.clone(),
                                target_id: target_id.clone(),
                            },
                        );
                    }
                }
                SwimAction::MarkDead { node_id } | SwimAction::RemovePeer { node_id } => {
                    if let Some(conn) = self.connections.remove(&node_id) {
                        conn.close(0u32.into(), b"dead");
                    }
                    self.coordinator.peer_manager_mut().remove_peer(&node_id);
                    self.update_peer_metric();
                }
                SwimAction::MarkSuspect { .. } | SwimAction::None => {}
            }
        }
    }

    fn on_maintenance(&mut self) {
        // 1. (Re)dial seeds we are not currently connected to.
        let now = std::time::Instant::now();
        for seed in self.seeds.clone() {
            let connected = match &seed.fingerprint {
                Some(fp) => self.connections.contains_key(fp),
                // Without a pinned fingerprint we can't map address→node_id
                // ahead of the handshake, so fall back to "dial if we have no
                // peers at all" to bootstrap, then rely on SWIM afterwards.
                None => !self.connections.is_empty(),
            };
            self.track_seed_outage(&seed, connected, now);
            if connected {
                continue;
            }
            self.dial(seed.raw_addr.clone());
        }

        // 2. Anti-entropy: offer our ban digest to every connected peer so a
        //    node that was offline catches up on bans it missed. Snapshotting
        //    bans needs the (async) state lock, so do it off-actor.
        let conns: Vec<quinn::Connection> = self.connections.values().cloned().collect();
        if conns.is_empty() {
            return;
        }
        let state = self.state.clone();
        tokio::spawn(async move {
            let bans: Vec<BanRecord> = {
                let st = state.lock().await;
                st.ban_store().get_all_bans().into_iter().cloned().collect()
            };
            let digest = GossipEngine::compute_digest(&bans);
            for conn in conns {
                send_msg(
                    conn,
                    ClusterMessage::DigestExchange {
                        merkle_root: digest.clone(),
                    },
                )
                .await;
            }
        });
    }

    // --- helpers -----------------------------------------------------------

    /// Mining runs on the blocking pool with one bounded in-flight job.
    /// Dropped jobs are retried by the next anti-entropy round.
    fn send_signed_bans(&self, targets: Vec<String>, records: Vec<BanRecord>) {
        let Ok(permit) = self.signing_slot.clone().try_acquire_owned() else {
            return;
        };
        let cache = self.sign_cache.clone();
        let key = self.pkcs8.clone();
        let node = self.node_id.clone();
        let conns: Vec<_> = targets
            .iter()
            .filter_map(|id| self.connections.get(id).cloned())
            .collect();
        tokio::spawn(async move {
            let signed = tokio::task::spawn_blocking(move || {
                let _permit = permit;
                let mut cache = cache.lock().unwrap_or_else(|e| e.into_inner());
                records
                    .into_iter()
                    .filter_map(|record| cache.sign(record, &node, &key, POW_DIFFICULTY).ok())
                    .collect::<Vec<_>>()
            })
            .await;
            let Ok(signed) = signed else {
                return;
            };
            for page in signed_pages(signed) {
                for conn in &conns {
                    send_msg(
                        conn.clone(),
                        ClusterMessage::DiffResponse {
                            records: page.clone(),
                        },
                    )
                    .await;
                }
            }
        });
    }

    fn peer_public_keys(&self) -> HashMap<String, Vec<u8>> {
        self.coordinator
            .peer_manager()
            .all_peers()
            .into_iter()
            .filter(|p| !p.public_key_bytes.is_empty())
            .map(|p| (p.node_id.clone(), p.public_key_bytes.clone()))
            .collect()
    }

    async fn snapshot_bans(&self) -> Vec<BanRecord> {
        let st = self.state.lock().await;
        st.ban_store().get_all_bans().into_iter().cloned().collect()
    }

    async fn local_digest(&self) -> Vec<u8> {
        GossipEngine::compute_digest(&self.snapshot_bans().await)
    }

    /// Persist + enforce remotely-received bans (already past the security
    /// filter). Whitelisted targets and bans we already hold are skipped. The
    /// record's `source` identifies its authenticated signer so logs/UI/SIEM
    /// preserve the origin rather than counting the relay as a detector. These are **not**
    /// re-announced (no echo).
    async fn apply_bans(&self, from: &str, records: Vec<BanRecord>) {
        let now = chrono::Utc::now();
        let mut to_enforce: Vec<IpNet> = Vec::new();
        {
            let mut st = self.state.lock().await;
            let mut enf = self.enforcer.lock().await;
            for mut rec in records {
                // Peers running older builds keep re-announcing bans that have
                // already expired; persisting them just re-creates entries the
                // expiry sweep removes again, looping forever.
                if !remote_policy_allows(&self.remote_policy, &rec, now) {
                    debug!(subject = %rec.subject, peer = %from, "cluster: remote ban already expired — skipping");
                    continue;
                }
                if st.whitelist().overlaps(&rec.subject) {
                    debug!(subject = %rec.subject, peer = %from, "cluster: remote ban hits whitelist — skipping");
                    continue;
                }
                if !st.accepts_remote_ban(&rec) || !remote_changes_state(&st, &rec) {
                    continue;
                }
                let subject = rec.subject;
                let reason = rec.reason.clone();
                // Provenance: this node did not detect the attacker itself — it
                // was blocked pre-emptively because a peer reported it.
                // The security filter preserves the authenticated signer, which
                // can differ from the transporting peer.
                if !matches!(rec.source, BanSource::ClusterPeer(_)) {
                    rec.source = BanSource::ClusterPeer(from.to_string());
                }
                match st.add_ban(rec) {
                    Ok(()) => {
                        info!(
                            %subject, peer = %from, reason = %reason,
                            "cluster: pre-emptively blocked IP reported by peer"
                        );
                        if let Err(e) = enf.apply_ban(&subject).await {
                            warn!(%subject, error = %e, "cluster: enforcer rejected remote ban");
                        }
                        to_enforce.push(subject);
                    }
                    Err(e) => warn!(%subject, error = %e, "cluster: failed to persist remote ban"),
                }
            }
        }
        if to_enforce.is_empty() {
            return;
        }
        let count = to_enforce.len();
        if let Some(m) = &self.metrics {
            let st = self.state.lock().await;
            m.active_bans
                .set(st.ban_store().get_all_bans().len() as i64);
        }
        info!(count, peer = %from, "cluster: applied remote bans");
    }

    /// Open a fresh uni-stream and send one message (fire-and-forget).
    fn send_to(&self, node_id: &str, msg: ClusterMessage) {
        let Some(conn) = self.connections.get(node_id) else {
            debug!(%node_id, "cluster: no live connection — dropping outbound message");
            return;
        };
        let conn = conn.clone();
        tokio::spawn(async move {
            send_msg(conn, msg).await;
        });
    }

    fn update_peer_metric(&self) {
        if let Some(m) = &self.metrics {
            m.peer_count.set(self.connections.len() as i64);
        }
    }

    /// Resolve `raw_addr` (host:port, DNS-resolved) and dial it. On success the
    /// resulting connection is fed back as a `PeerConnected` event.
    fn dial(&self, raw_addr: String) {
        {
            let mut inflight = self.dialing.lock().unwrap();
            if !inflight.insert(raw_addr.clone()) {
                return; // already dialing
            }
        }
        let transport = self.transport.clone();
        let tx = self.tx.clone();
        let dialing = self.dialing.clone();
        tokio::spawn(async move {
            let result = async {
                let addr = resolve(&raw_addr).await?;
                transport.connect_to_peer(addr).await.ok()
            }
            .await;
            match result {
                Some(conn) => forward_connected(conn, &tx).await,
                None => debug!(addr = %raw_addr, "cluster: dial failed"),
            }
            dialing.lock().unwrap().remove(&raw_addr);
        });
    }
}

/// The form in which a local ban is offered to peers, or `None` if it must
/// not be offered at all.
///
/// Peers accept only records whose lifetime and remaining TTL are both
/// `<= trust.remote_max_ttl_secs` (24 h by default, in every released build).
/// A longer local ban (path_probe/scanner 72 h, ssh 48 h, …) is therefore
/// offered as a fixed window: lifetime is cut into consecutive `max_secs`
/// slices starting at `created_at` and the slice containing `now` is announced
/// (`created_at' = created_at + k·max`, `expires_at' = min(expires_at,
/// created_at' + max)`). Within a slice the record is byte-identical, so the
/// PoW/signature come from the `SigningCache` (one new stamp per long ban per
/// slice, not per anti-entropy round). When the peer's copy expires at a slice
/// boundary, anti-entropy sends the next slice. Bans no longer than `max_secs`
/// are returned unchanged (same signatures as before this change).
///
/// Permanent bans are never offered: every build rejects them
/// (`remote_policy_allows`), and offering them only costs PoW. Expired ones
/// neither. The prefix limit stays the receiver's decision.
fn announced_form(
    record: &BanRecord,
    max_secs: i64,
    now: chrono::DateTime<chrono::Utc>,
) -> Option<BanRecord> {
    let expiry = record.expires_at?;
    if expiry <= now || expiry <= record.created_at || max_secs <= 0 {
        return None;
    }
    let max = chrono::Duration::seconds(max_secs);
    if expiry.signed_duration_since(record.created_at) <= max {
        return Some(record.clone());
    }
    let elapsed = now.signed_duration_since(record.created_at).num_seconds().max(0);
    let slice = elapsed / max_secs;
    let created_at = record.created_at + chrono::Duration::seconds(slice.checked_mul(max_secs)?);
    let mut windowed = record.clone();
    windowed.created_at = created_at;
    windowed.expires_at = Some(expiry.min(created_at + max));
    Some(windowed)
}

/// A finite, locally configured blast-radius limit, applied before quorum.
fn remote_policy_allows(
    policy: &TrustConfig,
    record: &BanRecord,
    now: chrono::DateTime<chrono::Utc>,
) -> bool {
    let min_prefix = match record.subject {
        IpNet::V4(_) => policy.remote_min_prefix_v4,
        IpNet::V6(_) => policy.remote_min_prefix_v6,
    };
    let Some(expiry) = record.expires_at else {
        return false;
    };
    let Ok(max_secs) = i64::try_from(policy.remote_max_ttl_secs) else {
        return false;
    };
    record.subject.prefix_len() >= min_prefix
        && record.created_at <= now + chrono::Duration::minutes(5)
        && expiry > now
        && expiry > record.created_at
        && expiry
            .signed_duration_since(record.created_at)
            .num_seconds()
            <= max_secs
        && expiry.signed_duration_since(now).num_seconds() <= max_secs
}

fn remote_changes_state(state: &StateManager, record: &BanRecord) -> bool {
    let Some(existing) = state.ban_store().is_banned(&record.subject.addr()) else {
        return true;
    };
    existing.subject == record.subject
        && matches!(existing.source, BanSource::ClusterPeer(_))
        && (record.created_at, record.expires_at) > (existing.created_at, existing.expires_at)
}

/// One message per uni-stream: `open_uni → length-prefixed bincode → finish`.
async fn send_msg(conn: quinn::Connection, msg: ClusterMessage) {
    let _ = tokio::time::timeout(Duration::from_secs(10), async {
        match conn.open_uni().await {
            Ok(mut stream) => {
                if let Err(e) = send_message(&mut stream, &msg).await {
                    debug!(error = %e, "cluster: send_message failed");
                    return;
                }
                let _ = stream.finish();
            }
            Err(e) => debug!(error = %e, "cluster: open_uni failed"),
        }
    })
    .await;
}

/// Per-connection reader: each accepted uni-stream carries exactly one message.
async fn reader_loop(node_id: String, conn: quinn::Connection, tx: mpsc::Sender<ActorEvent>) {
    let mut window = std::time::Instant::now();
    let mut bytes_received = 0usize;
    let mut messages_received = 0usize;
    loop {
        let mut recv = match conn.accept_uni().await {
            Ok(recv) => recv,
            Err(e) => {
                debug!(%node_id, error = %e, "cluster: connection closed");
                break;
            }
        };
        let bytes =
            match tokio::time::timeout(Duration::from_secs(10), read_bounded_message(&mut recv))
                .await
            {
                Ok(Ok(bytes)) => bytes,
                Ok(Err(e)) => {
                    debug!(%node_id, error = %e, "cluster: stream read error");
                    continue;
                }
                Err(_) => {
                    debug!(%node_id, "cluster: stream read deadline exceeded");
                    continue;
                }
            };
        if window.elapsed() >= Duration::from_secs(60) {
            window = std::time::Instant::now();
            bytes_received = 0;
            messages_received = 0;
        }
        bytes_received += bytes.len();
        messages_received += 1;
        if bytes_received > 16 * 1024 * 1024 || messages_received > 1024 {
            conn.close(0u32.into(), b"message budget exceeded");
            break;
        }
        match decode_message::<ClusterMessage>(&bytes) {
            Ok(msg) => {
                if tx
                    .send(ActorEvent::Inbound {
                        from: node_id.clone(),
                        msg,
                    })
                    .await
                    .is_err()
                {
                    break;
                }
            }
            Err(e) => debug!(%node_id, error = %e, "cluster: undecodable message"),
        }
    }
}

/// Resolve `host:port` to a `SocketAddr` (handles both literal IPs and DNS).
async fn resolve(addr: &str) -> Option<SocketAddr> {
    match tokio::net::lookup_host(addr).await {
        Ok(mut it) => it.next(),
        Err(e) => {
            debug!(addr, error = %e, "cluster: DNS resolution failed");
            None
        }
    }
}

#[cfg(test)]
mod security_tests {
    use super::*;
    use hiveguard_core::persistence::wal::WalSyncMode;

    fn record(subject: &str) -> BanRecord {
        let now = chrono::Utc::now();
        BanRecord {
            subject: subject.parse().unwrap(),
            created_at: now,
            expires_at: Some(now + chrono::Duration::hours(1)),
            severity: 100,
            reason: "test".into(),
            evidence_hash: [0; 32],
            source: BanSource::ClusterPeer("peer".into()),
            geo_info: None,
        }
    }

    #[test]
    fn remote_policy_bounds_prefix_lifetime_and_future_dates() {
        let policy = TrustConfig::default();
        let now = chrono::Utc::now();
        for subject in ["8.0.0.0/8", "2000::/3"] {
            assert!(!remote_policy_allows(&policy, &record(subject), now));
        }
        for subject in ["8.8.8.0/24", "2001:4860::/48"] {
            assert!(remote_policy_allows(&policy, &record(subject), now));
        }
        let mut ban = record("8.8.8.8/32");
        ban.expires_at = None;
        assert!(!remote_policy_allows(&policy, &ban, now));
        ban.expires_at = Some(now + chrono::Duration::days(2));
        assert!(!remote_policy_allows(&policy, &ban, now));
        ban.created_at = now + chrono::Duration::days(2);
        ban.expires_at = Some(ban.created_at + chrono::Duration::hours(1));
        assert!(!remote_policy_allows(&policy, &ban, now));
    }

    fn local(subject: &str, created_ago_h: i64, ttl_h: Option<i64>) -> BanRecord {
        let now = chrono::Utc::now();
        let mut rec = record(subject);
        rec.source = BanSource::LocalDetector("path_probe".into());
        rec.created_at = now - chrono::Duration::hours(created_ago_h);
        rec.expires_at = ttl_h.map(|h| rec.created_at + chrono::Duration::hours(h));
        rec
    }

    #[test]
    fn long_local_bans_are_announced_as_a_window_peers_accept() {
        let policy = TrustConfig::default();
        let max = policy.remote_max_ttl_secs as i64;
        let now = chrono::Utc::now();
        // (created hours ago, ttl hours) → expected announced (created offset, lifetime)
        for (ago, ttl, slice_start_h, lifetime_h) in [
            (0, 72, 0, 24),   // fresh path_probe/scanner ban
            (30, 72, 24, 24), // second day of a 72 h ban
            (50, 72, 48, 24), // last slice: expiry = original expiry
            (10, 48, 0, 24),  // ssh 48 h
            (25, 26, 24, 2),  // tail shorter than a slice
        ] {
            let rec = local("100.64.1.7/32", ago, Some(ttl));
            assert!(!remote_policy_allows(&policy, &rec, now), "precondition: raw ban rejected");
            let out = announced_form(&rec, max, now).expect("announceable");
            assert_eq!(out.created_at, rec.created_at + chrono::Duration::hours(slice_start_h));
            assert_eq!(
                out.expires_at.unwrap(),
                rec.expires_at.unwrap().min(out.created_at + chrono::Duration::hours(24))
            );
            assert_eq!(
                out.expires_at.unwrap().signed_duration_since(out.created_at),
                chrono::Duration::hours(lifetime_h)
            );
            assert!(out.expires_at.unwrap() <= rec.expires_at.unwrap());
            assert!(remote_policy_allows(&policy, &out, now), "ago={ago} ttl={ttl}");
            // Everything else is untouched (subject, reason, evidence, source).
            assert_eq!((out.subject, &out.reason, out.severity), (rec.subject, &rec.reason, rec.severity));
        }
    }

    #[test]
    fn announced_window_is_stable_within_a_slice_so_pow_is_cached() {
        let max = TrustConfig::default().remote_max_ttl_secs as i64;
        let rec = local("100.64.1.8/32", 30, Some(72));
        let now = chrono::Utc::now();
        let a = announced_form(&rec, max, now).unwrap();
        let b = announced_form(&rec, max, now + chrono::Duration::hours(5)).unwrap();
        assert_eq!(a, b);
        assert_eq!(GossipEngine::record_key(&a), GossipEngine::record_key(&b));
        let next = announced_form(&rec, max, now + chrono::Duration::hours(20)).unwrap();
        assert_ne!(a.created_at, next.created_at);
    }

    #[test]
    fn short_permanent_and_expired_bans() {
        let policy = TrustConfig::default();
        let max = policy.remote_max_ttl_secs as i64;
        let now = chrono::Utc::now();
        let short = local("100.64.1.9/32", 1, Some(24));
        assert_eq!(announced_form(&short, max, now), Some(short));
        assert!(announced_form(&local("100.64.1.10/32", 1, None), max, now).is_none());
        assert!(announced_form(&local("100.64.1.11/32", 80, Some(72)), max, now).is_none());
    }

    #[test]
    fn subnet_scope_limits_for_replication() {
        let policy = TrustConfig::default();
        let now = chrono::Utc::now();
        let max = policy.remote_max_ttl_secs as i64;
        // /24 v4 and /64 v6 (single-host equivalent) replicate, also when long.
        for subject in ["100.64.2.0/24", "2001:db8:1:2::/64", "2001:db8:1::/48"] {
            let out = announced_form(&local(subject, 0, Some(72)), max, now).unwrap();
            assert!(remote_policy_allows(&policy, &out, now), "{subject}");
        }
        // Wider than /24 (v4) or /48 (v6) never replicates.
        for subject in ["100.64.0.0/23", "2001:db8::/47"] {
            let out = announced_form(&local(subject, 0, Some(12)), max, now).unwrap();
            assert!(!remote_policy_allows(&policy, &out, now), "{subject}");
        }
    }

    #[test]
    fn identical_covered_and_local_bans_are_not_new_remote_decisions() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = StateManager::new(dir.path(), WalSyncMode::None).unwrap();
        let ban = record("8.8.8.0/24");
        state.add_ban(ban.clone()).unwrap();
        assert!(!remote_changes_state(&state, &ban));
        assert!(!remote_changes_state(&state, &record("8.8.8.8/32")));
        let mut newer = ban.clone();
        newer.expires_at = ban.expires_at.map(|e| e + chrono::Duration::minutes(1));
        assert!(remote_changes_state(&state, &newer));
        let mut local = ban;
        local.source = BanSource::LocalDetector("ssh".into());
        state.add_ban(local).unwrap();
        assert!(!remote_changes_state(&state, &newer));
    }
}
