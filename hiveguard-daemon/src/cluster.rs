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
use tokio::sync::{mpsc, watch, Mutex};
use tokio::time::{interval, Duration};
use tracing::{debug, info, warn};

use hiveguard_core::anti_poison::RateLimiter;
use hiveguard_core::ban_store::BanStore;
use hiveguard_core::config::{ClusterMode, HiveGuardConfig};
use hiveguard_core::persistence::state_manager::StateManager;
use hiveguard_core::trust::TrustManager;
use hiveguard_core::{BanRecord, BanSource};
use hiveguard_enforce::Enforcer;
use hiveguard_net::{
    extract_peer_fingerprint_and_key, read_bounded_message, send_message, decode_message,
    ClusterMessage, GossipAction, GossipConfig, GossipEngine, NodeIdentity, PeerInfo, PeerState,
    QuicTransport, SignedBanRecord, SwimAction, SwimConfig, SyncCoordinator,
};

use crate::metrics::SharedMetrics;

/// PoW difficulty (leading zero bits) mined into every outbound signed ban.
/// Matches `GossipConfig` default / `SignedBanRecord` minimum.
const POW_DIFFICULTY: u8 = 16;

/// How often the dialer reconnects to missing seeds and the actor emits an
/// anti-entropy digest exchange.
const MAINTENANCE_INTERVAL: Duration = Duration::from_secs(5);

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
        GossipConfig { fanout: 8, pow_difficulty: POW_DIFFICULTY },
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
                if tx.send(ActorEvent::LocalBan(rec)).await.is_err() { break; }
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
        ban_counts: HashMap::new(),
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
                .send(ActorEvent::PeerConnected { node_id: fp, public_key: pubkey, addr, conn })
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
    /// node_id → number of ban records received (anti-poison quarantine input).
    ban_counts: HashMap<String, usize>,
    connections: HashMap<String, quinn::Connection>,
    /// Addresses with an in-flight dial, to avoid pile-ups.
    dialing: Arc<std::sync::Mutex<HashSet<String>>>,
    state: Arc<Mutex<StateManager>>,
    enforcer: Arc<Mutex<Box<dyn Enforcer>>>,
    metrics: Option<SharedMetrics>,
    tx: mpsc::Sender<ActorEvent>,
}

impl ClusterActor {
    async fn run(mut self, mut rx: mpsc::Receiver<ActorEvent>, mut shutdown: watch::Receiver<bool>) {
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
                self.send_to(&from, ClusterMessage::Pong { sender_id: self.node_id.clone(), digest });
            }
            ClusterMessage::Pong { .. } => {
                self.coordinator.handle_pong(&from);
            }
            ClusterMessage::PingReq { target_id, .. } => {
                let digest = self.local_digest().await;
                self.send_to(&target_id, ClusterMessage::Ping { sender_id: self.node_id.clone(), digest });
            }
            ClusterMessage::BanSync { records, .. } => {
                self.ingest_remote_bans(&from, records).await;
            }
            ClusterMessage::DiffResponse { records } => {
                self.ingest_remote_bans(&from, records).await;
            }
            ClusterMessage::DigestExchange { merkle_root } => {
                let local_bans = self.snapshot_bans().await;
                if let Some(GossipAction::SendDiffRequest { missing_keys, .. }) =
                    self.coordinator.handle_digest_exchange(&merkle_root, &local_bans, &from)
                {
                    self.send_to(&from, ClusterMessage::DiffRequest { missing_keys });
                }
            }
            ClusterMessage::DiffRequest { missing_keys } => {
                let local_bans = self.snapshot_bans().await;
                let missing = self.coordinator.handle_diff_request(&missing_keys, &local_bans);
                let records: Vec<SignedBanRecord> =
                    missing.into_iter().filter_map(|r| self.sign(r)).collect();
                if !records.is_empty() {
                    self.send_to(&from, ClusterMessage::DiffResponse { records });
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
        let n = records.len();
        let peer_keys = self.peer_public_keys();
        let action = self.coordinator.handle_ban_sync_filtered(
            records,
            from,
            &self.trust,
            &mut self.rate_limiter,
            &self.ban_counts,
            &peer_keys,
        );
        *self.ban_counts.entry(from.to_string()).or_insert(0) += n;

        if let Some(GossipAction::ApplyBans { records }) = action {
            self.apply_bans(from, records).await;
        }
    }

    fn on_local_ban(&mut self, rec: BanRecord) {
        let Some(signed) = self.sign(rec) else { return };
        if let Some(GossipAction::SendBanSync { target_ids, records }) =
            self.coordinator.propagate_bans(vec![signed])
        {
            for target in target_ids {
                self.send_to(
                    &target,
                    ClusterMessage::BanSync { sender_id: self.node_id.clone(), records: records.clone() },
                );
            }
        }
    }

    fn on_probe(&mut self) {
        // SWIM digest is informational; an empty vec is fine for liveness.
        let actions = self.coordinator.run_probe_cycle(Vec::new());
        for action in actions {
            match action {
                SwimAction::SendPing { target_id, digest } => {
                    self.send_to(&target_id, ClusterMessage::Ping { sender_id: self.node_id.clone(), digest });
                }
                SwimAction::SendPingReq { target_id, via_peers } => {
                    for via in via_peers {
                        self.send_to(&via, ClusterMessage::PingReq {
                            sender_id: self.node_id.clone(),
                            target_id: target_id.clone(),
                        });
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
        for seed in self.seeds.clone() {
            let connected = match &seed.fingerprint {
                Some(fp) => self.connections.contains_key(fp),
                // Without a pinned fingerprint we can't map address→node_id
                // ahead of the handshake, so fall back to "dial if we have no
                // peers at all" to bootstrap, then rely on SWIM afterwards.
                None => !self.connections.is_empty(),
            };
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
                send_msg(conn, ClusterMessage::DigestExchange { merkle_root: digest.clone() }).await;
            }
        });
    }

    // --- helpers -----------------------------------------------------------

    /// Sign a ban record with the node's identity key. Returns `None` on the
    /// (practically impossible) signing/PoW failure.
    fn sign(&self, record: BanRecord) -> Option<SignedBanRecord> {
        match SignedBanRecord::sign(record, &self.node_id, &self.pkcs8, POW_DIFFICULTY) {
            Ok(s) => Some(s),
            Err(e) => {
                warn!(error = %e, "cluster: failed to sign ban record");
                None
            }
        }
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
    /// record's `source` is re-tagged `ClusterPeer(from)` so logs/UI/SIEM show
    /// the ban arrived via gossip rather than local detection. These are **not**
    /// re-announced (no echo).
    async fn apply_bans(&self, from: &str, records: Vec<BanRecord>) {
        let now = chrono::Utc::now();
        let mut to_enforce: Vec<IpNet> = Vec::new();
        {
            let mut st = self.state.lock().await;
            for mut rec in records {
                // Peers running older builds keep re-announcing bans that have
                // already expired; persisting them just re-creates entries the
                // expiry sweep removes again, looping forever.
                if rec.expires_at.is_some_and(|exp| exp <= now) {
                    debug!(subject = %rec.subject, peer = %from, "cluster: remote ban already expired — skipping");
                    continue;
                }
                let addr = rec.subject.addr();
                if st.whitelist().is_whitelisted(&addr) {
                    debug!(subject = %rec.subject, peer = %from, "cluster: remote ban hits whitelist — skipping");
                    continue;
                }
                if st.ban_store().is_banned(&addr).is_some() {
                    continue; // already known
                }
                let subject = rec.subject;
                let reason = rec.reason.clone();
                // Provenance: this node did not detect the attacker itself — it
                // was blocked pre-emptively because a peer reported it.
                rec.source = BanSource::ClusterPeer(from.to_string());
                match st.add_ban(rec) {
                    Ok(()) => {
                        info!(
                            %subject, peer = %from, reason = %reason,
                            "cluster: pre-emptively blocked IP reported by peer"
                        );
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
        {
            let mut enf = self.enforcer.lock().await;
            for subject in &to_enforce {
                if let Err(e) = enf.apply_ban(subject).await {
                    warn!(%subject, error = %e, "cluster: enforcer rejected remote ban");
                }
            }
        }
        if let Some(m) = &self.metrics {
            let st = self.state.lock().await;
            m.active_bans.set(st.ban_store().get_all_bans().len() as i64);
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
        tokio::spawn(async move { send_msg(conn, msg).await; });
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

/// One message per uni-stream: `open_uni → length-prefixed bincode → finish`.
async fn send_msg(conn: quinn::Connection, msg: ClusterMessage) {
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
}

/// Per-connection reader: each accepted uni-stream carries exactly one message.
async fn reader_loop(node_id: String, conn: quinn::Connection, tx: mpsc::Sender<ActorEvent>) {
    loop {
        match conn.accept_uni().await {
            Ok(mut recv) => match read_bounded_message(&mut recv).await {
                Ok(bytes) => match decode_message::<ClusterMessage>(&bytes) {
                    Ok(msg) => {
                        if tx.send(ActorEvent::Inbound { from: node_id.clone(), msg }).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => debug!(%node_id, error = %e, "cluster: undecodable message"),
                },
                Err(e) => debug!(%node_id, error = %e, "cluster: stream read error"),
            },
            Err(e) => {
                debug!(%node_id, error = %e, "cluster: connection closed");
                break;
            }
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
