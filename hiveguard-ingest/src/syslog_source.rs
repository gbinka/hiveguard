//! Network syslog log sources: UDP (RFC 5426), TCP (RFC 6587), TLS (RFC 5425).
//!
//! All three sources implement `LogSource`, parse incoming syslog messages with
//! the `syslog_parser`, and forward normalised events on the shared mpsc channel.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{mpsc, watch, Semaphore};
use tracing::{debug, info, trace, warn};

use hiveguard_core::config::{SyslogRouteConfig, SyslogTcpConfig, SyslogTlsConfig, SyslogUdpConfig};
use hiveguard_core::errors::HiveGuardError;
use hiveguard_core::models::NormalizedEvent;

use crate::source::LogSource;
use crate::syslog_parser::parse_syslog;
use crate::syslog_router::SyslogRouter;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum simultaneous TCP/TLS connections per listener.
const MAX_TCP_CONNECTIONS: usize = 1000;

/// Maximum UDP datagram size (RFC 5426 §3.1 allows up to 65535 bytes).
const MAX_UDP_DATAGRAM: usize = 65_535;

/// Per-IP rate limit for UDP messages (messages per second).
const UDP_RATE_LIMIT_PER_IP: u64 = 10_000;

// ---------------------------------------------------------------------------
// Per-IP rate limiter (UDP only)
// ---------------------------------------------------------------------------

struct RateLimiter {
    counts: HashMap<IpAddr, (u64, Instant)>,
    limit_per_sec: u64,
}

impl RateLimiter {
    fn new(limit_per_sec: u64) -> Self {
        Self {
            counts: HashMap::new(),
            limit_per_sec,
        }
    }

    /// Returns `true` if the sender is within the rate limit.
    fn allow(&mut self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let entry = self.counts.entry(ip).or_insert((0, now));
        if now.duration_since(entry.1).as_secs() >= 1 {
            *entry = (1, now);
            true
        } else {
            entry.0 += 1;
            entry.0 <= self.limit_per_sec
        }
    }

    /// Prune stale entries to prevent unbounded growth.
    fn prune(&mut self) {
        let now = Instant::now();
        self.counts
            .retain(|_, (_, ts)| now.duration_since(*ts).as_secs() < 10);
    }
}

// ---------------------------------------------------------------------------
// UDP Syslog Source
// ---------------------------------------------------------------------------

/// Syslog source listening on a UDP socket (RFC 5426 / RFC 5424).
pub struct SyslogUdpSource {
    config: SyslogUdpConfig,
    router: Arc<SyslogRouter>,
    stop_tx: Option<watch::Sender<bool>>,
}

impl SyslogUdpSource {
    /// Create a new UDP syslog source.
    ///
    /// `routes` are user-configured routing rules; pass `&[]` for built-in defaults.
    pub fn new(config: SyslogUdpConfig, routes: &[SyslogRouteConfig]) -> Result<Self, HiveGuardError> {
        Ok(Self {
            config,
            router: Arc::new(SyslogRouter::from_config(routes)?),
            stop_tx: None,
        })
    }
}

#[async_trait::async_trait]
impl LogSource for SyslogUdpSource {
    fn name(&self) -> &str {
        "syslog-udp"
    }

    async fn start(
        &mut self,
        sender: mpsc::Sender<NormalizedEvent>,
    ) -> Result<(), HiveGuardError> {
        let socket = UdpSocket::bind(&self.config.listen)
            .await
            .map_err(HiveGuardError::Io)?;

        let (stop_tx, mut stop_rx) = watch::channel(false);
        self.stop_tx = Some(stop_tx);

        let listen = self.config.listen.clone();

        let router = Arc::clone(&self.router);
        tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_UDP_DATAGRAM];
            let mut rate = RateLimiter::new(UDP_RATE_LIMIT_PER_IP);
            let mut prune_counter = 0u32;

            loop {
                tokio::select! {
                    _ = stop_rx.changed() => {
                        if *stop_rx.borrow() {
                            info!("UDP syslog source stopping");
                            break;
                        }
                    }
                    result = socket.recv_from(&mut buf) => {
                        match result {
                            Ok((len, addr)) => {
                                let sender_ip = addr.ip();

                                // Periodic rate-limiter maintenance
                                prune_counter = prune_counter.wrapping_add(1);
                                if prune_counter % 10_000 == 0 {
                                    rate.prune();
                                }

                                if !rate.allow(sender_ip) {
                                    trace!(ip = %sender_ip, "UDP syslog rate limit exceeded, dropping");
                                    continue;
                                }

                                let line = match std::str::from_utf8(&buf[..len]) {
                                    Ok(s) => s,
                                    Err(_) => {
                                        debug!(ip = %sender_ip, "Non-UTF8 UDP syslog datagram, skipping");
                                        continue;
                                    }
                                };

                                if let Some(msg) = parse_syslog(line) {
                                    if let Some(event) =
                                        router.route(msg, "syslog-udp", Some(sender_ip))
                                    {
                                        if sender.send(event).await.is_err() {
                                            info!("Channel closed, UDP syslog source stopping");
                                            return;
                                        }
                                    }
                                } else {
                                    trace!(ip = %sender_ip, "Failed to parse UDP syslog datagram");
                                }
                            }
                            Err(e) => {
                                warn!(error = %e, "UDP syslog recv_from error");
                            }
                        }
                    }
                }
            }
        });

        info!(listen = %listen, "UDP syslog source started");
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
// TCP Syslog Source
// ---------------------------------------------------------------------------

/// Syslog source listening on a TCP socket (RFC 6587).
pub struct SyslogTcpSource {
    config: SyslogTcpConfig,
    router: Arc<SyslogRouter>,
    stop_tx: Option<watch::Sender<bool>>,
}

impl SyslogTcpSource {
    /// Create a new TCP syslog source.
    ///
    /// `routes` are user-configured routing rules; pass `&[]` for built-in defaults.
    pub fn new(config: SyslogTcpConfig, routes: &[SyslogRouteConfig]) -> Result<Self, HiveGuardError> {
        Ok(Self {
            config,
            router: Arc::new(SyslogRouter::from_config(routes)?),
            stop_tx: None,
        })
    }
}

#[async_trait::async_trait]
impl LogSource for SyslogTcpSource {
    fn name(&self) -> &str {
        "syslog-tcp"
    }

    async fn start(
        &mut self,
        sender: mpsc::Sender<NormalizedEvent>,
    ) -> Result<(), HiveGuardError> {
        let listener = TcpListener::bind(&self.config.listen)
            .await
            .map_err(HiveGuardError::Io)?;

        let (stop_tx, stop_rx) = watch::channel(false);
        self.stop_tx = Some(stop_tx);

        let router = Arc::clone(&self.router);
        let semaphore = Arc::new(Semaphore::new(MAX_TCP_CONNECTIONS));
        let listen = self.config.listen.clone();

        tokio::spawn(async move {
            info!(listen = %listen, "TCP syslog listener started");
            let mut stop_rx_accept = stop_rx.clone();

            loop {
                tokio::select! {
                    _ = stop_rx_accept.changed() => {
                        if *stop_rx_accept.borrow() {
                            info!("TCP syslog source stopping");
                            break;
                        }
                    }
                    accept = listener.accept() => {
                        match accept {
                            Ok((stream, addr)) => {
                                let permit = match semaphore.clone().try_acquire_owned() {
                                    Ok(p) => p,
                                    Err(_) => {
                                        warn!(
                                            ip = %addr.ip(),
                                            "TCP syslog: max connections ({}) reached, dropping",
                                            MAX_TCP_CONNECTIONS
                                        );
                                        continue;
                                    }
                                };
                                let sender_clone = sender.clone();
                                let mut stop_rx_conn = stop_rx.clone();
                                let peer_ip = addr.ip();
                                let router_clone = Arc::clone(&router);
                                tokio::spawn(async move {
                                    let _permit = permit;
                                    handle_tcp_connection(
                                        stream,
                                        peer_ip,
                                        "syslog-tcp",
                                        sender_clone,
                                        &mut stop_rx_conn,
                                        &router_clone,
                                    )
                                    .await;
                                });
                            }
                            Err(e) => {
                                warn!(error = %e, "TCP syslog accept error");
                            }
                        }
                    }
                }
            }
        });

        info!(listen = %self.config.listen, "TCP syslog source started");
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
// TLS Syslog Source (RFC 5425)
// ---------------------------------------------------------------------------

/// Syslog source listening on a TLS-encrypted TCP socket (RFC 5425).
pub struct SyslogTlsSource {
    config: SyslogTlsConfig,
    router: Arc<SyslogRouter>,
    stop_tx: Option<watch::Sender<bool>>,
}

impl SyslogTlsSource {
    /// Create a new TLS syslog source.
    ///
    /// `routes` are user-configured routing rules; pass `&[]` for built-in defaults.
    pub fn new(config: SyslogTlsConfig, routes: &[SyslogRouteConfig]) -> Result<Self, HiveGuardError> {
        Ok(Self {
            config,
            router: Arc::new(SyslogRouter::from_config(routes)?),
            stop_tx: None,
        })
    }
}

#[async_trait::async_trait]
impl LogSource for SyslogTlsSource {
    fn name(&self) -> &str {
        "syslog-tls"
    }

    async fn start(
        &mut self,
        sender: mpsc::Sender<NormalizedEvent>,
    ) -> Result<(), HiveGuardError> {
        use std::io::BufReader as StdBufReader;
        use std::sync::Arc;
        use tokio_rustls::rustls::{self, pki_types, ServerConfig};
        use tokio_rustls::TlsAcceptor;

        // Load server certificate chain from PEM file
        let cert_file = std::fs::File::open(&self.config.cert)
            .map_err(|e| HiveGuardError::Config(format!("TLS cert open error: {e}")))?;
        let certs: Vec<pki_types::CertificateDer<'static>> =
            rustls_pemfile::certs(&mut StdBufReader::new(cert_file))
                .filter_map(|r| r.ok())
                .map(|c| c.into_owned())
                .collect();
        if certs.is_empty() {
            return Err(HiveGuardError::Config(
                "TLS cert file contains no certificates".to_string(),
            ));
        }

        // Load private key
        let key_file = std::fs::File::open(&self.config.key)
            .map_err(|e| HiveGuardError::Config(format!("TLS key open error: {e}")))?;
        let key = rustls_pemfile::private_key(&mut StdBufReader::new(key_file))
            .map_err(|e| HiveGuardError::Config(format!("TLS key read error: {e}")))?
            .ok_or_else(|| {
                HiveGuardError::Config("No private key found in TLS key file".to_string())
            })?
            .clone_key();

        // Build ServerConfig: optionally require mutual TLS
        let tls_config = if let Some(ref ca_path) = self.config.ca_cert {
            // Mutual TLS: verify client certificates against the provided CA
            let ca_file = std::fs::File::open(ca_path)
                .map_err(|e| HiveGuardError::Config(format!("TLS CA cert open error: {e}")))?;
            let mut root_store = rustls::RootCertStore::empty();
            for cert_result in rustls_pemfile::certs(&mut StdBufReader::new(ca_file)) {
                if let Ok(cert) = cert_result {
                    root_store.add(cert.into_owned()).map_err(|e| {
                        HiveGuardError::Config(format!("TLS CA add error: {e}"))
                    })?;
                }
            }
            let verifier =
                rustls::server::WebPkiClientVerifier::builder(Arc::new(root_store))
                    .build()
                    .map_err(|e| {
                        HiveGuardError::Config(format!("TLS client verifier build error: {e}"))
                    })?;
            ServerConfig::builder()
                .with_client_cert_verifier(verifier)
                .with_single_cert(certs, key)
                .map_err(|e| HiveGuardError::Config(format!("TLS server config error: {e}")))?
        } else {
            ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certs, key)
                .map_err(|e| HiveGuardError::Config(format!("TLS server config error: {e}")))?
        };

        let acceptor = TlsAcceptor::from(Arc::new(tls_config));
        let listener = TcpListener::bind(&self.config.listen)
            .await
            .map_err(HiveGuardError::Io)?;

        let (stop_tx, stop_rx) = watch::channel(false);
        self.stop_tx = Some(stop_tx);

        let router = Arc::clone(&self.router);
        let semaphore = Arc::new(Semaphore::new(MAX_TCP_CONNECTIONS));
        let listen = self.config.listen.clone();

        tokio::spawn(async move {
            info!(listen = %listen, "TLS syslog listener started");
            let mut stop_rx_accept = stop_rx.clone();

            loop {
                tokio::select! {
                    _ = stop_rx_accept.changed() => {
                        if *stop_rx_accept.borrow() {
                            info!("TLS syslog source stopping");
                            break;
                        }
                    }
                    accept = listener.accept() => {
                        match accept {
                            Ok((stream, addr)) => {
                                let permit = match semaphore.clone().try_acquire_owned() {
                                    Ok(p) => p,
                                    Err(_) => {
                                        warn!(
                                            ip = %addr.ip(),
                                            "TLS syslog: max connections reached, dropping"
                                        );
                                        continue;
                                    }
                                };
                                let acceptor_clone = acceptor.clone();
                                let sender_clone = sender.clone();
                                let mut stop_rx_conn = stop_rx.clone();
                                let peer_ip = addr.ip();
                                let router_clone = Arc::clone(&router);
                                tokio::spawn(async move {
                                    let _permit = permit;
                                    match acceptor_clone.accept(stream).await {
                                        Ok(tls_stream) => {
                                            handle_tcp_connection(
                                                tls_stream,
                                                peer_ip,
                                                "syslog-tls",
                                                sender_clone,
                                                &mut stop_rx_conn,
                                                &router_clone,
                                            )
                                            .await;
                                        }
                                        Err(e) => {
                                            debug!(
                                                ip = %peer_ip,
                                                error = %e,
                                                "TLS syslog handshake failed"
                                            );
                                        }
                                    }
                                });
                            }
                            Err(e) => {
                                warn!(error = %e, "TLS syslog accept error");
                            }
                        }
                    }
                }
            }
        });

        info!(listen = %self.config.listen, "TLS syslog source started");
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
// TCP framing helper (shared by plain TCP and TLS)
// ---------------------------------------------------------------------------

/// Handle a single TCP/TLS syslog connection (RFC 6587 framing).
///
/// Supports:
/// - **Octet-counting** (RFC 6587 §3.4.1): `<N> <SYSLOG-MSG>`
/// - **Non-transparent** (RFC 6587 §3.4.2): newline-delimited
async fn handle_tcp_connection<S>(
    stream: S,
    peer_ip: IpAddr,
    source_name: &str,
    sender: mpsc::Sender<NormalizedEvent>,
    stop_rx: &mut watch::Receiver<bool>,
    router: &SyslogRouter,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut reader = BufReader::new(stream);

    loop {
        let line = tokio::select! {
            _ = stop_rx.changed() => {
                if *stop_rx.borrow() { return; }
                continue;
            }
            result = read_syslog_frame(&mut reader) => {
                match result {
                    Ok(Some(line)) => line,
                    Ok(None) => {
                        debug!(ip = %peer_ip, "TCP syslog connection closed");
                        return;
                    }
                    Err(e) => {
                        warn!(ip = %peer_ip, error = %e, "TCP syslog frame read error");
                        return;
                    }
                }
            }
        };

        if let Some(msg) = parse_syslog(&line) {
            if let Some(event) = router.route(msg, source_name, Some(peer_ip)) {
                if sender.send(event).await.is_err() {
                    return;
                }
            }
        } else {
            trace!(ip = %peer_ip, "Failed to parse TCP syslog message");
        }
    }
}

/// Read one syslog frame using RFC 6587 framing.
///
/// - If the buffered data starts with an ASCII digit, assumes **octet-counting**
///   framing and reads exactly that many bytes.
/// - Otherwise falls back to **non-transparent** (newline-delimited) framing.
async fn read_syslog_frame<R>(reader: &mut R) -> std::io::Result<Option<String>>
where
    R: AsyncBufReadExt + Unpin,
{
    // Peek at the first byte to decide framing mode
    {
        let buf = reader.fill_buf().await?;
        if buf.is_empty() {
            return Ok(None);
        }
        if !buf[0].is_ascii_digit() {
            // Non-transparent framing: read until newline
            let mut line = String::new();
            let n = reader.read_line(&mut line).await?;
            if n == 0 {
                return Ok(None);
            }
            return Ok(Some(line));
        }
    }

    // Octet-counting framing: read decimal count, then SP, then exactly count bytes
    let mut count_str = String::with_capacity(10);
    loop {
        let buf = reader.fill_buf().await?;
        if buf.is_empty() {
            return Ok(None);
        }
        let b = buf[0];
        reader.consume(1);
        if b == b' ' {
            break;
        }
        if !b.is_ascii_digit() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid character in syslog octet count",
            ));
        }
        count_str.push(b as char);
        if count_str.len() > 10 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "syslog octet count field too long",
            ));
        }
    }

    let count: usize = count_str.parse().map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid syslog octet count")
    })?;
    if count > MAX_UDP_DATAGRAM {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "syslog message exceeds maximum allowed size",
        ));
    }

    let mut msg_buf = vec![0u8; count];
    reader.read_exact(&mut msg_buf).await?;
    let s = String::from_utf8_lossy(&msg_buf).into_owned();
    Ok(Some(s))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── RateLimiter ───────────────────────────────────────────────────────

    #[test]
    fn rate_limiter_allows_under_limit() {
        let mut rl = RateLimiter::new(100);
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        for _ in 0..100 {
            assert!(rl.allow(ip));
        }
    }

    #[test]
    fn rate_limiter_blocks_over_limit() {
        let mut rl = RateLimiter::new(5);
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        for _ in 0..5 {
            rl.allow(ip);
        }
        assert!(!rl.allow(ip));
    }

    // ── Router integration (generic fallback) ─────────────────────────────

    #[test]
    fn generic_event_uses_sender_ip_when_no_ip_in_message() {
        use crate::syslog_parser::{SyslogFacility, SyslogSeverity};
        let msg = crate::syslog_parser::SyslogMessage {
            facility: SyslogFacility::Auth,
            severity: SyslogSeverity::Warning,
            timestamp: None,
            hostname: Some("host".to_string()),
            app_name: Some("unknownapp".to_string()),
            procid: None,
            msgid: None,
            structured_data: vec![],
            message: "some log line without ip".to_string(),
        };
        let sender_ip: IpAddr = "10.0.0.1".parse().unwrap();
        let router = SyslogRouter::from_config(&[]).unwrap();
        let event = router.route(msg, "syslog-udp", Some(sender_ip)).unwrap();
        assert_eq!(event.source_ip, sender_ip);
        assert_eq!(event.source_name, "syslog-udp");
        assert_eq!(event.metadata["syslog_app_name"], "unknownapp");
    }

    #[test]
    fn generic_event_returns_none_when_no_ip_available() {
        use crate::syslog_parser::{SyslogFacility, SyslogSeverity};
        let msg = crate::syslog_parser::SyslogMessage {
            facility: SyslogFacility::Auth,
            severity: SyslogSeverity::Warning,
            timestamp: None,
            hostname: None,
            app_name: Some("myapp".to_string()),
            procid: None,
            msgid: None,
            structured_data: vec![],
            message: "no ip here whatsoever".to_string(),
        };
        let router = SyslogRouter::from_config(&[]).unwrap();
        assert!(router.route(msg, "syslog-udp", None).is_none());
    }

    // ── Framing ───────────────────────────────────────────────────────────

    /// Test octet-counting frame parsing.
    #[tokio::test]
    async fn octet_count_frame_roundtrip() {
        use tokio::io::BufReader as TokioBufReader;

        let msg = "<34>1 2024-01-01T00:00:00Z h sshd - - - test";
        let framed = format!("{} {}", msg.len(), msg);

        let mut reader = TokioBufReader::new(framed.as_bytes());
        let result = read_syslog_frame(&mut reader).await.unwrap().unwrap();
        assert_eq!(result, msg);
    }

    /// Test non-transparent (newline) frame parsing.
    #[tokio::test]
    async fn newline_frame_roundtrip() {
        use tokio::io::BufReader as TokioBufReader;

        let msg = "<34>Oct 11 22:14:15 mymachine su[100]: test\n";
        let mut reader = TokioBufReader::new(msg.as_bytes());
        let result = read_syslog_frame(&mut reader).await.unwrap().unwrap();
        assert!(result.contains("su"));
    }

    /// EOF on empty stream returns None.
    #[tokio::test]
    async fn empty_stream_returns_none() {
        use tokio::io::BufReader as TokioBufReader;

        let data: &[u8] = &[];
        let mut reader = TokioBufReader::new(data);
        let result = read_syslog_frame(&mut reader).await.unwrap();
        assert!(result.is_none());
    }
}
