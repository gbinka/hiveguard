use std::io::Cursor;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, BufReader};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{Semaphore, mpsc};
use tokio::task::JoinSet;
use tracing::{debug, info, trace, warn};

use hiveguard_core::config::{SyslogTcpConfig, SyslogTlsConfig, SyslogUdpConfig};
use hiveguard_core::models::NormalizedEvent;
use hiveguard_plugin_api::prelude::*;

use crate::syslog_parser::parse_syslog;
use crate::syslog_router::SyslogRouter;

const MAX_TCP_CONNECTIONS: usize = 1000;
const MAX_UDP_DATAGRAM: usize = 65_535;
const UDP_RATE_LIMIT_PER_IP: u64 = 10_000;

struct RateLimiter {
    counts: std::collections::HashMap<IpAddr, (u64, Instant)>,
    limit_per_sec: u64,
}

impl RateLimiter {
    fn new(limit_per_sec: u64) -> Self {
        Self { counts: std::collections::HashMap::new(), limit_per_sec }
    }

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

    fn prune(&mut self) {
        let now = Instant::now();
        self.counts.retain(|_, (_, ts)| now.duration_since(*ts).as_secs() < 10);
    }
}

pub async fn run_udp(config: SyslogUdpConfig, router: Arc<SyslogRouter>, source_name: String, sink: EventSink, shutdown: CancellationToken) -> PluginResult<()> {
    let socket = UdpSocket::bind(&config.listen).await?;
    let mut buf = vec![0u8; MAX_UDP_DATAGRAM];
    let mut rate = RateLimiter::new(UDP_RATE_LIMIT_PER_IP);
    let mut prune_counter = 0u32;

    info!(listen = %config.listen, plugin = %source_name, "UDP syslog source started");

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => {
                info!(listen = %config.listen, plugin = %source_name, "UDP syslog source stopping");
                return Ok(());
            }
            result = socket.recv_from(&mut buf) => {
                match result {
                    Ok((len, addr)) => {
                        let sender_ip = addr.ip();
                        prune_counter = prune_counter.wrapping_add(1);
                        if prune_counter % 10_000 == 0 {
                            rate.prune();
                        }
                        if !rate.allow(sender_ip) {
                            trace!(ip = %sender_ip, plugin = %source_name, "UDP syslog rate limit exceeded, dropping");
                            continue;
                        }
                        let line = match std::str::from_utf8(&buf[..len]) {
                            Ok(value) => value,
                            Err(_) => {
                                debug!(ip = %sender_ip, plugin = %source_name, "non-UTF8 UDP syslog datagram, skipping");
                                continue;
                            }
                        };
                        if let Some(msg) = parse_syslog(line) {
                            if let Some(event) = router.route(msg, &source_name, Some(sender_ip)) {
                                if sink.send(event).await.is_err() {
                                    return Ok(());
                                }
                            }
                        } else {
                            trace!(ip = %sender_ip, plugin = %source_name, "failed to parse UDP syslog datagram");
                        }
                    }
                    Err(error) => warn!(error = %error, plugin = %source_name, "UDP syslog recv_from error"),
                }
            }
        }
    }
}

pub async fn run_tcp(config: SyslogTcpConfig, router: Arc<SyslogRouter>, source_name: String, sink: EventSink, shutdown: CancellationToken) -> PluginResult<()> {
    let listener = TcpListener::bind(&config.listen).await?;
    let semaphore = Arc::new(Semaphore::new(MAX_TCP_CONNECTIONS));
    let mut tasks = JoinSet::new();

    info!(listen = %config.listen, plugin = %source_name, "TCP syslog listener started");

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            join_result = tasks.join_next(), if !tasks.is_empty() => {
                if let Some(Err(error)) = join_result {
                    debug!(error = %error, plugin = %source_name, "TCP syslog connection task exited with error");
                }
            }
            accept = listener.accept() => {
                match accept {
                    Ok((stream, addr)) => {
                        let permit = match semaphore.clone().try_acquire_owned() {
                            Ok(permit) => permit,
                            Err(_) => {
                                warn!(ip = %addr.ip(), plugin = %source_name, "TCP syslog max connections reached, dropping");
                                continue;
                            }
                        };
                        let router = router.clone();
                        let sink = sink.clone();
                        let shutdown = shutdown.clone();
                        let source_name = source_name.clone();
                        let peer_ip = addr.ip();
                        tasks.spawn(async move {
                            let _permit = permit;
                            handle_tcp_connection(stream, peer_ip, source_name, sink, shutdown, router).await;
                        });
                    }
                    Err(error) => warn!(error = %error, plugin = %source_name, "TCP syslog accept error"),
                }
            }
        }
    }

    tasks.abort_all();
    while let Some(join_result) = tasks.join_next().await {
        if let Err(error) = join_result {
            debug!(error = %error, plugin = %source_name, "TCP syslog task aborted during shutdown");
        }
    }
    info!(listen = %config.listen, plugin = %source_name, "TCP syslog source stopping");
    Ok(())
}

pub async fn run_tls(config: SyslogTlsConfig, router: Arc<SyslogRouter>, source_name: String, sink: EventSink, shutdown: CancellationToken) -> PluginResult<()> {
    use tokio_rustls::TlsAcceptor;

    let acceptor = TlsAcceptor::from(Arc::new(build_tls_server_config(&config).await?));
    let listener = TcpListener::bind(&config.listen).await?;
    let semaphore = Arc::new(Semaphore::new(MAX_TCP_CONNECTIONS));
    let mut tasks = JoinSet::new();

    info!(listen = %config.listen, plugin = %source_name, "TLS syslog listener started");

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            join_result = tasks.join_next(), if !tasks.is_empty() => {
                if let Some(Err(error)) = join_result {
                    debug!(error = %error, plugin = %source_name, "TLS syslog connection task exited with error");
                }
            }
            accept = listener.accept() => {
                match accept {
                    Ok((stream, addr)) => {
                        let permit = match semaphore.clone().try_acquire_owned() {
                            Ok(permit) => permit,
                            Err(_) => {
                                warn!(ip = %addr.ip(), plugin = %source_name, "TLS syslog max connections reached, dropping");
                                continue;
                            }
                        };
                        let acceptor = acceptor.clone();
                        let router = router.clone();
                        let sink = sink.clone();
                        let shutdown = shutdown.clone();
                        let source_name = source_name.clone();
                        let peer_ip = addr.ip();
                        tasks.spawn(async move {
                            let _permit = permit;
                            match acceptor.accept(stream).await {
                                Ok(tls_stream) => handle_tcp_connection(tls_stream, peer_ip, source_name, sink, shutdown, router).await,
                                Err(error) => debug!(ip = %peer_ip, error = %error, "TLS syslog handshake failed"),
                            }
                        });
                    }
                    Err(error) => warn!(error = %error, plugin = %source_name, "TLS syslog accept error"),
                }
            }
        }
    }

    tasks.abort_all();
    while let Some(join_result) = tasks.join_next().await {
        if let Err(error) = join_result {
            debug!(error = %error, plugin = %source_name, "TLS syslog task aborted during shutdown");
        }
    }
    info!(listen = %config.listen, plugin = %source_name, "TLS syslog source stopping");
    Ok(())
}

async fn build_tls_server_config(config: &SyslogTlsConfig) -> PluginResult<tokio_rustls::rustls::ServerConfig> {
    use tokio_rustls::rustls::{self, RootCertStore};

    let cert_pem = tokio::fs::read(&config.cert).await?;
    let key_pem = tokio::fs::read(&config.key).await?;
    let certs = parse_cert_chain(&cert_pem)?;
    if certs.is_empty() {
        return Err(PluginError::Runtime("TLS cert file contains no certificates".into()));
    }
    let key = parse_private_key(&key_pem)?;

    if let Some(ca_path) = &config.ca_cert {
        let ca_pem = tokio::fs::read(ca_path).await?;
        let mut root_store = RootCertStore::empty();
        for cert in parse_cert_chain(&ca_pem)? {
            root_store.add(cert).map_err(|error| PluginError::Runtime(format!("TLS CA add error: {error}")))?;
        }
        let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(root_store)).build().map_err(|error| PluginError::Runtime(format!("TLS client verifier build error: {error}")))?;
        rustls::ServerConfig::builder().with_client_cert_verifier(verifier).with_single_cert(certs, key).map_err(|error| PluginError::Runtime(format!("TLS server config error: {error}")))
    } else {
        rustls::ServerConfig::builder().with_no_client_auth().with_single_cert(certs, key).map_err(|error| PluginError::Runtime(format!("TLS server config error: {error}")))
    }
}

fn parse_cert_chain(bytes: &[u8]) -> PluginResult<Vec<tokio_rustls::rustls::pki_types::CertificateDer<'static>>> {
    let mut reader = Cursor::new(bytes);
    Ok(rustls_pemfile::certs(&mut reader).filter_map(|result| result.ok()).map(|cert| cert.into_owned()).collect())
}

fn parse_private_key(bytes: &[u8]) -> PluginResult<tokio_rustls::rustls::pki_types::PrivateKeyDer<'static>> {
    let mut reader = Cursor::new(bytes);
    rustls_pemfile::private_key(&mut reader)
        .map_err(|error| PluginError::Runtime(format!("TLS key read error: {error}")))?
        .ok_or_else(|| PluginError::Runtime("No private key found in TLS key file".into()))
        .map(|key| key.clone_key())
}

async fn handle_tcp_connection<S>(stream: S, peer_ip: IpAddr, source_name: String, sink: mpsc::Sender<NormalizedEvent>, shutdown: CancellationToken, router: Arc<SyslogRouter>)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut reader = BufReader::new(stream);
    loop {
        let line = tokio::select! {
            _ = shutdown.cancelled() => return,
            result = read_syslog_frame(&mut reader) => {
                match result {
                    Ok(Some(line)) => line,
                    Ok(None) => {
                        debug!(ip = %peer_ip, plugin = %source_name, "TCP syslog connection closed");
                        return;
                    }
                    Err(error) => {
                        warn!(ip = %peer_ip, error = %error, plugin = %source_name, "TCP syslog frame read error");
                        return;
                    }
                }
            }
        };
        if let Some(msg) = parse_syslog(&line) {
            if let Some(event) = router.route(msg, &source_name, Some(peer_ip)) {
                if sink.send(event).await.is_err() {
                    return;
                }
            }
        } else {
            trace!(ip = %peer_ip, plugin = %source_name, "failed to parse TCP syslog message");
        }
    }
}

async fn read_syslog_frame<R>(reader: &mut R) -> std::io::Result<Option<String>>
where
    R: AsyncBufRead + Unpin,
{
    {
        let buf = reader.fill_buf().await?;
        if buf.is_empty() {
            return Ok(None);
        }
        if !buf[0].is_ascii_digit() {
            let mut line = String::new();
            let n = reader.read_line(&mut line).await?;
            if n == 0 {
                return Ok(None);
            }
            return Ok(Some(line));
        }
    }

    let mut count_str = String::with_capacity(10);
    loop {
        let buf = reader.fill_buf().await?;
        if buf.is_empty() {
            return Ok(None);
        }
        let byte = buf[0];
        reader.consume(1);
        if byte == b' ' {
            break;
        }
        if !byte.is_ascii_digit() {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid character in syslog octet count"));
        }
        count_str.push(byte as char);
        if count_str.len() > 10 {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "syslog octet count field too long"));
        }
    }
    let count: usize = count_str.parse().map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid syslog octet count"))?;
    if count > MAX_UDP_DATAGRAM {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "syslog message exceeds maximum allowed size"));
    }
    let mut buf = vec![0u8; count];
    reader.read_exact(&mut buf).await?;
    Ok(Some(String::from_utf8_lossy(&buf).into_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::BufReader as TokioBufReader;

    #[test]
    fn rate_limiter_blocks_over_limit() {
        let mut limiter = RateLimiter::new(1);
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        assert!(limiter.allow(ip));
        assert!(!limiter.allow(ip));
    }

    #[tokio::test]
    async fn octet_count_frame_roundtrip() {
        let msg = "<34>1 2024-01-01T00:00:00Z h sshd - - - test";
        let framed = format!("{} {}", msg.len(), msg);
        let mut reader = TokioBufReader::new(framed.as_bytes());
        let result = read_syslog_frame(&mut reader).await.unwrap().unwrap();
        assert_eq!(result, msg);
    }

    #[tokio::test]
    async fn newline_frame_roundtrip() {
        let mut reader = TokioBufReader::new("<34>Oct 11 22:14:15 mymachine su[100]: test\n".as_bytes());
        let result = read_syslog_frame(&mut reader).await.unwrap().unwrap();
        assert!(result.contains("su"));
    }
}
