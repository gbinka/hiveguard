use std::io::Cursor;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, BufReader};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{mpsc, Semaphore};
use tokio::task::JoinSet;
use tracing::{debug, info, trace, warn};

use hiveguard_core::config::{SyslogTcpConfig, SyslogTlsConfig, SyslogUdpConfig};
use hiveguard_core::models::NormalizedEvent;
use hiveguard_plugin_api::prelude::*;

use crate::syslog_parser::parse_syslog;
use crate::syslog_router::SyslogRouter;
use crate::SenderPolicy;

const MAX_TCP_CONNECTIONS: usize = 1000;
const MAX_UDP_DATAGRAM: usize = 65_535;
const UDP_RATE_LIMIT_PER_IP: u64 = 10_000;
const MAX_TRACKED_UDP_SENDERS: usize = 10_000;
const FRAME_TIMEOUT: Duration = Duration::from_secs(30);
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

struct RateLimiter {
    counts: std::collections::HashMap<IpAddr, (u64, Instant)>,
    limit_per_sec: u64,
}

impl RateLimiter {
    fn new(limit_per_sec: u64) -> Self {
        Self {
            counts: std::collections::HashMap::new(),
            limit_per_sec,
        }
    }

    fn allow(&mut self, ip: IpAddr) -> bool {
        let now = Instant::now();
        if !self.counts.contains_key(&ip) && self.counts.len() >= MAX_TRACKED_UDP_SENDERS {
            return false;
        }
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
        self.counts
            .retain(|_, (_, ts)| now.duration_since(*ts).as_secs() < 10);
    }
}

pub async fn run_udp(
    config: SyslogUdpConfig,
    router: Arc<SyslogRouter>,
    senders: Arc<SenderPolicy>,
    source_name: String,
    sink: EventSink,
    shutdown: CancellationToken,
) -> PluginResult<()> {
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
                        if !senders.allows(sender_ip) {
                            continue;
                        }
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

pub async fn run_tcp(
    config: SyslogTcpConfig,
    router: Arc<SyslogRouter>,
    senders: Arc<SenderPolicy>,
    source_name: String,
    sink: EventSink,
    shutdown: CancellationToken,
) -> PluginResult<()> {
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
                        if !senders.allows(addr.ip()) {
                            continue;
                        }
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

pub async fn run_tls(
    config: SyslogTlsConfig,
    router: Arc<SyslogRouter>,
    senders: Arc<SenderPolicy>,
    source_name: String,
    sink: EventSink,
    shutdown: CancellationToken,
) -> PluginResult<()> {
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
                        if !senders.allows(addr.ip()) {
                            continue;
                        }
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
                            match tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await {
                                Ok(Ok(tls_stream)) => handle_tcp_connection(tls_stream, peer_ip, source_name, sink, shutdown, router).await,
                                Ok(Err(error)) => debug!(ip = %peer_ip, error = %error, "TLS syslog handshake failed"),
                                Err(_) => debug!(ip = %peer_ip, "TLS syslog handshake timed out"),
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

async fn build_tls_server_config(
    config: &SyslogTlsConfig,
) -> PluginResult<tokio_rustls::rustls::ServerConfig> {
    use tokio_rustls::rustls::{self, RootCertStore};

    let cert_pem = tokio::fs::read(&config.cert).await?;
    let key_pem = tokio::fs::read(&config.key).await?;
    let certs = parse_cert_chain(&cert_pem)?;
    if certs.is_empty() {
        return Err(PluginError::Runtime(
            "TLS cert file contains no certificates".into(),
        ));
    }
    let key = parse_private_key(&key_pem)?;

    if let Some(ca_path) = &config.ca_cert {
        let ca_pem = tokio::fs::read(ca_path).await?;
        let mut root_store = RootCertStore::empty();
        for cert in parse_cert_chain(&ca_pem)? {
            root_store
                .add(cert)
                .map_err(|error| PluginError::Runtime(format!("TLS CA add error: {error}")))?;
        }
        let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(root_store))
            .build()
            .map_err(|error| {
                PluginError::Runtime(format!("TLS client verifier build error: {error}"))
            })?;
        rustls::ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(certs, key)
            .map_err(|error| PluginError::Runtime(format!("TLS server config error: {error}")))
    } else {
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|error| PluginError::Runtime(format!("TLS server config error: {error}")))
    }
}

fn parse_cert_chain(
    bytes: &[u8],
) -> PluginResult<Vec<tokio_rustls::rustls::pki_types::CertificateDer<'static>>> {
    let mut reader = Cursor::new(bytes);
    Ok(rustls_pemfile::certs(&mut reader)
        .filter_map(|result| result.ok())
        .map(|cert| cert.into_owned())
        .collect())
}

fn parse_private_key(
    bytes: &[u8],
) -> PluginResult<tokio_rustls::rustls::pki_types::PrivateKeyDer<'static>> {
    let mut reader = Cursor::new(bytes);
    rustls_pemfile::private_key(&mut reader)
        .map_err(|error| PluginError::Runtime(format!("TLS key read error: {error}")))?
        .ok_or_else(|| PluginError::Runtime("No private key found in TLS key file".into()))
        .map(|key| key.clone_key())
}

async fn handle_tcp_connection<S>(
    stream: S,
    peer_ip: IpAddr,
    source_name: String,
    sink: mpsc::Sender<NormalizedEvent>,
    shutdown: CancellationToken,
    router: Arc<SyslogRouter>,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut reader = BufReader::new(stream);
    loop {
        let line = tokio::select! {
            _ = shutdown.cancelled() => return,
            result = read_syslog_frame_with_deadline(&mut reader, FRAME_TIMEOUT) => {
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

async fn read_syslog_frame_with_deadline<R>(
    reader: &mut R,
    deadline: Duration,
) -> std::io::Result<Option<String>>
where
    R: AsyncBufRead + Unpin,
{
    // A total frame deadline also stops peers trickling one byte at a time.
    tokio::time::timeout(deadline, read_syslog_frame(reader))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "syslog frame timed out"))?
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
            let mut line = Vec::new();
            loop {
                let buf = reader.fill_buf().await?;
                if buf.is_empty() {
                    break;
                }
                let newline = buf.iter().position(|&byte| byte == b'\n');
                let take = newline.map_or(buf.len(), |index| index + 1);
                if line.len() + take > MAX_UDP_DATAGRAM {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "syslog message exceeds maximum allowed size",
                    ));
                }
                line.extend_from_slice(&buf[..take]);
                reader.consume(take);
                if newline.is_some() {
                    break;
                }
            }
            return String::from_utf8(line).map(Some).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "syslog message is not UTF-8",
                )
            });
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
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid character in syslog octet count",
            ));
        }
        count_str.push(byte as char);
        if count_str.len() > 10 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "syslog octet count field too long",
            ));
        }
    }
    let count: usize = count_str.parse().map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid syslog octet count",
        )
    })?;
    if count > MAX_UDP_DATAGRAM {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "syslog message exceeds maximum allowed size",
        ));
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

    #[test]
    fn forged_udp_senders_cannot_grow_rate_table_without_bound() {
        let mut limiter = RateLimiter::new(100);
        for i in 0..MAX_TRACKED_UDP_SENDERS as u32 {
            assert!(limiter.allow(std::net::Ipv4Addr::from(i).into()));
        }
        assert!(!limiter.allow("11.22.33.44".parse().unwrap()));
        assert_eq!(limiter.counts.len(), MAX_TRACKED_UDP_SENDERS);
    }

    #[tokio::test]
    async fn overlong_newline_frame_is_rejected_before_eof() {
        let (mut writer, reader) = tokio::io::duplex(MAX_UDP_DATAGRAM * 2);
        use tokio::io::AsyncWriteExt;
        writer
            .write_all(&vec![b'x'; MAX_UDP_DATAGRAM + 1])
            .await
            .unwrap();
        // Keep writer open: rejection must not depend on newline or EOF.
        let mut reader = TokioBufReader::new(reader);
        let err = read_syslog_frame_with_deadline(&mut reader, Duration::from_secs(1))
            .await
            .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn incomplete_frames_have_a_deadline() {
        use tokio::io::AsyncWriteExt;
        for partial in ["<34>unfinished", "123 ", "12"] {
            let (mut writer, reader) = tokio::io::duplex(128);
            writer.write_all(partial.as_bytes()).await.unwrap();
            let mut reader = TokioBufReader::new(reader);
            let err = read_syslog_frame_with_deadline(&mut reader, Duration::from_millis(20))
                .await
                .unwrap_err();
            assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
        }
    }

    #[tokio::test]
    async fn newline_boundary_preserves_the_next_frame() {
        let input = format!("{}\n<34>second\n", "x".repeat(MAX_UDP_DATAGRAM - 1));
        let mut reader = TokioBufReader::new(input.as_bytes());
        assert_eq!(
            read_syslog_frame(&mut reader).await.unwrap().unwrap().len(),
            MAX_UDP_DATAGRAM
        );
        assert_eq!(
            read_syslog_frame(&mut reader).await.unwrap().unwrap(),
            "<34>second\n"
        );
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
        let mut reader =
            TokioBufReader::new("<34>Oct 11 22:14:15 mymachine su[100]: test\n".as_bytes());
        let result = read_syslog_frame(&mut reader).await.unwrap().unwrap();
        assert!(result.contains("su"));
    }
}
