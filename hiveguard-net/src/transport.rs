use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use quinn::{RecvStream, SendStream};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::server::WebPkiClientVerifier;
use rustls::{DigitallySignedStruct, DistinguishedName, RootCertStore, SignatureScheme};
use serde::{Deserialize, Serialize};
use tracing;

use hiveguard_core::HiveGuardError;

use crate::identity::NodeIdentity;

const ALPN_PROTOCOL: &[u8] = b"hiveguard/1";

/// Maximum size of a single cluster message received over QUIC (4 MiB).
/// Prevents memory exhaustion from malicious peers sending huge messages.
const MAX_MESSAGE_SIZE: usize = 4 * 1024 * 1024;

/// Extract the blake3 fingerprint from a peer's TLS certificate presented during
/// the QUIC handshake. Returns `None` if the peer did not present a certificate
/// or the public key cannot be extracted.
pub fn extract_peer_fingerprint(conn: &quinn::Connection) -> Option<String> {
    extract_peer_fingerprint_and_key(conn).map(|(fp, _)| fp)
}

/// Extract both fingerprint and raw public key bytes from a peer's TLS certificate.
/// Returns `None` if the peer did not present a certificate or parsing fails.
pub fn extract_peer_fingerprint_and_key(
    conn: &quinn::Connection,
) -> Option<(String, Vec<u8>)> {
    let identity = conn.peer_identity()?;
    let certs = identity.downcast_ref::<Vec<CertificateDer<'static>>>()?;
    let end_entity = certs.first()?;
    let (_, cert) = x509_parser::parse_x509_certificate(end_entity.as_ref()).ok()?;
    let public_key_raw = cert.public_key().subject_public_key.data.to_vec();
    let fingerprint = hex::encode(blake3::hash(&public_key_raw).as_bytes());
    Some((fingerprint, public_key_raw))
}

/// Compute blake3 fingerprint from a DER-encoded X.509 certificate.
pub fn extract_fingerprint_from_cert_der(cert_der: &CertificateDer<'_>) -> Option<String> {
    // Parse the certificate to extract the public key
    let (_, cert) = x509_parser::parse_x509_certificate(cert_der.as_ref()).ok()?;
    let public_key_raw = &cert.public_key().subject_public_key.data;
    Some(hex::encode(blake3::hash(&public_key_raw).as_bytes()))
}

/// QUIC transport layer with mutual TLS using self-signed certificates.
pub struct QuicTransport {
    listen_addr: SocketAddr,
    server_config: quinn::ServerConfig,
    client_config: quinn::ClientConfig,
    endpoint: Mutex<Option<quinn::Endpoint>>,
}

impl QuicTransport {
    /// Create a new QUIC transport from a node identity and listen address.
    ///
    /// Uses permissive TLS verifiers — suitable for development / auto-accept
    /// mode where peers are authenticated at the application layer via fingerprints.
    /// For production cluster mode use [`QuicTransport::new_with_ca`].
    pub fn new(listen_addr: SocketAddr, identity: &NodeIdentity) -> Result<Self, HiveGuardError> {
        let server_config = Self::build_server_config(
            CertificateDer::from(identity.certificate_der().to_vec()),
            identity.private_key_der(),
        )?;

        let client_config = Self::build_client_config(
            CertificateDer::from(identity.certificate_der().to_vec()),
            identity.private_key_der(),
        )?;

        Ok(Self {
            listen_addr,
            server_config,
            client_config,
            endpoint: Mutex::new(None),
        })
    }

    /// Create a QUIC transport with CA-chain enforcement (production cluster mode).
    ///
    /// Both inbound and outbound connections are verified against `ca_cert_der`:
    /// - **Server side**: any connecting peer must present a certificate signed by the CA.
    /// - **Client side**: the remote server must present a certificate signed by the CA.
    ///
    /// `ca_cert_der` is the raw DER bytes of the `ClusterCA` trust anchor — obtain
    /// it via [`ClusterCA::cert_der()`].
    pub fn new_with_ca(
        listen_addr: SocketAddr,
        identity: &NodeIdentity,
        ca_cert_der: &[u8],
    ) -> Result<Self, HiveGuardError> {
        let server_config = Self::build_server_config_ca(
            CertificateDer::from(identity.certificate_der().to_vec()),
            identity.private_key_der(),
            ca_cert_der,
        )?;

        let client_config = Self::build_client_config_ca(
            CertificateDer::from(identity.certificate_der().to_vec()),
            identity.private_key_der(),
            ca_cert_der,
        )?;

        Ok(Self {
            listen_addr,
            server_config,
            client_config,
            endpoint: Mutex::new(None),
        })
    }

    /// Start the QUIC server, binding to the configured listen address.
    /// Returns the endpoint which can accept incoming connections.
    pub async fn start_server(&self) -> Result<quinn::Endpoint, HiveGuardError> {
        let mut endpoint = quinn::Endpoint::server(self.server_config.clone(), self.listen_addr)
            .map_err(|e| HiveGuardError::Config(format!("QUIC server start failed: {e}")))?;

        endpoint.set_default_client_config(self.client_config.clone());

        let ret = endpoint.clone();
        {
            let mut guard = self.endpoint.lock().unwrap();
            *guard = Some(endpoint);
        }

        tracing::info!(addr = %self.listen_addr, "QUIC server started");
        Ok(ret)
    }

    /// Connect to a remote peer. The server must be started first.
    pub async fn connect_to_peer(
        &self,
        addr: SocketAddr,
    ) -> Result<quinn::Connection, HiveGuardError> {
        let endpoint = {
            let guard = self.endpoint.lock().unwrap();
            guard
                .clone()
                .ok_or_else(|| HiveGuardError::Config("QUIC server not started".into()))?
        };

        let conn = endpoint
            .connect(addr, "hiveguard-node")
            .map_err(|e| HiveGuardError::Config(format!("QUIC connect error: {e}")))?
            .await
            .map_err(|e| HiveGuardError::Config(format!("QUIC connection failed: {e}")))?;

        tracing::info!(remote = %addr, "Connected to peer");
        Ok(conn)
    }

    pub fn listen_addr(&self) -> SocketAddr {
        self.listen_addr
    }

    fn build_server_config(
        cert: CertificateDer<'static>,
        key_bytes: Vec<u8>,
    ) -> Result<quinn::ServerConfig, HiveGuardError> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let key = PrivateKeyDer::Pkcs8(key_bytes.into());

        let algs = provider.signature_verification_algorithms;
        let mut server_crypto = rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|e| HiveGuardError::Config(format!("TLS version config error: {e}")))?
            .with_client_cert_verifier(Arc::new(PermissiveCertVerifier { algs }))
            .with_single_cert(vec![cert], key)
            .map_err(|e| HiveGuardError::Config(format!("TLS server cert error: {e}")))?;

        server_crypto.alpn_protocols = vec![ALPN_PROTOCOL.to_vec()];

        let quic_config = quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)
            .map_err(|e| HiveGuardError::Config(format!("QUIC server config error: {e}")))?;

        Ok(quinn::ServerConfig::with_crypto(Arc::new(quic_config)))
    }

    fn build_client_config(
        cert: CertificateDer<'static>,
        key_bytes: Vec<u8>,
    ) -> Result<quinn::ClientConfig, HiveGuardError> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let key = PrivateKeyDer::Pkcs8(key_bytes.into());

        let algs = provider.signature_verification_algorithms;
        let mut client_crypto = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|e| HiveGuardError::Config(format!("TLS version config error: {e}")))?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PermissiveServerVerifier { algs }))
            .with_client_auth_cert(vec![cert], key)
            .map_err(|e| HiveGuardError::Config(format!("TLS client auth error: {e}")))?;

        client_crypto.alpn_protocols = vec![ALPN_PROTOCOL.to_vec()];

        let quic_config = quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)
            .map_err(|e| HiveGuardError::Config(format!("QUIC client config error: {e}")))?;

        Ok(quinn::ClientConfig::new(Arc::new(quic_config)))
    }

    /// Build a server config that requires connecting peers to present a certificate
    /// signed by `ca_cert_der`.  Uses `WebPkiClientVerifier` for chain validation.
    fn build_server_config_ca(
        cert: CertificateDer<'static>,
        key_bytes: Vec<u8>,
        ca_cert_der: &[u8],
    ) -> Result<quinn::ServerConfig, HiveGuardError> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let key = PrivateKeyDer::Pkcs8(key_bytes.into());

        let mut root_store = RootCertStore::empty();
        root_store
            .add(CertificateDer::from(ca_cert_der.to_vec()))
            .map_err(|e| HiveGuardError::Config(format!("CA cert invalid: {e}")))?;

        let client_verifier = WebPkiClientVerifier::builder_with_provider(
            Arc::new(root_store),
            provider.clone(),
        )
        .build()
        .map_err(|e| HiveGuardError::Config(format!("CA client verifier build failed: {e}")))?;

        let mut server_crypto = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|e| HiveGuardError::Config(format!("TLS version config error: {e}")))?
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(vec![cert], key)
            .map_err(|e| HiveGuardError::Config(format!("TLS server cert error: {e}")))?;

        server_crypto.alpn_protocols = vec![ALPN_PROTOCOL.to_vec()];

        let quic_config = quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)
            .map_err(|e| HiveGuardError::Config(format!("QUIC server config error: {e}")))?;

        Ok(quinn::ServerConfig::with_crypto(Arc::new(quic_config)))
    }

    /// Build a client config that verifies the remote server's certificate against
    /// `ca_cert_der`.  No `.dangerous()` — standard webpki chain validation.
    fn build_client_config_ca(
        cert: CertificateDer<'static>,
        key_bytes: Vec<u8>,
        ca_cert_der: &[u8],
    ) -> Result<quinn::ClientConfig, HiveGuardError> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let key = PrivateKeyDer::Pkcs8(key_bytes.into());

        let mut root_store = RootCertStore::empty();
        root_store
            .add(CertificateDer::from(ca_cert_der.to_vec()))
            .map_err(|e| HiveGuardError::Config(format!("CA cert invalid: {e}")))?;

        let mut client_crypto = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|e| HiveGuardError::Config(format!("TLS version config error: {e}")))?
            .with_root_certificates(root_store)
            .with_client_auth_cert(vec![cert], key)
            .map_err(|e| HiveGuardError::Config(format!("TLS client auth error: {e}")))?;

        client_crypto.alpn_protocols = vec![ALPN_PROTOCOL.to_vec()];

        let quic_config = quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)
            .map_err(|e| HiveGuardError::Config(format!("QUIC client config error: {e}")))?;

        Ok(quinn::ClientConfig::new(Arc::new(quic_config)))
    }
}

/// Read a complete message from a QUIC receive stream with bounded size.
///
/// The wire format is a 4-byte little-endian length prefix followed by
/// bincode-encoded payload. Returns `Err` if the declared length exceeds
/// `MAX_MESSAGE_SIZE`, preventing allocation bombs from malicious peers.
pub async fn read_bounded_message(stream: &mut RecvStream) -> Result<Vec<u8>, HiveGuardError> {
    // Read 4-byte length prefix
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .await
        .map_err(|e| HiveGuardError::Protocol(format!("QUIC stream read (len prefix): {e}")))?;

    let declared_len = u32::from_le_bytes(len_buf) as usize;
    if declared_len > MAX_MESSAGE_SIZE {
        tracing::warn!(
            declared = declared_len,
            max = MAX_MESSAGE_SIZE,
            "Rejected oversized message — length prefix exceeds limit"
        );
        return Err(HiveGuardError::Protocol(format!(
            "declared message length {declared_len} exceeds maximum of {MAX_MESSAGE_SIZE} bytes"
        )));
    }

    let mut buf = vec![0u8; declared_len];
    stream
        .read_exact(&mut buf)
        .await
        .map_err(|e| HiveGuardError::Protocol(format!("QUIC stream read (body): {e}")))?;

    Ok(buf)
}

/// Serialize a message to bincode and write it with a 4-byte length prefix.
pub async fn send_message<T: Serialize>(
    stream: &mut SendStream,
    msg: &T,
) -> Result<(), HiveGuardError> {
    let payload = bincode::serialize(msg)
        .map_err(|e| HiveGuardError::Protocol(format!("bincode serialization error: {e}")))?;

    if payload.len() > MAX_MESSAGE_SIZE {
        return Err(HiveGuardError::Protocol(format!(
            "serialized message ({} bytes) exceeds MAX_MESSAGE_SIZE",
            payload.len()
        )));
    }

    let len = (payload.len() as u32).to_le_bytes();
    stream
        .write_all(&len)
        .await
        .map_err(|e| HiveGuardError::Protocol(format!("QUIC stream write (len prefix): {e}")))?;
    stream
        .write_all(&payload)
        .await
        .map_err(|e| HiveGuardError::Protocol(format!("QUIC stream write (body): {e}")))?;
    Ok(())
}

/// Deserialize a bincode-encoded `ClusterMessage` from raw bytes produced by
/// `read_bounded_message`.
pub fn decode_message<T: for<'de> Deserialize<'de>>(
    data: &[u8],
) -> Result<T, HiveGuardError> {
    bincode::deserialize(data)
        .map_err(|e| HiveGuardError::Protocol(format!("bincode deserialization error: {e}")))
}

// ---------------------------------------------------------------------------
// Custom TLS verifiers for self-signed cluster mode.
//
// They intentionally skip CA-chain validation (peers present self-signed
// certs), BUT they DO verify the TLS handshake signature — i.e. they require
// the peer to prove possession of the private key matching the certificate it
// presents (`verify_tls1x_signature`, backed by the crypto provider's webpki
// algorithms). Without this proof-of-possession an attacker could replay a
// victim node's (public) certificate and inherit its fingerprint, then pass the
// application-layer fingerprint allow-list. Peer *authorization* (which
// fingerprints are allowed) still happens at the application layer in
// `PeerManager::validate_peer_connection`.
//
// Net effect over the public internet: an attacker cannot impersonate a node
// without that node's private key. For full PKI chain enforcement (an external
// trust anchor) use `QuicTransport::new_with_ca`.
// ---------------------------------------------------------------------------

/// Server-side verifier: accepts any self-signed client cert, but verifies the
/// client proves possession of its certificate's private key.
#[derive(Debug)]
struct PermissiveCertVerifier {
    algs: WebPkiSupportedAlgorithms,
}

impl ClientCertVerifier for PermissiveCertVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        // Self-signed chain accepted; the peer's identity is pinned by
        // fingerprint at the application layer, and key possession is proved
        // by `verify_tls13_signature` below.
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &self.algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }
}

/// Client-side verifier: accepts any self-signed server cert, but verifies the
/// server proves possession of its certificate's private key.
#[derive(Debug)]
struct PermissiveServerVerifier {
    algs: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for PermissiveServerVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &self.algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn transport_construction_succeeds() {
        let dir = TempDir::new().unwrap();
        let identity = NodeIdentity::generate(dir.path()).unwrap();
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

        let transport = QuicTransport::new(addr, &identity);
        assert!(transport.is_ok());
    }

    #[tokio::test]
    async fn server_starts_and_binds() {
        let dir = TempDir::new().unwrap();
        let identity = NodeIdentity::generate(dir.path()).unwrap();
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

        let transport = QuicTransport::new(addr, &identity).unwrap();
        let endpoint = transport.start_server().await.unwrap();

        let local_addr = endpoint.local_addr().unwrap();
        assert_ne!(local_addr.port(), 0);

        endpoint.close(0u32.into(), b"test done");
    }

    #[tokio::test]
    async fn connect_without_server_fails() {
        let dir = TempDir::new().unwrap();
        let identity = NodeIdentity::generate(dir.path()).unwrap();
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

        let transport = QuicTransport::new(addr, &identity).unwrap();
        // Don't call start_server — connect should fail
        let result = transport
            .connect_to_peer("127.0.0.1:9999".parse().unwrap())
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn server_client_connection() {
        let server_dir = TempDir::new().unwrap();
        let client_dir = TempDir::new().unwrap();

        let server_identity = NodeIdentity::generate(server_dir.path()).unwrap();
        let client_identity = NodeIdentity::generate(client_dir.path()).unwrap();

        // Start server on random port
        let server_transport =
            QuicTransport::new("127.0.0.1:0".parse().unwrap(), &server_identity).unwrap();
        let server_endpoint = server_transport.start_server().await.unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();

        // Accept in background
        let accept_handle = tokio::spawn(async move {
            let incoming = server_endpoint.accept().await.unwrap();
            let conn = incoming.await.unwrap();
            conn
        });

        // Client connects
        let client_transport =
            QuicTransport::new("127.0.0.1:0".parse().unwrap(), &client_identity).unwrap();
        client_transport.start_server().await.unwrap();

        let client_conn = client_transport.connect_to_peer(server_addr).await.unwrap();
        assert_eq!(client_conn.remote_address(), server_addr);

        let server_conn = accept_handle.await.unwrap();
        assert!(server_conn.close_reason().is_none());

        // Verify fingerprint extraction from the TLS session
        let client_fp = extract_peer_fingerprint(&server_conn);
        assert!(client_fp.is_some(), "Should extract client fingerprint from server side");
        let client_fp = client_fp.unwrap();
        assert_eq!(client_fp.len(), 64, "Fingerprint should be 64 hex chars");
        assert!(client_fp.chars().all(|c| c.is_ascii_hexdigit()));
        // The extracted fingerprint should match the client identity's fingerprint
        assert_eq!(client_fp, client_identity.fingerprint());

        client_conn.close(0u32.into(), b"bye");
    }

    #[test]
    fn extract_fingerprint_from_der_works() {
        let dir = TempDir::new().unwrap();
        let identity = NodeIdentity::generate(dir.path()).unwrap();
        let cert_der = CertificateDer::from(identity.certificate_der().to_vec());
        let fp = extract_fingerprint_from_cert_der(&cert_der);
        assert!(fp.is_some());
        let fp = fp.unwrap();
        assert_eq!(fp.len(), 64);
        assert_eq!(fp, identity.fingerprint());
    }

    #[test]
    fn ca_mode_transport_construction_succeeds() {
        use crate::ca::ClusterCA;

        let ca_dir = TempDir::new().unwrap();
        let ca = ClusterCA::generate(ca_dir.path()).unwrap();

        let node_dir = TempDir::new().unwrap();
        let identity = NodeIdentity::generate_signed_by(node_dir.path(), &ca).unwrap();

        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let transport = QuicTransport::new_with_ca(addr, &identity, ca.cert_der());
        assert!(transport.is_ok());
    }

    #[tokio::test]
    async fn ca_mode_server_client_connection() {
        use crate::ca::ClusterCA;

        let ca_dir = TempDir::new().unwrap();
        let ca = ClusterCA::generate(ca_dir.path()).unwrap();

        let server_dir = TempDir::new().unwrap();
        let client_dir = TempDir::new().unwrap();

        let server_identity = NodeIdentity::generate_signed_by(server_dir.path(), &ca).unwrap();
        let client_identity = NodeIdentity::generate_signed_by(client_dir.path(), &ca).unwrap();

        // Start server
        let server_transport =
            QuicTransport::new_with_ca("127.0.0.1:0".parse().unwrap(), &server_identity, ca.cert_der())
                .unwrap();
        let server_endpoint = server_transport.start_server().await.unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();

        // Accept in background
        let accept_handle = tokio::spawn(async move {
            let incoming = server_endpoint.accept().await.unwrap();
            incoming.await.unwrap()
        });

        // Client connects
        let client_transport =
            QuicTransport::new_with_ca("127.0.0.1:0".parse().unwrap(), &client_identity, ca.cert_der())
                .unwrap();
        client_transport.start_server().await.unwrap();

        let client_conn = client_transport.connect_to_peer(server_addr).await.unwrap();
        assert_eq!(client_conn.remote_address(), server_addr);

        let server_conn = accept_handle.await.unwrap();
        assert!(server_conn.close_reason().is_none());

        // Fingerprint extraction still works with CA-signed certs
        let client_fp = extract_peer_fingerprint(&server_conn).unwrap();
        assert_eq!(client_fp, client_identity.fingerprint());

        client_conn.close(0u32.into(), b"bye");
    }
}
