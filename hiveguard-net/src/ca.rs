use std::fs;
use std::path::Path;

use rcgen::{BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, PKCS_ED25519};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tracing;

use hiveguard_core::HiveGuardError;

const CA_KEY_FILE: &str = "ca.key";
const CA_CERT_FILE: &str = "ca.crt";
const CA_DIR: &str = "ca";

/// Cluster Certificate Authority.
///
/// Manages the root Ed25519 keypair and self-signed X.509 CA certificate.
/// All cluster node certificates must be signed by this CA. The CA cert DER
/// is the sole trust anchor — any peer presenting a CA-signed certificate is
/// admitted to the cluster; all others are rejected at the TLS layer.
///
/// Files persisted under `data_dir/ca/`:
/// - `ca.key` — PKCS#8 DER private key (mode 0600)
/// - `ca.crt` — DER-encoded CA certificate (trust anchor for distribution)
pub struct ClusterCA {
    keypair: KeyPair,
    /// rcgen Certificate used as issuer when signing node certs.
    /// Reconstructed from the stored DER on `load()` — the subject DN is
    /// preserved by `CertificateParams::from_ca_cert_der`.
    issuer_cert: rcgen::Certificate,
    /// Original DER bytes of the CA certificate.  This is what every node
    /// uses as the trust anchor in its `RootCertStore`.
    cert_der: Vec<u8>,
}

impl ClusterCA {
    /// Generate a new Ed25519 CA keypair and self-signed certificate.
    ///
    /// Persists the private key (mode 0600) and CA cert DER to `data_dir/ca/`.
    pub fn generate(data_dir: &Path) -> Result<Self, HiveGuardError> {
        let keypair = KeyPair::generate_for(&PKCS_ED25519)
            .map_err(|e| HiveGuardError::Config(format!("CA keypair generation failed: {e}")))?;

        let mut params = CertificateParams::new(vec!["hiveguard-cluster-ca".to_string()])
            .map_err(|e| HiveGuardError::Config(format!("CA cert params error: {e}")))?;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);

        let issuer_cert = params
            .self_signed(&keypair)
            .map_err(|e| HiveGuardError::Config(format!("CA self-sign failed: {e}")))?;

        let cert_der = issuer_cert.der().to_vec();

        let ca_dir = data_dir.join(CA_DIR);
        fs::create_dir_all(&ca_dir)?;

        let key_path = ca_dir.join(CA_KEY_FILE);
        fs::write(&key_path, keypair.serialize_der())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600))?;
        }
        fs::write(ca_dir.join(CA_CERT_FILE), &cert_der)?;

        tracing::info!("Generated new HiveGuard Cluster CA");
        Ok(Self { keypair, issuer_cert, cert_der })
    }

    /// Load an existing CA from `data_dir/ca/`.
    pub fn load(data_dir: &Path) -> Result<Self, HiveGuardError> {
        let ca_dir = data_dir.join(CA_DIR);
        let key_der = fs::read(ca_dir.join(CA_KEY_FILE))?;
        let cert_der = fs::read(ca_dir.join(CA_CERT_FILE))?;

        let keypair = KeyPair::from_der_and_sign_algo(
            &PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der)),
            &PKCS_ED25519,
        )
        .map_err(|e| HiveGuardError::Config(format!("Failed to load CA keypair: {e}")))?;

        // Reconstruct a Certificate object from the stored DER so it can be
        // used as the issuer in `signed_by`. The subject DN is preserved by
        // `from_ca_cert_der` — the node cert's Issuer field will match the
        // stored CA cert's Subject field for webpki chain validation.
        let cert_der_pki = CertificateDer::from(cert_der.clone());
        let params = CertificateParams::from_ca_cert_der(&cert_der_pki)
            .map_err(|e| HiveGuardError::Config(format!("Failed to parse CA cert: {e}")))?;
        let issuer_cert = params
            .self_signed(&keypair)
            .map_err(|e| HiveGuardError::Config(format!("Failed to reconstruct CA cert: {e}")))?;

        tracing::info!("Loaded HiveGuard Cluster CA");
        Ok(Self { keypair, issuer_cert, cert_der })
    }

    /// Load an existing CA or generate a new one if none exists.
    pub fn load_or_generate(data_dir: &Path) -> Result<Self, HiveGuardError> {
        let ca_dir = data_dir.join(CA_DIR);
        if ca_dir.join(CA_KEY_FILE).exists() && ca_dir.join(CA_CERT_FILE).exists() {
            Self::load(data_dir)
        } else {
            Self::generate(data_dir)
        }
    }

    /// Sign a new node certificate for the given Ed25519 keypair.
    ///
    /// The certificate carries:
    /// - SAN `hiveguard-node` (matches the QUIC server-name used in `connect_to_peer`)
    /// - EKU `serverAuth` + `clientAuth` (required by webpki for both roles)
    ///
    /// Returns the signed certificate DER bytes.
    pub fn sign_node_cert(&self, node_keypair: &KeyPair) -> Result<Vec<u8>, HiveGuardError> {
        let mut params = CertificateParams::new(vec!["hiveguard-node".to_string()])
            .map_err(|e| HiveGuardError::Config(format!("Node cert params error: {e}")))?;
        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];

        let signed = params
            .signed_by(node_keypair, &self.issuer_cert, &self.keypair)
            .map_err(|e| HiveGuardError::Config(format!("Node cert signing failed: {e}")))?;

        Ok(signed.der().to_vec())
    }

    /// DER bytes of the CA certificate — distribute this to all cluster members
    /// as the trust anchor for their `RootCertStore`.
    pub fn cert_der(&self) -> &[u8] {
        &self.cert_der
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn generate_persists_files() {
        let dir = TempDir::new().unwrap();
        let ca = ClusterCA::generate(dir.path()).unwrap();
        assert!(!ca.cert_der().is_empty());

        let ca_dir = dir.path().join("ca");
        assert!(ca_dir.join("ca.key").exists());
        assert!(ca_dir.join("ca.crt").exists());
    }

    #[test]
    fn load_returns_same_cert_der() {
        let dir = TempDir::new().unwrap();
        let ca = ClusterCA::generate(dir.path()).unwrap();
        let loaded = ClusterCA::load(dir.path()).unwrap();
        assert_eq!(ca.cert_der(), loaded.cert_der());
    }

    #[test]
    fn load_or_generate_idempotent() {
        let dir = TempDir::new().unwrap();
        let ca1 = ClusterCA::load_or_generate(dir.path()).unwrap();
        let ca2 = ClusterCA::load_or_generate(dir.path()).unwrap();
        assert_eq!(ca1.cert_der(), ca2.cert_der());
    }

    #[test]
    fn sign_node_cert_produces_valid_der() {
        let dir = TempDir::new().unwrap();
        let ca = ClusterCA::generate(dir.path()).unwrap();
        let node_key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let node_cert_der = ca.sign_node_cert(&node_key).unwrap();
        assert!(!node_cert_der.is_empty());

        // The signed cert must be parseable as a valid X.509 certificate
        let (_, cert) = x509_parser::parse_x509_certificate(&node_cert_der).unwrap();
        // Verify it's NOT a CA cert
        assert!(!cert.is_ca());
    }
}
