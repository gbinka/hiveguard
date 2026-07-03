use std::fs;
use std::path::Path;

use rcgen::{CertificateParams, KeyPair, PKCS_ED25519};
use tracing;

use hiveguard_core::HiveGuardError;

use crate::ca::ClusterCA;

const KEY_FILE: &str = "node.key";
const CERT_FILE: &str = "node.crt";
const IDENTITY_DIR: &str = "identity";

/// Node identity: Ed25519 keypair + self-signed X.509 certificate.
pub struct NodeIdentity {
    node_id: String,
    keypair: KeyPair,
    certificate_der: Vec<u8>,
}

impl NodeIdentity {
    /// Generate a new Ed25519 keypair and self-signed certificate, persisting to data_dir.
    pub fn generate(data_dir: &Path) -> Result<Self, HiveGuardError> {
        let key_pair = KeyPair::generate_for(&PKCS_ED25519)
            .map_err(|e| HiveGuardError::Config(format!("Ed25519 keypair generation failed: {e}")))?;

        let params = CertificateParams::new(vec!["hiveguard-node".to_string()])
            .map_err(|e| HiveGuardError::Config(format!("certificate params error: {e}")))?;

        let cert = params
            .self_signed(&key_pair)
            .map_err(|e| HiveGuardError::Config(format!("self-signed cert generation failed: {e}")))?;

        let cert_der = cert.der().to_vec();
        let fingerprint = Self::compute_fingerprint(&key_pair);

        let id_dir = data_dir.join(IDENTITY_DIR);
        fs::create_dir_all(&id_dir)?;

        let key_path = id_dir.join(KEY_FILE);
        fs::write(&key_path, key_pair.serialize_der())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600))?;
        }

        fs::write(id_dir.join(CERT_FILE), &cert_der)?;

        tracing::info!(fingerprint = %fingerprint, "Generated new node identity");

        Ok(Self {
            node_id: fingerprint,
            keypair: key_pair,
            certificate_der: cert_der,
        })
    }

    /// Load an existing identity from data_dir.
    pub fn load(data_dir: &Path) -> Result<Self, HiveGuardError> {
        let id_dir = data_dir.join(IDENTITY_DIR);
        let key_der = fs::read(id_dir.join(KEY_FILE))?;
        let cert_der = fs::read(id_dir.join(CERT_FILE))?;

        let private_key = rustls::pki_types::PrivatePkcs8KeyDer::from(key_der.clone());
        let key_pair = KeyPair::from_der_and_sign_algo(
            &rustls::pki_types::PrivateKeyDer::Pkcs8(private_key),
            &PKCS_ED25519,
        )
        .map_err(|e| HiveGuardError::Config(format!("failed to load Ed25519 keypair: {e}")))?;

        let fingerprint = Self::compute_fingerprint(&key_pair);

        tracing::info!(fingerprint = %fingerprint, "Loaded existing node identity");

        Ok(Self {
            node_id: fingerprint,
            keypair: key_pair,
            certificate_der: cert_der,
        })
    }

    /// Load existing identity or generate a new one if none exists.
    pub fn load_or_generate(data_dir: &Path) -> Result<Self, HiveGuardError> {
        let id_dir = data_dir.join(IDENTITY_DIR);
        if id_dir.join(KEY_FILE).exists() && id_dir.join(CERT_FILE).exists() {
            Self::load(data_dir)
        } else {
            Self::generate(data_dir)
        }
    }

    /// Generate a new Ed25519 keypair and a certificate signed by the given CA.
    ///
    /// Use this (instead of `generate`) when running in CA-enforced cluster mode.
    /// The resulting certificate contains `serverAuth` + `clientAuth` EKU and
    /// SAN `hiveguard-node`, satisfying webpki chain verification on both sides.
    pub fn generate_signed_by(data_dir: &Path, ca: &ClusterCA) -> Result<Self, HiveGuardError> {
        let key_pair = KeyPair::generate_for(&PKCS_ED25519)
            .map_err(|e| HiveGuardError::Config(format!("Ed25519 keypair generation failed: {e}")))?;

        let cert_der = ca.sign_node_cert(&key_pair)?;
        let fingerprint = Self::compute_fingerprint(&key_pair);

        let id_dir = data_dir.join(IDENTITY_DIR);
        fs::create_dir_all(&id_dir)?;

        let key_path = id_dir.join(KEY_FILE);
        fs::write(&key_path, key_pair.serialize_der())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600))?;
        }
        fs::write(id_dir.join(CERT_FILE), &cert_der)?;

        tracing::info!(fingerprint = %fingerprint, "Generated new CA-signed node identity");
        Ok(Self { node_id: fingerprint, keypair: key_pair, certificate_der: cert_der })
    }

    /// Load an existing identity or generate a new CA-signed one if none exists.
    pub fn load_or_generate_signed_by(data_dir: &Path, ca: &ClusterCA) -> Result<Self, HiveGuardError> {
        let id_dir = data_dir.join(IDENTITY_DIR);
        if id_dir.join(KEY_FILE).exists() && id_dir.join(CERT_FILE).exists() {
            Self::load(data_dir)
        } else {
            Self::generate_signed_by(data_dir, ca)
        }
    }

    /// Hex-encoded blake3 hash of the Ed25519 public key.
    pub fn fingerprint(&self) -> &str {
        &self.node_id
    }

    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    /// Raw DER-encoded X.509 certificate bytes.
    pub fn certificate_der(&self) -> &[u8] {
        &self.certificate_der
    }

    pub fn keypair(&self) -> &KeyPair {
        &self.keypair
    }

    /// PKCS#8 DER-encoded private key (for rustls).
    pub fn private_key_der(&self) -> Vec<u8> {
        self.keypair.serialize_der()
    }

    fn compute_fingerprint(keypair: &KeyPair) -> String {
        let hash = blake3::hash(keypair.public_key_raw());
        hex::encode(hash.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn generate_creates_identity_files() {
        let dir = TempDir::new().unwrap();
        let identity = NodeIdentity::generate(dir.path()).unwrap();

        assert!(!identity.fingerprint().is_empty());
        // blake3 hash = 32 bytes = 64 hex chars
        assert_eq!(identity.fingerprint().len(), 64);
        assert!(!identity.certificate_der().is_empty());
        assert!(!identity.private_key_der().is_empty());

        // Files exist on disk
        let id_dir = dir.path().join(IDENTITY_DIR);
        assert!(id_dir.join(KEY_FILE).exists());
        assert!(id_dir.join(CERT_FILE).exists());
    }

    #[test]
    fn generate_then_load_same_fingerprint() {
        let dir = TempDir::new().unwrap();
        let generated = NodeIdentity::generate(dir.path()).unwrap();
        let loaded = NodeIdentity::load(dir.path()).unwrap();

        assert_eq!(generated.fingerprint(), loaded.fingerprint());
        assert_eq!(generated.certificate_der(), loaded.certificate_der());
    }

    #[test]
    fn load_or_generate_creates_new_if_not_exists() {
        let dir = TempDir::new().unwrap();
        let identity = NodeIdentity::load_or_generate(dir.path()).unwrap();

        assert!(!identity.fingerprint().is_empty());
        assert!(dir.path().join(IDENTITY_DIR).join(KEY_FILE).exists());
    }

    #[test]
    fn load_or_generate_loads_existing() {
        let dir = TempDir::new().unwrap();
        let first = NodeIdentity::generate(dir.path()).unwrap();
        let second = NodeIdentity::load_or_generate(dir.path()).unwrap();

        assert_eq!(first.fingerprint(), second.fingerprint());
    }

    #[test]
    fn load_nonexistent_returns_error() {
        let dir = TempDir::new().unwrap();
        let result = NodeIdentity::load(dir.path());
        assert!(result.is_err());
    }

    #[test]
    fn fingerprint_is_hex_string() {
        let dir = TempDir::new().unwrap();
        let identity = NodeIdentity::generate(dir.path()).unwrap();
        let fp = identity.fingerprint();

        // All chars should be hex
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn two_identities_have_different_fingerprints() {
        let dir1 = TempDir::new().unwrap();
        let dir2 = TempDir::new().unwrap();
        let id1 = NodeIdentity::generate(dir1.path()).unwrap();
        let id2 = NodeIdentity::generate(dir2.path()).unwrap();

        assert_ne!(id1.fingerprint(), id2.fingerprint());
    }

    #[test]
    fn node_id_equals_fingerprint() {
        let dir = TempDir::new().unwrap();
        let identity = NodeIdentity::generate(dir.path()).unwrap();
        assert_eq!(identity.node_id(), identity.fingerprint());
    }
}
