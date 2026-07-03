//! Cyber Threat Intelligence (CTI) enrichment for HiveGuard.
//!
//! This crate provides:
//! - GeoIP & ASN enrichment via MaxMind GeoLite2 databases (`geoip` module)
//! - Database auto-update functionality (`updater` module)
//! - AbuseIPDB v2 API client with disk-cached provider (`abuseipdb` module)
//! - TTL-based IP reputation cache with disk persistence (`cache` module)
//! - Spamhaus DNSBL provider (`spamhaus` module)
//! - Tor exit-node list provider (`tor` module)
//! - AlienVault OTX reputation provider (`otx` module)
//! - Unified `CtiProvider` trait (`provider` module)
//! - CTI enrichment aggregator (`enricher` module)

pub mod abuseipdb;
pub mod cache;
pub mod enricher;
pub mod geoip;
pub mod otx;
pub mod provider;
pub mod spamhaus;
pub mod tor;
pub mod updater;

pub use abuseipdb::AbuseIpDbProvider;
pub use enricher::{CtiEnricher, CtiSignal, EnrichStats};
pub use geoip::{GeoIpDb, GeoIpError, SharedGeoIpDb};
pub use provider::CtiProvider;
pub use updater::GeoIpUpdater;
