//! # hiveguard-migrate-config
//!
//! Library backing the `hiveguard-migrate-config` binary.
//!
//! Given a legacy YAML document (sections like `sources`, `detectors`,
//! `enforcement`, `cti`, `alerting.destinations`, `sigma`), produces a new
//! YAML document with a uniform `plugins:` list while preserving the core
//! sections (`node`, `whitelist`, `trust`, `persistence`, `api`, `scoring`).

pub mod convert;
pub mod legacy;
pub mod schemas;

pub use convert::{convert, ConversionReport, ConvertedConfig};
