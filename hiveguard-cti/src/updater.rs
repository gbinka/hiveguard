use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use tracing::{error, info, warn};

use crate::geoip::{GeoIpDb, SharedGeoIpDb};

/// MaxMind GeoLite2 download base URL template.
const MAXMIND_DOWNLOAD_URL: &str =
    "https://download.maxmind.com/app/geoip_download";

/// Databases to download and their output filenames.
const EDITIONS: &[&str] = &["GeoLite2-Country", "GeoLite2-ASN"];

/// Handles downloading and hot-reloading MaxMind GeoLite2 databases.
///
/// Downloads are performed via the system `curl` binary (always available on
/// production Linux systems) to avoid pulling in a full HTTP client stack with
/// TLS dependencies.
pub struct GeoIpUpdater {
    data_dir: PathBuf,
    license_key: String,
    shared: SharedGeoIpDb,
}

impl GeoIpUpdater {
    /// Create a new updater.
    pub fn new(data_dir: PathBuf, license_key: String, shared: SharedGeoIpDb) -> Self {
        Self {
            data_dir,
            license_key,
            shared,
        }
    }

    /// Download fresh database files and hot-reload the shared handle.
    pub async fn update(&self) -> Result<(), UpdaterError> {
        let geoip_dir = self.data_dir.join("geoip");
        tokio::fs::create_dir_all(&geoip_dir)
            .await
            .map_err(UpdaterError::Io)?;

        let mut any_ok = false;
        for edition_id in EDITIONS {
            match self.download_one(edition_id, &geoip_dir).await {
                Ok(()) => {
                    info!("Downloaded {}", edition_id);
                    any_ok = true;
                }
                Err(e) => {
                    warn!("Failed to download {}: {}", edition_id, e);
                }
            }
        }

        if !any_ok {
            return Err(UpdaterError::NoDatabasesDownloaded);
        }

        self.reload().await;
        Ok(())
    }

    /// Reload the shared GeoIP database from disk without downloading.
    pub async fn reload(&self) {
        match GeoIpDb::load(&self.data_dir) {
            Ok(db) => {
                self.shared.store(Arc::new(Some(db)));
                info!("GeoIP databases hot-reloaded");
            }
            Err(e) => {
                error!("Failed to reload GeoIP databases: {}", e);
            }
        }
    }

    /// Start a background task that auto-updates the databases on the given interval.
    pub fn spawn_auto_update(self, interval: Duration) {
        tokio::spawn(async move {
            // Immediate update if databases are missing
            {
                let guard = self.shared.load();
                if guard.is_none() {
                    info!("GeoIP databases not found — attempting initial download");
                    if let Err(e) = self.update().await {
                        warn!("Initial GeoIP update failed: {}", e);
                    }
                }
            }

            let mut timer = tokio::time::interval(interval);
            timer.tick().await; // consume the immediate first tick

            loop {
                timer.tick().await;
                info!("Scheduled GeoIP update starting");
                if let Err(e) = self.update().await {
                    warn!("Scheduled GeoIP update failed: {}", e);
                }
            }
        });
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    /// Download one edition via `curl` and extract the `.mmdb` via `tar`.
    async fn download_one(
        &self,
        edition_id: &str,
        geoip_dir: &Path,
    ) -> Result<(), UpdaterError> {
        let url = format!(
            "{}?edition_id={}&license_key={}&suffix=tar.gz",
            MAXMIND_DOWNLOAD_URL, edition_id, self.license_key
        );

        let tmp_tar = geoip_dir.join(format!("{}.tar.gz.tmp", edition_id));
        let extract_dir = geoip_dir.join(format!(".extract_{}", edition_id));
        let final_path = geoip_dir.join(format!("{}.mmdb", edition_id));

        // --- Step 1: curl download (blocking subprocess via tokio) ---
        {
            let url_c = url.clone();
            let tmp_tar_c = tmp_tar.clone();
            tokio::task::spawn_blocking(move || -> Result<(), UpdaterError> {
                let status = Command::new("curl")
                    .args([
                        "--fail",
                        "--silent",
                        "--show-error",
                        "--location",
                        &url_c,
                        "-o",
                        tmp_tar_c.to_str().unwrap_or_default(),
                    ])
                    .status()
                    .map_err(|e| UpdaterError::CurlExec(e.to_string()))?;

                if !status.success() {
                    return Err(UpdaterError::CurlStatus(
                        status.code().unwrap_or(-1),
                    ));
                }
                Ok(())
            })
            .await
            .map_err(|e| UpdaterError::CurlExec(e.to_string()))??;
        }

        // --- Step 2: extract .mmdb from tar.gz (blocking) ---
        {
            let edition_owned = edition_id.to_string();
            let extract_dir_c = extract_dir.clone();
            let tmp_tar_c = tmp_tar.clone();
            let final_path_c = final_path.clone();

            tokio::task::spawn_blocking(move || -> Result<(), UpdaterError> {
                let _ = std::fs::remove_dir_all(&extract_dir_c);
                std::fs::create_dir_all(&extract_dir_c).map_err(UpdaterError::Io)?;

                let status = Command::new("tar")
                    .args([
                        "-xzf",
                        tmp_tar_c.to_str().unwrap_or_default(),
                        "-C",
                        extract_dir_c.to_str().unwrap_or_default(),
                        "--strip-components=1",
                    ])
                    .status()
                    .map_err(|e| UpdaterError::Archive(e.to_string()))?;

                if !status.success() {
                    return Err(UpdaterError::Archive("tar extraction failed".to_string()));
                }

                let mmdb_name = format!("{}.mmdb", edition_owned);
                let mmdb_src = find_file_recursive(&extract_dir_c, &mmdb_name)
                    .ok_or_else(|| {
                        UpdaterError::Archive(format!(
                            "{} not found in archive",
                            mmdb_name
                        ))
                    })?;

                // Atomic rename via temp file
                let tmp_final = final_path_c.with_extension("mmdb.new");
                std::fs::copy(&mmdb_src, &tmp_final).map_err(UpdaterError::Io)?;
                std::fs::rename(&tmp_final, &final_path_c).map_err(UpdaterError::Io)?;

                let _ = std::fs::remove_file(&tmp_tar_c);
                let _ = std::fs::remove_dir_all(&extract_dir_c);

                Ok(())
            })
            .await
            .map_err(|e| UpdaterError::Archive(e.to_string()))??;
        }

        Ok(())
    }
}

/// Recursively find a file by name inside a directory tree.
fn find_file_recursive(dir: &Path, name: &str) -> Option<PathBuf> {
    let entries = std::fs::read_dir(dir).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_file()
            && path.file_name().and_then(|n| n.to_str()) == Some(name)
        {
            return Some(path);
        }
        if path.is_dir() {
            if let Some(found) = find_file_recursive(&path, name) {
                return Some(found);
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum UpdaterError {
    #[error("curl executable not found or failed to run: {0}")]
    CurlExec(String),
    #[error("curl exited with status {0}")]
    CurlStatus(i32),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Archive extraction error: {0}")]
    Archive(String),
    #[error("No databases could be downloaded")]
    NoDatabasesDownloaded,
}
