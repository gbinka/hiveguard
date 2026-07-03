use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use tracing::{debug, info, warn};

/// Generic file watcher that tracks byte offset and delivers new lines.
/// Handles log rotation by detecting file truncation.
pub struct FileWatcher {
    path: PathBuf,
    offset: u64,
}

impl FileWatcher {
    /// Create a new FileWatcher for the given path.
    /// If `seek_to_end` is true, starts at end-of-file (skipping history).
    pub fn new(path: impl Into<PathBuf>, seek_to_end: bool) -> std::io::Result<Self> {
        let path = path.into();
        let offset = if seek_to_end {
            let metadata = std::fs::metadata(&path)?;
            metadata.len()
        } else {
            0
        };
        Ok(Self { path, offset })
    }

    /// Create a FileWatcher starting from a saved offset.
    pub fn with_offset(path: impl Into<PathBuf>, offset: u64) -> Self {
        Self {
            path: path.into(),
            offset,
        }
    }

    /// Read all new complete lines since the last read.
    /// Handles log rotation: if the file is shorter than our offset, resets to 0.
    pub fn read_new_lines(&mut self) -> std::io::Result<Vec<String>> {
        let mut file = std::fs::File::open(&self.path)?;
        let file_len = file.metadata()?.len();

        // Detect log rotation: file is shorter than our last offset
        if file_len < self.offset {
            info!(
                path = %self.path.display(),
                old_offset = self.offset,
                new_len = file_len,
                "File truncated (log rotation detected), resetting offset to 0"
            );
            self.offset = 0;
        }

        // No new data
        if file_len == self.offset {
            return Ok(Vec::new());
        }

        file.seek(SeekFrom::Start(self.offset))?;
        let reader = BufReader::new(&file);
        let mut lines = Vec::new();
        let mut bytes_read: u64 = 0;

        for line_result in reader.lines() {
            match line_result {
                Ok(line) => {
                    // +1 for the newline character
                    bytes_read += line.len() as u64 + 1;
                    lines.push(line);
                }
                Err(e) => {
                    warn!(error = %e, "Error reading line from file");
                    break;
                }
            }
        }

        self.offset += bytes_read;
        debug!(
            path = %self.path.display(),
            new_offset = self.offset,
            lines_read = lines.len(),
            "Read new lines"
        );

        Ok(lines)
    }

    /// Current byte offset in the file.
    pub fn offset(&self) -> u64 {
        self.offset
    }

    /// Set the offset (for restoring from persisted state).
    pub fn set_offset(&mut self, offset: u64) {
        self.offset = offset;
    }

    /// Path being watched.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Save offset to a file for persistence across restarts.
pub fn save_offset(data_dir: &Path, source_name: &str, offset: u64) -> std::io::Result<()> {
    let offsets_dir = data_dir.join("offsets");
    std::fs::create_dir_all(&offsets_dir)?;
    let offset_file = offsets_dir.join(format!("{}.offset", source_name));
    std::fs::write(&offset_file, offset.to_string())?;
    debug!(
        source = source_name,
        offset = offset,
        path = %offset_file.display(),
        "Saved offset"
    );
    Ok(())
}

/// Load a previously saved offset. Returns 0 if no offset file exists.
pub fn load_offset(data_dir: &Path, source_name: &str) -> u64 {
    let offset_file = data_dir.join("offsets").join(format!("{}.offset", source_name));
    match std::fs::read_to_string(&offset_file) {
        Ok(content) => content.trim().parse::<u64>().unwrap_or(0),
        Err(_) => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_read_new_lines_from_start() {
        let mut tmp = NamedTempFile::new().unwrap();
        writeln!(tmp, "line one").unwrap();
        writeln!(tmp, "line two").unwrap();
        writeln!(tmp, "line three").unwrap();
        tmp.flush().unwrap();

        let mut watcher = FileWatcher::new(tmp.path(), false).unwrap();
        let lines = watcher.read_new_lines().unwrap();
        assert_eq!(lines, vec!["line one", "line two", "line three"]);
    }

    #[test]
    fn test_seek_to_end_skips_existing() {
        let mut tmp = NamedTempFile::new().unwrap();
        writeln!(tmp, "existing line").unwrap();
        tmp.flush().unwrap();

        let mut watcher = FileWatcher::new(tmp.path(), true).unwrap();
        let lines = watcher.read_new_lines().unwrap();
        assert!(lines.is_empty());

        // Append new data
        writeln!(tmp, "new line").unwrap();
        tmp.flush().unwrap();
        let lines = watcher.read_new_lines().unwrap();
        assert_eq!(lines, vec!["new line"]);
    }

    #[test]
    fn test_incremental_reads() {
        let mut tmp = NamedTempFile::new().unwrap();
        writeln!(tmp, "first").unwrap();
        tmp.flush().unwrap();

        let mut watcher = FileWatcher::new(tmp.path(), false).unwrap();
        let lines = watcher.read_new_lines().unwrap();
        assert_eq!(lines, vec!["first"]);

        // No new data
        let lines = watcher.read_new_lines().unwrap();
        assert!(lines.is_empty());

        // Append more
        writeln!(tmp, "second").unwrap();
        writeln!(tmp, "third").unwrap();
        tmp.flush().unwrap();

        let lines = watcher.read_new_lines().unwrap();
        assert_eq!(lines, vec!["second", "third"]);
    }

    #[test]
    fn test_log_rotation_detection() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.log");

        // Write initial content
        std::fs::write(&path, "line one\nline two\n").unwrap();
        let mut watcher = FileWatcher::new(&path, false).unwrap();
        let lines = watcher.read_new_lines().unwrap();
        assert_eq!(lines.len(), 2);
        assert!(watcher.offset() > 0);

        // Simulate log rotation: overwrite with shorter content
        std::fs::write(&path, "new\n").unwrap();
        let lines = watcher.read_new_lines().unwrap();
        assert_eq!(lines, vec!["new"]);
    }

    #[test]
    fn test_save_and_load_offset() {
        let dir = tempfile::tempdir().unwrap();
        save_offset(dir.path(), "ssh", 12345).unwrap();
        let loaded = load_offset(dir.path(), "ssh");
        assert_eq!(loaded, 12345);
    }

    #[test]
    fn test_load_offset_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let loaded = load_offset(dir.path(), "nonexistent");
        assert_eq!(loaded, 0);
    }
}
