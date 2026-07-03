use thiserror::Error;

/// Application-level errors for all HiveGuard operations.
#[derive(Debug, Error)]
pub enum HiveGuardError {
    #[error("configuration error: {0}")]
    Config(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("parse error: {0}")]
    Parse(String),

    #[error("enforcement error: {0}")]
    Enforcement(String),

    #[error("storage error: {0}")]
    Storage(String),

    #[error("protocol error: {0}")]
    Protocol(String),
}
