use thiserror::Error;

pub type PluginResult<T> = std::result::Result<T, PluginError>;

#[derive(Debug, Error)]
pub enum PluginError {
    #[error("plugin config validation failed: {0}")]
    ConfigValidation(String),

    #[error("plugin config missing required field: {0}")]
    MissingConfig(&'static str),

    #[error("plugin init failed: {0}")]
    Init(String),

    #[error("plugin runtime error: {0}")]
    Runtime(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("secret resolution failed: {0}")]
    Secret(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("serde_json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("api version mismatch: plugin built for {plugin}, host expects {host}")]
    ApiVersionMismatch { plugin: u32, host: u32 },

    #[error("{0}")]
    Other(String),
}

impl From<hiveguard_core::errors::HiveGuardError> for PluginError {
    fn from(e: hiveguard_core::errors::HiveGuardError) -> Self {
        PluginError::Other(e.to_string())
    }
}
