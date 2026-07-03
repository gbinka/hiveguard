use thiserror::Error;

/// Errors produced by the `hiveguard-sigma` crate.
#[derive(Debug, Error)]
pub enum SigmaError {
    /// YAML deserialization error.
    #[error("YAML parse error: {0}")]
    Yaml(#[from] serde_yaml::Error),

    /// Structural problem in a rule (missing field, unexpected type, …).
    #[error("Rule parse error: {0}")]
    Parse(String),

    /// Condition expression is syntactically invalid.
    #[error("Invalid condition expression: {0}")]
    InvalidCondition(String),

    /// Condition references a selection name not defined in the detection block.
    #[error("Unknown selection '{0}' referenced in condition")]
    UnknownSelection(String),

    /// Regex compilation failed.
    #[error("Regex compile error: {0}")]
    Regex(#[from] regex::Error),
}

/// Convenience result alias.
pub type Result<T> = std::result::Result<T, SigmaError>;
