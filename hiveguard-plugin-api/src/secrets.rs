use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::RwLock;

use crate::error::{PluginError, PluginResult};

/// Resolves `${env:VAR}` and `${file:/path/to/secret}` placeholders inside
/// plugin configuration values.
///
/// Plugins receive a shared resolver via [`PluginContext`] and call
/// [`SecretResolver::resolve`] on any string that may contain secrets. The
/// host scans the parsed YAML during loader phase and rejects configs whose
/// resolution fails — so plugin authors can usually treat the post-init
/// values as plain strings.
pub struct SecretResolver {
    /// Pre-resolved cache, populated by the host from env + filesystem at
    /// startup. Plugins should not insert into it directly.
    cache: RwLock<HashMap<String, String>>,

    /// Override env reader for tests.
    env_override: Option<HashMap<String, String>>,
}

impl Default for SecretResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretResolver {
    pub fn new() -> Self {
        Self {
            cache: RwLock::new(HashMap::new()),
            env_override: None,
        }
    }

    /// Test constructor — env reads pull from `env` instead of the process.
    pub fn with_env(env: HashMap<String, String>) -> Self {
        Self {
            cache: RwLock::new(HashMap::new()),
            env_override: Some(env),
        }
    }

    /// Resolve every `${...}` placeholder in `input`.
    ///
    /// Supported forms:
    /// * `${env:VAR_NAME}` — replaced with `std::env::var("VAR_NAME")`.
    /// * `${file:/abs/path}` — replaced with the (trimmed) file contents.
    ///
    /// Unknown forms and unmatched braces are left as-is, so this function is
    /// safe to call on every string in the config.
    pub fn resolve(&self, input: &str) -> PluginResult<String> {
        let mut out = String::with_capacity(input.len());
        let mut rest = input;

        while let Some(start) = rest.find("${") {
            out.push_str(&rest[..start]);
            let after = &rest[start + 2..];
            let Some(end) = after.find('}') else {
                // No closing brace — preserve the literal and stop.
                out.push_str("${");
                out.push_str(after);
                return Ok(out);
            };
            let placeholder = &after[..end];
            let resolved = self.resolve_one(placeholder)?;
            out.push_str(&resolved);
            rest = &after[end + 1..];
        }
        out.push_str(rest);
        Ok(out)
    }

    fn resolve_one(&self, placeholder: &str) -> PluginResult<String> {
        if let Some(cached) = self
            .cache
            .read()
            .expect("secret cache poisoned")
            .get(placeholder)
        {
            return Ok(cached.clone());
        }

        let value = if let Some(name) = placeholder.strip_prefix("env:") {
            self.read_env(name)?
        } else if let Some(path) = placeholder.strip_prefix("file:") {
            self.read_file(PathBuf::from(path))?
        } else {
            return Err(PluginError::Secret(format!(
                "unknown placeholder `${{{placeholder}}}` — expected `env:` or `file:` prefix"
            )));
        };

        self.cache
            .write()
            .expect("secret cache poisoned")
            .insert(placeholder.to_owned(), value.clone());
        Ok(value)
    }

    fn read_env(&self, name: &str) -> PluginResult<String> {
        if let Some(env) = &self.env_override {
            return env
                .get(name)
                .cloned()
                .ok_or_else(|| PluginError::Secret(format!("env var `{name}` not set")));
        }
        std::env::var(name)
            .map_err(|_| PluginError::Secret(format!("env var `{name}` not set")))
    }

    fn read_file(&self, path: PathBuf) -> PluginResult<String> {
        std::fs::read_to_string(&path)
            .map(|s| s.trim().to_owned())
            .map_err(|e| PluginError::Secret(format!("read {}: {e}", path.display())))
    }
}

/// One `${…}` placeholder found in a config string (not resolved).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Placeholder {
    /// `${env:NAME}`
    Env(String),
    /// `${file:/abs/path}`
    File(PathBuf),
}

/// `true` when `input` contains a `${` placeholder opener.
pub fn contains_placeholder(input: &str) -> bool {
    input.contains("${")
}

/// Parse (but never resolve) every `${…}` placeholder in `input`.
///
/// This is the syntax check used by dry-run validation: it never reads an
/// environment variable or a file, so it cannot leak a secret or the contents
/// of an arbitrary file. Rules: the brace must be closed, the prefix must be
/// `env:` or `file:`, an env name must match `[A-Za-z_][A-Za-z0-9_]*`, a file
/// path must be absolute (an unterminated `${` is a literal, as in
/// [`SecretResolver::resolve`]). Errors name the placeholder text only.
pub fn parse_placeholders(input: &str) -> Result<Vec<Placeholder>, String> {
    let mut out = Vec::new();
    let mut rest = input;
    while let Some(start) = rest.find("${") {
        let after = &rest[start + 2..];
        let Some(end) = after.find('}') else {
            // Same rule as `SecretResolver::resolve`: an unterminated `${` is
            // kept literally, not an error.
            return Ok(out);
        };
        let body = &after[..end];
        if let Some(name) = body.strip_prefix("env:") {
            let mut chars = name.chars();
            let valid = matches!(chars.next(), Some(c) if c == '_' || c.is_ascii_alphabetic())
                && chars.all(|c| c == '_' || c.is_ascii_alphanumeric());
            if !valid {
                return Err(format!("invalid env placeholder `${{env:{name}}}` (expected [A-Za-z_][A-Za-z0-9_]*)"));
            }
            out.push(Placeholder::Env(name.to_string()));
        } else if let Some(path) = body.strip_prefix("file:") {
            if !path.starts_with('/') {
                return Err(format!("file placeholder `${{file:{path}}}` must use an absolute path"));
            }
            out.push(Placeholder::File(PathBuf::from(path)));
        } else {
            return Err(format!(
                "unknown placeholder `${{{body}}}` — expected `env:` or `file:` prefix"
            ));
        }
        rest = &after[end + 1..];
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholder_syntax_is_checked_without_resolving() {
        assert_eq!(parse_placeholders("plain").unwrap(), vec![]);
        assert_eq!(
            parse_placeholders("a${env:HG_TOKEN}b${file:/etc/hiveguard/t}").unwrap(),
            vec![Placeholder::Env("HG_TOKEN".into()), Placeholder::File("/etc/hiveguard/t".into())]
        );
        // A file that does exist is still not read.
        assert_eq!(
            parse_placeholders("${file:/etc/hostname}").unwrap(),
            vec![Placeholder::File("/etc/hostname".into())]
        );
        assert!(parse_placeholders("${env:1BAD}").is_err());
        assert!(parse_placeholders("${env:}").is_err());
        assert!(parse_placeholders("${file:relative/path}").is_err());
        assert!(parse_placeholders("${vault:x}").is_err());
        assert_eq!(parse_placeholders("${env:OPEN").unwrap(), vec![]);
        assert!(contains_placeholder("x${env:A}"));
        assert!(!contains_placeholder("$ {x}"));
    }

    #[test]
    fn passes_through_plain_string() {
        let r = SecretResolver::new();
        assert_eq!(r.resolve("hello world").unwrap(), "hello world");
    }

    #[test]
    fn resolves_env_placeholder() {
        let mut env = HashMap::new();
        env.insert("MY_SECRET".to_owned(), "abc123".to_owned());
        let r = SecretResolver::with_env(env);
        let out = r.resolve("token=${env:MY_SECRET}!").unwrap();
        assert_eq!(out, "token=abc123!");
    }

    #[test]
    fn errors_on_missing_env() {
        let r = SecretResolver::with_env(HashMap::new());
        assert!(r.resolve("x=${env:NOPE}").is_err());
    }

    #[test]
    fn unmatched_brace_kept_literal() {
        let r = SecretResolver::new();
        assert_eq!(r.resolve("$ {not a placeholder").unwrap(), "$ {not a placeholder");
    }
}
