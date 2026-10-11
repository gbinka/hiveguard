use jsonschema::error::{TypeKind, ValidationErrorKind};

use crate::error::{PluginError, PluginResult};

/// One schema violation: the JSON pointer of the offending value plus a
/// description of the failed rule. The description **never quotes the value
/// itself** — the value may come from an expanded `${file:…}` / `${env:…}`
/// placeholder (a secret, or the contents of an arbitrary file), and these
/// messages end up in API responses and the journal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaViolation {
    /// JSON pointer into the validated value (`""` = the root, `/window_secs`).
    pub instance_path: String,
    /// Kind of failure, e.g. `expected integer`, `missing required property "path"`.
    pub message: String,
}

impl std::fmt::Display for SchemaViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let path = if self.instance_path.is_empty() { "/" } else { self.instance_path.as_str() };
        write!(f, "{path}: {}", self.message)
    }
}

/// Describe a failed schema rule without echoing the instance value.
fn describe_kind(kind: &ValidationErrorKind) -> String {
    use ValidationErrorKind as K;
    match kind {
        K::AdditionalItems { limit } => format!("too many array items (at most {limit} allowed)"),
        K::AdditionalProperties { unexpected } => {
            let names: Vec<String> = unexpected.iter().map(|u| format!("`{u}`")).collect();
            format!("additional property {} is not allowed", names.join(", "))
        }
        K::AnyOf => "does not match any of the allowed schemas (anyOf)".into(),
        K::Constant { expected_value } => format!("must equal {expected_value}"),
        K::Contains => "no array item matches the required schema (contains)".into(),
        K::Enum { options } => format!("must be one of {options}"),
        K::ExclusiveMaximum { limit } => format!("must be less than {limit}"),
        K::ExclusiveMinimum { limit } => format!("must be greater than {limit}"),
        K::FalseSchema => "no value is allowed here".into(),
        K::Format { format } => format!("is not a valid `{format}`"),
        K::MaxItems { limit } => format!("must have at most {limit} items"),
        K::Maximum { limit } => format!("must be at most {limit}"),
        K::MaxLength { limit } => format!("must be at most {limit} characters long"),
        K::MaxProperties { limit } => format!("must have at most {limit} properties"),
        K::MinItems { limit } => format!("must have at least {limit} items"),
        K::Minimum { limit } => format!("must be at least {limit}"),
        K::MinLength { limit } => format!("must be at least {limit} characters long"),
        K::MinProperties { limit } => format!("must have at least {limit} properties"),
        K::MultipleOf { multiple_of } => format!("must be a multiple of {multiple_of}"),
        K::Not { .. } => "matches a schema it must not match (not)".into(),
        K::OneOfMultipleValid => "matches more than one schema (oneOf)".into(),
        K::OneOfNotValid => "does not match exactly one schema (oneOf)".into(),
        K::Pattern { pattern } => format!("does not match the pattern `{pattern}`"),
        K::PropertyNames { error } => format!("invalid property name: {}", describe_kind(&error.kind)),
        K::Required { property } => format!("missing required property {property}"),
        K::Type { kind } => match kind {
            TypeKind::Single(t) => format!("expected {t}"),
            TypeKind::Multiple(ts) => {
                let names: Vec<String> = ts.into_iter().map(|t| t.to_string()).collect();
                format!("expected one of {}", names.join(", "))
            }
        },
        K::UnevaluatedProperties { unexpected } => {
            format!("unevaluated properties are not allowed: {}", unexpected.join(", "))
        }
        K::UniqueItems => "array items must be unique".into(),
        K::ContentEncoding { content_encoding } => format!("is not valid `{content_encoding}` content"),
        K::ContentMediaType { content_media_type } => format!("is not valid `{content_media_type}` content"),
        // Schema-side problems (bad $ref, compile errors, custom keywords):
        // never instance-derived, but keep them generic anyway.
        _ => "violates the schema".into(),
    }
}

/// Validate `value` against `schema_json` and return every violation
/// (empty = valid). `Err` only when the schema itself is broken.
pub fn schema_violations(
    schema_json: &str,
    value: &serde_json::Value,
) -> PluginResult<Vec<SchemaViolation>> {
    let schema: serde_json::Value = serde_json::from_str(schema_json)
        .map_err(|e| PluginError::ConfigValidation(format!("invalid JSON Schema: {e}")))?;

    let compiled = jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft7)
        .compile(&schema)
        .map_err(|e| PluginError::ConfigValidation(format!("schema compile failed: {e}")))?;

    let out = match compiled.validate(value) {
        Ok(()) => Vec::new(),
        Err(errors) => errors
            .map(|err| SchemaViolation {
                instance_path: err.instance_path.to_string(),
                message: describe_kind(&err.kind),
            })
            .collect(),
    };
    Ok(out)
}

/// Format violations the way the loader reports them.
pub fn format_violations(violations: &[SchemaViolation]) -> String {
    let joined = violations
        .iter()
        .map(|v| format!("  - {v}"))
        .collect::<Vec<_>>()
        .join("\n");
    format!("config violates schema:\n{joined}")
}

/// Validate `value` against `schema_json` (a JSON Schema draft-07 string).
///
/// The host calls this before instantiating a plugin so that misconfigurations
/// are surfaced early with a precise error pointing to the offending field.
/// Error messages name the field and the failed rule but never the value.
pub fn validate_against_schema(schema_json: &str, value: &serde_json::Value) -> PluginResult<()> {
    let violations = schema_violations(schema_json, value)?;
    if violations.is_empty() {
        return Ok(());
    }
    Err(PluginError::ConfigValidation(format_violations(&violations)))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SCHEMA: &str = r#"{
        "type": "object",
        "required": ["url"],
        "properties": {
            "url": { "type": "string", "format": "uri" },
            "window_secs": { "type": "integer", "minimum": 1 },
            "mode": { "enum": ["a", "b"] }
        },
        "additionalProperties": false
    }"#;

    #[test]
    fn valid_config_passes() {
        let v = serde_json::json!({ "url": "https://example.com" });
        validate_against_schema(SCHEMA, &v).unwrap();
    }

    #[test]
    fn missing_required_field_fails() {
        let v = serde_json::json!({});
        let err = validate_against_schema(SCHEMA, &v).unwrap_err();
        assert!(matches!(err, PluginError::ConfigValidation(_)));
        assert!(err.to_string().contains("missing required property \"url\""), "{err}");
    }

    #[test]
    fn messages_never_quote_the_instance_value() {
        // A secret / file content expanded into a wrongly typed field must not
        // be echoed back (regression: `${file:/etc/hostname}` in an integer).
        let secret = "node-a-secret-file-content";
        let v = serde_json::json!({ "url": "https://example.org", "window_secs": secret, "mode": secret });
        let err = validate_against_schema(SCHEMA, &v).unwrap_err().to_string();
        assert!(!err.contains(secret), "{err}");
        assert!(err.contains("/window_secs: expected integer"), "{err}");
        assert!(err.contains("/mode: must be one of"), "{err}");

        let v = serde_json::json!({ "url": "https://example.org", "window_secs": 0, "unknown_key": 1 });
        let err = validate_against_schema(SCHEMA, &v).unwrap_err().to_string();
        assert!(err.contains("must be at least 1"), "{err}");
        // Unknown *keys* are named (they come from the config text, not from a secret).
        assert!(err.contains("additional property"), "{err}");
    }

    #[test]
    fn violations_carry_instance_paths() {
        let v = serde_json::json!({ "url": "https://example.org", "window_secs": "x" });
        let list = schema_violations(SCHEMA, &v).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].instance_path, "/window_secs");
        assert_eq!(list[0].message, "expected integer");
    }
}
