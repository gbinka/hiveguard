use crate::error::{PluginError, PluginResult};

/// Validate `value` against `schema_json` (a JSON Schema draft-07 string).
///
/// The host calls this before instantiating a plugin so that misconfigurations
/// are surfaced early with a precise error pointing to the offending field.
pub fn validate_against_schema(schema_json: &str, value: &serde_json::Value) -> PluginResult<()> {
    let schema: serde_json::Value = serde_json::from_str(schema_json)
        .map_err(|e| PluginError::ConfigValidation(format!("invalid JSON Schema: {e}")))?;

    let compiled = jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft7)
        .compile(&schema)
        .map_err(|e| PluginError::ConfigValidation(format!("schema compile failed: {e}")))?;

    if let Err(errors) = compiled.validate(value) {
        let joined = errors
            .map(|err| format!("  - {}: {}", err.instance_path, err))
            .collect::<Vec<_>>()
            .join("\n");
        return Err(PluginError::ConfigValidation(format!(
            "config violates schema:\n{joined}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SCHEMA: &str = r#"{
        "type": "object",
        "required": ["url"],
        "properties": {
            "url": { "type": "string", "format": "uri" }
        }
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
    }
}
