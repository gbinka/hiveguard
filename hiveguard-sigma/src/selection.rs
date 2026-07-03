//! Sigma selection parsing and evaluation.
//!
//! A selection is a named block inside the `detection:` YAML mapping.
//! It describes a set of field/value conditions; the condition expression
//! then references these selections by name.

use std::net::IpAddr;

use regex::Regex;
use serde_yaml::Value as YamlValue;

use crate::error::{Result, SigmaError};
use crate::fieldmap::FieldMapper;
use hiveguard_core::models::NormalizedEvent;

// ---------------------------------------------------------------------------
// FieldModifier
// ---------------------------------------------------------------------------

/// Modifier applied to a Sigma field comparison.
///
/// Modifiers are specified after a `|` in the field name, e.g. `path|contains`.
/// Multiple modifiers can be chained: `cmd|contains|all`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldModifier {
    /// Substring match (case-insensitive).
    Contains,
    /// Prefix match (case-insensitive).
    StartsWith,
    /// Suffix match (case-insensitive).
    EndsWith,
    /// Regular-expression match (case-sensitive per regex flags).
    Re,
    /// CIDR containment check.
    Cidr,
    /// Change OR relationship between values to AND (all values must match).
    All,
    /// Base64-encode the pattern value before matching.
    Base64,
    /// Normalize Windows-style dashes (treat `/` and `-` as interchangeable).
    WinDash,
    /// UTF-16 encoding (treated as passthrough in text matching).
    Utf16,
    /// Wide-string encoding (treated as passthrough in text matching).
    Wide,
    /// Unknown / unsupported modifier — silently ignored for forward-compatibility.
    Unknown(String),
}

impl FieldModifier {
    fn parse(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "contains" => Self::Contains,
            "startswith" => Self::StartsWith,
            "endswith" => Self::EndsWith,
            "re" => Self::Re,
            "cidr" => Self::Cidr,
            "all" => Self::All,
            "base64" | "base64offset" => Self::Base64,
            "windash" => Self::WinDash,
            "utf16le" | "utf16be" | "utf16" => Self::Utf16,
            "wide" => Self::Wide,
            other => Self::Unknown(other.to_string()),
        }
    }
}

// ---------------------------------------------------------------------------
// SigmaValue
// ---------------------------------------------------------------------------

/// An individual value in a Sigma field condition.
#[derive(Debug, Clone)]
pub enum SigmaValue {
    /// Regular string value (may contain `*` wildcards in keyword searches).
    String(String),
    /// Explicit null — matches absent / empty fields.
    Null,
}

impl SigmaValue {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            SigmaValue::String(s) => Some(s.as_str()),
            SigmaValue::Null => None,
        }
    }
}

fn yaml_to_sigma_value(v: &YamlValue) -> SigmaValue {
    match v {
        YamlValue::String(s) => SigmaValue::String(s.clone()),
        YamlValue::Number(n) => SigmaValue::String(n.to_string()),
        YamlValue::Bool(b) => SigmaValue::String(b.to_string()),
        YamlValue::Null => SigmaValue::Null,
        _ => SigmaValue::String(format!("{v:?}")),
    }
}

fn yaml_value_to_string(v: &YamlValue) -> String {
    match v {
        YamlValue::String(s) => s.clone(),
        YamlValue::Number(n) => n.to_string(),
        YamlValue::Bool(b) => b.to_string(),
        _ => String::new(),
    }
}

// ---------------------------------------------------------------------------
// FieldCondition
// ---------------------------------------------------------------------------

/// A single field/value condition extracted from a Sigma selection.
#[derive(Debug, Clone)]
pub struct FieldCondition {
    /// The event field to check. `None` = keyword search across the raw log line.
    pub field: Option<String>,
    /// Ordered modifiers applied to the comparison.
    pub modifiers: Vec<FieldModifier>,
    /// Values to test against (OR relationship by default, AND when `All` modifier present).
    pub values: Vec<SigmaValue>,
    /// Pre-compiled regexes for the `Re` modifier, parallel to `values` (None for non-Re values).
    pub(crate) compiled_re: Vec<Option<Regex>>,
}

impl FieldCondition {
    /// Test this condition against a normalized event using the supplied field mapper.
    pub fn matches(&self, event: &NormalizedEvent, mapper: &FieldMapper) -> bool {
        let use_all = self.modifiers.contains(&FieldModifier::All);

        // Determine the haystack (field value or raw log line).
        let field_value: Option<String> = match &self.field {
            Some(fname) => mapper.get_field(event, fname),
            None => Some(event.raw_line.clone()),
        };

        // Null matching: check if any value is Null.
        let has_null_value = self.values.iter().any(|v| matches!(v, SigmaValue::Null));
        if has_null_value {
            let field_absent = field_value.is_none() || field_value.as_deref() == Some("");
            let non_null_count = self.values.iter().filter(|v| !matches!(v, SigmaValue::Null)).count();
            if non_null_count == 0 {
                return field_absent;
            }
            // Mixed: null OR other values
            if !use_all && field_absent {
                return true;
            }
        }

        let Some(haystack) = field_value else {
            // Field absent: only matches if values list is empty.
            return self.values.is_empty();
        };

        // Collect (original_index, &str) for non-null values to preserve compiled_re indices.
        let string_values: Vec<(usize, &str)> = self
            .values
            .iter()
            .enumerate()
            .filter_map(|(i, v)| v.as_str().map(|s| (i, s)))
            .collect();
        if string_values.is_empty() {
            return true;
        }

        let check_at = |(idx, needle): &(usize, &str)| -> bool {
            let re = self.compiled_re.get(*idx).and_then(|x| x.as_ref());
            self.match_single(&haystack, needle, re)
        };

        if use_all {
            string_values.iter().all(check_at)
        } else {
            string_values.iter().any(check_at)
        }
    }

    /// Determine the primary match type from modifiers (first type-modifier wins).
    fn primary_match_modifier(&self) -> Option<&FieldModifier> {
        self.modifiers.iter().find(|m| {
            matches!(
                m,
                FieldModifier::Contains
                    | FieldModifier::StartsWith
                    | FieldModifier::EndsWith
                    | FieldModifier::Re
                    | FieldModifier::Cidr
            )
        })
    }

    fn match_single(&self, haystack: &str, needle: &str, compiled_re: Option<&Regex>) -> bool {
        let lh = haystack.to_lowercase();
        let ln = needle.to_lowercase();

        match self.primary_match_modifier() {
            Some(FieldModifier::Contains) => lh.contains(ln.as_str()),
            Some(FieldModifier::StartsWith) => lh.starts_with(ln.as_str()),
            Some(FieldModifier::EndsWith) => lh.ends_with(ln.as_str()),
            Some(FieldModifier::Re) => {
                if let Some(re) = compiled_re {
                    re.is_match(haystack)
                } else {
                    // Fallback: compile on-the-fly (should not happen with properly parsed rules).
                    Regex::new(needle).map_or(false, |re| re.is_match(haystack))
                }
            }
            Some(FieldModifier::Cidr) => {
                let ip: Option<IpAddr> = haystack.parse().ok();
                let net: Option<ipnet::IpNet> = needle.parse().ok();
                match (ip, net) {
                    (Some(ip), Some(net)) => net.contains(&ip),
                    _ => false,
                }
            }
            _ => {
                // Default: case-insensitive exact match.
                // Sigma also supports `*` as a glob wildcard in plain values.
                if needle.contains('*') || needle.contains('?') {
                    glob_match(&ln, lh.as_str())
                } else {
                    lh == ln
                }
            }
        }
    }
}

/// Simple glob match: `*` matches any sequence, `?` matches one character.
fn glob_match(pattern: &str, text: &str) -> bool {
    let p_chars: Vec<char> = pattern.chars().collect();
    let t_chars: Vec<char> = text.chars().collect();
    glob_match_inner(&p_chars, &t_chars)
}

fn glob_match_inner(pattern: &[char], text: &[char]) -> bool {
    match (pattern.first(), text.first()) {
        (None, None) => true,
        (None, _) => false,
        (Some('*'), _) => {
            // * can match zero or more characters
            glob_match_inner(&pattern[1..], text)
                || (!text.is_empty() && glob_match_inner(pattern, &text[1..]))
        }
        (Some('?'), Some(_)) => glob_match_inner(&pattern[1..], &text[1..]),
        (Some(p), Some(t)) if p == t => glob_match_inner(&pattern[1..], &text[1..]),
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// SigmaSelection
// ---------------------------------------------------------------------------

/// A named selection block parsed from the detection YAML.
#[derive(Debug, Clone)]
pub enum SigmaSelection {
    /// AND relationship between all field conditions (most common).
    FieldMap(Vec<FieldCondition>),
    /// OR relationship between groups; within each group all conditions must match.
    OrList(Vec<Vec<FieldCondition>>),
    /// Keyword search: any keyword must appear in the raw log line (case-insensitive).
    Keywords(Vec<String>),
}

impl SigmaSelection {
    /// Parse a selection from its YAML value.
    pub fn from_yaml_value(value: &YamlValue, name: &str) -> Result<Self> {
        parse_selection_from_value(value, name)
    }

    /// Evaluate this selection against a `NormalizedEvent`.
    pub fn matches(&self, event: &NormalizedEvent, mapper: &FieldMapper) -> bool {
        match self {
            SigmaSelection::FieldMap(conditions) => {
                conditions.iter().all(|c| c.matches(event, mapper))
            }
            SigmaSelection::OrList(groups) => groups.iter().any(|group| {
                group.iter().all(|c| c.matches(event, mapper))
            }),
            SigmaSelection::Keywords(keywords) => {
                let raw_lower = event.raw_line.to_lowercase();
                keywords
                    .iter()
                    .any(|kw| raw_lower.contains(kw.to_lowercase().as_str()))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Parsing helpers
// ---------------------------------------------------------------------------

fn parse_selection_from_value(value: &YamlValue, name: &str) -> Result<SigmaSelection> {
    match value {
        YamlValue::Mapping(map) => {
            let conditions = parse_field_map(map, name)?;
            Ok(SigmaSelection::FieldMap(conditions))
        }
        YamlValue::Sequence(seq) => {
            if seq.is_empty() {
                return Ok(SigmaSelection::Keywords(vec![]));
            }
            // Determine sequence type by looking at the first element.
            match &seq[0] {
                YamlValue::Mapping(_) => {
                    // List of maps → OR relationship.
                    let mut groups = Vec::new();
                    for item in seq {
                        match item {
                            YamlValue::Mapping(m) => groups.push(parse_field_map(m, name)?),
                            _ => {
                                return Err(SigmaError::Parse(format!(
                                    "selection '{name}': expected mapping in sequence, got non-mapping"
                                )))
                            }
                        }
                    }
                    Ok(SigmaSelection::OrList(groups))
                }
                _ => {
                    // List of scalars → keyword search.
                    let keywords = seq.iter().map(yaml_value_to_string).collect();
                    Ok(SigmaSelection::Keywords(keywords))
                }
            }
        }
        _ => Err(SigmaError::Parse(format!(
            "selection '{name}': expected mapping or sequence, got scalar"
        ))),
    }
}

fn parse_field_map(
    map: &serde_yaml::Mapping,
    selection_name: &str,
) -> Result<Vec<FieldCondition>> {
    let mut conditions = Vec::new();
    for (k, v) in map.iter() {
        let key = k
            .as_str()
            .ok_or_else(|| SigmaError::Parse("field key must be a string".to_string()))?;
        let cond = parse_field_condition(key, v, selection_name)?;
        conditions.push(cond);
    }
    Ok(conditions)
}

fn parse_field_condition(
    key: &str,
    value: &YamlValue,
    _selection_name: &str,
) -> Result<FieldCondition> {
    // key = "FieldName" or "FieldName|mod1|mod2"
    let parts: Vec<&str> = key.split('|').collect();
    let field_name = parts[0].trim().to_string();
    let modifiers: Vec<FieldModifier> = parts[1..].iter().map(|s| FieldModifier::parse(s)).collect();

    let values = parse_condition_values(value);

    // An empty field name or the literal "keywords" means a keyword search.
    let field = if field_name.is_empty() || field_name == "keywords" {
        None
    } else {
        Some(field_name)
    };

    // Pre-compile regexes when the Re modifier is present.
    let is_re = modifiers.iter().any(|m| matches!(m, FieldModifier::Re));
    let compiled_re: Vec<Option<Regex>> = if is_re {
        values
            .iter()
            .map(|v| v.as_str().and_then(|s| Regex::new(s).ok()))
            .collect()
    } else {
        vec![None; values.len()]
    };

    Ok(FieldCondition {
        field,
        modifiers,
        values,
        compiled_re,
    })
}

fn parse_condition_values(value: &YamlValue) -> Vec<SigmaValue> {
    match value {
        YamlValue::Sequence(seq) => seq.iter().map(yaml_to_sigma_value).collect(),
        other => vec![yaml_to_sigma_value(other)],
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use hiveguard_core::models::{EventType, NormalizedEvent};
    use std::collections::HashMap;

    fn make_event(raw: &str, metadata: HashMap<&str, &str>) -> NormalizedEvent {
        NormalizedEvent {
            timestamp: chrono::Utc::now(),
            source_ip: "1.2.3.4".parse().unwrap(),
            event_type: EventType::HttpRequest,
            source_name: "test".to_string(),
            raw_line: raw.to_string(),
            metadata: metadata
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        }
    }

    fn default_mapper() -> FieldMapper {
        FieldMapper::new()
    }

    #[test]
    fn field_map_exact_match() {
        let yaml: YamlValue = serde_yaml::from_str("http_status: '403'").unwrap();
        let sel = SigmaSelection::from_yaml_value(&yaml, "sel").unwrap();
        let event = make_event("", HashMap::from([("http_status", "403")]));
        assert!(sel.matches(&event, &default_mapper()));
    }

    #[test]
    fn field_map_exact_no_match() {
        let yaml: YamlValue = serde_yaml::from_str("http_status: '200'").unwrap();
        let sel = SigmaSelection::from_yaml_value(&yaml, "sel").unwrap();
        let event = make_event("", HashMap::from([("http_status", "403")]));
        assert!(!sel.matches(&event, &default_mapper()));
    }

    #[test]
    fn field_map_contains_modifier() {
        let yaml: YamlValue =
            serde_yaml::from_str("'CommandLine|contains': 'powershell'").unwrap();
        let sel = SigmaSelection::from_yaml_value(&yaml, "sel").unwrap();
        let event = make_event("", HashMap::from([("command", "C:\\Windows\\powershell.exe -enc")]));
        assert!(sel.matches(&event, &default_mapper()));
    }

    #[test]
    fn field_map_startswith_modifier() {
        let yaml: YamlValue =
            serde_yaml::from_str("'CommandLine|startswith': '/bin/'").unwrap();
        let sel = SigmaSelection::from_yaml_value(&yaml, "sel").unwrap();
        let event = make_event("", HashMap::from([("command", "/bin/bash -c 'id'")]));
        assert!(sel.matches(&event, &default_mapper()));
    }

    #[test]
    fn field_map_endswith_modifier() {
        let yaml: YamlValue = serde_yaml::from_str("'CommandLine|endswith': '.ps1'").unwrap();
        let sel = SigmaSelection::from_yaml_value(&yaml, "sel").unwrap();
        let event = make_event("", HashMap::from([("command", "wscript payload.ps1")]));
        assert!(sel.matches(&event, &default_mapper()));
    }

    #[test]
    fn field_map_re_modifier() {
        let yaml: YamlValue = serde_yaml::from_str("'http_path|re': '^/admin.*'").unwrap();
        let sel = SigmaSelection::from_yaml_value(&yaml, "sel").unwrap();
        let event = make_event("", HashMap::from([("http_path", "/admin/login")]));
        assert!(sel.matches(&event, &default_mapper()));
    }

    #[test]
    fn field_map_list_of_values_or() {
        let yaml: YamlValue = serde_yaml::from_str(
            "EventID:\n  - '4625'\n  - '4634'",
        )
        .unwrap();
        let sel = SigmaSelection::from_yaml_value(&yaml, "sel").unwrap();
        let ev1 = make_event("", HashMap::from([("event_id", "4625")]));
        let ev2 = make_event("", HashMap::from([("event_id", "4634")]));
        let ev3 = make_event("", HashMap::from([("event_id", "9999")]));
        assert!(sel.matches(&ev1, &default_mapper()));
        assert!(sel.matches(&ev2, &default_mapper()));
        assert!(!sel.matches(&ev3, &default_mapper()));
    }

    #[test]
    fn field_map_contains_all_modifier() {
        let yaml: YamlValue = serde_yaml::from_str(
            "'CommandLine|contains|all':\n  - 'powershell'\n  - '-encoded'",
        )
        .unwrap();
        let sel = SigmaSelection::from_yaml_value(&yaml, "sel").unwrap();
        let ev_both = make_event("", HashMap::from([("command", "powershell -encoded dQBuAGkAYwBvAGQAZQ==")]));
        let ev_one = make_event("", HashMap::from([("command", "powershell -noexit")]));
        assert!(sel.matches(&ev_both, &default_mapper()));
        assert!(!sel.matches(&ev_one, &default_mapper()));
    }

    #[test]
    fn or_list_selection() {
        let yaml: YamlValue = serde_yaml::from_str(
            "- EventID: '4625'\n  LogonType: '3'\n- EventID: '4624'\n  LogonType: '10'",
        )
        .unwrap();
        let sel = SigmaSelection::from_yaml_value(&yaml, "sel").unwrap();
        let ev_match1 = make_event(
            "",
            HashMap::from([("event_id", "4625"), ("logon_type", "3")]),
        );
        let ev_match2 = make_event(
            "",
            HashMap::from([("event_id", "4624"), ("logon_type", "10")]),
        );
        let ev_no = make_event(
            "",
            HashMap::from([("event_id", "4625"), ("logon_type", "10")]),
        );
        assert!(sel.matches(&ev_match1, &default_mapper()));
        assert!(sel.matches(&ev_match2, &default_mapper()));
        assert!(!sel.matches(&ev_no, &default_mapper()));
    }

    #[test]
    fn keywords_selection() {
        let yaml: YamlValue =
            serde_yaml::from_str("- 'failed password'\n- 'authentication failure'").unwrap();
        let sel = SigmaSelection::from_yaml_value(&yaml, "keywords").unwrap();
        let ev_yes = make_event("sshd: Failed password for root", HashMap::new());
        let ev_no = make_event("sshd: Accepted publickey for root", HashMap::new());
        assert!(sel.matches(&ev_yes, &default_mapper()));
        assert!(!sel.matches(&ev_no, &default_mapper()));
    }

    #[test]
    fn source_ip_field_mapping() {
        let yaml: YamlValue =
            serde_yaml::from_str("SourceAddress: '1.2.3.4'").unwrap();
        let sel = SigmaSelection::from_yaml_value(&yaml, "sel").unwrap();
        let event = make_event("", HashMap::new()); // source_ip = 1.2.3.4
        assert!(sel.matches(&event, &default_mapper()));
    }

    #[test]
    fn cidr_modifier() {
        let yaml: YamlValue =
            serde_yaml::from_str("'SourceAddress|cidr': '192.168.0.0/16'").unwrap();
        let sel = SigmaSelection::from_yaml_value(&yaml, "sel").unwrap();
        let mut ev_in = make_event("", HashMap::new());
        ev_in.source_ip = "192.168.1.50".parse().unwrap();
        let mut ev_out = make_event("", HashMap::new());
        ev_out.source_ip = "10.0.0.1".parse().unwrap();
        assert!(sel.matches(&ev_in, &default_mapper()));
        assert!(!sel.matches(&ev_out, &default_mapper()));
    }

    #[test]
    fn glob_wildcard_match() {
        assert!(glob_match("*.exe", "notepad.exe"));
        assert!(glob_match("pow*shell", "powershell"));
        assert!(!glob_match("*.exe", "notepad.dll"));
    }
}
