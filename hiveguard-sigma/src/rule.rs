//! Sigma rule data structures and YAML parsing.
//!
//! ## Usage
//!
//! ```rust,ignore
//! let rule = SigmaRule::from_yaml(yaml_text)?;
//! println!("{} (severity {})", rule.title, rule.level.to_severity());
//! ```

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_yaml::Value as YamlValue;

use crate::condition::{parse_condition, ConditionExpr};
use crate::error::{Result, SigmaError};
use crate::fieldmap::FieldMapper;
use crate::selection::SigmaSelection;
use hiveguard_core::models::NormalizedEvent;

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

/// Publication status of a Sigma rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum SigmaStatus {
    /// Rule is ready for production.
    Stable,
    /// Rule is under development / may have false positives.
    #[default]
    Experimental,
    /// Rule has been superseded or retired.
    Deprecated,
    /// Used for testing purposes only.
    Test,
    /// Not supported on this platform.
    Unsupported,
}

/// Severity level of a Sigma rule.
///
/// Maps to HiveGuard's internal severity (0–255).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum SigmaLevel {
    Informational,
    #[default]
    Low,
    Medium,
    High,
    Critical,
}

impl SigmaLevel {
    /// Convert a Sigma level to a HiveGuard severity byte.
    ///
    /// | Level         | Severity |
    /// |---------------|---------|
    /// | informational | 10      |
    /// | low           | 30      |
    /// | medium        | 60      |
    /// | high          | 80      |
    /// | critical      | 120     |
    pub fn to_severity(&self) -> u8 {
        match self {
            SigmaLevel::Informational => 10,
            SigmaLevel::Low => 30,
            SigmaLevel::Medium => 60,
            SigmaLevel::High => 80,
            SigmaLevel::Critical => 120,
        }
    }
}

// ---------------------------------------------------------------------------
// Log source
// ---------------------------------------------------------------------------

/// Sigma log source specifier.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SigmaLogSource {
    /// Log category (e.g. `authentication`, `webserver`).
    pub category: Option<String>,
    /// Product name (e.g. `linux`, `windows`).
    pub product: Option<String>,
    /// Service name (e.g. `ssh`, `nginx`).
    pub service: Option<String>,
}

// ---------------------------------------------------------------------------
// Detection block
// ---------------------------------------------------------------------------

/// Parsed detection block — selections + condition string.
#[derive(Debug, Clone)]
pub struct SigmaDetection {
    /// Named selections extracted from the detection map.
    pub selections: HashMap<String, SigmaSelection>,
    /// Raw condition expression (e.g. `"selection and not filter"`).
    pub condition: String,
    /// Optional aggregation timeframe (e.g. `"5m"`).
    pub timeframe: Option<String>,
}

// ---------------------------------------------------------------------------
// SigmaRule
// ---------------------------------------------------------------------------

/// A fully parsed Sigma detection rule.
#[derive(Debug, Clone)]
pub struct SigmaRule {
    /// Rule title (required).
    pub title: String,
    /// Optional rule UUID.
    pub id: Option<String>,
    /// Rule publication status.
    pub status: SigmaStatus,
    /// Human-readable description.
    pub description: Option<String>,
    /// Rule author(s).
    pub author: Option<String>,
    /// Publication date (free-form string, often `"YYYY/MM/DD"`).
    pub date: Option<String>,
    /// MITRE ATT&CK tags and other labels.
    pub tags: Vec<String>,
    /// External references (URLs, CVE IDs, …).
    pub references: Vec<String>,
    /// Log source specifier.
    pub logsource: SigmaLogSource,
    /// Detection logic.
    pub detection: SigmaDetection,
    /// Severity level.
    pub level: SigmaLevel,
    /// Known-false-positive notes.
    pub falsepositives: Vec<String>,
    /// Pre-parsed condition AST (cached for repeated evaluation).
    pub(crate) condition_ast: ConditionExpr,
}

impl SigmaRule {
    // ── Constructors ──────────────────────────────────────────────────────

    /// Parse a Sigma rule from YAML text.
    pub fn from_yaml(yaml_text: &str) -> Result<Self> {
        let value: YamlValue = serde_yaml::from_str(yaml_text)?;
        Self::from_yaml_value(value)
    }

    /// Parse a Sigma rule from an already-deserialized `serde_yaml::Value`.
    pub fn from_yaml_value(value: YamlValue) -> Result<Self> {
        let map = value
            .as_mapping()
            .ok_or_else(|| SigmaError::Parse("rule must be a YAML mapping".to_string()))?;

        let title = require_str(map, "title")?.to_owned();
        let id = optional_str(map, "id").map(str::to_owned);
        let status = parse_status(optional_str(map, "status").unwrap_or("experimental"));
        let description = optional_str(map, "description").map(str::to_owned);
        let author = optional_str(map, "author").map(str::to_owned);
        let date = optional_str(map, "date").map(str::to_owned);
        let tags = string_list(map, "tags");
        let references = string_list(map, "references");
        let falsepositives = string_list(map, "falsepositives");
        let logsource = parse_logsource(map)?;
        let level = parse_level(optional_str(map, "level").unwrap_or("low"));
        let detection = parse_detection(map)?;

        let condition_ast = parse_condition(&detection.condition)
            .map_err(|e| SigmaError::Parse(format!("condition parse error: {e}")))?;

        Ok(SigmaRule {
            title,
            id,
            status,
            description,
            author,
            date,
            tags,
            references,
            logsource,
            detection,
            level,
            falsepositives,
            condition_ast,
        })
    }

    // ── Evaluation ────────────────────────────────────────────────────────

    /// Test whether a `NormalizedEvent` matches this rule.
    pub fn matches(&self, event: &NormalizedEvent, mapper: &FieldMapper) -> bool {
        use std::collections::HashSet;

        let all_names: HashSet<String> = self.detection.selections.keys().cloned().collect();

        let matched: HashSet<String> = self
            .detection
            .selections
            .iter()
            .filter(|(_, sel)| sel.matches(event, mapper))
            .map(|(name, _)| name.clone())
            .collect();

        crate::condition::evaluate_condition(&self.condition_ast, &matched, &all_names)
    }

    /// Convenience: severity as a `u8`.
    pub fn severity(&self) -> u8 {
        self.level.to_severity()
    }
}

// ---------------------------------------------------------------------------
// Parsing helpers
// ---------------------------------------------------------------------------

fn require_str<'a>(map: &'a serde_yaml::Mapping, key: &str) -> Result<&'a str> {
    map.get(key)
        .and_then(|v| v.as_str())
        .ok_or_else(|| SigmaError::Parse(format!("missing required field '{key}'")))
}

fn optional_str<'a>(map: &'a serde_yaml::Mapping, key: &str) -> Option<&'a str> {
    map.get(key).and_then(|v| v.as_str())
}

fn string_list(map: &serde_yaml::Mapping, key: &str) -> Vec<String> {
    match map.get(key) {
        Some(YamlValue::Sequence(seq)) => seq
            .iter()
            .filter_map(|v| v.as_str())
            .map(str::to_owned)
            .collect(),
        Some(YamlValue::String(s)) => vec![s.clone()],
        _ => vec![],
    }
}

fn parse_status(s: &str) -> SigmaStatus {
    match s.to_lowercase().as_str() {
        "stable" => SigmaStatus::Stable,
        "deprecated" => SigmaStatus::Deprecated,
        "test" => SigmaStatus::Test,
        "unsupported" => SigmaStatus::Unsupported,
        _ => SigmaStatus::Experimental,
    }
}

fn parse_level(s: &str) -> SigmaLevel {
    match s.to_lowercase().as_str() {
        "informational" => SigmaLevel::Informational,
        "medium" => SigmaLevel::Medium,
        "high" => SigmaLevel::High,
        "critical" => SigmaLevel::Critical,
        _ => SigmaLevel::Low,
    }
}

fn parse_logsource(map: &serde_yaml::Mapping) -> Result<SigmaLogSource> {
    let ls_value = map
        .get("logsource")
        .ok_or_else(|| SigmaError::Parse("missing required field 'logsource'".to_string()))?;

    let ls_map = ls_value
        .as_mapping()
        .ok_or_else(|| SigmaError::Parse("'logsource' must be a mapping".to_string()))?;

    Ok(SigmaLogSource {
        category: optional_str(ls_map, "category").map(str::to_owned),
        product: optional_str(ls_map, "product").map(str::to_owned),
        service: optional_str(ls_map, "service").map(str::to_owned),
    })
}

fn parse_detection(map: &serde_yaml::Mapping) -> Result<SigmaDetection> {
    let det_value = map
        .get("detection")
        .ok_or_else(|| SigmaError::Parse("missing required field 'detection'".to_string()))?;

    let det_map = det_value
        .as_mapping()
        .ok_or_else(|| SigmaError::Parse("'detection' must be a mapping".to_string()))?;

    // Extract `condition` (required) and optional `timeframe`.
    let condition = optional_str(det_map, "condition")
        .ok_or_else(|| SigmaError::Parse("'detection.condition' is required".to_string()))?
        .to_owned();

    let timeframe = optional_str(det_map, "timeframe").map(str::to_owned);

    // All remaining keys are selections.
    let mut selections: HashMap<String, SigmaSelection> = HashMap::new();
    for (k, v) in det_map.iter() {
        let key = match k.as_str() {
            Some(s) => s,
            None => continue,
        };
        if key == "condition" || key == "timeframe" {
            continue;
        }
        let sel = SigmaSelection::from_yaml_value(v, key)?;
        selections.insert(key.to_owned(), sel);
    }

    Ok(SigmaDetection {
        selections,
        condition,
        timeframe,
    })
}

// ---------------------------------------------------------------------------
// Tests — 20 example rules (Task 4.1.1)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use hiveguard_core::models::{EventType, NormalizedEvent};

    fn make_event_with_meta(
        source_ip: &str,
        raw: &str,
        meta: &[(&str, &str)],
    ) -> NormalizedEvent {
        NormalizedEvent {
            timestamp: chrono::Utc::now(),
            source_ip: source_ip.parse().unwrap(),
            event_type: EventType::HttpRequest,
            source_name: "test".to_string(),
            raw_line: raw.to_string(),
            metadata: meta
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        }
    }

    fn mapper() -> FieldMapper {
        FieldMapper::new()
    }

    // ── Rule 1: SSH brute-force (keyword) ─────────────────────────────────
    #[test]
    fn rule_01_ssh_bruteforce_keyword() {
        let yaml = r#"
title: SSH Brute Force Attempt
id: a1b2c3d4-0001-0001-0001-000000000001
status: stable
description: Detects multiple failed SSH login attempts
tags:
  - attack.credential_access
  - attack.t1110
logsource:
  product: linux
  service: ssh
detection:
  keywords:
    - "Failed password"
    - "Invalid user"
  condition: keywords
level: medium
falsepositives:
  - Legitimate failed logins
"#;
        let rule = SigmaRule::from_yaml(yaml).unwrap();
        assert_eq!(rule.title, "SSH Brute Force Attempt");
        assert_eq!(rule.level, SigmaLevel::Medium);
        assert_eq!(rule.severity(), 60);

        let ev_match = make_event_with_meta("1.2.3.4", "Failed password for root from 1.2.3.4", &[]);
        let ev_no = make_event_with_meta("1.2.3.4", "Accepted publickey for root", &[]);
        assert!(rule.matches(&ev_match, &mapper()));
        assert!(!rule.matches(&ev_no, &mapper()));
    }

    // ── Rule 2: HTTP path probe ────────────────────────────────────────────
    #[test]
    fn rule_02_http_path_probe() {
        let yaml = r#"
title: WordPress Admin Login Probe
status: experimental
logsource:
  category: webserver
detection:
  selection:
    'http_path|contains': '/wp-admin'
  condition: selection
level: low
falsepositives:
  - Legitimate WordPress admins
"#;
        let rule = SigmaRule::from_yaml(yaml).unwrap();
        assert_eq!(rule.title, "WordPress Admin Login Probe");

        let ev_yes = make_event_with_meta("5.5.5.5", "", &[("http_path", "/wp-admin/login.php")]);
        let ev_no = make_event_with_meta("5.5.5.5", "", &[("http_path", "/index.html")]);
        assert!(rule.matches(&ev_yes, &mapper()));
        assert!(!rule.matches(&ev_no, &mapper()));
    }

    // ── Rule 3: SQL injection via URL ──────────────────────────────────────
    #[test]
    fn rule_03_sql_injection_url() {
        let yaml = r#"
title: SQL Injection in URL
status: experimental
logsource:
  category: webserver
detection:
  selection:
    'http_path|contains':
      - "' OR '"
      - "UNION SELECT"
      - "1=1"
  condition: selection
level: high
falsepositives:
  - Security scanners
"#;
        let rule = SigmaRule::from_yaml(yaml).unwrap();
        assert_eq!(rule.level, SigmaLevel::High);

        let ev_yes = make_event_with_meta("6.6.6.6", "", &[("http_path", "/search?q=1=1")]);
        let ev_no = make_event_with_meta("6.6.6.6", "", &[("http_path", "/search?q=hello")]);
        assert!(rule.matches(&ev_yes, &mapper()));
        assert!(!rule.matches(&ev_no, &mapper()));
    }

    // ── Rule 4: Path traversal ─────────────────────────────────────────────
    #[test]
    fn rule_04_path_traversal() {
        let yaml = r#"
title: Path Traversal Attack
status: stable
logsource:
  category: webserver
detection:
  selection:
    'http_path|contains':
      - "../"
      - "..%2F"
      - "..%5C"
  condition: selection
level: high
falsepositives:
  - None
"#;
        let rule = SigmaRule::from_yaml(yaml).unwrap();
        let ev_yes = make_event_with_meta("7.7.7.7", "", &[("http_path", "/files/../../../../etc/passwd")]);
        let ev_no = make_event_with_meta("7.7.7.7", "", &[("http_path", "/files/data.txt")]);
        assert!(rule.matches(&ev_yes, &mapper()));
        assert!(!rule.matches(&ev_no, &mapper()));
    }

    // ── Rule 5: Windows command execution ──────────────────────────────────
    #[test]
    fn rule_05_windows_cmd_execution() {
        let yaml = r#"
title: Suspicious PowerShell Encoded Command
status: stable
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    'CommandLine|contains|all':
      - 'powershell'
      - '-EncodedCommand'
  condition: selection
level: high
falsepositives:
  - Administrative scripts
"#;
        let rule = SigmaRule::from_yaml(yaml).unwrap();
        let ev_yes = make_event_with_meta("0.0.0.0", "", &[("command", "powershell -EncodedCommand dQBuAGkAYwBvAGQAZQ==")]);
        let ev_partial = make_event_with_meta("0.0.0.0", "", &[("command", "powershell -noexit")]);
        assert!(rule.matches(&ev_yes, &mapper()));
        assert!(!rule.matches(&ev_partial, &mapper()));
    }

    // ── Rule 6: Event ID based ─────────────────────────────────────────────
    #[test]
    fn rule_06_event_id_list() {
        let yaml = r#"
title: Windows Logon Failure
status: stable
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID:
      - '4625'
      - '4771'
  condition: selection
level: low
falsepositives:
  - Mistyped passwords
"#;
        let rule = SigmaRule::from_yaml(yaml).unwrap();
        let ev_4625 = make_event_with_meta("0.0.0.0", "", &[("event_id", "4625")]);
        let ev_4771 = make_event_with_meta("0.0.0.0", "", &[("event_id", "4771")]);
        let ev_ok = make_event_with_meta("0.0.0.0", "", &[("event_id", "4624")]);
        assert!(rule.matches(&ev_4625, &mapper()));
        assert!(rule.matches(&ev_4771, &mapper()));
        assert!(!rule.matches(&ev_ok, &mapper()));
    }

    // ── Rule 7: Multiple selections with AND condition ─────────────────────
    #[test]
    fn rule_07_selection_and_filter() {
        let yaml = r#"
title: Admin Path Access Excluding Localhost
status: experimental
logsource:
  category: webserver
detection:
  selection:
    'http_path|startswith': '/admin'
  filter:
    SourceAddress: '127.0.0.1'
  condition: selection and not filter
level: medium
falsepositives:
  - None
"#;
        let rule = SigmaRule::from_yaml(yaml).unwrap();
        // Access from external IP → match
        let ev_ext = make_event_with_meta("10.0.0.1", "", &[("http_path", "/admin/panel")]);
        // Access from localhost → filtered
        let ev_local = make_event_with_meta("127.0.0.1", "", &[("http_path", "/admin/panel")]);
        assert!(rule.matches(&ev_ext, &mapper()));
        assert!(!rule.matches(&ev_local, &mapper()));
    }

    // ── Rule 8: OR of selections ───────────────────────────────────────────
    #[test]
    fn rule_08_or_selections() {
        let yaml = r#"
title: Web Shell Detection
status: experimental
logsource:
  category: webserver
detection:
  webshell_php:
    'http_path|endswith': '.php'
    'http_status': '200'
  webshell_asp:
    'http_path|endswith': '.asp'
    'http_status': '200'
  condition: webshell_php or webshell_asp
level: high
falsepositives:
  - Normal PHP/ASP apps
"#;
        let rule = SigmaRule::from_yaml(yaml).unwrap();
        let ev_php = make_event_with_meta("1.1.1.1", "", &[("http_path", "/shell.php"), ("http_status", "200")]);
        let ev_asp = make_event_with_meta("1.1.1.1", "", &[("http_path", "/backdoor.asp"), ("http_status", "200")]);
        let ev_none = make_event_with_meta("1.1.1.1", "", &[("http_path", "/index.html"), ("http_status", "200")]);
        assert!(rule.matches(&ev_php, &mapper()));
        assert!(rule.matches(&ev_asp, &mapper()));
        assert!(!rule.matches(&ev_none, &mapper()));
    }

    // ── Rule 9: Regex modifier ────────────────────────────────────────────
    #[test]
    fn rule_09_regex_modifier() {
        let yaml = r#"
title: Suspicious User-Agent Pattern
status: experimental
logsource:
  category: webserver
detection:
  selection:
    'UserAgent|re': '(?i)(sqlmap|nikto|nmap|masscan)'
  condition: selection
level: high
falsepositives:
  - Internal security scanning
"#;
        let rule = SigmaRule::from_yaml(yaml).unwrap();
        let ev_yes = make_event_with_meta("2.2.2.2", "", &[("user_agent", "sqlmap/1.4")]);
        let ev_no = make_event_with_meta("2.2.2.2", "", &[("user_agent", "Mozilla/5.0")]);
        assert!(rule.matches(&ev_yes, &mapper()));
        assert!(!rule.matches(&ev_no, &mapper()));
    }

    // ── Rule 10: CIDR modifier ────────────────────────────────────────────
    #[test]
    fn rule_10_cidr_modifier() {
        let yaml = r#"
title: Traffic from Known Malicious Range
status: experimental
logsource:
  category: network
detection:
  selection:
    'SourceAddress|cidr': '185.220.0.0/16'
  condition: selection
level: high
falsepositives:
  - None expected
"#;
        let rule = SigmaRule::from_yaml(yaml).unwrap();
        let ev_yes = make_event_with_meta("185.220.1.1", "", &[]);
        let ev_no = make_event_with_meta("8.8.8.8", "", &[]);
        assert!(rule.matches(&ev_yes, &mapper()));
        assert!(!rule.matches(&ev_no, &mapper()));
    }

    // ── Rule 11: 1 of selection* ──────────────────────────────────────────
    #[test]
    fn rule_11_one_of_wildcard() {
        let yaml = r#"
title: Any Scanner Indicator
status: experimental
logsource:
  category: webserver
detection:
  sel_nikto:
    'UserAgent|contains': 'nikto'
  sel_sqlmap:
    'UserAgent|contains': 'sqlmap'
  sel_nmap:
    'UserAgent|contains': 'nmap'
  condition: 1 of sel*
level: medium
falsepositives:
  - Security audits
"#;
        let rule = SigmaRule::from_yaml(yaml).unwrap();
        let ev_nikto = make_event_with_meta("3.3.3.3", "", &[("user_agent", "Nikto/2.1")]);
        let ev_normal = make_event_with_meta("3.3.3.3", "", &[("user_agent", "curl/7.68")]);
        assert!(rule.matches(&ev_nikto, &mapper()));
        assert!(!rule.matches(&ev_normal, &mapper()));
    }

    // ── Rule 12: Minimal rule (only required fields) ──────────────────────
    #[test]
    fn rule_12_minimal_required_fields() {
        let yaml = r#"
title: Minimal Rule
logsource:
  category: test
detection:
  selection:
    http_status: '500'
  condition: selection
"#;
        let rule = SigmaRule::from_yaml(yaml).unwrap();
        assert_eq!(rule.title, "Minimal Rule");
        assert_eq!(rule.level, SigmaLevel::Low); // default
        assert_eq!(rule.status, SigmaStatus::Experimental); // default
        assert!(rule.tags.is_empty());
    }

    // ── Rule 13: Critical severity ───────────────────────────────────────
    #[test]
    fn rule_13_critical_severity() {
        let yaml = r#"
title: Honeypot Trigger
status: stable
logsource:
  category: webserver
detection:
  selection:
    'http_path': '/honeypot-trap'
  condition: selection
level: critical
falsepositives:
  - None
"#;
        let rule = SigmaRule::from_yaml(yaml).unwrap();
        assert_eq!(rule.level, SigmaLevel::Critical);
        assert_eq!(rule.severity(), 120);
    }

    // ── Rule 14: Informational level ─────────────────────────────────────
    #[test]
    fn rule_14_informational_level() {
        let yaml = r#"
title: Info Event
logsource:
  category: test
detection:
  selection:
    http_status: '200'
  condition: selection
level: informational
"#;
        let rule = SigmaRule::from_yaml(yaml).unwrap();
        assert_eq!(rule.level, SigmaLevel::Informational);
        assert_eq!(rule.severity(), 10);
    }

    // ── Rule 15: Or-list selection (list of maps) ─────────────────────────
    #[test]
    fn rule_15_or_list_selection() {
        let yaml = r#"
title: Suspicious Logon
status: stable
logsource:
  product: windows
  service: security
detection:
  selection:
    - EventID: '4625'
      logon_type: '3'
    - EventID: '4624'
      logon_type: '10'
  condition: selection
level: medium
"#;
        let rule = SigmaRule::from_yaml(yaml).unwrap();
        let ev_match1 = make_event_with_meta("0.0.0.0", "", &[("event_id", "4625"), ("logon_type", "3")]);
        let ev_match2 = make_event_with_meta("0.0.0.0", "", &[("event_id", "4624"), ("logon_type", "10")]);
        let ev_no = make_event_with_meta("0.0.0.0", "", &[("event_id", "4625"), ("logon_type", "10")]);
        assert!(rule.matches(&ev_match1, &mapper()));
        assert!(rule.matches(&ev_match2, &mapper()));
        assert!(!rule.matches(&ev_no, &mapper()));
    }

    // ── Rule 16: Tags and references ──────────────────────────────────────
    #[test]
    fn rule_16_tags_and_references() {
        let yaml = r#"
title: T1110 Brute Force
id: abcdef12-0000-0000-0000-000000000016
author: HiveGuard Team
date: 2024/01/15
references:
  - https://attack.mitre.org/techniques/T1110/
tags:
  - attack.credential_access
  - attack.t1110
logsource:
  product: linux
  service: ssh
detection:
  selection:
    'raw_line|contains': 'Failed password'
  condition: selection
level: medium
"#;
        let rule = SigmaRule::from_yaml(yaml).unwrap();
        assert_eq!(rule.id.as_deref(), Some("abcdef12-0000-0000-0000-000000000016"));
        assert_eq!(rule.author.as_deref(), Some("HiveGuard Team"));
        assert_eq!(rule.tags.len(), 2);
        assert_eq!(rule.references.len(), 1);
    }

    // ── Rule 17: postfix SMTP brute-force ────────────────────────────────
    #[test]
    fn rule_17_smtp_brute_force_keyword() {
        let yaml = r#"
title: SMTP Authentication Brute Force
status: stable
logsource:
  product: postfix
  service: smtp
detection:
  keywords:
    - "authentication failed"
    - "SASL LOGIN authentication failed"
  condition: keywords
level: medium
"#;
        let rule = SigmaRule::from_yaml(yaml).unwrap();
        let ev_yes = make_event_with_meta("9.9.9.9", "SASL LOGIN authentication failed: UGFzc3dvcmQ=", &[]);
        let ev_no = make_event_with_meta("9.9.9.9", "connect from mail.example.com", &[]);
        assert!(rule.matches(&ev_yes, &mapper()));
        assert!(!rule.matches(&ev_no, &mapper()));
    }

    // ── Rule 18: HTTP 4xx flood signature ────────────────────────────────
    #[test]
    fn rule_18_http_4xx_flood_signature() {
        let yaml = r#"
title: Excessive HTTP 4xx Errors
status: experimental
logsource:
  category: webserver
detection:
  selection:
    'http_status|startswith': '4'
  filter_normal:
    'http_status': '404'
    'http_path': '/favicon.ico'
  condition: selection and not filter_normal
level: low
"#;
        let rule = SigmaRule::from_yaml(yaml).unwrap();
        let ev_403 = make_event_with_meta("4.4.4.4", "", &[("http_status", "403"), ("http_path", "/admin")]);
        let ev_404_fav = make_event_with_meta("4.4.4.4", "", &[("http_status", "404"), ("http_path", "/favicon.ico")]);
        let ev_404_other = make_event_with_meta("4.4.4.4", "", &[("http_status", "404"), ("http_path", "/missing")]);
        assert!(rule.matches(&ev_403, &mapper()));
        assert!(!rule.matches(&ev_404_fav, &mapper()));
        assert!(rule.matches(&ev_404_other, &mapper()));
    }

    // ── Rule 19: Parenthesized condition ─────────────────────────────────
    #[test]
    fn rule_19_parenthesized_condition() {
        let yaml = r#"
title: Combined Attack Indicators
status: experimental
logsource:
  category: webserver
detection:
  path_indicator:
    'http_path|contains': '/shell'
  ua_indicator:
    'UserAgent|contains': 'curl'
  ip_filter:
    SourceAddress: '10.0.0.1'
  condition: (path_indicator or ua_indicator) and not ip_filter
level: high
"#;
        let rule = SigmaRule::from_yaml(yaml).unwrap();
        // shell path from external IP → match
        let ev_shell_ext = make_event_with_meta("1.1.1.1", "", &[("http_path", "/shell.php"), ("user_agent", "Python")]);
        // shell path from whitelisted IP → no match
        let ev_shell_trusted = make_event_with_meta("10.0.0.1", "", &[("http_path", "/shell.php")]);
        // curl from external → match
        let ev_curl_ext = make_event_with_meta("2.2.2.2", "", &[("user_agent", "curl/7.0"), ("http_path", "/index")]);
        // curl from trusted → no match
        let ev_curl_trusted = make_event_with_meta("10.0.0.1", "", &[("user_agent", "curl/7.0")]);
        assert!(rule.matches(&ev_shell_ext, &mapper()));
        assert!(!rule.matches(&ev_shell_trusted, &mapper()));
        assert!(rule.matches(&ev_curl_ext, &mapper()));
        assert!(!rule.matches(&ev_curl_trusted, &mapper()));
    }

    // ── Rule 20: count aggregation parses without error ───────────────────
    #[test]
    fn rule_20_count_aggregation_parses() {
        let yaml = r#"
title: Brute Force by Count
status: experimental
logsource:
  product: linux
  service: ssh
detection:
  selection:
    'raw_line|contains': 'Failed password'
  condition: selection | count() > 10
  timeframe: 5m
level: high
"#;
        // Rule must parse without error (count() > 10 is simplified to `true` in 4.1).
        let rule = SigmaRule::from_yaml(yaml).unwrap();
        assert_eq!(rule.detection.timeframe.as_deref(), Some("5m"));
        // count aggregation always returns true in Phase 4.1
        let ev = make_event_with_meta("1.1.1.1", "Failed password for root", &[]);
        // The condition is `selection | count() > 10`.
        // After AND-interpretation: selection AND count() — both must be true.
        // count() is always true, so only `selection` matters.
        assert!(rule.matches(&ev, &mapper()));
    }

    // ── Parsing error tests ───────────────────────────────────────────────

    #[test]
    fn missing_title_fails() {
        let yaml = r#"
status: stable
logsource:
  category: test
detection:
  selection:
    field: value
  condition: selection
"#;
        assert!(SigmaRule::from_yaml(yaml).is_err());
    }

    #[test]
    fn missing_logsource_fails() {
        let yaml = r#"
title: No Logsource
detection:
  selection:
    field: value
  condition: selection
"#;
        assert!(SigmaRule::from_yaml(yaml).is_err());
    }

    #[test]
    fn missing_detection_fails() {
        let yaml = r#"
title: No Detection
logsource:
  category: test
"#;
        assert!(SigmaRule::from_yaml(yaml).is_err());
    }

    #[test]
    fn level_severity_mapping() {
        assert_eq!(SigmaLevel::Informational.to_severity(), 10);
        assert_eq!(SigmaLevel::Low.to_severity(), 30);
        assert_eq!(SigmaLevel::Medium.to_severity(), 60);
        assert_eq!(SigmaLevel::High.to_severity(), 80);
        assert_eq!(SigmaLevel::Critical.to_severity(), 120);
    }
}
