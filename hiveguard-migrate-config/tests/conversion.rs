use std::collections::HashSet;
use std::process::Command;

use hiveguard_config::HiveGuardConfig;
use hiveguard_migrate_config::convert;

const FIXTURE: &str = include_str!("fixtures/legacy_minimal.yaml");

fn binary_path() -> std::path::PathBuf {
    // Use the same target dir layout as the harness — cargo sets CARGO_BIN_EXE_*.
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_hiveguard-migrate-config"))
}

#[test]
fn fixture_converts_to_expected_plugins() {
    let result = convert(FIXTURE).expect("convert");

    let ids: HashSet<&str> = result
        .report
        .generated_plugins
        .iter()
        .map(|s| s.as_str())
        .collect();

    // Sources: ssh (journald) + nginx access log
    assert!(ids.contains("source.journald"), "missing source.journald");
    assert!(
        ids.contains("source.file.nginx"),
        "missing source.file.nginx"
    );
    // Detectors: ssh_bruteforce (folds in user_enum), path_probe, honeypot
    assert!(ids.contains("detector.ssh_bruteforce"));
    assert!(ids.contains("detector.path_probe"));
    assert!(ids.contains("detector.honeypot"));
    // Enforcer
    assert!(ids.contains("enforcer.nftables"));
    // Notifier
    assert!(ids.contains("notifier.slack"));

    // Preserved sections
    assert!(result
        .report
        .preserved_sections
        .iter()
        .any(|s| s == "node"));
    assert!(result
        .report
        .preserved_sections
        .iter()
        .any(|s| s == "scoring"));
    assert!(result
        .report
        .preserved_sections
        .iter()
        .any(|s| s == "whitelist"));
}

#[test]
fn migrated_yaml_parses_as_hiveguard_config() {
    let result = convert(FIXTURE).expect("convert");
    let cfg: HiveGuardConfig = serde_yaml::from_str(&result.yaml)
        .expect("converted YAML must be parseable as HiveGuardConfig");
    assert_eq!(cfg.node.name, "fixture-node");
    assert!(
        cfg.plugins.len() >= 6,
        "expected at least 6 plugin entries, got {}",
        cfg.plugins.len()
    );
}

#[test]
fn schema_validation_passes_on_fixture() {
    let result = convert(FIXTURE).expect("convert");
    assert!(
        result.report.validation_errors.is_empty(),
        "validation errors: {:#?}",
        result.report.validation_errors
    );
}

#[test]
fn dry_run_does_not_write_to_disk() {
    let tmp = tempfile::tempdir().unwrap();
    let input_path = tmp.path().join("legacy.yaml");
    let expected_output = tmp.path().join("legacy.migrated.yaml");
    std::fs::write(&input_path, FIXTURE).unwrap();

    let status = Command::new(binary_path())
        .arg("--input")
        .arg(&input_path)
        .arg("--dry-run")
        .output()
        .expect("run binary");

    assert!(
        status.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&status.stderr)
    );
    assert!(
        !expected_output.exists(),
        "dry-run must not create {expected_output:?}"
    );
    // stdout should contain the converted YAML
    let stdout = String::from_utf8(status.stdout).unwrap();
    assert!(
        stdout.contains("plugins:"),
        "stdout missing plugins list:\n{stdout}"
    );
}

#[test]
fn schema_validation_detects_invalid_config() {
    // Forge a legacy config with a value the schema rejects (subnet_threshold = 0).
    let bad = r#"
node:
  name: x
  data_dir: /tmp
detectors:
  distributed_slow:
    enabled: true
    subnet_threshold: 0
"#;
    let result = convert(bad).expect("convert");
    assert!(
        result
            .report
            .validation_errors
            .iter()
            .any(|e| e.starts_with("detector.distributed_slow:")),
        "expected validation error for distributed_slow, got: {:#?}",
        result.report.validation_errors
    );
}

#[test]
fn unknown_top_level_key_emits_warning_and_is_preserved() {
    let yaml = r#"
node:
  name: x
  data_dir: /tmp
mystery_section:
  hello: world
"#;
    let result = convert(yaml).expect("convert");
    assert!(result
        .report
        .warnings
        .iter()
        .any(|w| w.contains("mystery_section")));
    assert!(
        result.yaml.contains("mystery_section"),
        "unknown sections should be preserved verbatim"
    );
}
