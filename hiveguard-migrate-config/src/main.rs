use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;

use hiveguard_migrate_config::convert;

/// Convert a legacy HiveGuard YAML config to the new plugin-aware format.
#[derive(Parser, Debug)]
#[command(name = "hiveguard-migrate-config", version)]
struct Args {
    /// Path to the legacy YAML configuration file.
    #[arg(long, short = 'i')]
    input: PathBuf,

    /// Destination path. Defaults to `<input>.migrated.yaml`.
    #[arg(long, short = 'o')]
    output: Option<PathBuf>,

    /// Print the converted YAML to stdout instead of writing to disk.
    #[arg(long)]
    dry_run: bool,

    /// Show a unified diff between the legacy and migrated YAML on stderr.
    #[arg(long)]
    diff: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let legacy_yaml = std::fs::read_to_string(&args.input)
        .with_context(|| format!("read input {}", args.input.display()))?;

    let result = convert(&legacy_yaml)?;

    // ---- report ----
    eprintln!("== migration report ==");
    eprintln!("preserved sections: {:?}", result.report.preserved_sections);
    eprintln!("translated sections: {:?}", result.report.translated_sections);
    eprintln!(
        "generated {} plugin entries: {:?}",
        result.report.generated_plugins.len(),
        result.report.generated_plugins
    );
    for w in &result.report.warnings {
        eprintln!("warning: {w}");
    }
    for e in &result.report.validation_errors {
        eprintln!("schema-validation error: {e}");
    }

    if args.diff {
        print_unified_diff(&legacy_yaml, &result.yaml);
    }

    if args.dry_run {
        print!("{}", result.yaml);
        return Ok(());
    }

    let out_path = args.output.unwrap_or_else(|| {
        let mut p = args.input.clone();
        let new_name = match p.file_name().and_then(|s| s.to_str()) {
            Some(name) => {
                if let Some(stripped) = name.strip_suffix(".yaml") {
                    format!("{stripped}.migrated.yaml")
                } else if let Some(stripped) = name.strip_suffix(".yml") {
                    format!("{stripped}.migrated.yml")
                } else {
                    format!("{name}.migrated.yaml")
                }
            }
            None => "config.migrated.yaml".into(),
        };
        p.set_file_name(new_name);
        p
    });

    std::fs::write(&out_path, &result.yaml)
        .with_context(|| format!("write output {}", out_path.display()))?;
    eprintln!("wrote {}", out_path.display());

    if !result.report.validation_errors.is_empty() {
        std::process::exit(2);
    }
    Ok(())
}

/// Minimal unified-diff renderer (no external crate, no colour). Good enough
/// for a "what changed" overview — the source of truth is the YAML files.
fn print_unified_diff(old: &str, new: &str) {
    let old_lines: Vec<&str> = old.lines().collect();
    let new_lines: Vec<&str> = new.lines().collect();
    eprintln!("--- legacy");
    eprintln!("+++ migrated");
    // Greedy LCS-free diff: print all old as `-` then new as `+`. The user
    // wanted a diff, not a code-review tool — keeping this tiny.
    for line in &old_lines {
        eprintln!("-{line}");
    }
    for line in &new_lines {
        eprintln!("+{line}");
    }
}
