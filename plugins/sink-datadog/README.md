# sink.datadog

## ⚠️  NOT IMPLEMENTED YET

Plugin scaffold for the Datadog bulk sink. Currently fail-loud during
`init` so operators don't accidentally configure a no-op sink.

Until this is fully migrated from `daemon/src/datadog_exporter.rs` (legacy LOC
of existing legacy code) configure Datadog shipping via the legacy
`siem.datadog.*` section in YAML — the daemon still honours it.

Track migration progress in REFACTOR_PROGRESS.md.
