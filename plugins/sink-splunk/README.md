# sink.splunk

## ⚠️  NOT IMPLEMENTED YET

Plugin scaffold for the Splunk bulk sink. Currently fail-loud during
`init` so operators don't accidentally configure a no-op sink.

Until this is fully migrated from `daemon/src/splunk_exporter.rs` (legacy LOC
of existing legacy code) configure Splunk shipping via the legacy
`siem.splunk.*` section in YAML — the daemon still honours it.

Track migration progress in REFACTOR_PROGRESS.md.
