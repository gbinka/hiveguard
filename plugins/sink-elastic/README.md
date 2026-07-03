# sink.elastic

## ⚠️  NOT IMPLEMENTED YET

Plugin scaffold for the Elasticsearch bulk sink. Currently fail-loud during
`init` so operators don't accidentally configure a no-op sink.

Until this is fully migrated from `daemon/src/elastic_exporter.rs` (815 LOC
of existing legacy code) configure Elasticsearch shipping via the legacy
`siem.elasticsearch.*` section in YAML — the daemon still honours it.

Track migration progress in REFACTOR_PROGRESS.md.
