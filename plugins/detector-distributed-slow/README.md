# detector.distributed_slow

Automatic detection is disabled. Counting distinct addresses in a /24 or /48
cannot distinguish legitimate visitors from a coordinated attack. The plugin
loads existing configurations but emits no detection signals and creates no
subnet bans. Other detectors remain responsible for abuse detection.

Legacy `window_secs`, `subnet_threshold`, `ban_duration_secs` and `ban_scope`
fields are accepted for configuration compatibility and have no effect.
Existing bans are not removed by this change; review them separately across
cluster peers. Re-enabling subnet bans requires independent abuse correlation.
