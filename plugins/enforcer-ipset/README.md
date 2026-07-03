# enforcer.ipset

## ⚠️  NOT IMPLEMENTED YET

This plugin is intentionally fail-loud during refactor phase A2. Initializing
`enforcer.ipset` returns `PluginError::Init` so operators cannot accidentally
run with no real enforcement.

Use `enforcer.nftables` for active firewall enforcement, or `enforcer.observe`
for explicit dry-run mode.

IPSet enforcer plugin scaffold tracked in A2 TODOs.
