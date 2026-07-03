# Enforcer plugin

Apply and remove bans at the firewall / CDN layer. Reference impls (after
Fala A2): `plugins/enforcer-nftables`, `plugins/enforcer-cloudflare`.

> Before reading this: finish [AUTHORING.md](./AUTHORING.md).

## Trait

```rust
#[async_trait]
pub trait EnforcerPlugin: Plugin {
    async fn setup(&mut self) -> PluginResult<()> { Ok(()) }    // optional
    async fn apply_ban(&mut self, subject: &IpNet) -> PluginResult<()>;
    async fn remove_ban(&mut self, subject: &IpNet) -> PluginResult<()>;
    async fn sync_full(&mut self, banned: &[IpNet]) -> PluginResult<()>;
    async fn get_current_bans(&self) -> PluginResult<Vec<IpNet>>;
}
```

## What the host guarantees

- `setup` runs once after `init`, before any `apply_ban`. Use it to create
  tables, sets, chains.
- `apply_ban` and `remove_ban` are called from a single task — no concurrent
  mutations. Both take `&mut self` to make this explicit.
- `sync_full` is called after WAL replay / cluster sync, to make the kernel
  state match the canonical ban list. Must be idempotent.
- `get_current_bans` is used for drift detection — what the kernel actually
  has, not what the daemon thinks.

## What you implement

### 1. Idempotence

Every method must be safe to call repeatedly:

- `apply_ban` on an already-banned `subject` — succeed without error.
- `remove_ban` on a not-banned `subject` — succeed without error.
- `setup` on an already-set-up firewall — succeed without error.

The pipeline relies on this when replaying WAL or recovering from partial
failures.

### 2. Atomicity of `sync_full`

`sync_full(&banned)` must result in the kernel containing **exactly** `banned`
— no more, no less. For nftables, use `nft -f -` with `flush set` + `add
element` in one transaction. For ipset, use `ipset restore`. For CDN APIs,
use bulk diff (`current - banned` to remove, `banned - current` to add).

Never use individual `apply_ban` calls in a loop inside `sync_full`. Time
window between flush and first add is when traffic gets through.

### 3. Batching (optional but recommended)

For high-volume backends (nftables can update faster than the kernel can
commit), batch consecutive `apply_ban` calls in a configurable window:

```rust
pub struct NftablesEnforcer {
    pending: Vec<IpNet>,
    batch_interval: Duration,
    // ...
}
```

Reference: legacy `hiveguard-enforce::NftablesEnforcer` had this pattern;
port it.

## Config

| Field | Type | Purpose |
|-------|------|---------|
| `table` | string | nftables table name (default `hiveguard`) |
| `set` | string | nftables set name (default `blocklist`) |
| `batch_interval` | duration string | How long to coalesce apply_ban calls |
| `ipv6` | bool | Manage IPv6 set too |
| `api_token` | string `${env:…}` | For CDN backends |
| `account_id` | string | For Cloudflare |

## Metrics

```
hiveguard_plugin_enforcer_<name>_apply_total
hiveguard_plugin_enforcer_<name>_remove_total
hiveguard_plugin_enforcer_<name>_apply_errors_total
hiveguard_plugin_enforcer_<name>_sync_duration_seconds (histogram)
hiveguard_plugin_enforcer_<name>_drift_count        # diff vs canonical
```

## Common pitfalls

- **Calling out to a shell** with user-controlled input — never format
  `IpNet`s into shell command lines. Use library APIs (`nftables-json`,
  `mnl` bindings) or pass through stdin to `nft -f -`.
- **Not handling rotation** — when the firewall is reloaded externally
  (e.g. another tool flushes the table), your in-memory state diverges.
  Use `get_current_bans()` periodically (host does this) and `sync_full`
  to reconcile.
- **Privilege errors** — nftables needs `CAP_NET_ADMIN`. Detect missing
  capability in `setup()` and return `PluginError::Init` with a clear
  message — don't crash later on the first `apply_ban`.
- **IPv6 ignored** — if your config has `ipv6: true`, you need a separate
  set (`hiveguard6`). Test both.

## observe-only (compliance / dry-run)

`plugins/enforcer-observe` doesn't touch the firewall — it just logs and
exposes the would-be bans for inspection. Useful for:

- Testing detector tuning before going live.
- Compliance modes where the firewall is managed externally.
- Air-gapped previews.

If you write a new enforcer, please also support `--dry-run` semantics where
sensible (config flag, not a separate plugin).
