# enforcer.nftables

The enforcer preserves exact logical bans, including hosts covered by a broader
CIDR. Each change atomically replaces normalized nft sets, so removing or
expiring a subnet restores any remaining host bans. The daemon's persisted ban
state is authoritative: synchronize it at startup (including an empty list) and
periodically to repair failed operations or external changes. Failed transactions
return an error and leave the previous applied cache intact.

The configured table and its `input` chain belong to HiveGuard. Setup atomically
replaces that chain's six drop rules, preserving set contents and eliminating
rules duplicated by older versions. Every nft process has a ten-second deadline.

## `prerouting_hook` (default `false`)

The `input` hook does not see traffic that is DNAT-ed to another destination,
e.g. ports published by Docker (`0.0.0.0:5023->80/tcp`): such packets go
prerouting → forward → container, so a banned source still reaches the
container. With `prerouting_hook: true` the enforcer also owns a chain
`prerouting` (`type filter hook prerouting priority -300; policy accept;`)
holding the same six drop rules on the same sets:

```yaml
plugins:
  - id: enforcer.nftables
    config:
      table: hiveguard
      set_name: hiveguard_blocklist
      prerouting_hook: true
```

Priority -300 (`raw`) runs before conntrack (-200) and before destination NAT
(-100), so banned packets are dropped before Docker can redirect them and
without creating conntrack entries. Locally generated packets never traverse
prerouting. Side effect: replies from a banned address to connections opened
by containers (forwarded traffic) are dropped as well, exactly as the `input`
chain already does for the host itself.

Both chains are created/replaced in the same atomic `nft -f -` transaction.
On startup with the key off (or absent) a leftover `prerouting` chain from an
earlier run is flushed and deleted in that same transaction. Nothing is removed
at shutdown: bans keep being enforced while the daemon restarts.

Rollback note: builds older than this key reject it (`additionalProperties:
false`). Remove `prerouting_hook` from the config before running such a binary;
`scripts/upgrade/upgrade.py rollback` refuses to proceed otherwise and its
firewall restore recreates the table without the prerouting chain.

Run kernel integration tests in a disposable user/network namespace:

```sh
unshare -Urn cargo test -p hiveguard-enforce nftables::tests::integration_ -- --ignored --test-threads=1
```

These tests require nft and user/network namespace support. Never run them in
the host network namespace: they create and delete the test `hiveguard` table.
