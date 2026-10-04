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

Run kernel integration tests in a disposable user/network namespace:

```sh
unshare -Urn cargo test -p hiveguard-enforce nftables::tests::integration_ -- --ignored --test-threads=1
```

These tests require nft and user/network namespace support. Never run them in
the host network namespace: they create and delete the test `hiveguard` table.
