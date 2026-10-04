# Guarded deployment packages

These scripts stage a reviewed release for an operator to install later. Copying
a package does not install or start HiveGuard. Never include live configuration,
identity keys, database copies or private inspection reports in a public release
or Git commit.

Build the executables and optional panel:

```sh
cargo build --release --locked -p hiveguard-daemon \
  --bin hiveguard-daemon --bin hiveguard-upgrade-check
cd web-panel
npm ci
npm run build
```

## Upgrade an existing installation

A package contains `hiveguard` (the release `hiveguard-daemon` executable),
`hiveguard-upgrade-check`, `upgrade.py`, `upgrade.sh`, `simulate.py`, an optional
`web/` build, instructions, metadata, `target.json`, and `SHA256SUMS` covering
every package file except the manifest itself. Do not ship symlinks. The release
scripts require Python 3.10+, systemd, nftables and root network namespaces.

Create `target.json` from a read-only inspection of the actual host. It requires
exactly these fields; placeholder values below are deliberately not deployable:

```json
{
  "hostname": "reviewed-short-hostname",
  "machine_id_sha256": "SHA256_OF_EXACT_ETC_MACHINE_ID_BYTES",
  "old_binary_sha256": "SHA256_OF_REVIEWED_INSTALLED_EXECUTABLE",
  "data_dir": "/var/lib/hiveguard",
  "config_path": "/etc/hiveguard/config.yaml",
  "binary_path": "/usr/local/bin/hiveguard",
  "control_socket": "/run/hiveguard/hiveguard.sock",
  "service_user": "hiveguard",
  "service_group": "hiveguard",
  "exec_start": "/usr/local/bin/hiveguard -c /etc/hiveguard/config.yaml"
}
```

The profile binds every action, including rollback, to both the hostname and the
hash of `/etc/machine-id`. It does not contain credentials. These scripts target
the `hiveguard.service` unit and exclusive `inet hiveguard` table with the
`hiveguard_blocklist` set family. Other layouts require review and adaptation;
changing the profile alone does not make an arbitrary installation supported.

The operator runs, from an SSH shell on the intended host:

```sh
sha256sum -c SHA256SUMS &&
sudo ./upgrade.sh check "${SSH_CONNECTION%% *}" &&
sudo ./upgrade.sh install "${SSH_CONNECTION%% *}"
```

`check` validates the source address whitelist, configuration and database, then
exercises the new daemon on a copy in an isolated network namespace. It refuses
foreign firewall objects, active whitelist conflicts and kernel-only bans. It
does not stop or reconfigure the production daemon. A live copy is only an early
check: installation subsequently validates a fresh consistent copy after stopping
the old process and compares it with the old process's active bans.

`install` runs independently of the SSH session under systemd. It arms a separate
five-minute recovery timer **before** the first stop, backs up the full data
directory, configuration and executable, and replaces the executable atomically.
The configuration is not edited. Existing firewall rules remain active while the
daemon is stopped. CPU and memory limits apply to HiveGuard; other services and
firewall tables are not replaced. A successful installation includes at least
75 seconds of observation, source-start checks, a stable PID, complete active-ban
coverage and a final persistence check. Natural ban expiration remains enabled.

The logs print the exact backup directory. Manual rollback:

```sh
sudo ./upgrade.sh rollback /var/backups/hiveguard/EXACT_BACKUP_FROM_LOG
```

Rollback exports the newest valid state to V3 before restoring the old binary,
preserving bans created after the upgrade. If that state is corrupt or has lost
pre-upgrade bans, it falls back to the validated pre-upgrade backup and preserves
the later raw files for recovery. New bans may require manual recovery in that
failure case. V4 revocations are retained in a sidecar; older binaries cannot
enforce their semantics. Never downgrade by replacing only the executable.

The guardian cannot recover a failed kernel, disk or systemd. Test representative
traffic and observe the first upgraded host before rolling out sequentially.

## First installation

`fresh_install.py` and `fresh-install.sh` are a separate path for a host without an
existing HiveGuard installation. Their host-bound profile uses
`mode: "fresh-observe"`. They refuse existing HiveGuard service, account or data
paths. The initial configuration uses `enforcer.observe`, disables gossip and
binds the authenticated panel to loopback. It does **not** apply firewall bans.
Enabling enforcement or cluster membership is a separate reviewed change after
observing local detection. Consult the package's host-specific instructions.

## Tests

```sh
cd scripts/upgrade
PYTHONDONTWRITEBYTECODE=1 HIVEGUARD_TEST_NETNS=1 \
HIVEGUARD_TEST_FRESH_BINARY=../../target/release/hiveguard-daemon \
HIVEGUARD_TEST_FRESH_CHECKER=../../target/release/hiveguard-upgrade-check \
python3 -m unittest discover -v
```

Kernel tests require unprivileged user/network namespaces on the test machine;
all firewall mutations are confined to a verified separate network namespace.
Never run a simulation directly in the host network namespace.
