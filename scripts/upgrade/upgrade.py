#!/usr/bin/env python3
"""Guarded, host-specific HiveGuard upgrade. Invoked from a root-owned package.

check: read production, test a copy in a separate network namespace.
install: consistent backup, strict validation, atomic binary replacement,
         independent rollback timer, 75 seconds of verification.
rollback: preserve current state, convert it to V3, restore the old executable.
No command flushes the host ruleset or edits the HiveGuard configuration.
"""
import argparse
import datetime as dt
import fcntl
import hashlib
import ipaddress
import json
import os
import re
from pathlib import Path
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time

RELEASE = "20261004-audit"
UNIT = "hiveguard-upgrade-20261004"
DATA = Path("/var/lib/hiveguard")
CONFIG = Path("/etc/hiveguard/config.yaml")
BINARY = Path("/usr/local/bin/hiveguard")
CONTROL = "/run/hiveguard/hiveguard.sock"
DROPIN = Path("/etc/systemd/system/hiveguard.service.d/90-upgrade-resources.conf")
BACKUPS = Path("/var/backups/hiveguard")
PACKAGE = Path(__file__).resolve().parent
OLD_SHA = "112dbb2b7e34ab7880c0b846c39155dd7fc65a5ce4ed400d9efda41383d860a4"
# Defaults remain available for offline helper tests. Every actual invocation
# replaces these values from its required, checksummed package target.json.
HOSTNAME = "node-a"
SERVICE_USER = "hiveguard"
SERVICE_GROUP = "hiveguard"
EXEC_START = "/usr/local/bin/hiveguard -c /etc/hiveguard/config.yaml"
TABLE = "hiveguard"
BASE_SET = "hiveguard_blocklist"
SETS = {BASE_SET, BASE_SET + "_v6", BASE_SET + "_sync", BASE_SET + "_v6_sync",
        BASE_SET + "_sync_next", BASE_SET + "_v6_sync_next"}


def load_target_profile():
    """Load and bind a package to one host, before any action or service call.

    Machine identity is SHA-256 of the exact bytes in /etc/machine-id (as with
    sha256sum). hostname is the short hostname. Profiles contain no credentials.
    This is intentionally called only by main(), never at module import time.
    """
    global HOSTNAME, OLD_SHA, DATA, CONFIG, BINARY, CONTROL
    global SERVICE_USER, SERVICE_GROUP, EXEC_START
    try:
        profile = json.loads((PACKAGE / "target.json").read_text())
    except (OSError, ValueError) as error:
        raise RuntimeError("Required package target.json is missing or invalid") from error
    required = {
        "hostname", "machine_id_sha256", "old_binary_sha256", "data_dir",
        "config_path", "binary_path", "control_socket", "service_user",
        "service_group", "exec_start",
    }
    if not isinstance(profile, dict) or set(profile) != required:
        raise RuntimeError("target.json must contain exactly the required host-profile fields")
    if any(not isinstance(value, str) or not value for value in profile.values()):
        raise RuntimeError("target.json fields must be nonempty strings")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{0,62}", profile["hostname"]):
        raise RuntimeError("target.json hostname must be a short hostname")
    for key in ("machine_id_sha256", "old_binary_sha256"):
        if not re.fullmatch(r"[0-9a-f]{64}", profile[key]):
            raise RuntimeError(f"target.json {key} must be a lowercase SHA-256 digest")
    for key in ("data_dir", "config_path", "binary_path", "control_socket"):
        raw = profile[key]
        path = Path(raw)
        if (not re.fullmatch(r"/[A-Za-z0-9_./-]+", raw) or raw != str(path)
                or ".." in path.parts or path == Path("/")):
            raise RuntimeError(f"target.json {key} must be a canonical absolute path")
    data = Path(profile["data_dir"])
    if data == BACKUPS or data in BACKUPS.parents or BACKUPS in data.parents:
        raise RuntimeError("Profile data directory must not overlap the backup directory")
    if len(os.fsencode(profile["control_socket"])) >= 108:
        raise RuntimeError("Profile control socket path is too long")
    for key in ("service_user", "service_group"):
        if not re.fullmatch(r"[a-z_][a-z0-9_-]*\$?", profile[key]):
            raise RuntimeError(f"target.json {key} is not a supported account name")
    expected_argv = f"{profile['binary_path']} -c {profile['config_path']}"
    if profile["exec_start"] != expected_argv:
        raise RuntimeError("Profile exec_start must run binary_path with -c config_path")
    if socket.gethostname().split(".")[0] != profile["hostname"]:
        raise RuntimeError(f"Package targets hostname {profile['hostname']}; this is a different host")
    if sha(Path("/etc/machine-id")) != profile["machine_id_sha256"]:
        raise RuntimeError("Package machine-id does not match this server")
    HOSTNAME = profile["hostname"]
    OLD_SHA = profile["old_binary_sha256"]
    DATA, CONFIG, BINARY = map(Path, (profile["data_dir"], profile["config_path"], profile["binary_path"]))
    CONTROL = profile["control_socket"]
    SERVICE_USER, SERVICE_GROUP = profile["service_user"], profile["service_group"]
    EXEC_START = expected_argv
    return profile


def run(argv, timeout=30, input=None):
    p = subprocess.run([str(x) for x in argv], input=input, text=True,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    if p.returncode:
        raise RuntimeError(f"{argv[0]} failed ({p.returncode}): {p.stderr[-1800:]}")
    return p.stdout


def save_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")
    with path.open("rb") as file:
        os.fsync(file.fileno())


def lock_path():
    # /run/lock may be world-writable. Keep the lock inside a root-only
    # directory, and never truncate an existing file while acquiring it.
    directory = Path('/run/hiveguard-upgrade-lock')
    directory.mkdir(mode=0o700, exist_ok=True)
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
        raise RuntimeError('Unsafe deployment lock directory')
    path = directory / 'lock'
    if path.is_symlink():
        raise RuntimeError('Unexpected symlink in deployment lock directory')
    return path


def sha(path):
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def now():
    return dt.datetime.now(dt.timezone.utc)


def expiry(record):
    text = record.get("expires_at")
    return dt.datetime.max.replace(tzinfo=dt.timezone.utc) if text is None else dt.datetime.fromisoformat(text.replace("Z", "+00:00"))


def from_peer(record):
    """Ban relayed by a cluster peer, in any of the report/socket/API shapes."""
    source = record.get("source")
    if isinstance(source, dict):
        return "ClusterPeer" in source
    return isinstance(source, str) and source.startswith(("ClusterPeer(", "peer:"))


def assert_preserved(before, after, at=None):
    """Require exact subjects and no shortened lifetime for every still-live ban.

    Exception: a ban relayed by a peer may be shortened while it stays active.
    Older daemons stamped relayed bans with their own receive time and default
    duration; the new daemon adopts the originating node's real expiry when
    the peer re-announces it, which is a correction, not a loss.
    """
    at = at or now()
    by_subject = {r["subject"]: r for r in after}

    def lost(r):
        if r["subject"] not in by_subject:
            return True
        kept = expiry(by_subject[r["subject"]])
        if kept >= expiry(r):
            return False
        return not (from_peer(r) and kept > at)

    missing = [r["subject"] for r in before if expiry(r) > at and lost(r)]
    if missing:
        raise RuntimeError(f"{len(missing)} active bans disappeared or lost lifetime; first: {missing[:5]}")


def element_nets(element):
    if isinstance(element, str):
        return [ipaddress.ip_network(element, strict=False)]
    if isinstance(element, dict):
        if "elem" in element:
            return element_nets(element["elem"]["val"])
        if "prefix" in element:
            p = element["prefix"]
            return [ipaddress.ip_network(f"{p['addr']}/{p['len']}", strict=False)]
        if "range" in element:
            a, b = map(ipaddress.ip_address, element["range"])
            return list(ipaddress.summarize_address_range(a, b))
    raise RuntimeError("Unrecognized nft element; refusing to assume it is safe")


def collapsed(nets):
    return [n for version in (4, 6) for n in ipaddress.collapse_addresses(
        [n for n in nets if n.version == version])]


def covered(net, pool):
    return any(net.version == sup.version and net.subnet_of(sup) for sup in pool)


def inspect_nft(document, exactly_six=False, allow_incomplete=False):
    """Only the known exclusive HiveGuard table/chain/set layout may be replaced."""
    seen_sets, seen_chains, rules, nets = set(), [], [], []
    for item in document["nftables"]:
        if "metainfo" in item:
            continue
        kind, obj = next(iter(item.items()))
        if obj.get("family") != "inet" or obj.get("table", obj.get("name")) != TABLE:
            raise RuntimeError("Unexpected nft table identity")
        if kind == "table":
            continue
        if kind == "chain":
            if (obj.get("name"), obj.get("type"), obj.get("hook"), obj.get("prio"), obj.get("policy")) != (
                    "input", "filter", "input", -10, "accept"):
                raise RuntimeError("Unexpected chain in HiveGuard table; automatic replacement refused")
            seen_chains.append(obj["name"])
        elif kind == "set":
            name = obj["name"]
            family = "ipv6_addr" if "_v6" in name else "ipv4_addr"
            if name not in SETS or obj.get("type") != family or set(obj.get("flags", [])) != {"interval"}:
                raise RuntimeError("Unexpected set layout in HiveGuard table")
            seen_sets.add(name)
            for element in obj.get("elem", []):
                nets.extend(element_nets(element))
        elif kind == "rule":
            expr = obj.get("expr", [])
            if obj.get("chain") != "input" or len(expr) != 2 or expr[1] != {"drop": None}:
                raise RuntimeError("Foreign rule in managed chain; refusing to erase it")
            match = expr[0].get("match", {})
            right = match.get("right", "")
            family = "ip6" if "_v6" in str(right) else "ip"
            if (match.get("op") not in ("==", "in") or right not in {"@" + s for s in SETS}
                    or match.get("left") != {"payload": {"protocol": family, "field": "saddr"}}):
                raise RuntimeError("Foreign match in managed chain; automatic replacement refused")
            rules.append(right[1:])
        else:
            raise RuntimeError(f"Unrecognized managed table object: {kind}")
    if not allow_incomplete and (seen_sets != SETS or seen_chains != ["input"] or set(rules) != SETS):
        raise RuntimeError("Incomplete HiveGuard table; manual review required")
    if exactly_six and len(rules) != 6:
        raise RuntimeError("Expected exactly six drop rules after upgrade")
    return collapsed(nets)


def nft_document():
    return json.loads(run(["nft", "-j", "list", "table", "inet", TABLE]))


def assert_coverage(records, pool):
    missing = [r["subject"] for r in records if expiry(r) > now()
               and not covered(ipaddress.ip_network(r["subject"], strict=False), pool)]
    if missing:
        raise RuntimeError(f"Firewall misses {len(missing)} active bans: {missing[:5]}")


def check_live_coverage(records, exactly_six=False):
    # State insertion precedes the enforcer's asynchronous queue. Retry a fixed
    # view briefly rather than confusing an in-flight ban with lost enforcement.
    for attempt in range(6):
        pool = inspect_nft(nft_document(), exactly_six=exactly_six)
        try:
            assert_coverage(records, pool)
            return
        except RuntimeError:
            if attempt == 5:
                raise
            time.sleep(1)


def assert_no_orphans(report, pool):
    stored = collapsed([ipaddress.ip_network(r["subject"], strict=False) for r in report["bans"]])
    if any(not covered(net, stored) for net in pool):
        raise RuntimeError("Kernel-only ban found; refusing to discard it during full sync")


def firewall_restore(records, extra_pool, table_exists=True):
    """Build one atomic transaction with canonical, non-overlapping intervals."""
    nets = collapsed(extra_pool + [ipaddress.ip_network(r["subject"], strict=False)
                                  for r in records if expiry(r) > now()])
    lines = ["delete table inet hiveguard"] if table_exists else []
    lines.append("table inet hiveguard {")
    for name in sorted(SETS):
        version = 6 if "_v6" in name else 4
        lines.append(f"set {name} {{ type ipv{version}_addr; flags interval;")
        if name in (BASE_SET, BASE_SET + "_v6"):
            members = [str(n) for n in nets if n.version == version]
            if members:
                lines.append("elements = { " + ", ".join(members) + " };")
        lines.append("}")
    lines.append("chain input { type filter hook input priority -10; policy accept;")
    for name in sorted(SETS):
        lines.append(f"{'ip6' if '_v6' in name else 'ip'} saddr @{name} drop")
    return "\n".join(lines + ["}", "}", ""])


def socket_bans():
    with socket.socket(socket.AF_UNIX) as sock:
        sock.settimeout(8)
        sock.connect(CONTROL)
        sock.sendall(b'{"ListBans":{"limit":null}}\n')
        with sock.makefile("rb") as stream:
            reply = stream.readline(32 * 1024 * 1024)
        return json.loads(reply)["BanList"]["bans"]


def stable_copy(destination):
    destination.mkdir(mode=0o700)
    for _ in range(20):
        first = {name: (DATA / name).read_bytes() for name in ("snapshot.bin", "wal.bin")}
        second = {name: (DATA / name).read_bytes() for name in first}
        if first == second:
            for name, value in first.items():
                (destination / name).write_bytes(value)
            return
        time.sleep(.05)
    raise RuntimeError("Database kept changing during preflight copy; retry check")


def verify(data, output, ssh_ip=None, config=True, legacy=None):
    args = [PACKAGE / "hiveguard-upgrade-check", "--data-dir", data, "--output", output]
    if config:
        args += ["--config", CONFIG]
    if ssh_ip:
        args += ["--ssh-ip", ssh_ip]
    if legacy:
        args += ["--legacy-output-dir", legacy]
    try:
        run(args, timeout=45)
    except Exception as error:
        raise RuntimeError(f"Strict database/config validation failed; details: {output}") from error
    report = json.loads(output.read_text())
    if not report["ok"] or not report["roundtrip_exact"] or not report["source_files_unchanged"]:
        raise RuntimeError("Strict state roundtrip failed")
    if config:
        cfg = report["config"]
        if Path(cfg["configured_data_dir"]).resolve() != DATA or cfg["nftables"] != [{"table": TABLE, "set_name": BASE_SET}]:
            raise RuntimeError("Configuration paths/firewall differ from the reviewed target")
        if any(p.startswith("enforcer.") and p != "enforcer.nftables" for p in cfg["plugins"]):
            raise RuntimeError("Multiple/different enforcers require manual review")
        if not report.get("ssh_whitelisted"):
            raise RuntimeError("Current SSH client is not whitelisted; deployment aborted before changes")
    return report


def copy_preserving(source, destination):
    run(["cp", "-a", "--", source, destination], timeout=60)


def target_checks(require_old=True):
    if os.geteuid() != 0 or socket.gethostname().split(".")[0] != HOSTNAME:
        raise RuntimeError(f"This package requires root on {HOSTNAME} only")
    if DATA.is_symlink() or DATA.is_mount() or CONFIG.is_symlink() or BINARY.is_symlink():
        raise RuntimeError("Unexpected symlink/mount in production paths")
    if require_old and sha(BINARY) != OLD_SHA:
        raise RuntimeError("Installed binary differs from the reviewed old release")
    if shutil.disk_usage(DATA).free < 2 * 1024**3:
        raise RuntimeError("Less than 2 GiB free disk")
    props = run(["systemctl", "show", "hiveguard", "-p", "User", "-p", "Group", "-p", "ExecStart", "-p", "ExecStopPost", "-p", "ActiveState"])
    if f"User={SERVICE_USER}\n" not in props or f"Group={SERVICE_GROUP}\n" not in props or "ActiveState=active" not in props:
        raise RuntimeError("Service identity/state differs from preflight")
    actual_argv = [value.strip() for value in re.findall(r"argv\[\]=([^;]*)(?:;|$)", props)]
    if actual_argv != [EXEC_START]:
        raise RuntimeError("Service ExecStart differs from reviewed deployment")
    if any(line.startswith("ExecStopPost=") and line != "ExecStopPost=" for line in props.splitlines()):
        raise RuntimeError("ExecStopPost may modify firewall; manual review required")


def preflight(work, ssh_ip):
    target_checks()
    work.mkdir(parents=True, mode=0o700)
    stable_copy(work / "state-copy")
    report = verify(work / "state-copy", work / "report.json", ssh_ip)
    document = nft_document()
    pool = inspect_nft(document)
    assert_no_orphans(report, pool)
    missing_before = sum(expiry(record) > now() and not covered(
        ipaddress.ip_network(record['subject'], strict=False), pool) for record in report['bans'])
    if missing_before:
        print(f"Existing firewall drift: {missing_before} active bans lack coverage; "
              "isolated simulation must restore complete coverage before installation is allowed.", flush=True)
    save_json(work / "nft.json", document)
    (work / "nft.txt").write_text(run(["nft", "list", "table", "inet", TABLE]))
    host_ns = os.readlink("/proc/self/ns/net")
    args = ["unshare", "--net", "/usr/bin/python3", PACKAGE / "simulate.py",
            "--binary", PACKAGE / "hiveguard", "--checker", PACKAGE / "hiveguard-upgrade-check",
            "--data-dir", work / "state-copy", "--report", work / "report.json",
            "--output", work / "simulation", "--host-netns", host_ns,
            "--restore-nft", work / "nft.txt"]
    result = run(args, timeout=75)
    (work / "simulation-result.txt").write_text(result)
    print(f"Preflight OK: {report['total_count']} records; {report['active_count']} active. Source unchanged.", flush=True)
    return report


def replace_file(source, destination, mode=0o755, owner=(0, 0)):
    fd, name = tempfile.mkstemp(prefix=destination.name + ".upgrade-", dir=destination.parent)
    os.close(fd)
    temporary = Path(name)
    try:
        shutil.copyfile(source, temporary)
        os.chmod(temporary, mode)
        os.chown(temporary, *owner)
        with temporary.open("rb") as file:
            os.fsync(file.fileno())
        os.replace(temporary, destination)
        fd = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        temporary.unlink(missing_ok=True)


def stop_service():
    run(["systemctl", "stop", "hiveguard"], timeout=100)
    pid = run(["systemctl", "show", "hiveguard", "-p", "MainPID", "--value"]).strip()
    if pid != "0":
        raise RuntimeError("Old process is still alive; no data/binary replacement performed")


def rollback(backup, automatic=False):
    if (backup / "rolled-back").exists() or (automatic and (backup / "committed").exists()):
        return
    if not (backup / "rollback-ready").exists():
        # No production file can be replaced before this durable marker.
        if sha(BINARY) != OLD_SHA:
            raise RuntimeError("No complete backup and unexpected binary; manual recovery needed")
        run(["systemctl", "start", "hiveguard"], timeout=100)
        print("Old service resumed; upgrade stopped before any replacement.", flush=True)
        return
    stop_service()
    saved = backup / ("post-upgrade-state-" + str(time.time_ns()))
    copy_preserving(DATA, saved)
    baseline = json.loads((backup / "baseline.json").read_text())
    legacy = backup / ("legacy-" + str(time.time_ns()))
    fallback = False
    try:
        current = verify(saved, backup / ("rollback-report-" + str(time.time_ns()) + ".json"), config=False, legacy=legacy)
        assert_preserved(baseline["bans"], current["bans"])
    except Exception as error:
        # A migration failure must not prevent recovery. Keep the damaged files
        # for diagnosis, then use the consistent, already-validated pre-upgrade DB.
        (backup / "rollback-fallback.txt").write_text(str(error) + "\n")
        legacy = backup / ("legacy-baseline-" + str(time.time_ns()))
        current = verify(backup / "data.before", backup / ("fallback-report-" + str(time.time_ns()) + ".json"), config=False, legacy=legacy)
        assert_preserved(baseline["bans"], current["bans"])
        fallback = True
    tables = json.loads(run(["nft", "-j", "list", "tables"]))
    table_exists = any(item.get("table", {}).get("family") == "inet" and
                       item.get("table", {}).get("name") == TABLE for item in tables["nftables"])
    # Missing managed objects may be the reason for recovery. Foreign objects
    # still abort; incomplete own objects are repaired by the atomic transaction.
    extra_pool = inspect_nft(nft_document(), allow_incomplete=True) if table_exists else []
    uid, gid = DATA.stat().st_uid, DATA.stat().st_gid
    replace_file(legacy / "snapshot.bin", DATA / "snapshot.bin", 0o640, (uid, gid))
    replace_file(legacy / "wal.bin", DATA / "wal.bin", 0o640, (uid, gid))
    replace_file(backup / "hiveguard.old", BINARY)
    if (backup / "resource-dropin.old").exists():
        copy_preserving(backup / "resource-dropin.old", DROPIN)
    else:
        DROPIN.unlink(missing_ok=True)
    old_index = backup / "data.before" / "ui-web" / "dist" / "index.html"
    if old_index.exists():
        replace_file(old_index, DATA / "ui-web" / "dist" / "index.html", 0o644, (uid, gid))
    run(["systemctl", "daemon-reload"])
    # Atomic replacement of this one table only; never flush another firewall.
    run(["nft", "-f", "-"], input=firewall_restore(current["bans"], extra_pool, table_exists))
    run(["systemctl", "start", "hiveguard"], timeout=100)
    assert_preserved(current["bans"], socket_bans())
    check_live_coverage(current["bans"])
    (backup / "rolled-back").write_text("Old executable restored with current bans exported to V3.\n")
    print(f"ROLLBACK OK; preserved {current['total_count']} records; baseline fallback={fallback}. Backup: {backup}", flush=True)


def install(ssh_ip):
    stamp = now().strftime("%Y%m%dT%H%M%SZ")
    backup = BACKUPS / (stamp + "-" + RELEASE)
    baseline = preflight(backup / "preflight", ssh_ip)
    live_before = socket_bans()
    # Armed before the first stop. An early failure resumes the untouched old
    # service; after rollback-ready, the same guardian restores the full backup.
    watchdog = "hiveguard-upgrade-rollback-" + stamp.lower()
    run(["systemd-run", "--quiet", "--unit", watchdog, "--on-active=300s",
         "/usr/bin/python3", "-I", PACKAGE / "upgrade.py", "rollback", "--backup", backup, "--automatic"])
    (backup / "watchdog-unit").write_text(watchdog)
    changed = False
    try:
        stop_service()
        copy_preserving(DATA, backup / "data.before")
        copy_preserving(CONFIG, backup / "config.yaml.before")
        copy_preserving(BINARY, backup / "hiveguard.old")
        (backup / "unit.before").write_text(run(["systemctl", "cat", "hiveguard"]))
        (backup / "nft.txt").write_text(run(["nft", "list", "table", "inet", TABLE]))
        save_json(backup / "nft.json", nft_document())
        baseline = verify(backup / "data.before", backup / "baseline.json", ssh_ip)
        assert_preserved(live_before, baseline["bans"])
        assert_no_orphans(baseline, inspect_nft(json.loads((backup / "nft.json").read_text())))
        if baseline["config"]["sha256"] != sha(CONFIG):
            raise RuntimeError("Configuration changed during preflight")
        if DROPIN.exists():
            copy_preserving(DROPIN, backup / "resource-dropin.old")
        save_json(backup / "rollback-ready", {"ready": True})
        changed = True
        replace_file(PACKAGE / "hiveguard", BINARY)
        DROPIN.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        DROPIN.write_text("[Service]\nCPUQuota=200%\nMemoryHigh=768M\nMemoryMax=1G\nTasksMax=256\n")
        os.chmod(DROPIN, 0o644)
        run(["systemctl", "daemon-reload"])
        run(["systemctl", "start", "hiveguard"], timeout=75)
        pid = run(["systemctl", "show", "hiveguard", "-p", "MainPID", "--value"]).strip()
        for delay in (0, 15, 15, 15, 15, 15):
            time.sleep(delay)
            if run(["systemctl", "is-active", "hiveguard"]).strip() != "active":
                raise RuntimeError("Service became inactive")
            if run(["systemctl", "show", "hiveguard", "-p", "MainPID", "--value"]).strip() != pid:
                raise RuntimeError("Service restarted during observation")
            current = socket_bans()
            assert_preserved(baseline["bans"], current)
            check_live_coverage(current, exactly_six=True)
        journal = run(["journalctl", "-u", "hiveguard", "_PID=" + pid, "--no-pager", "-o", "cat"])
        (backup / "startup.log").write_text(journal)
        for marker in ("log source exited; restarting", "Firewall reconciliation failed", "Failed to apply ban", "panicked"):
            if marker in journal:
                raise RuntimeError("Startup/ingest/enforcement failure in new daemon logs")
        source_count = sum(p.startswith("source.") for p in baseline["config"]["plugins"])
        if journal.count("log source starting") < source_count:
            raise RuntimeError("Not all configured sources started")
        if sha(CONFIG) != baseline["config"]["sha256"]:
            raise RuntimeError("Configuration unexpectedly changed")
        # Hashed assets first, entrypoint last; existing clients keep old assets.
        web = DATA / "ui-web" / "dist"
        if web.is_dir() and (PACKAGE / "web").is_dir():
            for src in (PACKAGE / "web").rglob("*"):
                if src.is_file() and src.name != "index.html":
                    dst = web / src.relative_to(PACKAGE / "web")
                    dst.parent.mkdir(parents=True, exist_ok=True)
                    os.chmod(dst.parent, 0o755)
                    if not dst.exists():
                        shutil.copy2(src, dst)
                        os.chmod(dst, 0o644)
            replace_file(PACKAGE / "web" / "index.html", web / "index.html", 0o644, (DATA.stat().st_uid, DATA.stat().st_gid))
        save_json(backup / "after.json", {"bans": current, "pid": pid, "binary_sha256": sha(BINARY)})
        # Also confirm that newly persisted records remain readable, independently
        # of the running daemon's in-memory view.
        stable_copy(backup / "state.after")
        persisted = verify(backup / "state.after", backup / "persisted-after.json", ssh_ip)
        assert_preserved(baseline["bans"], persisted["bans"])
        assert_preserved(current, persisted["bans"])
        save_json(backup / "committed", {"verified": True})
        # A timer cancellation failure cannot invalidate a committed upgrade;
        # its callback checks the durable marker before touching the service.
        try:
            subprocess.run(["systemctl", "stop", watchdog + ".timer"], timeout=30, check=False)
        except subprocess.TimeoutExpired:
            pass
        print(f"UPGRADE OK: {len(current)} records in running daemon. Backup: {backup}", flush=True)
    except BaseException:
        print(f"UPGRADE FAILED; backup: {backup}", flush=True)
        if changed:
            # Same process owns the unit: do not ask systemd to stop ourselves.
            rollback(backup)
        else:
            run(["systemctl", "start", "hiveguard"], timeout=100)
        raise


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["check", "install", "rollback"])
    parser.add_argument("--ssh-ip")
    parser.add_argument("--backup", type=Path)
    parser.add_argument("--automatic", action="store_true")
    args = parser.parse_args()
    os.umask(0o077)
    if os.geteuid() != 0:
        raise RuntimeError("Run through sudo upgrade.sh")
    load_target_profile()
    if args.action == "rollback":
        if args.backup is None or args.backup.resolve().parent != BACKUPS:
            raise RuntimeError("An exact backup directory is required")
        if args.automatic:
            if (args.backup / "committed").exists() or (args.backup / "rolled-back").exists():
                return
            # Stop the owning unit before waiting for its lock. This callback
            # itself runs in a separate, independently scheduled systemd unit.
            # --collect removes an exited transient unit, including after a
            # crash. "Unit not loaded" therefore must not defeat recovery.
            subprocess.run(["systemctl", "stop", UNIT + ".service"],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=100, check=False)
            state = subprocess.run(["systemctl", "is-active", UNIT + ".service"],
                                   capture_output=True, text=True, timeout=30).stdout.strip()
            if state in {"active", "activating", "deactivating", "reloading"}:
                raise RuntimeError("Installer still running; cannot race database recovery")
        with open(lock_path(), "a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            rollback(args.backup, args.automatic)
        return
    ipaddress.ip_address(args.ssh_ip)
    with open(lock_path(), "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if args.action == "check":
            work = BACKUPS / ("check-" + now().strftime("%Y%m%dT%H%M%SZ"))
            preflight(work, args.ssh_ip)
        else:
            install(args.ssh_ip)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"ABORT: {error}", file=sys.stderr, flush=True)
        sys.exit(1)
