#!/usr/bin/env python3
"""Exercise an upgrade on a cloned state and nftables in an isolated netns.

Example (capture host namespace BEFORE unshare):
  host_netns=$(readlink /proc/self/ns/net)
  unshare --user --map-root-user --net python3 simulate.py \
    --host-netns "$host_netns" --binary ./hiveguard-daemon \
    --checker ./hiveguard-upgrade-check --data-dir ./production-state \
    --report ./state-report.json --output ./simulation

No production service, configuration, or firewall is modified. The source state
must be a consistent, previously collected copy, not a live daemon's data dir.
"""

import argparse
import datetime as dt
import hashlib
import ipaddress
import json
import os
import re
from pathlib import Path
import shutil
import signal
import stat
import subprocess
import sys
import time

TABLE = "hiveguard"
BASE = "hiveguard_blocklist"
SETS = {
    **{BASE + suffix: 4 for suffix in ("", "_sync", "_sync_next")},
    **{BASE + "_v6" + suffix: 6 for suffix in ("", "_sync", "_sync_next")},
}


class CheckFailed(Exception):
    pass


def require(condition, message):
    if not condition:
        raise CheckFailed(message)


def namespace_guard(host_netns):
    current = os.readlink("/proc/self/ns/net")
    require(re.fullmatch(r"net:\[\d+\]", host_netns) is not None,
            "--host-netns must be the host network namespace readlink value")
    require(current != host_netns,
            "refusing to run in the host network namespace; invoke through unshare --net")


def tree_hashes(root):
    result = {}
    for path in sorted(root.rglob("*")):
        require(not path.is_symlink(), "source state contains a symlink")
        if path.is_dir():
            continue
        require(path.is_file(), "source state contains a non-regular file")
        digest = hashlib.sha256()
        with path.open("rb") as source:
            for block in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(block)
        result[str(path.relative_to(root))] = digest.hexdigest()
    return result


def parse_time(value):
    parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    require(parsed.tzinfo is not None, "ban expiry lacks a timezone")
    return parsed


def active(record, now):
    expiry = record.get("expires_at")
    return expiry is None or parse_time(expiry) > now


def records(report):
    require(isinstance(report.get("bans"), list), "checker report is missing bans")
    result = {}
    for record in report["bans"]:
        require(isinstance(record, dict) and "subject" in record and "expires_at" in record,
                "checker report contains an invalid ban record")
        subject = str(ipaddress.ip_network(record["subject"], strict=False))
        require(subject not in result, "checker report contains duplicate ban subjects")
        result[subject] = record
    return result


def element_interval(element, version):
    """Decode nft JSON singleton, prefix, range, and decorated element forms."""
    if isinstance(element, dict) and "elem" in element:
        wrapped = element["elem"]
        require(isinstance(wrapped, dict) and "val" in wrapped, "unknown nft element wrapper")
        return element_interval(wrapped["val"], version)
    if isinstance(element, str):
        network = ipaddress.ip_network(element, strict=False)
        require(network.version == version, "nft set contains the wrong address family")
        return int(network.network_address), int(network.broadcast_address)
    if isinstance(element, dict) and "prefix" in element:
        prefix = element["prefix"]
        return element_interval(f'{prefix["addr"]}/{prefix["len"]}', version)
    if isinstance(element, dict) and "range" in element:
        first, last = map(ipaddress.ip_address, element["range"])
        require(first.version == last.version == version and int(first) <= int(last),
                "invalid nft address range")
        return int(first), int(last)
    raise CheckFailed("unsupported nft set element representation")


def merge_intervals(intervals):
    merged = []
    for first, last in sorted(intervals):
        if merged and first <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(last, merged[-1][1]))
        else:
            merged.append((first, last))
    return merged


def nft_state(document):
    intervals = {4: [], 6: []}
    seen_sets = set()
    rules = []
    input_chain = None
    for item in document.get("nftables", []):
        value = item.get("set")
        if value and value.get("family") == "inet" and value.get("table") == TABLE:
            name = value.get("name")
            if name in SETS:
                require(name not in seen_sets, "duplicate nft managed set")
                seen_sets.add(name)
                version = SETS[name]
                require(value.get("type") == f"ipv{version}_addr", "unexpected nft managed set type")
                intervals[version].extend(element_interval(e, version) for e in value.get("elem", []))
        chain = item.get("chain")
        if chain and chain.get("family") == "inet" and chain.get("table") == TABLE and chain.get("name") == "input":
            input_chain = chain
        rule = item.get("rule")
        if rule and rule.get("family") == "inet" and rule.get("table") == TABLE and rule.get("chain") == "input":
            rules.append(rule)
    require(seen_sets == set(SETS), "nft is missing one or more managed sets")
    require(input_chain and input_chain.get("hook") == "input" and input_chain.get("type") == "filter"
            and input_chain.get("prio") == -10 and input_chain.get("policy") == "accept",
            "nft managed chain has unexpected hook, priority, type, or policy")
    require(len(rules) == 6, "nft managed input chain must contain exactly six drop rules")
    matched_sets = []
    for rule in rules:
        expressions = rule.get("expr", [])
        matches = [e["match"] for e in expressions if "match" in e]
        drops = [e for e in expressions if "drop" in e]
        require(len(expressions) == 2 and len(matches) == 1 and len(drops) == 1,
                "unexpected expression in nft managed drop rule")
        match = matches[0]
        right = match.get("right")
        require(isinstance(right, str) and right.startswith("@") and right[1:] in SETS,
                "nft drop rule references an unexpected set")
        name = right[1:]
        protocol = "ip" if SETS[name] == 4 else "ip6"
        require(match.get("op") in ("==", "in")
                and match.get("left") == {"payload": {"protocol": protocol, "field": "saddr"}},
                "nft drop rule does not match source addresses")
        matched_sets.append(name)
    require(set(matched_sets) == set(SETS), "nft drop rules are duplicated or missing")
    return {version: merge_intervals(values) for version, values in intervals.items()}


def missing_coverage(bans, coverage, now):
    missing = 0
    for subject, record in bans.items():
        if not active(record, now):
            continue
        network = ipaddress.ip_network(subject)
        low, high = int(network.network_address), int(network.broadcast_address)
        if not any(first <= low and last >= high for first, last in coverage[network.version]):
            missing += 1
    return missing


def compare_roundtrip(expected, actual, now):
    missing = changed = 0
    for subject, record in expected.items():
        if not active(record, now):
            continue
        if subject not in actual:
            missing += 1
        elif actual[subject] != record:
            changed += 1
    extra = sum(active(record, now) for subject, record in actual.items() if subject not in expected)
    require(missing == changed == extra == 0,
            f"state roundtrip mismatch: missing_active={missing}, changed_active={changed}, unexpected_active={extra}")


def execute(args):
    started = time.monotonic()
    namespace_guard(args.host_netns)  # Must run before mkdir/copy/nft/daemon.
    source = Path(args.data_dir).resolve(strict=True)
    require(source.is_dir(), "--data-dir must be a directory")
    output_arg = Path(args.output)
    require(not output_arg.is_symlink(), "--output must not be a symlink")
    output = output_arg.resolve()
    require(source != output and source not in output.parents and output not in source.parents,
            "source and output directories must not overlap")
    require(not output.exists() or (output.is_dir() and not any(output.iterdir())),
            "--output must be a new or empty directory")
    binary = Path(args.binary).resolve(strict=True)
    checker = Path(args.checker).resolve(strict=True)
    report = json.loads(Path(args.report).read_text())
    require(report.get("ok") is True, "input checker report did not pass")
    expected = records(report)
    source_before = tree_hashes(source)
    require(source_before, "source state is empty")
    output.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(output, 0o700)
    clone = output / "data"
    shutil.copytree(source, clone)
    require(tree_hashes(clone) == source_before, "state copy differs from source")
    config = {
        "node": {"name": "upgrade-test", "data_dir": str(clone), "listen_gossip": "", "seeds": []},
        "plugins": [
            {"id": "enforcer.nftables", "config": {"table": TABLE, "set_name": BASE, "batch_interval_secs": 1}},
            {"id": "scoring.default", "config": {}},
        ],
    }
    config_path = output / "config.json"
    config_path.write_text(json.dumps(config, indent=2) + "\n")
    if args.restore_nft:
        namespace_guard(args.host_netns)
        with (output / "restore-nft.log").open("w") as log:
            restored = subprocess.run(["nft", "-f", str(Path(args.restore_nft).resolve(strict=True))],
                                      stdout=log, stderr=subprocess.STDOUT, timeout=10)
        require(restored.returncode == 0, "restoring previous nft table failed; see restore-nft.log")
    env = os.environ.copy()
    for key in ("NOTIFY_SOCKET", "WATCHDOG_USEC", "WATCHDOG_PID", "LISTEN_FDS", "LISTEN_PID", "LISTEN_FDNAMES"):
        env.pop(key, None)
    env["TOKIO_WORKER_THREADS"] = "2"
    env["RUST_LOG"] = "info"
    socket = output / "control.sock"
    require(len(os.fsencode(socket)) < 108, "output path is too long for the Unix control socket")
    process = None
    coverage = None
    exit_code = None
    try:
        with (output / "daemon.log").open("w") as log:
            process = subprocess.Popen([str(binary), "--config", str(config_path), "--socket", str(socket)],
                                       stdout=log, stderr=subprocess.STDOUT, env=env, start_new_session=True)
            deadline = time.monotonic() + 30
            last_problem = "readiness socket missing"
            while time.monotonic() < deadline:
                require(process.poll() is None, "daemon exited before readiness; see daemon.log")
                if socket.exists() and stat.S_ISSOCK(socket.stat().st_mode):
                    result = subprocess.run(["nft", "-j", "list", "table", "inet", TABLE],
                                            capture_output=True, text=True, timeout=3)
                    if result.returncode == 0:
                        try:
                            document = json.loads(result.stdout)
                            coverage = nft_state(document)
                            missing = missing_coverage(expected, coverage, dt.datetime.now(dt.timezone.utc))
                            require(missing == 0, f"nft does not cover {missing} active ban records")
                            (output / "nft-running.json").write_text(json.dumps(document, indent=2) + "\n")
                            break
                        except CheckFailed as error:
                            last_problem = str(error)
                time.sleep(0.1)
            else:
                raise CheckFailed(f"daemon readiness timed out: {last_problem}")
            readiness_seconds = time.monotonic() - started
            shutdown_started = time.monotonic()
            process.send_signal(signal.SIGTERM)
            exit_code = process.wait(timeout=15)
            shutdown_seconds = time.monotonic() - shutdown_started
            require(exit_code == 0, "daemon did not shut down cleanly after SIGTERM")
            require(not Path(f"/proc/{process.pid}").exists(), "daemon process was not reaped")
        after_path = output / "state-after.json"
        with (output / "checker.log").open("w") as log:
            checked = subprocess.run([str(checker), "--data-dir", str(clone), "--output", str(after_path)],
                                     stdout=log, stderr=subprocess.STDOUT, env=env, timeout=30)
        require(checked.returncode == 0 and after_path.is_file(), "post-shutdown state checker failed; see checker.log")
        after = json.loads(after_path.read_text())
        require(after.get("ok") is True, "post-shutdown checker report did not pass")
        now = dt.datetime.now(dt.timezone.utc)
        compare_roundtrip(expected, records(after), now)
        require(tree_hashes(source) == source_before, "source state files changed during simulation")
        require((clone / "snapshot.bin").is_file(), "shutdown did not produce a snapshot")
        return {
            "ok": True, "expected_total": len(expected),
            "expected_active_at_finish": sum(active(record, now) for record in expected.values()),
            "active_after": after["active_count"], "total_after": after["total_count"],
            "covered_active": sum(active(record, now) for record in expected.values()),
            "managed_drop_rules": 6, "source_files_unchanged": True, "records_retained": True,
            "daemon_exit": exit_code, "daemon_reaped": True,
            "readiness_seconds": round(readiness_seconds, 3), "shutdown_seconds": round(shutdown_seconds, 3),
            "elapsed_seconds": round(time.monotonic() - started, 3),
        }
    finally:
        if process is not None and process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=5)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    for name in ("binary", "checker", "data-dir", "report", "output", "host-netns"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--restore-nft")
    args = parser.parse_args()
    try:
        summary = execute(args)
    except Exception as error:
        summary = {"ok": False, "error": str(error), "error_type": type(error).__name__}
    print(json.dumps(summary, sort_keys=True), flush=True)
    return 0 if summary["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
