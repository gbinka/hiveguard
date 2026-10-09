#!/usr/bin/env python3
"""Upgrade guard tests. All production paths and service operations are mocked.

Optional real nft test (always in a new user + network namespace):
  HIVEGUARD_TEST_NETNS=1 python3 -B -m unittest discover -s scripts/upgrade -p test_upgrade.py
"""
import contextlib
import copy
import datetime as dt
import io
import ipaddress
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import mock_open, patch

import upgrade


AT = dt.datetime(2026, 10, 4, 12, tzinfo=dt.timezone.utc)


def ban(subject="192.0.2.1/32", expiry="2026-10-05T00:00:00Z"):
    return {"subject": subject, "expires_at": expiry, "created_at": "2026-10-03T00:00:00Z",
            "severity": 100, "reason": "test ban", "source": "ManualAdmin"}


def nft_fixture(nets=()):
    items = [{"table": {"family": "inet", "name": "hiveguard"}},
             {"chain": {"family": "inet", "table": "hiveguard", "name": "input", "type": "filter",
                        "hook": "input", "prio": -10, "policy": "accept"}}]
    for name in sorted(upgrade.SETS):
        version = 6 if "_v6" in name else 4
        elements = [str(n) for n in nets if n.version == version] if name in (upgrade.BASE_SET, upgrade.BASE_SET + "_v6") else []
        items.append({"set": {"family": "inet", "table": "hiveguard", "name": name,
                              "type": f"ipv{version}_addr", "flags": ["interval"], "elem": elements}})
        items.append({"rule": {"family": "inet", "table": "hiveguard", "chain": "input", "expr": [
            {"match": {"op": "==", "left": {"payload": {"protocol": "ip6" if version == 6 else "ip", "field": "saddr"}},
                       "right": "@" + name}}, {"drop": None}]}})
    return {"nftables": items}


class BanPreservationTests(unittest.TestCase):
    def test_missing_live_subject_is_rejected_even_if_another_subject_covers_it(self):
        with self.assertRaisesRegex(RuntimeError, "active bans disappeared"):
            upgrade.assert_preserved([ban()], [ban("192.0.2.0/24")], AT)

    def test_shortened_lifetime_is_rejected_and_extension_is_allowed(self):
        before = [ban()]
        with self.assertRaises(RuntimeError):
            upgrade.assert_preserved(before, [ban(expiry="2026-10-04T23:59:59Z")], AT)
        upgrade.assert_preserved(before, [ban(expiry="2026-10-06T00:00:00Z")], AT)

    def test_peer_relayed_ban_may_adopt_origin_expiry_while_active(self):
        for source in ({"ClusterPeer": "bd3b"}, 'ClusterPeer("bd3b")', "peer:bd3b"):
            relayed = dict(ban(), source=source)
            shorter = dict(ban(expiry="2026-10-04T18:00:00Z"), source=source)
            upgrade.assert_preserved([relayed], [shorter], AT)
            expired = dict(ban(expiry="2026-10-04T11:00:00Z"), source=source)
            with self.assertRaises(RuntimeError):
                upgrade.assert_preserved([relayed], [expired], AT)
            with self.assertRaises(RuntimeError):
                upgrade.assert_preserved([relayed], [], AT)

    def test_local_ban_still_may_not_be_shortened(self):
        for source in ({"LocalDetector": "ssh_bruteforce"}, 'LocalDetector("ssh_bruteforce")', "ManualAdmin"):
            with self.assertRaises(RuntimeError):
                upgrade.assert_preserved([dict(ban(), source=source)],
                                         [dict(ban(expiry="2026-10-04T18:00:00Z"), source=source)], AT)

    def test_permanent_ban_must_remain_permanent(self):
        before = [ban(expiry=None)]
        with self.assertRaises(RuntimeError):
            upgrade.assert_preserved(before, [ban(expiry="2099-01-01T00:00:00Z")], AT)
        upgrade.assert_preserved(before, [ban(expiry=None)], AT)

    def test_naturally_expired_ban_may_disappear(self):
        upgrade.assert_preserved([ban(expiry="2026-10-04T11:59:59Z")], [], AT)
        upgrade.assert_preserved([ban(expiry="2026-10-04T12:00:00Z")], [], AT)


class FirewallGuardTests(unittest.TestCase):
    def test_duplicate_managed_rules_allowed_only_before_upgrade(self):
        document = nft_fixture()
        self.assertEqual(upgrade.inspect_nft(document, exactly_six=True), [])
        document["nftables"].append(copy.deepcopy(document["nftables"][-1]))
        self.assertEqual(upgrade.inspect_nft(document), [])
        with self.assertRaisesRegex(RuntimeError, "exactly six"):
            upgrade.inspect_nft(document, exactly_six=True)

    def test_foreign_rule_and_foreign_match_are_rejected(self):
        document = nft_fixture()
        document["nftables"][-1]["rule"]["expr"][1] = {"accept": None}
        with self.assertRaisesRegex(RuntimeError, "Foreign rule"):
            upgrade.inspect_nft(document)
        document = nft_fixture()
        document["nftables"][-1]["rule"]["expr"][0]["match"]["left"]["payload"]["field"] = "daddr"
        with self.assertRaisesRegex(RuntimeError, "Foreign match"):
            upgrade.inspect_nft(document)
        document = nft_fixture()
        document["nftables"].append({"chain": {"family": "inet", "table": "hiveguard", "name": "administrator_rules"}})
        with self.assertRaisesRegex(RuntimeError, "Unexpected chain"):
            upgrade.inspect_nft(document)

    def test_kernel_only_guard_checks_whole_ranges_and_both_families(self):
        report = {"bans": [ban("192.0.2.0/25"), ban("192.0.2.128/25"), ban("2001:db8::/64")]}
        upgrade.assert_no_orphans(report, [ipaddress.ip_network("192.0.2.0/24"), ipaddress.ip_network("2001:db8::1/128")])
        for orphan in ["192.0.3.1/32", "2001:db9::/64", "192.0.2.0/23"]:
            with self.subTest(orphan=orphan), self.assertRaisesRegex(RuntimeError, "Kernel-only ban"):
                upgrade.assert_no_orphans(report, [ipaddress.ip_network(orphan)])

    def test_coverage_does_not_mistake_first_address_for_whole_banned_range(self):
        with patch.object(upgrade, "now", return_value=AT):
            with self.assertRaisesRegex(RuntimeError, "Firewall misses"):
                upgrade.assert_coverage([ban("192.0.2.0/24")], [ipaddress.ip_network("192.0.2.0/25")])
            upgrade.assert_coverage([ban("192.0.2.1/32")], [ipaddress.ip_network("192.0.2.0/24")])

    def test_partial_own_table_is_allowed_only_for_rollback_but_foreign_objects_never_are(self):
        partial = {"nftables": [
            {"table": {"family": "inet", "name": "hiveguard"}},
            {"set": {"family": "inet", "table": "hiveguard", "name": upgrade.BASE_SET,
                     "type": "ipv4_addr", "flags": ["interval"], "elem": ["192.0.2.1"]}},
        ]}
        with self.assertRaisesRegex(RuntimeError, "Incomplete HiveGuard table"):
            upgrade.inspect_nft(partial)
        self.assertEqual(upgrade.inspect_nft(partial, allow_incomplete=True), [ipaddress.ip_network("192.0.2.1/32")])
        partial["nftables"].append({"chain": {"family": "inet", "table": "hiveguard", "name": "administrator_rules"}})
        with self.assertRaisesRegex(RuntimeError, "Unexpected chain"):
            upgrade.inspect_nft(partial, allow_incomplete=True)

    def test_live_coverage_retries_a_pending_ban_then_accepts_it(self):
        documents = [nft_fixture(), nft_fixture([ipaddress.ip_network("192.0.2.0/24")])]
        with patch.object(upgrade, "nft_document", side_effect=documents) as read, \
                patch.object(upgrade.time, "sleep") as sleep:
            upgrade.check_live_coverage([ban(expiry=None)], exactly_six=True)
        self.assertEqual(read.call_count, 2)
        sleep.assert_called_once_with(1)

    def test_live_coverage_is_bounded_and_does_not_retry_foreign_rules(self):
        with patch.object(upgrade, "nft_document", return_value=nft_fixture()) as read, \
                patch.object(upgrade.time, "sleep") as sleep:
            with self.assertRaisesRegex(RuntimeError, "Firewall misses"):
                upgrade.check_live_coverage([ban(expiry=None)], exactly_six=True)
        self.assertEqual(read.call_count, 6)
        self.assertEqual(sleep.call_count, 5)
        foreign = nft_fixture()
        foreign["nftables"][-1]["rule"]["expr"][1] = {"accept": None}
        with patch.object(upgrade, "nft_document", return_value=foreign) as read, \
                patch.object(upgrade.time, "sleep") as sleep:
            with self.assertRaisesRegex(RuntimeError, "Foreign rule"):
                upgrade.check_live_coverage([ban(expiry=None)])
        self.assertEqual(read.call_count, 1)
        sleep.assert_not_called()

    @unittest.skipUnless(os.environ.get("HIVEGUARD_TEST_NETNS") == "1", "set HIVEGUARD_TEST_NETNS=1 for isolated kernel test")
    def test_restore_transaction_with_ipv4_ipv6_overlaps_in_real_nft(self):
        records = [ban("192.0.2.0/24", None), ban("192.0.2.1/32", None),
                   ban("2001:db8::/64", None), ban("2001:db8::5/128", None),
                   ban("203.0.113.0/24", "2020-01-01T00:00:00Z")]
        extra = [ipaddress.ip_network("198.51.100.0/25"), ipaddress.ip_network("198.51.100.128/25"),
                 ipaddress.ip_network("2001:db8:1::/64")]
        transaction = upgrade.firewall_restore(records, extra, table_exists=True)
        child = '''import os, subprocess, sys
assert os.readlink('/proc/self/ns/net') != sys.argv[1], 'host namespace must never run nft mutation'
subprocess.run(['nft','add','table','inet','hiveguard'],check=True)
subprocess.run(['nft','-f','-'],input=sys.stdin.read(),text=True,check=True)
subprocess.run(['nft','-j','list','table','inet','hiveguard'],check=True)
'''
        result = subprocess.run(["unshare", "--user", "--map-root-user", "--net", sys.executable,
                                 "-c", child, os.readlink("/proc/self/ns/net")], input=transaction,
                                capture_output=True, text=True, timeout=10, check=True)
        pool = upgrade.inspect_nft(json.loads(result.stdout), exactly_six=True)
        self.assertEqual(pool, [ipaddress.ip_network(n) for n in
                              ["192.0.2.0/24", "198.51.100.0/24", "2001:db8::/64", "2001:db8:1::/64"]])


class AtomicReplaceTests(unittest.TestCase):
    def test_interrupted_replace_keeps_old_file_and_next_attempt_ignores_stale_temp(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, destination = root / "new", root / "hiveguard"
            source.write_bytes(b"new executable")
            destination.write_bytes(b"old executable")
            stale = root / "hiveguard.upgrade-interrupted"
            stale.write_bytes(b"interrupted previous attempt")
            with patch.object(upgrade.os, "chown"), patch.object(upgrade.os, "replace", side_effect=OSError("simulated interrupted rename")):
                with self.assertRaisesRegex(OSError, "interrupted rename"):
                    upgrade.replace_file(source, destination)
            self.assertEqual(destination.read_bytes(), b"old executable")
            self.assertEqual(set(root.glob("hiveguard.upgrade-*")), {stale})
            with patch.object(upgrade.os, "chown"):
                upgrade.replace_file(source, destination, mode=0o750)
            self.assertEqual(destination.read_bytes(), b"new executable")
            self.assertEqual(destination.stat().st_mode & 0o777, 0o750)
            self.assertEqual(stale.read_bytes(), b"interrupted previous attempt")
            self.assertEqual(set(root.glob("hiveguard.upgrade-*")), {stale})


class RollbackTests(unittest.TestCase):
    def run_fallback(self, root, baseline_is_valid=True):
        data, backup = root / "data", root / "backup"
        data.mkdir(); backup.mkdir()
        (data / "snapshot.bin").write_bytes(b"corrupted new snapshot")
        (data / "wal.bin").write_bytes(b"new wal evidence")
        before = backup / "data.before"
        before.mkdir()
        (before / "snapshot.bin").write_bytes(b"verified baseline")
        (before / "wal.bin").write_bytes(b"baseline wal")
        (backup / "hiveguard.old").write_bytes(b"old executable")
        binary = root / "hiveguard"
        binary.write_bytes(b"new executable")
        dropin = root / "resource.conf"
        dropin.write_text("new limits")
        (backup / "rollback-ready").write_text("ready")
        baseline = {"bans": [ban("192.0.2.0/24", None)], "total_count": 1}
        (backup / "baseline.json").write_text(json.dumps(baseline))
        calls = []

        def fake_verify(source, output, **kwargs):
            calls.append(Path(source))
            if len(calls) == 1:
                self.assertEqual((Path(source) / "snapshot.bin").read_bytes(), b"corrupted new snapshot")
                raise RuntimeError("corrupt current snapshot")
            self.assertEqual(Path(source), before)
            self.assertEqual((before / "snapshot.bin").read_bytes(), b"verified baseline")
            legacy = kwargs["legacy"]
            legacy.mkdir()
            (legacy / "snapshot.bin").write_bytes(b"V3 baseline export")
            (legacy / "wal.bin").write_bytes(b"")
            return baseline if baseline_is_valid else {"bans": [], "total_count": 0}

        def fake_copy(source, destination):
            if Path(source).is_dir():
                shutil.copytree(source, destination)
            else:
                shutil.copy2(source, destination)

        commands = []
        def fake_run(argv, **kwargs):
            commands.append(([str(value) for value in argv], kwargs))
            if argv[:4] == ["nft", "-j", "list", "tables"]:
                return json.dumps({"nftables": [{"table": {"family": "inet", "name": "hiveguard"}}]})
            return ""

        old_pool = [ipaddress.ip_network("198.51.100.7/32")]
        documents = [nft_fixture(old_pool), nft_fixture(old_pool + [ipaddress.ip_network("192.0.2.0/24")])]
        with contextlib.ExitStack() as stack:
            for name, value in {"DATA": data, "BINARY": binary, "DROPIN": dropin}.items():
                stack.enter_context(patch.object(upgrade, name, value))
            stack.enter_context(patch.object(upgrade, "stop_service"))
            stack.enter_context(patch.object(upgrade, "copy_preserving", side_effect=fake_copy))
            stack.enter_context(patch.object(upgrade, "verify", side_effect=fake_verify))
            stack.enter_context(patch.object(upgrade, "run", side_effect=fake_run))
            stack.enter_context(patch.object(upgrade, "socket_bans", return_value=baseline["bans"]))
            stack.enter_context(patch.object(upgrade, "nft_document", side_effect=documents))
            stack.enter_context(patch.object(upgrade.os, "chown"))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            if baseline_is_valid:
                upgrade.rollback(backup)
            else:
                with self.assertRaisesRegex(RuntimeError, "active bans disappeared"):
                    upgrade.rollback(backup)
        return data, backup, binary, dropin, calls, commands

    def test_corrupted_current_state_falls_back_to_verified_baseline_and_keeps_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            data, backup, binary, dropin, calls, commands = self.run_fallback(Path(directory))
            self.assertEqual(len(calls), 2)
            self.assertEqual((calls[0] / "snapshot.bin").read_bytes(), b"corrupted new snapshot")
            self.assertEqual((data / "snapshot.bin").read_bytes(), b"V3 baseline export")
            self.assertEqual((data / "wal.bin").read_bytes(), b"")
            self.assertEqual(binary.read_bytes(), b"old executable")
            self.assertFalse(dropin.exists())
            self.assertTrue((backup / "rolled-back").exists())
            self.assertIn("corrupt current snapshot", (backup / "rollback-fallback.txt").read_text())
            transaction = [kwargs["input"] for argv, kwargs in commands if argv == ["nft", "-f", "-"]][0]
            self.assertIn("192.0.2.0/24", transaction)
            self.assertIn("198.51.100.7/32", transaction)  # retain kernel protection from the newer run
            self.assertNotIn("flush ruleset", transaction)
            self.assertIn((["systemctl", "start", "hiveguard"], {"timeout": 100}), commands)

    def test_invalid_fallback_cannot_replace_live_data_or_executable(self):
        with tempfile.TemporaryDirectory() as directory:
            data, backup, binary, _, _, commands = self.run_fallback(Path(directory), baseline_is_valid=False)
            self.assertEqual((data / "snapshot.bin").read_bytes(), b"corrupted new snapshot")
            self.assertEqual(binary.read_bytes(), b"new executable")
            self.assertFalse((backup / "rolled-back").exists())
            self.assertFalse(any(argv[:2] == ["nft", "-f"] for argv, _ in commands))
            self.assertFalse(any(argv == ["systemctl", "start", "hiveguard"] for argv, _ in commands))


class InstallPersistenceTests(unittest.TestCase):
    def exercise_install(self, root, persistence_valid, omit_new_ban=False):
        data, package, backups = root / "data", root / "package", root / "backups"
        data.mkdir(); package.mkdir()
        (data / "snapshot.bin").write_bytes(b"old persisted state")
        (data / "wal.bin").write_bytes(b"")
        binary, config, dropin = root / "hiveguard", root / "config.yaml", root / "dropin" / "resources.conf"
        binary.write_bytes(b"old executable")
        config.write_text("unchanged config")
        (package / "hiveguard").write_bytes(b"new executable")
        baseline = {"bans": [ban(expiry=None)], "total_count": 1,
                    "config": {"sha256": upgrade.sha(config), "plugins": []}}
        backup = backups / (AT.strftime("%Y%m%dT%H%M%SZ") + "-" + upgrade.RELEASE)
        checked_paths = []
        live = baseline["bans"] + ([ban("198.51.100.8/32", None)] if omit_new_ban else [])

        def preflight(work, ssh_ip):
            work.mkdir(parents=True)
            return baseline

        def copy_files(source, destination):
            if Path(source).is_dir():
                shutil.copytree(source, destination)
            else:
                shutil.copy2(source, destination)

        def verify(source, output, *args, **kwargs):
            checked_paths.append(source)
            if source.name == "state.after":
                self.assertEqual((source / "snapshot.bin").read_bytes(), b"new persisted state")
                self.assertFalse((backup / "committed").exists())
                if not persistence_valid:
                    raise RuntimeError("new persisted snapshot is unreadable")
            output.write_text(json.dumps(baseline))
            return baseline

        def run(argv, **kwargs):
            args = [str(value) for value in argv]
            if args[:3] == ["systemctl", "start", "hiveguard"]:
                self.assertTrue((backup / "rollback-ready").exists())
                (data / "snapshot.bin").write_bytes(b"new persisted state")
            if args[:3] == ["systemctl", "is-active", "hiveguard"]:
                return "active\n"
            if args[:3] == ["systemctl", "show", "hiveguard"]:
                return "123\n"
            return ""

        with contextlib.ExitStack() as stack:
            for name, value in {"DATA": data, "CONFIG": config, "BINARY": binary, "DROPIN": dropin,
                                "PACKAGE": package, "BACKUPS": backups}.items():
                stack.enter_context(patch.object(upgrade, name, value))
            stack.enter_context(patch.object(upgrade, "now", return_value=AT))
            stack.enter_context(patch.object(upgrade, "preflight", side_effect=preflight))
            stack.enter_context(patch.object(upgrade, "copy_preserving", side_effect=copy_files))
            stack.enter_context(patch.object(upgrade, "stable_copy", side_effect=lambda target: shutil.copytree(data, target)))
            stack.enter_context(patch.object(upgrade, "verify", side_effect=verify))
            stack.enter_context(patch.object(upgrade, "run", side_effect=run))
            stack.enter_context(patch.object(upgrade, "socket_bans", side_effect=[baseline["bans"]] + [live] * 6))
            initial_nft = nft_fixture([ipaddress.ip_network("192.0.2.1/32")])
            running_nft = nft_fixture([ipaddress.ip_network(record["subject"]) for record in live])
            stack.enter_context(patch.object(upgrade, "nft_document", side_effect=[initial_nft] + [running_nft] * 6))
            stack.enter_context(patch.object(upgrade, "stop_service"))
            rollback = stack.enter_context(patch.object(upgrade, "rollback"))
            stack.enter_context(patch.object(upgrade.os, "chown"))
            stack.enter_context(patch.object(upgrade.time, "sleep"))
            stack.enter_context(patch.object(upgrade.subprocess, "run"))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            if persistence_valid and not omit_new_ban:
                upgrade.install("127.0.0.1")
                rollback.assert_not_called()
            else:
                message = "active bans disappeared" if omit_new_ban else "persisted snapshot is unreadable"
                with self.assertRaisesRegex(RuntimeError, message):
                    upgrade.install("127.0.0.1")
                rollback.assert_called_once_with(backup)
        self.assertEqual(checked_paths, [backup / "data.before", backup / "state.after"])
        self.assertEqual((backup / "state.after" / "snapshot.bin").read_bytes(), b"new persisted state")
        self.assertEqual((backup / "data.before" / "snapshot.bin").read_bytes(), b"old persisted state")
        self.assertEqual((backup / "committed").exists(), persistence_valid and not omit_new_ban)

    def test_install_verifies_persisted_after_copy_before_committing(self):
        with tempfile.TemporaryDirectory() as directory:
            self.exercise_install(Path(directory), persistence_valid=True)

    def test_unreadable_after_copy_triggers_rollback_without_commit(self):
        with tempfile.TemporaryDirectory() as directory:
            self.exercise_install(Path(directory), persistence_valid=False)

    def test_readable_after_copy_missing_new_live_ban_triggers_rollback(self):
        with tempfile.TemporaryDirectory() as directory:
            self.exercise_install(Path(directory), persistence_valid=True, omit_new_ban=True)


class AutomaticRollbackTests(unittest.TestCase):
    def invoke_automatic(self, root, unit_state):
        backup = root / "saved"
        backup.mkdir()
        events = []
        def systemctl(args, **kwargs):
            events.append(args[1])
            if args[1] == "stop":
                return subprocess.CompletedProcess(args, 5, stdout="", stderr="Unit not loaded")
            self.assertEqual(args[1], "is-active")
            return subprocess.CompletedProcess(args, 3, stdout=unit_state + "\n", stderr="")
        lock_file = mock_open()
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(upgrade, "BACKUPS", root))
            stack.enter_context(patch.object(upgrade, "load_target_profile"))
            stack.enter_context(patch.object(upgrade, "lock_path", return_value=root / 'lock'))
            stack.enter_context(patch.object(upgrade.os, "geteuid", return_value=0))
            stack.enter_context(patch.object(upgrade.socket, "gethostname", return_value="node-a"))
            stack.enter_context(patch.object(upgrade.os, "umask"))
            stack.enter_context(patch.object(upgrade.subprocess, "run", side_effect=systemctl))
            stack.enter_context(patch.object(sys, "argv", ["upgrade.py", "rollback", "--backup", str(backup), "--automatic"]))
            stack.enter_context(patch("builtins.open", lock_file))
            flock = stack.enter_context(patch.object(upgrade.fcntl, "flock", side_effect=lambda *args: events.append("lock")))
            rollback = stack.enter_context(patch.object(upgrade, "rollback", side_effect=lambda *args: events.append("rollback")))
            if unit_state == "unknown":
                upgrade.main()
                self.assertEqual(events, ["stop", "is-active", "lock", "rollback"])
                flock.assert_called_once_with(lock_file(), upgrade.fcntl.LOCK_EX)
                rollback.assert_called_once_with(backup, True)
            else:
                with self.assertRaisesRegex(RuntimeError, "Installer still running"):
                    upgrade.main()
                self.assertEqual(events, ["stop", "is-active"])
                flock.assert_not_called()
                rollback.assert_not_called()

    def test_collected_installer_exit5_still_takes_lock_and_rolls_back(self):
        with tempfile.TemporaryDirectory() as directory:
            self.invoke_automatic(Path(directory), "unknown")

    def test_installer_live_or_transitioning_state_prevents_recovery_race(self):
        for state in ("active", "activating", "deactivating", "reloading"):
            with self.subTest(state=state), tempfile.TemporaryDirectory() as directory:
                self.invoke_automatic(Path(directory), state)


if __name__ == "__main__":
    unittest.main()
