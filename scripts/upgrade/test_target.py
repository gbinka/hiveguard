#!/usr/bin/env python3
"""Host binding tests: service calls and /etc/machine-id reads are mocked."""
import contextlib
import copy
import hashlib
import json
from pathlib import Path
import runpy
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

import upgrade


MACHINE_BYTES = b"0123456789abcdef0123456789abcdef\n"
MACHINE_SHA = hashlib.sha256(MACHINE_BYTES).hexdigest()
PROFILE = {
    "hostname": "target-host",
    "machine_id_sha256": MACHINE_SHA,
    "old_binary_sha256": "a" * 64,
    "data_dir": "/var/lib/hiveguard",
    "config_path": "/etc/hiveguard/config.yaml",
    "binary_path": "/usr/local/bin/hiveguard",
    "control_socket": "/run/hiveguard/hiveguard.sock",
    "service_user": "hiveguard",
    "service_group": "hiveguard",
    "exec_start": "/usr/local/bin/hiveguard -c /etc/hiveguard/config.yaml",
}
PROFILE_GLOBALS = ("HOSTNAME", "OLD_SHA", "DATA", "CONFIG", "BINARY", "CONTROL",
                   "SERVICE_USER", "SERVICE_GROUP", "EXEC_START")


class DeploymentLockTests(unittest.TestCase):
    def test_lock_rejects_untrusted_directory_before_opening_a_file(self):
        for mode, uid in ((0o040777, 0), (0o040700, 1000), (0o120700, 0)):
            with self.subTest(mode=mode, uid=uid):
                directory = MagicMock()
                directory.lstat.return_value = SimpleNamespace(st_mode=mode, st_uid=uid)
                with patch.object(upgrade, 'Path', return_value=directory):
                    with self.assertRaisesRegex(RuntimeError, 'Unsafe deployment lock directory'):
                        upgrade.lock_path()
                directory.__truediv__.assert_not_called()

    def test_private_directory_still_rejects_symlink_lock(self):
        directory = MagicMock()
        directory.lstat.return_value = SimpleNamespace(st_mode=0o040700, st_uid=0)
        directory.__truediv__.return_value.is_symlink.return_value = True
        with patch.object(upgrade, 'Path', return_value=directory):
            with self.assertRaisesRegex(RuntimeError, 'Unexpected symlink'):
                upgrade.lock_path()


class TargetProfileTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.package = Path(self.directory.name)
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(upgrade, "PACKAGE", self.package))
        # Profile loading changes globals for the action; isolate each test.
        self.stack.enter_context(patch.multiple(upgrade, **{
            key: getattr(upgrade, key) for key in PROFILE_GLOBALS
        }))
        self.stack.enter_context(patch.object(upgrade.socket, "gethostname", return_value="target-host"))
        self.machine_digest = self.stack.enter_context(patch.object(upgrade, "sha", return_value=MACHINE_SHA))

    def write_profile(self, profile=None):
        profile = copy.deepcopy(PROFILE if profile is None else profile)
        (self.package / "target.json").write_text(json.dumps(profile))
        return profile

    def test_profile_is_not_loaded_by_importing_offline_helpers(self):
        with patch.object(Path, "read_text", side_effect=AssertionError("profile read during import")):
            imported = runpy.run_path(upgrade.__file__, run_name="offline_upgrade_helpers")
        self.assertEqual(imported["DATA"], Path("/var/lib/hiveguard"))

    def test_valid_profile_binds_identity_and_all_deployment_paths(self):
        profile = self.write_profile({**PROFILE,
            "data_dir": "/srv/security/state", "config_path": "/etc/security/config.yaml",
            "binary_path": "/opt/security/hiveguard", "control_socket": "/run/security/daemon.sock",
            "service_user": "security", "service_group": "security-group",
            "exec_start": "/opt/security/hiveguard -c /etc/security/config.yaml",
        })
        self.assertEqual(upgrade.load_target_profile(), profile)
        self.machine_digest.assert_called_once_with(Path("/etc/machine-id"))
        self.assertEqual(upgrade.HOSTNAME, "target-host")
        self.assertEqual(upgrade.OLD_SHA, "a" * 64)
        self.assertEqual(upgrade.DATA, Path(profile["data_dir"]))
        self.assertEqual(upgrade.CONFIG, Path(profile["config_path"]))
        self.assertEqual(upgrade.BINARY, Path(profile["binary_path"]))
        self.assertEqual(upgrade.CONTROL, profile["control_socket"])
        self.assertEqual(upgrade.SERVICE_USER, "security")
        self.assertEqual(upgrade.SERVICE_GROUP, "security-group")
        self.assertEqual(upgrade.EXEC_START, profile["exec_start"])

    def test_missing_or_incomplete_profile_does_not_use_old_host_defaults(self):
        with self.assertRaisesRegex(RuntimeError, "target.json is missing"):
            upgrade.load_target_profile()
        for key in PROFILE:
            profile = copy.deepcopy(PROFILE)
            del profile[key]
            self.write_profile(profile)
            with self.subTest(missing=key), self.assertRaisesRegex(RuntimeError, "required host-profile fields"):
                upgrade.load_target_profile()

    def test_unknown_profile_fields_are_rejected_instead_of_ignored(self):
        self.write_profile({**PROFILE, "nft_table": "other"})
        with self.assertRaisesRegex(RuntimeError, "required host-profile fields"):
            upgrade.load_target_profile()

    def test_same_hostname_but_wrong_machine_is_rejected(self):
        self.write_profile()
        self.machine_digest.return_value = "b" * 64
        with self.assertRaisesRegex(RuntimeError, "machine-id does not match"):
            upgrade.load_target_profile()
        self.assertNotEqual(upgrade.HOSTNAME, "target-host")

    def test_machine_hash_is_for_exact_file_bytes_not_stripped_text(self):
        self.write_profile({**PROFILE, "machine_id_sha256": hashlib.sha256(MACHINE_BYTES.strip()).hexdigest()})
        with self.assertRaisesRegex(RuntimeError, "machine-id does not match"):
            upgrade.load_target_profile()

    def test_matching_machine_does_not_override_hostname_mismatch(self):
        self.write_profile()
        with patch.object(upgrade.socket, "gethostname", return_value="other-host"):
            with self.assertRaisesRegex(RuntimeError, "different host"):
                upgrade.load_target_profile()
        self.machine_digest.assert_not_called()

    def test_malformed_and_unsafe_paths_do_not_reach_identity_or_service_calls(self):
        for key, value in [("data_dir", "relative/state"), ("data_dir", "/var/lib/../state"),
                           ("data_dir", "/var"), ("binary_path", "/tmp/program\nother"),
                           ("control_socket", "/run/" + "x" * 110), ("service_user", "bad\nUser=root"),
                           ("exec_start", "/bin/sh -c run-anything"),
                           ("old_binary_sha256", "not-a-hash")]:
            self.write_profile({**PROFILE, key: value})
            with self.subTest(key=key, value=value), self.assertRaises(RuntimeError):
                upgrade.load_target_profile()
        self.machine_digest.assert_not_called()

    def test_every_action_checks_profile_before_service_calls_including_guardian(self):
        for action in ("check", "install", "rollback"):
            for failure in ("missing", "hostname", "machine"):
                (self.package / "target.json").unlink(missing_ok=True)
                if failure != "missing":
                    self.write_profile()
                argv = ["upgrade.py", action]
                if action == "rollback":
                    argv += ["--backup", "/var/backups/hiveguard/test", "--automatic"]
                else:
                    argv += ["--ssh-ip", "127.0.0.1"]
                hostname = "different" if failure == "hostname" else "target-host"
                self.machine_digest.return_value = "b" * 64 if failure == "machine" else MACHINE_SHA
                with self.subTest(action=action, failure=failure), contextlib.ExitStack() as stack:
                    stack.enter_context(patch.object(sys, "argv", argv))
                    stack.enter_context(patch.object(upgrade.os, "geteuid", return_value=0))
                    stack.enter_context(patch.object(upgrade.os, "umask"))
                    stack.enter_context(patch.object(upgrade.socket, "gethostname", return_value=hostname))
                    commands = stack.enter_context(patch.object(upgrade, "run"))
                    subprocesses = stack.enter_context(patch.object(upgrade.subprocess, "run"))
                    lock = stack.enter_context(patch.object(upgrade.fcntl, "flock"))
                    with self.assertRaises(RuntimeError):
                        upgrade.main()
                    commands.assert_not_called()
                    subprocesses.assert_not_called()
                    lock.assert_not_called()

    def test_service_argv_must_match_whole_profile_not_just_a_prefix(self):
        self.write_profile()
        upgrade.load_target_profile()
        self.machine_digest.return_value = PROFILE["old_binary_sha256"]
        props = ("User=hiveguard\nGroup=hiveguard\nActiveState=active\nExecStopPost=\n"
                 "ExecStart={ path=/usr/local/bin/hiveguard ; argv[]=" + PROFILE["exec_start"] + " ; ignore_errors=no ; }\n")
        with patch.object(upgrade.os, "geteuid", return_value=0), \
                patch.object(upgrade.shutil, "disk_usage", return_value=type("Space", (), {"free": 3 * 1024**3})()), \
                patch.object(Path, "is_symlink", return_value=False), patch.object(Path, "is_mount", return_value=False), \
                patch.object(upgrade, "run", return_value=props) as command:
            upgrade.target_checks()
            command.return_value = props.replace("config.yaml ;", "config.yaml.unreviewed ;")
            with self.assertRaisesRegex(RuntimeError, "ExecStart differs"):
                upgrade.target_checks()


if __name__ == "__main__":
    unittest.main()
