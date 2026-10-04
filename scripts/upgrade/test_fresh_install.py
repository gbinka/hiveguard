#!/usr/bin/env python3
"""No host services/accounts are changed. Optional smoke uses isolated netns."""
import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

import fresh_install as fresh


class FreshConfigurationTests(unittest.TestCase):
    def test_observe_only_config_has_no_network_ingest_or_gossip_and_protects_admin(self):
        cfg = fresh.config('node-d', '198.51.100.10', ['203.0.113.20', '2001:db8::1'], 'private-token')
        ids = [entry['id'] for entry in cfg['plugins']]
        self.assertEqual([name for name in ids if name.startswith('enforcer.')], ['enforcer.observe'])
        self.assertEqual(cfg['node']['listen_gossip'], '')
        self.assertEqual(cfg['node']['seeds'], [])
        self.assertEqual([name for name in ids if name.startswith('source.')], ['source.journald', 'source.file.nginx'])
        self.assertIn('198.51.100.10/32', cfg['whitelist'])
        self.assertIn('203.0.113.20/32', cfg['whitelist'])
        self.assertIn('2001:db8::1/128', cfg['whitelist'])
        ui = next(entry['config'] for entry in cfg['plugins'] if entry['id'] == 'ui.rest')
        self.assertEqual(ui['bind_addr'], '127.0.0.1:8443')
        self.assertNotIn('ingest', ui)
        self.assertEqual(ui['auth_token'], 'private-token')

    def test_unit_has_no_capabilities_and_limits_writes_and_resources(self):
        unit = fresh.unit_text()
        self.assertIn('CapabilityBoundingSet=\n', unit)
        self.assertIn('AmbientCapabilities=\n', unit)
        self.assertNotIn('CAP_NET_ADMIN', unit)
        for directive in ['CPUQuota=200%', 'MemoryHigh=768M', 'MemoryMax=1G', 'TasksMax=256',
                          'ProtectSystem=strict', 'NoNewPrivileges=true', 'SupplementaryGroups=adm systemd-journal']:
            self.assertIn(directive, unit)

    def test_wrong_machine_identity_aborts_before_any_installation_probe(self):
        profile = {'mode': 'fresh-observe', 'hostname': 'node-d', 'machine_id_sha256': '0' * 64}
        with tempfile.TemporaryDirectory() as directory:
            package = Path(directory)
            (package / 'target.json').write_text(json.dumps(profile))
            with patch.object(fresh, 'PACKAGE', package), patch.object(fresh.os, 'geteuid', return_value=0), \
                    patch.object(fresh.socket, 'gethostname', return_value='node-d'), \
                    patch.object(fresh, 'absent') as absent:
                with self.assertRaisesRegex(RuntimeError, 'Wrong machine identity'):
                    fresh.target_checks('127.0.0.1')
                absent.assert_not_called()

    def test_health_requires_both_log_sources_running(self):
        def response(value):
            return io.StringIO(json.dumps(value))
        for state, expected in [('Running', True), ('Starting', False), ('Restarting: denied', False)]:
            with self.subTest(state=state), patch.object(fresh.urllib.request, 'urlopen', side_effect=[
                response({'status': 'ok'}), response([
                    {'id': 'source.journald', 'health': state},
                    {'id': 'source.file.nginx', 'health': 'Running'}])]):
                self.assertEqual(fresh.health('private-token'), expected)

    def test_untrusted_lock_directory_cannot_truncate_a_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            protected = root / 'protected'; protected.mkdir()
            (protected / 'lock').write_text('must remain intact')
            link = root / 'installer-lock'; link.symlink_to(protected, target_is_directory=True)
            with patch.object(fresh, 'LOCK_DIR', link), patch.object(fresh.os, 'geteuid', return_value=0), \
                    patch.object(fresh.os, 'umask'), patch.object(sys, 'argv', ['fresh_install.py', 'check', '--ssh-ip', '127.0.0.1']):
                with self.assertRaisesRegex(RuntimeError, 'Unsafe lock directory'):
                    fresh.main()
            self.assertEqual((protected / 'lock').read_text(), 'must remain intact')

    def test_existing_path_including_dangling_symlink_aborts_without_commands(self):
        with tempfile.TemporaryDirectory() as directory:
            existing = Path(directory) / 'hiveguard'
            existing.symlink_to(Path(directory) / 'absent')
            with patch.object(fresh, 'DATA', existing), patch.object(fresh, 'run') as run:
                with self.assertRaisesRegex(RuntimeError, 'Existing path'):
                    fresh.absent()
                run.assert_not_called()

    def test_existing_account_aborts_after_confirming_service_absence(self):
        with patch.object(fresh.os.path, 'lexists', return_value=False), \
                patch.object(fresh, 'run', return_value='not-found\n'), \
                patch.object(fresh.pwd, 'getpwnam', return_value=object()):
            with self.assertRaisesRegex(RuntimeError, 'Existing hiveguard account/group'):
                fresh.absent()

    def test_exclusive_write_cannot_overwrite_existing_data(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'snapshot.bin'
            path.write_bytes(b'existing state')
            with self.assertRaises(FileExistsError):
                fresh.write_new(path, b'new state')
            self.assertEqual(path.read_bytes(), b'existing state')

    def test_explicit_modes_survive_restrictive_installer_umask(self):
        with tempfile.TemporaryDirectory() as directory:
            old = os.umask(0o027)
            try:
                binary, config = Path(directory) / 'binary', Path(directory) / 'config'
                fresh.write_new(binary, b'executable', 0o755)
                fresh.write_new(config, b'secret', 0o640)
                self.assertEqual(binary.stat().st_mode & 0o777, 0o755)
                self.assertEqual(config.stat().st_mode & 0o777, 0o640)
            finally:
                os.umask(old)

    def test_smoke_rejects_host_network_namespace_before_creating_files(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(RuntimeError, 'separate network namespace'):
                fresh.smoke(directory, os.readlink('/proc/self/ns/net'))
            self.assertEqual(list(Path(directory).iterdir()), [])


class FreshFailureTests(unittest.TestCase):
    def test_partial_install_stops_only_its_created_service_and_retains_files_without_token_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            package = root / 'package'; package.mkdir()
            (package / 'hiveguard').write_bytes(b'new binary')
            data, config, binary, unit = root / 'data', root / 'etc' / 'config.yaml', root / 'hiveguard', root / 'hiveguard.service'
            output, error = io.StringIO(), io.StringIO()
            account = types.SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid())
            calls = []
            def command(argv, **kwargs):
                calls.append([str(a) for a in argv])
                if argv[:3] == ['systemctl', 'enable', '--now']:
                    raise RuntimeError('simulated start failure')
                if 'journalctl' in argv:
                    return '{"MESSAGE":"synthetic journal permission probe"}\n'
                return ''
            with contextlib.ExitStack() as stack:
                for name, value in {'PACKAGE': package, 'DATA': data, 'CONFIG': config, 'BINARY': binary, 'UNIT': unit}.items():
                    stack.enter_context(patch.object(fresh, name, value))
                stack.enter_context(patch.object(fresh, 'absent'))
                stack.enter_context(patch.object(fresh, 'run', side_effect=command))
                stack.enter_context(patch.object(fresh.pwd, 'getpwnam', return_value=account))
                stack.enter_context(patch.object(fresh.os, 'chown'))
                stack.enter_context(patch.object(fresh.secrets, 'token_urlsafe', return_value='MUST-NOT-BE-PRINTED'))
                stop = stack.enter_context(patch.object(fresh.subprocess, 'run'))
                stack.enter_context(contextlib.redirect_stdout(output))
                stack.enter_context(contextlib.redirect_stderr(error))
                with self.assertRaisesRegex(RuntimeError, 'start failure'):
                    fresh.install({'hostname': 'test'}, '127.0.0.1', [])
                stop.assert_called_once_with(['systemctl', 'disable', '--now', 'hiveguard.service'], capture_output=True, timeout=45)
            self.assertTrue(config.exists())
            self.assertTrue(data.is_dir())
            self.assertTrue(unit.exists())
            self.assertEqual(binary.read_bytes(), b'new binary')
            self.assertNotIn('MUST-NOT-BE-PRINTED', output.getvalue() + error.getvalue())
            self.assertEqual(config.stat().st_mode & 0o777, 0o640)
            self.assertFalse(any(args[0] == 'nft' for args in calls))
            self.assertIn(['runuser', '-u', 'hiveguard', '--', 'test', '-r', str(fresh.NGINX)], calls)
            self.assertTrue(any(args[:5] == ['runuser', '-u', 'hiveguard', '--', 'journalctl'] for args in calls))

    def test_abort_before_unit_creation_never_stops_an_existing_service(self):
        with patch.object(fresh, 'absent', side_effect=RuntimeError('existing data')), \
                patch.object(fresh, 'run') as run, patch.object(fresh.subprocess, 'run') as stop:
            with self.assertRaisesRegex(RuntimeError, 'existing data'):
                fresh.install({'hostname': 'test'}, '127.0.0.1', [])
            run.assert_not_called(); stop.assert_not_called()


@unittest.skipUnless(os.environ.get('HIVEGUARD_TEST_FRESH_BINARY'), 'set HIVEGUARD_TEST_FRESH_BINARY and HIVEGUARD_TEST_FRESH_CHECKER for real isolated smoke')
class FreshIntegrationTests(unittest.TestCase):
    def test_release_starts_and_shuts_down_with_synthetic_sources(self):
        with tempfile.TemporaryDirectory(prefix='hg-fresh-integration-') as directory:
            root = Path(directory); package = root / 'pkg'; package.mkdir(); work = root / 'work'; work.mkdir()
            shutil.copyfile(Path(fresh.__file__), package / 'fresh_install.py')
            for variable, name in [('HIVEGUARD_TEST_FRESH_BINARY', 'hiveguard'), ('HIVEGUARD_TEST_FRESH_CHECKER', 'hiveguard-upgrade-check')]:
                os.link(Path(os.environ[variable]).resolve(), package / name)
            (work / 'planned.json').write_text(json.dumps(fresh.config('test', '127.0.0.1', [], 'offline-only')))
            result = subprocess.run(['unshare', '--user', '--map-root-user', '--net', sys.executable, '-I',
                                     str(package / 'fresh_install.py'), '_smoke', '--work', str(work),
                                     '--host-netns', os.readlink('/proc/self/ns/net')], capture_output=True, text=True, timeout=60)
            log = (work / 'daemon.log').read_text() if (work / 'daemon.log').exists() else ''
            self.assertEqual(result.returncode, 0, result.stderr + '\n' + log)
            report = json.loads((work / 'checked.json').read_text())
            self.assertTrue(report['ok'])
            self.assertTrue(report['roundtrip_exact'])
            self.assertEqual(report['total_count'], 0)
            self.assertIn('HiveGuard daemon stopped', log)
            self.assertNotIn('log source exited; restarting', log)


if __name__ == '__main__':
    unittest.main()
