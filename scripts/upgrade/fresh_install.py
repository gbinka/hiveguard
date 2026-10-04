#!/usr/bin/env python3
"""First installation in OBSERVE-ONLY mode: records detections, never changes nft.
Use the verified fresh-install.sh wrapper. Existing installations always abort.
"""
import argparse
import fcntl
import grp
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import pwd
import secrets
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
import urllib.request

PACKAGE = Path(__file__).resolve().parent
DATA, CONFIG = Path('/var/lib/hiveguard'), Path('/etc/hiveguard/config.yaml')
BINARY, UNIT = Path('/usr/local/bin/hiveguard'), Path('/etc/systemd/system/hiveguard.service')
RUNTIME, NGINX = Path('/run/hiveguard'), Path('/var/log/nginx/access.log')
LOCK_DIR = Path('/run/hiveguard-fresh-installer')


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def run(args, timeout=30):
    result = subprocess.run([str(v) for v in args], capture_output=True, text=True, timeout=timeout)
    require(result.returncode == 0, f'{args[0]} failed; no existing data was removed')
    return result.stdout


def write_new(path, content, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(fd, 'wb') as file:
        os.fchmod(file.fileno(), mode)  # executable/config permissions must not depend on caller umask
        file.write(content if isinstance(content, bytes) else content.encode())
        file.flush()
        os.fsync(file.fileno())


def config(hostname, ssh_ip, addresses, token, data=DATA, nginx=NGINX, static=None):
    whitelist = sorted({str(ipaddress.ip_network(value, strict=False)) for value in [ssh_ip, *addresses, '127.0.0.0/8', '::1/128']})
    ui = {'bind_addr': '127.0.0.1:8443', 'auth_token': token}
    if static:
        ui['static_dir'] = str(static)
    return {'node': {'name': hostname, 'data_dir': str(data), 'listen_gossip': '', 'seeds': []},
            'whitelist': whitelist, 'plugins': [
                {'id': 'enforcer.observe', 'config': {}},
                {'id': 'scoring.default', 'config': {'ban_severity_threshold': 100}},
                {'id': 'source.journald', 'config': {'units': ['ssh.service'], 'since_boot': False, 'event_type': 'AuthFailure'}},
                {'id': 'source.file.nginx', 'config': {'path': str(nginx), 'seek_to_end': True}},
                {'id': 'detector.ssh_bruteforce', 'config': {'threshold': 10, 'window_secs': 300, 'enum_threshold': 10, 'enum_window_secs': 120}},
                {'id': 'detector.http_flood', 'config': {'window_secs': 60, 'ip_threshold': 1200, 'subnet_threshold': 0}},
                {'id': 'ui.rest', 'config': ui}]}


def unit_text():
    return f'''[Unit]
Description=HiveGuard OBSERVE-ONLY (no firewall enforcement)
After=network.target
[Service]
Type=simple
User=hiveguard
Group=hiveguard
SupplementaryGroups=adm systemd-journal
ExecStart={BINARY} --config {CONFIG} --socket {RUNTIME}/hiveguard.sock
Restart=on-failure
RestartSec=5
TimeoutStopSec=30
RuntimeDirectory=hiveguard
RuntimeDirectoryMode=0750
UMask=0027
Environment=TOKIO_WORKER_THREADS=2
CPUQuota=200%
MemoryHigh=768M
MemoryMax=1G
TasksMax=256
NoNewPrivileges=true
CapabilityBoundingSet=
AmbientCapabilities=
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
ReadWritePaths={DATA} {RUNTIME}
[Install]
WantedBy=multi-user.target
'''


def absent():
    for path in (DATA, CONFIG.parent, BINARY, UNIT, RUNTIME):
        require(not os.path.lexists(path), f'Existing path {path}; first installation refused')
    require(run(['systemctl', 'show', 'hiveguard.service', '-p', 'LoadState', '--value']).strip() == 'not-found',
            'HiveGuard service already exists')
    for lookup in (pwd.getpwnam, grp.getgrnam):
        try:
            lookup('hiveguard')
        except KeyError:
            continue
        raise RuntimeError('Existing hiveguard account/group; manual review required')


def target_checks(ssh_ip):
    require(os.geteuid() == 0, 'Use sudo fresh-install.sh')
    profile = json.loads((PACKAGE / 'target.json').read_text())
    require(profile.get('mode') == 'fresh-observe', 'Package must explicitly select fresh-observe')
    require(profile.get('hostname') == socket.gethostname().split('.')[0], 'Wrong target hostname')
    require(profile.get('machine_id_sha256') == hashlib.sha256(Path('/etc/machine-id').read_bytes()).hexdigest(), 'Wrong machine identity')
    ipaddress.ip_address(ssh_ip)
    absent()
    for group in ('adm', 'systemd-journal'):
        grp.getgrnam(group)
    for service in ('ssh.service', 'nginx.service'):
        require(run(['systemctl', 'is-active', service]).strip() == 'active', f'{service} must be active')
    info = NGINX.stat()
    require(NGINX.is_file() and info.st_gid == grp.getgrnam('adm').gr_gid and info.st_mode & 0o040, 'nginx access log must be readable by adm')
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 8443))
    require(shutil.disk_usage('/var/lib').free >= 1024**3, 'At least 1 GiB free space required')
    addresses = [a['local'] for link in json.loads(run(['ip', '-j', 'address', 'show'])) for a in link.get('addr_info', []) if a.get('family') in ('inet', 'inet6')]
    return profile, addresses


def health(token):
    def request(path):
        req = urllib.request.Request('http://127.0.0.1:8443' + path, headers={'Authorization': 'Bearer ' + token})
        with urllib.request.urlopen(req, timeout=2) as response:
            return json.load(response)
    if request('/api/health').get('status') != 'ok':
        return False
    plugins = {entry['id']: entry['health'] for entry in request('/api/plugins')}
    return all(plugins.get(name) == 'Running' for name in ('source.journald', 'source.file.nginx'))


def smoke(work, host_netns):
    require(os.readlink('/proc/self/ns/net') != host_netns, 'Smoke test requires a separate network namespace')
    run(['ip', 'link', 'set', 'lo', 'up'])
    work = Path(work)
    data, nginx, shim = work / 'data', work / 'access.log', work / 'bin'
    shim.mkdir()
    write_new(nginx, '127.0.0.1 - - [04/Oct/2026:12:00:00 +0000] "GET / HTTP/1.1" 200 1 "-" "probe"\n')
    write_new(shim / 'journalctl', '#!/usr/bin/python3\nimport time\ntime.sleep(90)\n', 0o755)
    token = 'isolated-preflight-only'
    cfg = config('fresh-observe-test', '127.0.0.1', [], token, data, nginx)
    cfg_path, control = work / 'smoke.json', work / 'control.sock'
    write_new(cfg_path, json.dumps(cfg))
    env = {k: v for k, v in os.environ.items() if not k.startswith(('WATCHDOG_', 'LISTEN_')) and k != 'NOTIFY_SOCKET'}
    env.update(PATH=str(shim) + ':/usr/sbin:/usr/bin:/sbin:/bin', TOKIO_WORKER_THREADS='2', RUST_LOG='info')
    with (work / 'daemon.log').open('w') as log:
        process = subprocess.Popen([str(PACKAGE / 'hiveguard'), '--config', str(cfg_path), '--socket', str(control)],
                                   stdout=log, stderr=subprocess.STDOUT, env=env, start_new_session=True)
        try:
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline:
                require(process.poll() is None, 'Isolated daemon exited before readiness')
                try:
                    if control.exists() and health(token):
                        break
                except OSError:
                    pass
                time.sleep(.1)
            else:
                raise RuntimeError('Isolated daemon readiness timed out')
            process.send_signal(signal.SIGTERM)
            require(process.wait(timeout=15) == 0, 'Isolated daemon shutdown failed')
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)
    require((data / 'snapshot.bin').exists(), 'Isolated daemon did not persist state')
    run([PACKAGE / 'hiveguard-upgrade-check', '--data-dir', data, '--config', work / 'planned.json', '--output', work / 'checked.json'], timeout=30)
    require(json.loads((work / 'checked.json').read_text())['ok'], 'Offline configuration/state validation failed')


def preflight(profile, ssh_ip, addresses):
    # The only writable locations used by check are a private /tmp directory
    # and the wrapper's verified root-owned package stage.
    with tempfile.TemporaryDirectory(prefix='hg-fresh-check-') as temporary:
        work = Path(temporary)
        write_new(work / 'planned.json', json.dumps(config(profile['hostname'], ssh_ip, addresses, 'generated-during-install')))
        run(['unshare', '--net', '/usr/bin/python3', '-I', Path(__file__).resolve(), '_smoke', '--work', work,
             '--host-netns', os.readlink('/proc/self/ns/net')], timeout=70)
    print('CHECK OK: isolated startup/shutdown and schemas passed; OBSERVE-ONLY, firewall unchanged.', flush=True)


def install(profile, ssh_ip, addresses):
    absent()  # Recheck immediately before any application path/account creation.
    created_unit = False
    try:
        run(['useradd', '--system', '--user-group', '--home-dir', DATA, '--no-create-home', '--shell', '/usr/sbin/nologin', '--groups', 'adm,systemd-journal', 'hiveguard'])
        account = pwd.getpwnam('hiveguard')
        run(['runuser', '-u', 'hiveguard', '--', 'test', '-r', NGINX])
        journal = run(['runuser', '-u', 'hiveguard', '--', 'journalctl', '-u', 'ssh.service', '-n', '1', '--no-pager', '--output=json'])
        require(any(isinstance(json.loads(line), dict) for line in journal.splitlines()), 'hiveguard account cannot read SSH journal entries')
        DATA.mkdir(mode=0o750)
        os.chown(DATA, account.pw_uid, account.pw_gid)
        CONFIG.parent.mkdir(mode=0o750)
        os.chown(CONFIG.parent, 0, account.pw_gid)
        static = None
        if (PACKAGE / 'web' / 'index.html').is_file():
            static = DATA / 'ui-web' / 'dist'
            shutil.copytree(PACKAGE / 'web', static)
            for path in [static.parent, static, *static.rglob('*')]:
                os.chmod(path, 0o755 if path.is_dir() else 0o644)
        token = secrets.token_urlsafe(32)
        write_new(CONFIG, json.dumps(config(profile['hostname'], ssh_ip, addresses, token, static=static), indent=2) + '\n', 0o640)
        os.chown(CONFIG, 0, account.pw_gid)
        write_new(BINARY, (PACKAGE / 'hiveguard').read_bytes(), 0o755)
        write_new(UNIT, unit_text(), 0o644)
        created_unit = True
        run(['systemctl', 'daemon-reload'])
        run(['systemctl', 'enable', '--now', 'hiveguard.service'], timeout=60)
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            try:
                if (RUNTIME / 'hiveguard.sock').exists() and health(token):
                    break
            except OSError:
                pass
            time.sleep(.2)
        else:
            raise RuntimeError('Service did not become ready')
        pid = run(['systemctl', 'show', 'hiveguard.service', '-p', 'MainPID', '--value']).strip()
        require(pid.isdigit() and int(pid) > 0, 'Service has no running process')
        for _ in range(3):
            time.sleep(1)
            require(health(token), 'A log source stopped or is restarting')
            require(run(['systemctl', 'show', 'hiveguard.service', '-p', 'MainPID', '--value']).strip() == pid, 'Service restarted during observation')
        require(run(['systemctl', 'is-active', 'hiveguard.service']).strip() == 'active', 'Service is not active')
        print('INSTALLED: OBSERVE-ONLY; no traffic is blocked. UI: SSH tunnel to 127.0.0.1:8443. Token remains in root-protected config.', flush=True)
    except BaseException:
        if created_unit:
            subprocess.run(['systemctl', 'disable', '--now', 'hiveguard.service'], capture_output=True, timeout=45)
        print('Installation incomplete: created files/account retained for diagnosis; no existing data removed.', file=sys.stderr)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['check', 'install', '_smoke'])
    parser.add_argument('--ssh-ip')
    parser.add_argument('--work')
    parser.add_argument('--host-netns')
    args = parser.parse_args()
    os.umask(0o027)
    if args.action == '_smoke':
        require(args.work and args.host_netns, 'Missing isolated test arguments')
        smoke(args.work, args.host_netns)
        return
    require(os.geteuid() == 0, 'Use sudo fresh-install.sh')
    LOCK_DIR.mkdir(mode=0o700, exist_ok=True)
    info = LOCK_DIR.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o700, 'Unsafe lock directory')
    fd = os.open(LOCK_DIR / 'lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'r+') as lock:
        info = os.fstat(lock.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1, 'Unsafe lock file')
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        profile, addresses = target_checks(args.ssh_ip)
        preflight(profile, args.ssh_ip, addresses)
        if args.action == 'install':
            install(profile, args.ssh_ip, addresses)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(f'ABORT: {error}', file=sys.stderr)
        sys.exit(1)
