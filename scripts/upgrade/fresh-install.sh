#!/usr/bin/env bash
set -euo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
unset PYTHONPATH PYTHONHOME
umask 077
[[ $EUID -eq 0 ]] || { echo 'Użycie: sudo ./fresh-install.sh check|install IP_SSH' >&2; exit 1; }
[[ $# -eq 2 && ($1 == check || $1 == install) ]] || { echo 'Wymagane: check|install IP_SSH' >&2; exit 1; }
package=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
cd -- "$package"
sha256sum --strict --check SHA256SUMS
/usr/bin/python3 -I - <<'PY'
import hashlib, json, re, socket
from pathlib import Path
manifest = Path('SHA256SUMS').read_text().splitlines()
for name in ['target.json', 'fresh_install.py', 'fresh-install.sh', 'hiveguard', 'hiveguard-upgrade-check']:
    if not any(re.fullmatch(r'[0-9a-f]{64} [ *]' + re.escape(name), line) for line in manifest):
        raise SystemExit('Required file missing from verified manifest: ' + name)
profile = json.loads(Path('target.json').read_text())
if profile.get('mode') != 'fresh-observe' or profile.get('hostname') != socket.gethostname().split('.')[0]:
    raise SystemExit('Wrong target or mode: expected explicitly approved fresh-observe profile')
if profile.get('machine_id_sha256') != hashlib.sha256(Path('/etc/machine-id').read_bytes()).hexdigest():
    raise SystemExit('Wrong machine identity')
PY
digest=$(sha256sum SHA256SUMS)
digest=${digest%% *}
parent=/var/lib/hiveguard-installers
stage="$parent/fresh-${digest:0:16}"
[[ ! -L "$parent" && ! -L "$stage" ]] || { echo 'Unexpected symlink' >&2; exit 1; }
install -d -o root -g root -m 0755 "$parent"
if [[ ! -e "$stage" ]]; then
  [[ -z $(find "$package" -type l -print -quit) ]] || { echo 'Package contains symlinks' >&2; exit 1; }
  temporary=$(mktemp -d "$parent/.prepare-XXXXXXXX")
  trap 'rm -rf -- "$temporary"' EXIT
  cp -R -- "$package/." "$temporary/"
  chown -R root:root "$temporary"
  find "$temporary" -type d -exec chmod 0755 {} +
  find "$temporary" -type f -exec chmod 0644 {} +
  chmod 0755 "$temporary/hiveguard" "$temporary/hiveguard-upgrade-check" "$temporary/fresh-install.sh"
  (cd -- "$temporary" && sha256sum --strict --check SHA256SUMS)
  mv -T -- "$temporary" "$stage"
  trap - EXIT
fi
[[ $(stat -c '%u' "$stage") == 0 && $(stat -c '%a' "$stage") == 755 ]] || { echo 'Unsafe stage ownership/mode' >&2; exit 1; }
cd -- "$stage"
sha256sum --strict --check SHA256SUMS
unit="hiveguard-fresh-$1-$(date -u +%Y%m%dT%H%M%S)"
echo "OBSERVE-ONLY: zero zmian firewalla. Jednostka: $unit (przetrwa zerwanie SSH)."
status=0
systemd-run --unit "$unit" --collect --wait \
  --property=Type=exec --property=StandardOutput=journal --property=StandardError=journal \
  --property=RuntimeMaxSec=180 --property=TimeoutStopSec=20 \
  --property=CPUQuota=200% --property=MemoryMax=1G --property=TasksMax=256 \
  /usr/bin/python3 -I "$stage/fresh_install.py" "$1" --ssh-ip "$2" || status=$?
journalctl -u "$unit" --no-pager -n 60 || true
exit "$status"
