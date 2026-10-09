#!/usr/bin/env bash
set -euo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
unset PYTHONPATH PYTHONHOME
umask 077

if [[ $EUID -ne 0 ]]; then
  echo 'Uruchom: sudo ./upgrade.sh check|install ADRES_IP_SSH' >&2
  exit 1
fi
action=${1:-}
argument=${2:-}
case "$action" in
  check|install|rollback) ;;
  *) echo 'Użycie: upgrade.sh check|install IP_SSH lub rollback KATALOG_BACKUPU' >&2; exit 1 ;;
esac
[[ -n "$argument" && $# -eq 2 ]] || { echo 'Brak wymaganego argumentu.' >&2; exit 1; }
package=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
cd -- "$package"
sha256sum --strict --check SHA256SUMS
# target.json must itself be covered by the verified package manifest.
expected_hostname=$(/usr/bin/python3 -I - <<'PYPROFILE'
import json
from pathlib import Path
import re
manifest = Path("SHA256SUMS").read_text().splitlines()
if not any(re.fullmatch(r"[0-9a-f]{64} [ *]target\.json", line) for line in manifest):
    raise SystemExit("Brak target.json w zweryfikowanym SHA256SUMS.")
profile = json.loads(Path("target.json").read_text())
hostname = profile.get("hostname")
if not isinstance(hostname, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{0,62}", hostname):
    raise SystemExit("Nieprawidłowy hostname w target.json.")
print(hostname)
PYPROFILE
)
[[ $(hostname -s) == "$expected_hostname" ]] || {
  echo "To paczka wyłącznie dla $expected_hostname." >&2
  exit 1
}
digest=$(sha256sum SHA256SUMS)
digest=${digest%% *}
parent=/var/lib/hiveguard-upgrades
stage="$parent/20261009-${digest:0:16}"
install -d -o root -g root -m 0755 "$parent"
[[ ! -L "$parent" && ! -L "$stage" ]] || { echo 'Nieoczekiwany symlink.' >&2; exit 1; }
if [[ ! -e "$stage" ]]; then
  temporary=$(mktemp -d "$parent/.prepare-XXXXXXXX")
  trap 'rm -rf -- "$temporary"' EXIT
  if [[ -n $(find "$package" -type l -print -quit) ]]; then
    echo 'Paczka zawiera symlink; przerwano.' >&2
    exit 1
  fi
  cp -R -- "$package/." "$temporary/"
  chown -R root:root "$temporary"
  find "$temporary" -type d -exec chmod 0755 {} +
  find "$temporary" -type f -exec chmod 0644 {} +
  chmod 0755 "$temporary/hiveguard" "$temporary/hiveguard-upgrade-check" "$temporary/upgrade.sh"
  (cd -- "$temporary" && sha256sum --strict --check SHA256SUMS)
  mv -T -- "$temporary" "$stage"
  trap - EXIT
fi
cd -- "$stage"
sha256sum --strict --check SHA256SUMS

case "$action" in
  check) unit="hiveguard-upgrade-check-$(date -u +%Y%m%dT%H%M%S)"; args=(check --ssh-ip "$argument") ;;
  install) unit=hiveguard-upgrade-20261009; args=(install --ssh-ip "$argument") ;;
  rollback) unit="hiveguard-upgrade-manual-rollback-$(date -u +%Y%m%dT%H%M%S)"; args=(rollback --backup "$argument") ;;
esac
echo "Praca pod kontrolą systemd: $unit (przetrwa zerwanie SSH)."
echo "Log: sudo journalctl -u $unit --no-pager -n 100"
status=0
systemd-run --unit "$unit" --collect --wait \
  --property=Type=exec --property=StandardOutput=journal --property=StandardError=journal \
  --property=RuntimeMaxSec=600 --property=TimeoutStopSec=20 \
  --property=CPUQuota=200% --property=MemoryMax=1G --property=TasksMax=256 \
  /usr/bin/python3 -I "$stage/upgrade.py" "${args[@]}" || status=$?
journalctl -u "$unit" --no-pager -n 100 || true
exit "$status"
