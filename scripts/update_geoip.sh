#!/usr/bin/env bash
# update_geoip.sh — Download MaxMind GeoLite2 Country and ASN databases.
#
# Usage:
#   bash update_geoip.sh [--license-key KEY] [--data-dir DIR]
#
# Options:
#   --license-key KEY   MaxMind license key (required if not set via MAXMIND_LICENSE_KEY env var)
#   --data-dir    DIR   HiveGuard data directory (default: /var/lib/hiveguard)
#
# The script downloads GeoLite2-Country.mmdb and GeoLite2-ASN.mmdb into
# <data-dir>/geoip/, using atomic rename so a live daemon always reads a
# consistent database.

set -euo pipefail

# ── Defaults ──────────────────────────────────────────────────────────────────
LICENSE_KEY="${MAXMIND_LICENSE_KEY:-}"
DATA_DIR="/var/lib/hiveguard"
MAXMIND_URL="https://download.maxmind.com/app/geoip_download"

# ── Parse arguments ───────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --license-key)
      LICENSE_KEY="$2"
      shift 2
      ;;
    --data-dir)
      DATA_DIR="$2"
      shift 2
      ;;
    *)
      echo "Unknown argument: $1" >&2
      echo "Usage: $0 [--license-key KEY] [--data-dir DIR]" >&2
      exit 1
      ;;
  esac
done

# ── Validate ──────────────────────────────────────────────────────────────────
if [[ -z "$LICENSE_KEY" ]]; then
  echo "Error: MaxMind license key is required." >&2
  echo "Pass --license-key KEY or export MAXMIND_LICENSE_KEY=KEY" >&2
  exit 1
fi

GEOIP_DIR="${DATA_DIR}/geoip"
mkdir -p "$GEOIP_DIR"

# ── Download helper ───────────────────────────────────────────────────────────
download_db() {
  local edition_id="$1"
  local output_file="${GEOIP_DIR}/${edition_id}.mmdb"
  local tmp_file="${output_file}.tmp.tar.gz"
  local extract_dir="${GEOIP_DIR}/.extract_${edition_id}"

  echo "Downloading ${edition_id} …"

  curl -fsSL \
    "${MAXMIND_URL}?edition_id=${edition_id}&license_key=${LICENSE_KEY}&suffix=tar.gz" \
    -o "$tmp_file"

  rm -rf "$extract_dir"
  mkdir -p "$extract_dir"
  tar -xzf "$tmp_file" -C "$extract_dir" --strip-components=1

  local mmdb_src
  mmdb_src=$(find "$extract_dir" -name "${edition_id}.mmdb" | head -n 1)

  if [[ -z "$mmdb_src" ]]; then
    echo "Error: ${edition_id}.mmdb not found in downloaded archive." >&2
    rm -rf "$tmp_file" "$extract_dir"
    return 1
  fi

  # Atomic rename
  mv "$mmdb_src" "${output_file}.new"
  mv "${output_file}.new" "$output_file"

  rm -rf "$tmp_file" "$extract_dir"
  echo "  → saved to ${output_file}"
}

# ── Main ──────────────────────────────────────────────────────────────────────
ANY_OK=false

for EDITION in GeoLite2-Country GeoLite2-ASN; do
  if download_db "$EDITION"; then
    ANY_OK=true
  else
    echo "Warning: failed to download ${EDITION}" >&2
  fi
done

if [[ "$ANY_OK" != "true" ]]; then
  echo "Error: no databases were downloaded." >&2
  exit 1
fi

echo "GeoIP databases updated in ${GEOIP_DIR}"
