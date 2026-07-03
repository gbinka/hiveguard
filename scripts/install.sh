#!/usr/bin/env bash
# HiveGuard install script
# Usage: sudo ./install.sh [path-to-binary]
#
# Installs the hiveguard binary, creates a system user, sets up the config
# directory and data directory, installs the systemd service, and enables it.

set -euo pipefail

BINARY="${1:-./target/release/hiveguard-daemon}"
INSTALL_BIN="/usr/local/bin/hiveguard"
CONFIG_DIR="/etc/hiveguard"
CONFIG_FILE="${CONFIG_DIR}/config.yaml"
DATA_DIR="/var/lib/hiveguard"
SERVICE_SRC="$(dirname "$0")/../hiveguard.service"
SERVICE_DST="/etc/systemd/system/hiveguard.service"
USER="hiveguard"
GROUP="hiveguard"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

# Must run as root
if [[ $EUID -ne 0 ]]; then
    error "This script must be run as root (use sudo)"
    exit 1
fi

# Check that the binary exists
if [[ ! -f "$BINARY" ]]; then
    error "Binary not found: $BINARY"
    echo "  Build first: cargo build --release -p hiveguard-daemon"
    echo "  Or provide path: $0 /path/to/hiveguard-daemon"
    exit 1
fi

# Check that the service file exists
if [[ ! -f "$SERVICE_SRC" ]]; then
    error "Service file not found: $SERVICE_SRC"
    exit 1
fi

# --- Step 1: Create system user ---
if id "$USER" &>/dev/null; then
    info "System user '$USER' already exists"
else
    info "Creating system user '$USER'"
    useradd --system --no-create-home --shell /usr/sbin/nologin "$USER"
fi

# --- Step 2: Install binary ---
info "Installing binary to $INSTALL_BIN"
install -m 0755 "$BINARY" "$INSTALL_BIN"

# --- Step 3: Create config directory and install config ---
info "Setting up config directory $CONFIG_DIR"
mkdir -p "$CONFIG_DIR"

if [[ -f "$CONFIG_FILE" ]]; then
    warn "Config file already exists at $CONFIG_FILE — not overwriting"
else
    EXAMPLE_CONFIG="$(dirname "$0")/../config.example.yaml"
    if [[ -f "$EXAMPLE_CONFIG" ]]; then
        info "Installing example config to $CONFIG_FILE"
        install -m 0640 "$EXAMPLE_CONFIG" "$CONFIG_FILE"
        chown root:"$GROUP" "$CONFIG_FILE"
    else
        warn "No example config found; create $CONFIG_FILE manually"
    fi
fi

# --- Step 4: Create data directory ---
info "Creating data directory $DATA_DIR"
mkdir -p "$DATA_DIR"
chown "$USER":"$GROUP" "$DATA_DIR"
chmod 0750 "$DATA_DIR"

# --- Step 5: Install systemd service ---
info "Installing systemd service to $SERVICE_DST"
install -m 0644 "$SERVICE_SRC" "$SERVICE_DST"

# --- Step 6: Reload systemd and enable service ---
info "Reloading systemd daemon"
systemctl daemon-reload

info "Enabling hiveguard service"
systemctl enable hiveguard

echo ""
info "Installation complete!"
echo ""
echo "  Next steps:"
echo "    1. Edit configuration:  sudo nano $CONFIG_FILE"
echo "    2. Start the service:   sudo systemctl start hiveguard"
echo "    3. Check status:        sudo systemctl status hiveguard"
echo "    4. View logs:           sudo journalctl -u hiveguard -f"
echo ""
