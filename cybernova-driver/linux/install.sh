#!/bin/bash
#
# CyberNova LSM Module — Build & Install Script
# Installs the kernel module and sets up securityfs.
#
# Usage:
#   ./install.sh              # Build + Install
#   ./install.sh --uninstall   # Remove module
#
set -e

MODULE="cybernova_lsm"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[+]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
err()   { echo -e "${RED}[-]${NC} $1"; }

if [ "$EUID" -ne 0 ]; then
    err "Please run as root (sudo)"
    exit 1
fi

# ── Uninstall ───────────────────────────────────────────────────────────────

if [ "$1" == "--uninstall" ]; then
    info "Unloading CyberNova LSM..."
    if lsmod | grep -q "^${MODULE}"; then
        rmmod "$MODULE"
        info "Module unloaded"
    else
        warn "Module not loaded"
    fi
    info "Cleanup complete"
    exit 0
fi

# ── Check prerequisites ─────────────────────────────────────────────────────

info "Checking prerequisites..."

if ! command -v make &>/dev/null; then
    err "make not found. Install build-essential: apt install build-essential"
    exit 1
fi

KVERSION=$(uname -r)
KHEADERS="/lib/modules/${KVERSION}/build"
if [ ! -d "$KHEADERS" ]; then
    err "Kernel headers not found for ${KVERSION}."
    err "Install: apt install linux-headers-${KVERSION}"
    exit 1
fi
info "Kernel: ${KVERSION}"

# ── Build ───────────────────────────────────────────────────────────────────

info "Building module..."
cd "$SCRIPT_DIR"
make clean 2>/dev/null || true
make -C "$KHEADERS" M="$PWD" modules

if [ ! -f "${MODULE}.ko" ]; then
    err "Build failed — ${MODULE}.ko not found"
    exit 1
fi
info "Build successful: ${MODULE}.ko"

# ── Install ─────────────────────────────────────────────────────────────────

info "Installing module..."
MODDIR="/lib/modules/${KVERSION}/extra"
mkdir -p "$MODDIR"
cp "${MODULE}.ko" "$MODDIR/"
depmod -a

# Load module
info "Loading CyberNova LSM..."
insmod "${MODULE}.ko"

if lsmod | grep -q "^${MODULE}"; then
    info "Module loaded successfully"
else
    err "Module failed to load — check dmesg"
    dmesg | tail -5
    exit 1
fi

# ── Mount securityfs ────────────────────────────────────────────────────────

SYSFS_PATH="/sys/kernel/security/${MODULE}"
if [ ! -d "$SYSFS_PATH" ]; then
    info "Mounting securityfs..."
    mount -t securityfs securityfs /sys/kernel/security 2>/dev/null || true
    if [ ! -d "$SYSFS_PATH" ]; then
        warn "securityfs not available — blocklist updates will fail"
        warn "Try: mount -t securityfs securityfs /sys/kernel/security"
    fi
fi

if [ -d "$SYSFS_PATH" ]; then
    info "CyberNova LSM ready at ${SYSFS_PATH}"
    echo "  blocklist  : ${SYSFS_PATH}/blocklist  (write to update, read to list)"
    echo "  stats      : ${SYSFS_PATH}/stats      (read-only)"
fi

# ── Persist (optional) ──────────────────────────────────────────────────────

if [ ! -f "/etc/modules-load.d/${MODULE}.conf" ]; then
    info "To load on boot:"
    echo "  echo '${MODULE}' > /etc/modules-load.d/${MODULE}.conf"
    echo "  echo 'securityfs /sys/kernel/security securityfs defaults 0 0' >> /etc/fstab"
fi

info "Installation complete."
echo ""
echo "Usage:"
echo "  # Update blocklist (one hash per line: <hex> [severity] [description])"
echo "  echo 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 99 test' > ${SYSFS_PATH}/blocklist"
echo ""
echo "  # View stats"
echo "  cat ${SYSFS_PATH}/stats"
echo ""
echo "  # Clear blocklist"
echo "  echo 'clear' > ${SYSFS_PATH}/blocklist"
