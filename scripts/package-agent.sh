#!/usr/bin/env bash
# ============================================================================
# CyberNova Agent Packaging Script
# Produces: RPM, DEB, Homebrew formula, Windows MSI
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
AGENT_DIR="$PROJECT_ROOT/agent/rust"
DIST_DIR="$PROJECT_ROOT/dist/agent"
BUILD_DIR="$PROJECT_ROOT/build/agent-pkg"

VERSION="${1:-$(grep '^version = ' "$AGENT_DIR/Cargo.toml" | head -1 | cut -d'"' -f2)}"
ITERATION="${2:-1}"
MAINTAINER="CyberNova <support@cybernova.ai>"
DESCRIPTION="CyberNova security monitoring agent - endpoint telemetry collector"
LICENSE="MIT"
VENDOR="CyberNova"
URL="https://cybernova.ai"

# --- Prerequisites -----------------------------------------------------------
command -v fpm &>/dev/null || { echo "ERROR: fpm (effing package manager) is required. Install via: gem install fpm"; exit 1; }
command -v curl &>/dev/null || { echo "ERROR: curl is required"; exit 1; }

mkdir -p "$BUILD_DIR" "$DIST_DIR"

# --- Build the binary if not already built -----------------------------------
BINARY="$DIST_DIR/cybernova-agent"
if [ ! -f "$BINARY" ]; then
    echo "==> Binary not found, building..."
    bash "$SCRIPT_DIR/build-agent.sh" "$VERSION"
fi

# --- Staging directory -------------------------------------------------------
STAGING="$BUILD_DIR/staging"
rm -rf "$STAGING"
mkdir -p "$STAGING"

# --- File layout -------------------------------------------------------------
# /opt/cybernova/bin/cybernova-agent
# /etc/cybernova/agent.toml
# /etc/cybernova/certs/             (admin provisions certs)
# /var/lib/cybernova/              (SQLite DB)
# /var/log/cybernova/              (logs)
# /lib/systemd/system/cybernova-agent.service

BINDIR="$STAGING/opt/cybernova/bin"
CONFDIR="$STAGING/etc/cybernova"
SERVICEDIR="$STAGING/lib/systemd/system"
VARDIR="$STAGING/var/lib/cybernova"
LOGDIR="$STAGING/var/log/cybernova"

mkdir -p "$BINDIR" "$CONFDIR" "$SERVICEDIR" "$VARDIR" "$LOGDIR"

cp "$PROJECT_ROOT/agent/rust/agent.toml.example" "$CONFDIR/agent.toml"
cp "$PROJECT_ROOT/agent/agent.service" "$SERVICEDIR/cybernova-agent.service"
cp "$BINARY" "$BINDIR/cybernova-agent"
chmod 755 "$BINDIR/cybernova-agent"

# --- Pre/post install scripts ------------------------------------------------
mkdir -p "$BUILD_DIR/scripts"

cat > "$BUILD_DIR/scripts/postinst" <<'POSTINST'
#!/bin/sh
set -e

# Create cybernova user if not exists
if ! getent passwd cybernova >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin cybernova
fi

# Set permissions on data/log directories
chown -R cybernova:cybernova /var/lib/cybernova /var/log/cybernova
chmod 750 /var/lib/cybernova /var/log/cybernova
chown root:root /opt/cybernova/bin/cybernova-agent
chmod 755 /opt/cybernova/bin/cybernova-agent

# Reload systemd and enable service
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload
    systemctl enable cybernova-agent
    echo "==> cybernova-agent enabled. Start with: systemctl start cybernova-agent"
fi
POSTINST

cat > "$BUILD_DIR/scripts/prerm" <<'PRERM'
#!/bin/sh
set -e
if command -v systemctl >/dev/null 2>&1; then
    systemctl stop cybernova-agent 2>/dev/null || true
    systemctl disable cybernova-agent 2>/dev/null || true
fi
PRERM

cat > "$BUILD_DIR/scripts/postrm" <<'POSTRM'
#!/bin/sh
set -e
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload
fi
# Remove data only on purge
if [ "$1" = "purge" ]; then
    rm -rf /var/lib/cybernova /var/log/cybernova
fi
POSTRM

chmod +x "$BUILD_DIR/scripts/postinst" "$BUILD_DIR/scripts/prerm" "$BUILD_DIR/scripts/postrm"


# =============================================================================
# 1. RPM — Red Hat / CentOS / Fedora
# =============================================================================
echo ""
echo "==> Building RPM..."

fpm --input-type dir \
    --output-type rpm \
    --name cybernova-agent \
    --version "$VERSION" \
    --iteration "$ITERATION" \
    --vendor "$VENDOR" \
    --maintainer "$MAINTAINER" \
    --description "$DESCRIPTION" \
    --url "$URL" \
    --license "$LICENSE" \
    --architecture x86_64 \
    --category "System Environment/Daemons" \
    --rpm-user cybernova \
    --rpm-group cybernova \
    --rpm-digest sha256 \
    --after-install "$BUILD_DIR/scripts/postinst" \
    --before-remove "$BUILD_DIR/scripts/prerm" \
    --after-remove "$BUILD_DIR/scripts/postrm" \
    --package "$DIST_DIR/cybernova-agent-${VERSION}-${ITERATION}.x86_64.rpm" \
    --directories /opt/cybernova \
    --directories /etc/cybernova \
    --directories /var/lib/cybernova \
    --directories /var/log/cybernova \
    "$STAGING/="

echo "    -> $DIST_DIR/cybernova-agent-${VERSION}-${ITERATION}.x86_64.rpm"


# =============================================================================
# 2. DEB — Debian / Ubuntu
# =============================================================================
echo ""
echo "==> Building DEB..."

fpm --input-type dir \
    --output-type deb \
    --name cybernova-agent \
    --version "$VERSION" \
    --iteration "$ITERATION" \
    --vendor "$VENDOR" \
    --maintainer "$MAINTAINER" \
    --description "$DESCRIPTION" \
    --url "$URL" \
    --license "$LICENSE" \
    --architecture amd64 \
    --deb-user cybernova \
    --deb-group cybernova \
    --deb-priority optional \
    --after-install "$BUILD_DIR/scripts/postinst" \
    --before-remove "$BUILD_DIR/scripts/prerm" \
    --after-remove "$BUILD_DIR/scripts/postrm" \
    --package "$DIST_DIR/cybernova-agent_${VERSION}-${ITERATION}_amd64.deb" \
    --directories /opt/cybernova \
    --directories /etc/cybernova \
    --directories /var/lib/cybernova \
    --directories /var/log/cybernova \
    "$STAGING/="

echo "    -> $DIST_DIR/cybernova-agent_${VERSION}-${ITERATION}_amd64.deb"


# =============================================================================
# 3. Homebrew Formula — macOS
# =============================================================================
echo ""
echo "==> Building Homebrew formula..."

BREW_DIR="$BUILD_DIR/homebrew"
mkdir -p "$BREW_DIR"

BINARY_AMD64="$DIST_DIR/cybernova-agent-linux-x86_64-v${VERSION}"
BINARY_ARM64="$DIST_DIR/cybernova-agent-linux-aarch64-v${VERSION}"

SHA256_AMD64=""
SHA256_ARM64=""

if [ -f "${BINARY_AMD64}.sha256" ]; then
    SHA256_AMD64=$(cat "${BINARY_AMD64}.sha256")
fi
if [ -f "${BINARY_ARM64}.sha256" ]; then
    SHA256_ARM64=$(cat "${BINARY_ARM64}.sha256")
fi

cat > "$BREW_DIR/cybernova-agent.rb" <<FORMULA
# typed: false
# frozen_string_literal: true

class CybernovaAgent < Formula
  desc "${DESCRIPTION}"
  homepage "${URL}"
  license "${LICENSE}"
  version "${VERSION}"

  on_macos do
    if Hardware::CPU.arm?
      url "${URL}/releases/download/v${VERSION}/cybernova-agent-darwin-arm64-v${VERSION}.tar.gz"
      sha256 "${SHA256_ARM64}"
    else
      url "${URL}/releases/download/v${VERSION}/cybernova-agent-darwin-amd64-v${VERSION}.tar.gz"
      sha256 "${SHA256_AMD64}"
    end
  end

  def install
    bin.install "cybernova-agent"
    etc.install "agent.toml" => "cybernova/agent.toml" unless build.head?
  end

  service do
    run [opt_bin/"cybernova-agent", "--config", etc/"cybernova/agent.toml"]
    keep_alive true
    run_type :immediate
    log_path var/"log/cybernova-agent.log"
    error_log_path var/"log/cybernova-agent.error.log"
  end

  test do
    system "#{bin}/cybernova-agent", "--help"
  end
end
FORMULA

cp "$BREW_DIR/cybernova-agent.rb" "$DIST_DIR/cybernova-agent.rb"
echo "    -> $DIST_DIR/cybernova-agent.rb"

# Also create a macOS release tarball placeholder
cat > "$BUILD_DIR/build-macos.sh" <<'MACOS'
#!/usr/bin/env bash
# Build macOS agent binary (run on macOS build host)
set -euo pipefail
VERSION="${1:-0.1.0}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
AGENT_DIR="$PROJECT_ROOT/agent/rust"
DIST_DIR="$PROJECT_ROOT/dist/agent"

for arch in "x86_64-apple-darwin" "aarch64-apple-darwin"; do
    echo "==> Building for $arch..."
    rustup target add "$arch" 2>/dev/null || true
    cargo build --manifest-path "$AGENT_DIR/Cargo.toml" --release --target "$arch"

    target_arch="amd64"
    [[ "$arch" == aarch64* ]] && target_arch="arm64"
    src="$AGENT_DIR/target/$arch/release/cybernova-agent"
    dst="$DIST_DIR/cybernova-agent-darwin-${target_arch}-v${VERSION}"
    cp "$src" "$dst"
    chmod 755 "$dst"
    tar czf "${dst}.tar.gz" -C "$(dirname "$dst")" "$(basename "$dst")"
    echo "    -> ${dst}.tar.gz"
done
MACOS
chmod +x "$BUILD_DIR/build-macos.sh"


# =============================================================================
# 4. Windows MSI — via WiX Toolset
# =============================================================================
echo ""
echo "==> Building Windows MSI..."

WIX_DIR="$BUILD_DIR/wix"
mkdir -p "$WIX_DIR"

# WiX 3.x XML definition
cat > "$WIX_DIR/cybernova-agent.wxs" <<'WIX'
<?xml version="1.0" encoding="UTF-8"?>
<Wix xmlns="http://schemas.microsoft.com/wix/2006/wi">
    <Product Id="*"
             Name="CyberNova Agent"
             Language="1033"
             Version="$(var.Version)"
             Manufacturer="CyberNova"
             UpgradeCode="A1B2C3D4-E5F6-7890-ABCD-EF1234567890">

        <Package InstallerVersion="200"
                 Compressed="yes"
                 InstallScope="perMachine"
                 Platform="x64" />

        <MajorUpgrade DowngradeErrorMessage="A newer version of CyberNova Agent is already installed." />
        <MediaTemplate EmbedCab="yes" />

        <!-- Directory structure -->
        <Directory Id="TARGETDIR" Name="SourceDir">
            <Directory Id="ProgramFiles64Folder">
                <Directory Id="CYBERNOVA_DIR" Name="CyberNova">
                    <Directory Id="INSTALLDIR" Name="Agent">
                        <Directory Id="BINDIR" Name="bin" />
                        <Directory Id="CONFDIR" Name="config" />
                        <Directory Id="DATADIR" Name="data" />
                        <Directory Id="LOGDIR" Name="logs" />
                    </Directory>
                </Directory>
            </Directory>
            <Directory Id="ProgramMenuFolder">
                <Directory Id="StartMenuDir" Name="CyberNova" />
            </Directory>
        </Directory>

        <!-- Files -->
        <DirectoryRef Id="BINDIR">
            <Component Id="AgentBinary" Guid="*">
                <File Id="cybernova_agent_exe"
                      Name="cybernova-agent.exe"
                      Source="$(var.BinaryPath)"
                      Vital="yes"
                      KeyPath="yes" />
            </Component>
        </DirectoryRef>

        <DirectoryRef Id="CONFDIR">
            <Component Id="AgentConfig" Guid="*">
                <File Id="agent_toml"
                      Name="agent.toml"
                      Source="$(var.ConfigPath)"
                      Vital="yes"
                      KeyPath="yes" />
            </Component>
        </DirectoryRef>

        <!-- Service installation -->
        <Component Id="AgentService" Guid="*" DirectoryRef="BINDIR">
            <ServiceInstall Id="CyberNovaAgentService"
                            Name="CyberNovaAgent"
                            DisplayName="CyberNova Security Agent"
                            Description="Endpoint telemetry collector for CyberNova SIEM"
                            Type="ownProcess"
                            Start="auto"
                            ErrorControl="normal"
                            Arguments='--config "[CONFDIR]agent.toml"'
                            Vital="yes" />
            <ServiceControl Id="StartService"
                            Name="CyberNovaAgent"
                            Start="install"
                            Stop="both"
                            Remove="uninstall" />
        </Component>

        <!-- Start menu shortcut -->
        <DirectoryRef Id="StartMenuDir">
            <Component Id="StartMenuShortcut" Guid="*">
                <Shortcut Id="DocShortcut"
                          Name="CyberNova Agent Docs"
                          Description="CyberNova Agent Documentation"
                          Target="https://cybernova.ai/docs/agent" />
                <RemoveFolder Id="StartMenuDir" On="uninstall" />
                <RegistryValue Root="HKCU"
                               Key="Software\CyberNova\Agent"
                               Name="installed"
                               Type="integer"
                               Value="1"
                               KeyPath="yes" />
            </Component>
        </DirectoryRef>

        <!-- Features -->
        <Feature Id="Complete" Level="1">
            <ComponentRef Id="AgentBinary" />
            <ComponentRef Id="AgentConfig" />
            <ComponentRef Id="AgentService" />
            <ComponentRef Id="StartMenuShortcut" />
        </Feature>
    </Product>
</Wix>
WIX

# MSI build helper script (WiX required on build host)
cat > "$BUILD_DIR/build-msi.sh" <<'MSI'
#!/usr/bin/env bash
# Build Windows MSI package (requires WiX toolset on Linux or Windows)
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$SCRIPT_DIR/../.."
AGENT_DIR="$PROJECT_ROOT/agent/rust"
DIST_DIR="$PROJECT_ROOT/dist/agent"
WIX_DIR="$SCRIPT_DIR/wix"
VERSION="${1:-0.1.0}"

# Cross-compile the Windows binary first (on Linux using cross)
cross build --manifest-path "$AGENT_DIR/Cargo.toml" --release --target x86_64-pc-windows-gnu
BINARY="$AGENT_DIR/target/x86_64-pc-windows-gnu/release/cybernova-agent.exe"
CONFIG="$PROJECT_ROOT/agent/rust/agent.toml.example"

# Use candle + light from WiX (or wine + WiX)
if command -v candle &>/dev/null; then
    candle -dVERSION="$VERSION" -dBinaryPath="$BINARY" -dConfigPath="$CONFIG" \
        -out "$WIX_DIR/cybernova-agent.wixobj" "$WIX_DIR/cybernova-agent.wxs"
    light -out "$DIST_DIR/cybernova-agent-${VERSION}-x64.msi" \
        "$WIX_DIR/cybernova-agent.wixobj"
    echo "    -> $DIST_DIR/cybernova-agent-${VERSION}-x64.msi"
else
    echo "WARN: WiX (candle/light) not found. Skipping MSI."
    echo "      Install via: apt install wixl or from https://wixtoolset.org"
fi
MSI
chmod +x "$BUILD_DIR/build-msi.sh" "$BUILD_DIR/build-macos.sh"

# Copy helper scripts to dist
cp "$BUILD_DIR/build-macos.sh" "$DIST_DIR/build-macos.sh"
cp "$BUILD_DIR/build-msi.sh" "$DIST_DIR/build-msi.sh"


# =============================================================================
# Summary
# =============================================================================
echo ""
echo "================================================================================"
echo "  CyberNova Agent Packaging Complete v$VERSION"
echo "================================================================================"
echo ""
echo "Output directory: $DIST_DIR"
echo ""
ls -lh "$DIST_DIR"/*.rpm "$DIST_DIR"/*.deb 2>/dev/null || true
echo ""
echo "To install:"
echo "  DEB:  sudo dpkg -i cybernova-agent_${VERSION}-${ITERATION}_amd64.deb"
echo "  RPM:  sudo rpm -ivh cybernova-agent-${VERSION}-${ITERATION}.x86_64.rpm"
echo "  macOS: brew install cybernova-agent.rb"
echo "  Windows: cybernova-agent-${VERSION}-x64.msi"
echo ""
echo "Note: macOS and Windows binaries require native build hosts."
echo "      See build/build-macos.sh and build/build-msi.sh for details."
