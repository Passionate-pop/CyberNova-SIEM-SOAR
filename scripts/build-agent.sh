#!/usr/bin/env bash
set -euo pipefail

# CyberNova Rust Agent Build Script
# Produces statically-linked binaries for Linux x86_64 and aarch64
# Uses cross (https://github.com/cross-rs/cross) for cross-compilation

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
AGENT_DIR="$PROJECT_ROOT/agent/rust"
OUTPUT_DIR="$PROJECT_ROOT/dist/agent"

BIN_NAME="cybernova-agent"
VERSION="${1:-$(cargo pkgid 2>/dev/null | cut -d# -f2 | cut -d: -f2 || echo "0.1.0")}"

TARGETS=(
    "x86_64-unknown-linux-musl"
    "aarch64-unknown-linux-musl"
)

echo "==> CyberNova Agent Build v$VERSION"
echo "    Project root: $PROJECT_ROOT"
echo ""

# ----- Check for cross -----
if ! command -v cross &>/dev/null; then
    echo "==> Installing cross..."
    cargo install cross --git https://github.com/cross-rs/cross
fi

# ----- Build for each target -----
mkdir -p "$OUTPUT_DIR"

for target in "${TARGETS[@]}"; do
    echo "==> Building for $target..."

    cross build \
        --manifest-path "$AGENT_DIR/Cargo.toml" \
        --release \
        --target "$target"

    # Extract arch from target triple
    arch=$(echo "$target" | cut -d- -f1)

    src="$AGENT_DIR/target/$target/release/$BIN_NAME"
    dst="$OUTPUT_DIR/${BIN_NAME}-linux-${arch}-v${VERSION}"

    if [ -f "$src" ]; then
        cp "$src" "$dst"
        chmod 755 "$dst"
        sha256sum "$dst" | cut -d' ' -f1 > "${dst}.sha256"
        echo "    -> $dst ($(du -h "$dst" | cut -f1))"
    else
        echo "    !! Build artifact not found: $src"
        exit 1
    fi
done

# ----- Create convenience symlinks -----
ln -sf "${BIN_NAME}-linux-x86_64-v${VERSION}" "$OUTPUT_DIR/${BIN_NAME}-linux-amd64"
ln -sf "${BIN_NAME}-linux-aarch64-v${VERSION}" "$OUTPUT_DIR/${BIN_NAME}-linux-arm64"

echo ""
echo "==> Build complete. Output in: $OUTPUT_DIR"
ls -lh "$OUTPUT_DIR"
