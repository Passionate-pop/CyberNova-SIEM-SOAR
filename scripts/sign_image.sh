#!/usr/bin/env bash
set -euo pipefail

# ── CyberNova container image signing with cosign ──────────────
# Usage:
#   ./scripts/sign_image.sh <image:tag>                 # keyless (OIDC)
#   ./scripts/sign_image.sh <image:tag> <key-ref>       # key-based
#
# Examples:
#   ./scripts/sign_image.sh cybernova:latest
#   ./scripts/sign_image.sh cybernova:v1.2.3 cosign.key
#   COSIGN_PASSWORD=secret ./scripts/sign_image.sh cybernova:v1.2.3 cosign.key

IMAGE="${1:?Usage: $0 <image:tag> [key-ref]}"
KEY="${2:-}"

if ! command -v cosign &>/dev/null; then
    echo "ERROR: cosign not found. Install it from https://github.com/sigstore/cosign"
    exit 1
fi

echo "=== Signing image: $IMAGE ==="

if [ -n "$KEY" ]; then
    echo "Using key: $KEY"
    cosign sign --key "$KEY" "$IMAGE"
else
    echo "Using keyless signing (OIDC)"
    COSIGN_EXPERIMENTAL=1 cosign sign "$IMAGE"
fi

echo "=== Verification ==="
cosign verify "$IMAGE" ${KEY:+--key "$KEY"} 2>&1 | head -5
echo "=== Image signed successfully ==="
