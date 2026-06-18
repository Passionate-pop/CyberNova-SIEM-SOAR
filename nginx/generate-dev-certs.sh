#!/bin/bash
# Generate self-signed SSL certificates for CyberNova development
set -e

CERT_DIR="$(dirname "$0")/ssl"
mkdir -p "$CERT_DIR"

if [ ! -f "$CERT_DIR/cert.pem" ] || [ ! -f "$CERT_DIR/key.pem" ]; then
    echo "[ssl] Generating self-signed SSL certificates for development..."
    openssl req -x509 -nodes -days 365 \
        -newkey rsa:2048 \
        -keyout "$CERT_DIR/key.pem" \
        -out "$CERT_DIR/cert.pem" \
        -subj "/C=US/ST=Local/L=Local/O=CyberNova/CN=localhost" \
        2>/dev/null
    echo "[ssl] SSL certificates generated in $CERT_DIR/"
else
    echo "[ssl] SSL certificates already exist in $CERT_DIR/"
fi
