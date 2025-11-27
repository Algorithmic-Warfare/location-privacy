#!/usr/bin/env bash
set -euo pipefail

PUBLISH_SCRIPT="./scripts/publish_local.sh"
PKG_DIR="packages/location"

echo "[watch] Move source changed, rebuilding..."

# Build Move package
if sui move build --path "$PKG_DIR"; then
    echo "[watch] Build succeeded"
else
    echo "[watch] Build failed" >&2
    exit 1
fi

# Publish to local network
if bash "$PUBLISH_SCRIPT" "$PKG_DIR"; then
    echo "[watch] Publish succeeded"
else
    echo "[watch] Publish failed" >&2
    exit 1
fi
