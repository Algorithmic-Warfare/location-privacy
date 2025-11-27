#!/usr/bin/env bash
set -euo pipefail

PKG_DIR="packages/location"

echo "Building Move package..."
sui move build --path "$PKG_DIR"

echo "Running Move tests..."
sui move test --path "$PKG_DIR"
