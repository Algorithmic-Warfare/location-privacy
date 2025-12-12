#!/usr/bin/env bash
set -euo pipefail

# Simple file watcher that doesn't require watchexec
# Watches packages/location/sources for .move file changes

PKG_DIR="packages/location"
SOURCES_DIR="$PKG_DIR/sources"

echo "Watching $SOURCES_DIR for changes..."
echo "Press Ctrl+C to stop"
echo ""

# Get initial checksum
get_checksum() {
    find "$SOURCES_DIR" -name "*.move" -type f -exec md5 {} \; 2>/dev/null | md5 || echo "none"
}

LAST_CHECKSUM=$(get_checksum)

# Initial build and publish
bash scripts/deploy_watch.sh

while true; do
    sleep 2
    CURRENT_CHECKSUM=$(get_checksum)
    
    if [ "$CURRENT_CHECKSUM" != "$LAST_CHECKSUM" ]; then
        echo ""
        echo "==============================================="
        echo "Change detected, rebuilding..."
        echo "==============================================="
        bash scripts/deploy_watch.sh
        LAST_CHECKSUM=$(get_checksum)
    fi
done
