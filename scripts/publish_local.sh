#!/usr/bin/env bash
set -euo pipefail

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required" >&2
  exit 1
fi

PACKAGE_PATH=${1:-packages/location}

cd "$PACKAGE_PATH"

if [ ! -f "./Move.toml" ]; then
  echo "Expected Move.toml in $PACKAGE_PATH, but not found." >&2
  exit 1
fi

echo "Publishing location package ($PACKAGE_PATH) to local network (capturing JSON output)..."

# Prefer JSON output for reliable parsing. Capture ONLY stdout (pure JSON) then echo it for visibility.
if ! PUBLISH_JSON=$(sui client publish --gas-budget 30000000 --skip-dependency-verification --json ); then
  echo "Publish command failed (non-zero exit)." >&2
  exit 1
fi
echo "$PUBLISH_JSON" >&2

# Persist raw output for debugging (rotated to keep only last 5 copies)
LOG_FILE=.last_publish_output.json
if [ -f "$LOG_FILE" ]; then
  mv "$LOG_FILE" "$LOG_FILE.$(date +%s)" 2>/dev/null || true
  ls -t .last_publish_output.json.* 2>/dev/null | tail -n +6 | xargs -r rm -- 2>/dev/null || true
fi
echo "$PUBLISH_JSON" > "$LOG_FILE"

# Try multiple strategies to extract the package id.
PACKAGE_ID=$(echo "$PUBLISH_JSON" | jq -r '.packageId // empty')
if [ -z "$PACKAGE_ID" ] || [ "$PACKAGE_ID" = "null" ]; then
  # Fallback: look in objectChanges for published type (most reliable for newer CLI)
  PACKAGE_ID=$(echo "$PUBLISH_JSON" | jq -r '.objectChanges[]? | select(.type == "published") | .packageId' | head -n1)
fi
if [ -z "$PACKAGE_ID" ] || [ "$PACKAGE_ID" = "null" ]; then
  # Fallback: look into created objects for an immutable object id (older CLI variants)
  PACKAGE_ID=$(echo "$PUBLISH_JSON" | jq -r '.effects.created[]? | select(.owner=="Immutable").reference.objectId' | head -n1)
fi
if [ -z "$PACKAGE_ID" ] || [ "$PACKAGE_ID" = "null" ]; then
  # Final grep fallback (case-insensitive) if JSON parse failed for some reason (e.g., non-json sections interleaved)
  PACKAGE_ID=$(echo "$PUBLISH_JSON" | grep -Eio 'package[id[:space:]]+0x[0-9a-f]{64}' | grep -Eio '0x[0-9a-f]{64}' | head -n1 || true)
fi

if [ -z "$PACKAGE_ID" ]; then
  echo "Failed to parse package id from publish output. See $LOG_FILE for raw output." >&2
  # Do NOT silently succeed; this should remain a hard failure so callers can react.
  exit 1
fi

# Extract ServerCap ID from created objects
SERVER_CAP_ID=$(echo "$PUBLISH_JSON" | jq -r '.objectChanges[]? | select(.objectType // "" | contains("::ServerCap")) | .objectId' | head -n1)
if [ -z "$SERVER_CAP_ID" ] || [ "$SERVER_CAP_ID" = "null" ]; then
  echo "Warning: Failed to parse ServerCap ID from publish output. Manual setup required." >&2
  SERVER_CAP_ID=""
fi

# Store deployment info in package directory
cat > .env.local <<EOF
PACKAGE_ID=$PACKAGE_ID
SERVER_CAP_ID=$SERVER_CAP_ID
EOF

echo "Stored deployment info in .env.local"
echo "PACKAGE_ID=$PACKAGE_ID"
echo "SERVER_CAP_ID=$SERVER_CAP_ID"

# Update proof-server .env file with package ID and ServerCap ID
PROOF_SERVER_ENV="../../crates/proof-server/.env"
if [ ! -f "$PROOF_SERVER_ENV" ]; then
  # Create from example if doesn't exist
  if [ -f "../../crates/proof-server/.env.example" ]; then
    cp "../../crates/proof-server/.env.example" "$PROOF_SERVER_ENV"
    echo "Created $PROOF_SERVER_ENV from .env.example"
  else
    touch "$PROOF_SERVER_ENV"
    echo "Created empty $PROOF_SERVER_ENV"
  fi
fi

# Update or add the package ID
if grep -q "^SUI_PACKAGE_ID=" "$PROOF_SERVER_ENV"; then
  sed -i.bak "s|^SUI_PACKAGE_ID=.*|SUI_PACKAGE_ID=$PACKAGE_ID|" "$PROOF_SERVER_ENV"
else
  echo "" >> "$PROOF_SERVER_ENV"
  echo "SUI_PACKAGE_ID=$PACKAGE_ID" >> "$PROOF_SERVER_ENV"
fi

# Update or add the ServerCap ID (only if we found one)
if [ -n "$SERVER_CAP_ID" ]; then
  if grep -q "^SUI_SERVER_CAP_ID=" "$PROOF_SERVER_ENV"; then
    sed -i.bak "s|^SUI_SERVER_CAP_ID=.*|SUI_SERVER_CAP_ID=$SERVER_CAP_ID|" "$PROOF_SERVER_ENV"
  else
    echo "SUI_SERVER_CAP_ID=$SERVER_CAP_ID" >> "$PROOF_SERVER_ENV"
  fi
fi

# Clean up backup files
rm -f "${PROOF_SERVER_ENV}.bak"

echo "✓ Updated $PROOF_SERVER_ENV:"
echo "  - SUI_PACKAGE_ID=$PACKAGE_ID"
if [ -n "$SERVER_CAP_ID" ]; then
  echo "  - SUI_SERVER_CAP_ID=$SERVER_CAP_ID"
fi

# Update proof-client .env file (only add proof server URL if missing)
PROOF_CLIENT_ENV="../../packages/proof-client/.env"
if [ ! -f "$PROOF_CLIENT_ENV" ]; then
  touch "$PROOF_CLIENT_ENV"
  echo "Created $PROOF_CLIENT_ENV"
fi

# Add proof server URL if not present
if ! grep -q "^VITE_PROOF_SERVER_URL=" "$PROOF_CLIENT_ENV"; then
  echo "VITE_PROOF_SERVER_URL=http://localhost:3001" >> "$PROOF_CLIENT_ENV"
  echo "✓ Added VITE_PROOF_SERVER_URL to $PROOF_CLIENT_ENV"
fi

cd - > /dev/null
