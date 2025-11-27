#!/usr/bin/env bash
set -euo pipefail

# Automated commitment publishing script
# This script fetches commitment bytes from the proof server and publishes them on-chain

PROOF_SERVER_URL="${PROOF_SERVER_URL:-http://localhost:3001}"

echo "=== Automated Commitment Publishing ==="
echo ""

# Read package ID and server cap from env file
if [ ! -f "crates/proof-server/.env" ]; then
  echo "Error: crates/proof-server/.env not found" >&2
  exit 1
fi

source crates/proof-server/.env

if [ -z "${SUI_PACKAGE_ID:-}" ]; then
  echo "Error: SUI_PACKAGE_ID not set in crates/proof-server/.env" >&2
  exit 1
fi

if [ -z "${SUI_SERVER_CAP_ID:-}" ]; then
  echo "Error: SUI_SERVER_CAP_ID not set in crates/proof-server/.env" >&2
  exit 1
fi

echo "Package ID: $SUI_PACKAGE_ID"
echo "ServerCap ID: $SUI_SERVER_CAP_ID"
echo ""

# Fetch commitment bytes from server
echo "Fetching commitment bytes from server..."
COMMITMENT_HEX=$(curl -s "$PROOF_SERVER_URL/api/info" | jq -r '.commitment_bytes')

if [ -z "$COMMITMENT_HEX" ] || [ "$COMMITMENT_HEX" = "null" ]; then
  echo "Error: Could not fetch commitment bytes from server" >&2
  exit 1
fi

echo "Commitment: $COMMITMENT_HEX"
echo ""

# Get active address
ACTIVE_ADDRESS=$(sui client active-address)
echo "Active address: $ACTIVE_ADDRESS"
echo ""

# Publish commitment on-chain
echo "Publishing commitment on-chain..."
RESULT=$(sui client call \
  --package "$SUI_PACKAGE_ID" \
  --module proximity \
  --function create_commitment \
  --args "$SUI_SERVER_CAP_ID" "[$COMMITMENT_HEX]" "$ACTIVE_ADDRESS" \
  --gas-budget 30000000 \
  --json)

# Extract commitment object ID from created objects
COMMITMENT_ID=$(echo "$RESULT" | jq -r '.effects.created[] | select(.owner.Shared) | .reference.objectId' | head -n1)

if [ -z "$COMMITMENT_ID" ] || [ "$COMMITMENT_ID" = "null" ]; then
  echo "Error: Could not extract commitment ID from transaction result" >&2
  echo "Transaction result:" >&2
  echo "$RESULT" | jq . >&2
  exit 1
fi

echo ""
echo "✓ Commitment published successfully!"
echo "Commitment ID: $COMMITMENT_ID"
echo ""

# Update server .env with commitment ID
ENV_FILE="crates/proof-server/.env"
if grep -q "^SUI_COMMITMENT_ID=" "$ENV_FILE"; then
  sed -i.bak "s|^SUI_COMMITMENT_ID=.*|SUI_COMMITMENT_ID=$COMMITMENT_ID|" "$ENV_FILE"
else
  echo "SUI_COMMITMENT_ID=$COMMITMENT_ID" >> "$ENV_FILE"
fi
rm -f "${ENV_FILE}.bak"

echo "✓ Updated $ENV_FILE with commitment ID"
echo ""
echo "Next steps:"
echo "1. Restart the proof server to load the new commitment ID"
echo "2. (Optional) Run this script again with --verifying-key flag to publish verifying key"
echo "3. Use the client to generate and verify proofs!"
