#!/usr/bin/env bash
set -euo pipefail

echo "============================================"
echo "Setting up on-chain commitment"
echo "============================================"
echo ""

# Check if server is running
if ! curl -s http://127.0.0.1:3000/health > /dev/null; then
    echo "❌ Proof server is not running!"
    echo "   Start it with: npm run server:start"
    exit 1
fi

# Get server info
echo "Step 1: Getting commitment from server..."
SERVER_INFO=$(curl -s http://127.0.0.1:3000/api/info)
COMMITMENT_BYTES=$(echo "$SERVER_INFO" | jq -r '.commitment_bytes')

echo "   Commitment bytes: $COMMITMENT_BYTES"

# Check if package is deployed
if [ ! -f "packages/location/.env.local" ]; then
    echo "❌ Package not deployed!"
    echo "   Deploy it with: npm run publish:local"
    exit 1
fi

source packages/location/.env.local

if [ -z "$PACKAGE_ID" ]; then
    echo "❌ PACKAGE_ID not found in packages/location/.env.local"
    exit 1
fi

echo "   Package ID: $PACKAGE_ID"

# TODO: Implement Sui transaction to create commitment on-chain
# For now, this is a placeholder that shows what needs to be done

echo ""
echo "Step 2: Creating commitment on-chain..."
echo "   ⚠️  Manual step required:"
echo "   "
echo "   Run the following Sui command to create a commitment:"
echo "   "
echo "   sui client call \\"
echo "     --package $PACKAGE_ID \\"
echo "     --module proximity \\"
echo "     --function create_commitment \\"
echo "     --args <SERVER_CAP_OBJECT_ID> [$COMMITMENT_BYTES] <OWNER_ADDRESS>"
echo ""
echo "   Replace <SERVER_CAP_OBJECT_ID> with the ServerCap object ID from deployment"
echo "   Replace <OWNER_ADDRESS> with your address"
echo ""

# Save package ID for client
echo "PACKAGE_ID=$PACKAGE_ID" > packages/proof-client/.env.local

echo "✅ Setup complete (manual commitment creation required)"
