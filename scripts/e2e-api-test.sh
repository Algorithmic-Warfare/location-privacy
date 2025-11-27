#!/usr/bin/env bash
set -euo pipefail

echo "============================================"
echo "Location Privacy E2E API Test"
echo "============================================"
echo ""
echo "This script runs the full E2E flow:"
echo "  1. Start local Sui network"
echo "  2. Deploy Move contracts"
echo "  3. Start proof generation API server"
echo "  4. Run JS client to test the flow"
echo ""

cd "$(dirname "$0")/.."

# Check prerequisites
echo "Checking prerequisites..."

if ! command -v sui &> /dev/null; then
    echo "❌ sui CLI not found. Please install Sui."
    exit 1
fi

if ! command -v cargo &> /dev/null; then
    echo "❌ cargo not found. Please install Rust."
    exit 1
fi

if ! command -v node &> /dev/null; then
    echo "❌ node not found. Please install Node.js."
    exit 1
fi

echo "✅ Prerequisites installed"
echo ""

# Step 1: Check if Sui network is running
echo "Step 1: Checking Sui network..."
if curl -s http://127.0.0.1:9000 > /dev/null 2>&1; then
    echo "✅ Sui network is running"
else
    echo "❌ Sui network not running!"
    echo "   Start it with: npm run start:sui"
    echo "   Or use: npm run start:local (for full orchestration)"
    exit 1
fi

# Step 2: Check if contracts are deployed
echo ""
echo "Step 2: Checking contract deployment..."
if [ -f "packages/location/.env.local" ]; then
    source packages/location/.env.local
    if [ -n "$PACKAGE_ID" ]; then
        echo "✅ Contracts deployed: $PACKAGE_ID"
    else
        echo "❌ PACKAGE_ID not found!"
        echo "   Deploy with: npm run publish:local"
        exit 1
    fi
else
    echo "❌ Contracts not deployed!"
    echo "   Deploy with: npm run publish:local"
    exit 1
fi

# Step 3: Build and start API server
echo ""
echo "Step 3: Building API server..."
cd crates/proof-server
cargo build --release 2>&1 | grep -E "(Compiling|Finished|error)" || true
if [ $? -eq 0 ]; then
    echo "✅ API server built"
else
    echo "❌ API server build failed"
    exit 1
fi

echo ""
echo "Step 4: Starting API server..."
export RUST_LOG="info,proof_server=debug"
export SERVER_ADDR="127.0.0.1:3000"

# Start server in background
cargo run --release > ../../api-server.log 2>&1 &
SERVER_PID=$!
echo "   Server PID: $SERVER_PID"

# Wait for server to be ready
echo "   Waiting for server to be ready..."
for i in {1..30}; do
    if curl -s http://127.0.0.1:3000/health > /dev/null 2>&1; then
        echo "✅ API server is ready"
        break
    fi
    if [ $i -eq 30 ]; then
        echo "❌ API server failed to start (timeout)"
        kill $SERVER_PID 2>/dev/null || true
        cat ../../api-server.log
        exit 1
    fi
    sleep 1
done

cd ../..

# Step 5: Install JS client dependencies
echo ""
echo "Step 5: Setting up JS client..."
cd packages/proof-client
if [ ! -d "node_modules" ]; then
    echo "   Installing dependencies..."
    npm install > /dev/null 2>&1
    echo "✅ Dependencies installed"
else
    echo "✅ Dependencies already installed"
fi

# Step 6: Run client test
echo ""
echo "Step 6: Running client E2E test..."
echo ""

# Copy env if exists
if [ -f "../../.env.local" ]; then
    cp ../../.env.local .env.local
fi

# Set API server URL
echo "API_SERVER_URL=http://127.0.0.1:3000" >> .env.local
echo "SUI_NETWORK=localnet" >> .env.local

# Run client
npm start

CLIENT_EXIT=$?

# Cleanup
echo ""
echo "Cleaning up..."
kill $SERVER_PID 2>/dev/null || true
wait $SERVER_PID 2>/dev/null || true

cd ../..

if [ $CLIENT_EXIT -eq 0 ]; then
    echo ""
    echo "============================================"
    echo "E2E API Test Complete! ✅"
    echo "============================================"
    echo ""
    echo "Summary:"
    echo "  ✅ Sui network running"
    echo "  ✅ Contracts deployed"
    echo "  ✅ API server generated proofs"
    echo "  ✅ JS client verified flow"
    echo ""
    echo "Server logs saved to: api-server.log"
    exit 0
else
    echo ""
    echo "============================================"
    echo "E2E API Test Failed ❌"
    echo "============================================"
    echo ""
    echo "Check logs:"
    echo "  - API server: api-server.log"
    echo "  - Client output above"
    exit 1
fi
