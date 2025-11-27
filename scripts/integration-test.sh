#!/usr/bin/env bash
set -euo pipefail

echo "============================================"
echo "Location Privacy E2E Integration Test"
echo "============================================"
echo ""

cd "$(dirname "$0")/.."

# Step 1: Build and test Rust library
echo "Step 1: Building Rust library..."
cd crates/commitmentgen
cargo build --release
echo "✓ Rust library built"

# Step 2: Run Rust tests
echo ""
echo "Step 2: Running Rust tests..."
cargo test
echo "✓ Rust tests passed"

# Step 3: Generate E2E test data (commitments, proofs, verifying keys)
echo ""
echo "Step 3: Generating E2E test data..."
cargo run --example e2e_test_setup
echo "✓ Test data generated"

# Step 4: Copy generated test to Move package
echo ""
echo "Step 4: Copying test data to Move package..."
if [ -f "generated_move_tests.move" ]; then
    cp generated_move_tests.move ../../packages/location/tests/location_tests.move
    echo "✓ Test data copied to packages/location/tests/location_tests.move"
else
    echo "⚠ Warning: generated_move_tests.move not found. Skipping copy."
fi

# Step 5: Build Move contracts
echo ""
echo "Step 5: Building Move contracts..."
cd ../../packages/location
sui move build
echo "✓ Move contracts built"

# Step 6: Run Move tests
echo ""
echo "Step 6: Running Move tests..."
sui move test
echo "✓ Move tests passed"

echo ""
echo "============================================"
echo "Integration test complete!"
echo "============================================"
echo ""
echo "Summary:"
echo "  ✓ Rust library built and tested"
echo "  ✓ zkSNARK proofs and commitments generated"
echo "  ✓ Move contracts verified proofs successfully"
echo ""
echo "All data constraints validated end-to-end."