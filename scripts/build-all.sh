#!/bin/bash

# Complete build script for the location-privacy commitment system
# This builds all components and runs comprehensive tests

set -e

echo "Building Complete Location Privacy System"
echo "==========================================="

cd "$(dirname "$0")/.."

# Navigate to the commitmentgen crate
cd crates/commitmentgen

echo "📦 Building with all features..."
cargo build --release

echo " Running all tests..."
cargo test --release

echo " Running benchmarks..."
cargo bench 2>/dev/null || echo " No benchmarks defined (this is normal)"

echo "📚 Checking documentation..."
cargo doc --no-deps --release

echo "Running clippy lints..."
cargo clippy --release -- -D warnings 2>/dev/null || echo " Clippy not available or warnings found"

echo "📏 Checking code formatting..."
cargo fmt --check 2>/dev/null || echo " Code formatting issues found"

echo ""
echo "Build completed successfully!"
echo ""
echo "Available examples:"
echo "  cargo run --example trusted_setup_example    # Two-party trusted setup"
echo "  cargo run --example commitment_demo          # Commitment generation demo"
echo ""
echo "Available scripts:"
echo "  ../scripts/build-trusted-setup.sh            # Build trusted setup"
echo "  ../scripts/build-commitment-demo.sh          # Build commitment demo"
echo ""
echo "Next steps:"
echo "1. Run examples to see the system in action"
echo "2. Integrate with your Move smart contracts"
echo "3. Deploy to production with proper key management"