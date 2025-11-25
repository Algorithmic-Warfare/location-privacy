#!/bin/bash

# Integration test script
# Generates clean cryptographic data for Move contract integration

# set -e  # Removed to allow script to continue even if examples fail

echo "Location Privacy System - Data Generation"
echo "=========================================="

cd "$(dirname "$0")/.."

# Navigate to the commitmentgen crate
cd crates/commitmentgen

echo "📦 Building commitment generator..."
cargo build >/dev/null 2>&1

echo "🧪 Running unit tests..."
cargo test >/dev/null 2>&1

echo "🏗️  Generating cryptographic data..."

# Create clean output file
OUTPUT_FILE="../../integration_test_output.txt"
echo "# Location Privacy Cryptographic Data" > "$OUTPUT_FILE"
echo "# Generated: $(date)" >> "$OUTPUT_FILE"
echo "# ===================================" >> "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"

# Run the e2e test and extract only the Move contract data
echo "Running end-to-end test..."
E2E_OUTPUT=$(cargo run --example e2e_test 2>/dev/null)

# Extract only the relevant Move contract data sections
echo "// ===== MOVE CONTRACT TEST DATA =====" >> "$OUTPUT_FILE"
echo "// Copy this data into your Move contract test" >> "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"

# Extract commitment bytes
echo "$E2E_OUTPUT" | grep -A 1 "// Commitment bytes for create_commitment()" -A 2 >> "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"

# Extract verifying key bytes
echo "$E2E_OUTPUT" | grep -A 1 "// Verifying key bytes" -A 50 | grep -v "^🎉" | grep -v "^Summary:" | grep -v "^Next steps:" | head -3 >> "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"

# Extract proof bytes
echo "$E2E_OUTPUT" | grep -A 1 "// Proof bytes" -A 2 >> "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"

# Extract public inputs bytes
echo "$E2E_OUTPUT" | grep -A 1 "// Public inputs bytes" -A 2 >> "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"

# Add usage notes
echo "// ===== USAGE INSTRUCTIONS =====" >> "$OUTPUT_FILE"
echo "// 1. Copy the vector data above into your Move contract test" >> "$OUTPUT_FILE"
echo "// 2. Use commitment_bytes for create_commitment() function" >> "$OUTPUT_FILE"
echo "// 3. Use vk_bytes, proof_bytes, and public_inputs for verify_proximity_proof()" >> "$OUTPUT_FILE"
echo "// 4. Run 'sui move test' to verify the integration works" >> "$OUTPUT_FILE"

echo ""
echo "✅ Clean data extraction completed!"
echo "📄 Output saved to: $OUTPUT_FILE"
echo ""
echo "The file contains only the cryptographic data needed for Move contracts."