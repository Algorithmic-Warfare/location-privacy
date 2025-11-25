# Location Privacy Scripts

This directory contains essential scripts for building and testing the location privacy commitment system.

## Available Scripts

### `build-all.sh`
Complete build script that compiles the entire system, runs all tests, and performs code quality checks.

```bash
./scripts/build-all.sh
```

### `integration-test.sh`
Generates clean cryptographic data for Move contract integration.

```bash
./scripts/integration-test.sh
```

**Output File:** `integration_test_output.txt` (contains only the essential data)

**Clean Output Includes:**
- Commitment bytes in `vector<u8>` format
- Verifying key bytes for Groth16 verification
- Proof bytes and public inputs for proximity proofs
- Usage instructions for Move contract integration

## Prerequisites

- Rust toolchain (cargo, rustc)
- Sui CLI (for Move contract integration)

## Quick Start

1. **Build everything:**
   ```bash
   ./scripts/build-all.sh
   ```

2. **Generate integration data:**
   ```bash
   ./scripts/integration-test.sh
   ```

## Output

Each script provides:
- Build status and test results
- Example data for Move contracts
- Integration instructions
- 🚀 Next steps for deployment

## Security Notes

- Use the examples to understand the cryptographic operations
- In production, always use two-party trusted setup with independent parties
- Store proving keys securely and never expose blinding factors