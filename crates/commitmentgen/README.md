# CommitmentGen

A Rust crate for generating cryptographic commitments and zero-knowledge proofs for location privacy.

## Overview

This crate provides functionality for:
- Generating Pedersen commitments to 3D coordinates
- Creating zero-knowledge proofs of proximity between coordinates
- Serializing commitments and proofs for blockchain submission

## Features

- **Pedersen Commitments**: Hide location coordinates while maintaining cryptographic binding
- **Zero-Knowledge Proofs**: Prove proximity without revealing actual coordinates
- **Trusted Setup**: Two-party and single-party setup ceremonies for generating proving keys
- **BN254 Curve**: Optimized for efficient blockchain verification
- **Location Privacy**: Prevent offline brute-force attacks on hidden coordinates

## Usage

### Basic Commitment Generation

```rust
use commitmentgen::{LocationCommitmentGenerator, PedersenParams, Coordinates};

let params = PedersenParams {
    g: G1Affine::generator(),
    h: G1Affine::generator(),
    k: G1Affine::generator(),
    m: G1Affine::generator(),
};

let commitment_gen = LocationCommitmentGenerator::new(params);

// Create a commitment to coordinates
let coords = Coordinates { x: 47608013, y: -122335167, z: 0 };
let blinding = LocationCommitmentGenerator::generate_blinding();
let commitment = commitment_gen.create_commitment(&coords, &blinding);

// Serialize for on-chain storage
let commitment_bytes = LocationCommitmentGenerator::serialize_commitment(&commitment);
```

### Trusted Setup Ceremony

#### Two-Party Setup (Recommended for Security)

```rust
use commitmentgen::trusted_setup::{TwoPartySetup, SetupResult};

let max_distance_squared = Fr::from(10_000_000_000u64); // 10km² in mm²
let mut setup = TwoPartySetup::new(max_distance_squared);

// Party A contributes randomness
let party_a_contribution = setup.party_a_contribute()?;

// Party B contributes randomness
let party_b_contribution = setup.party_b_contribute()?;

// Finalize setup (combines contributions)
let setup_result: SetupResult = setup.finalize_setup()?;
```

#### Single-Party Setup (Development Only)

```rust
use commitmentgen::trusted_setup::single_party_setup;

let max_distance_squared = Fr::from(10_000_000_000u64);
let setup_result = single_party_setup(max_distance_squared)?;
```

#### Serialize/Deserialize Setup Keys

```rust
use commitmentgen::trusted_setup::{serialize_setup_result, deserialize_setup_result};

// Serialize for storage
let (proving_key_bytes, verifying_key_bytes) = serialize_setup_result(&setup_result)?;

// Deserialize when needed
let loaded_setup = deserialize_setup_result(&proving_key_bytes, &verifying_key_bytes)?;
```

### Proof Generation (Requires Trusted Setup)

```rust
// Note: This requires a proving key from trusted setup
// let prover = ProximityProver::new(proving_key, verifying_key, params);
// let (proof, public_inputs) = prover.generate_proof(
//     &target_coords,
//     &blinding,
//     &player_coords,
//     &commitment,
//     nonce,
//     10.0, // 10km max distance
// ).unwrap();
```

## Dependencies

- `ark-bn254`: BN254 elliptic curve operations
- `ark-groth16`: Groth16 zero-knowledge proof system
- `ark-r1cs-std`: R1CS constraint system gadgets
- `rand`: Cryptographically secure random number generation

## Building

```bash
cargo build
```

## Testing

```bash
cargo test
```

## Examples

Run the trusted setup example:

```bash
cargo run --example trusted_setup_example
```

This demonstrates both single-party and two-party trusted setup ceremonies.

## Scripts

The `../scripts/` directory contains build scripts for the entire location privacy system:

```bash
# Build everything and run comprehensive tests
../scripts/build-all.sh

# Generate integration test data for Move contracts
../scripts/integration-test.sh
```

## Examples

Run these examples to understand the system:

```bash
# Basic commitment generation
cargo run --example commitment_demo

# Trusted setup ceremony demonstration
cargo run --example trusted_setup_example

# End-to-end test data generation
cargo run --example e2e_test
```

## Security Notes

- The Pedersen commitment parameters should use independent generators in production
- The zero-knowledge proof circuit is currently incomplete (marked with TODOs)
- **Trusted Setup Security**: Two-party setup provides better security than single-party
- In production, use multi-party computation (MPC) protocols for trusted setup
- Single-party setup should only be used for development/testing
- Blinding factors must be kept secret by the server

## Trusted Setup Security

### Two-Party Setup
- Both parties contribute independent randomness
- Neither party can control the final keys alone
- Contributions are combined securely
- Recommended for production use

### Single-Party Setup
- **Not secure for production**
- Single party controls all randomness
- Vulnerable to backdoors
- Only suitable for development/testing

### Production Recommendations
1. Use MPC protocols with 3+ parties for maximum security
2. Have parties from different organizations
3. Destroy all randomness after setup completion
4. Independently verify setup correctness

## License

See the main project LICENSE file.