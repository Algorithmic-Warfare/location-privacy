# CommitmentGen

A Rust crate for generating cryptographic commitments and zero-knowledge proofs for location privacy using Poseidon hash functions and Groth16 zkSNARKs.

## Overview

This crate provides functionality for:
- Generating Poseidon hash commitments to 3D coordinates with cryptographic blinding
- Creating zero-knowledge proofs of proximity between coordinates
- Serializing commitments and proofs for blockchain submission
- Trusted setup ceremonies for generating proving/verifying keys

## Features

- **Poseidon Hash Commitments**: Efficient zkSNARK-friendly hash function for hiding coordinates (C = Poseidon(x, y, z, r))
- **Zero-Knowledge Proofs**: Prove proximity without revealing actual coordinates using Groth16 zkSNARKs
- **Blinding Factor Security**: 254-bit cryptographically secure random blinding factors prevent offline brute-force attacks
- **Canonical Verifying Key**: Ensures only CCP-generated proofs can be verified on-chain
- **Trusted Setup**: Two-party and single-party setup ceremonies for generating proving keys
- **BN254 Curve**: Optimized for efficient blockchain verification with ~150-200 R1CS constraints
- **Negative Coordinate Support**: Proper modular arithmetic for signed 128-bit coordinates
- **Location Privacy**: Cryptographically prevents offline coordinate guessing attacks

## Usage

### Basic Poseidon Commitment Generation

```rust
use commitmentgen::{
    create_poseidon_commitment, 
    get_poseidon_config, 
    generate_blinding, 
    coord_to_fr, 
    Coordinates
};
use ark_serialize::CanonicalSerialize;

// Get standard Poseidon configuration for BN254
let poseidon_config = get_poseidon_config();

// Create a commitment to coordinates (supports negative values)
let coords = Coordinates { 
    x: -23534879266777860000i128, 
    y: -435314932817330200i128, 
    z: -4336253132989268000i128 
};

// Generate cryptographically secure 254-bit blinding factor
let blinding = generate_blinding();

// Create Poseidon hash commitment: C = Poseidon(x, y, z, r)
let commitment_hash = create_poseidon_commitment(
    coord_to_fr(coords.x),
    coord_to_fr(coords.y),
    coord_to_fr(coords.z),
    blinding,
    &poseidon_config,
);

// Serialize to 32 bytes (single field element) for on-chain storage
let mut commitment_bytes = Vec::new();
commitment_hash.serialize_compressed(&mut commitment_bytes).unwrap();
assert_eq!(commitment_bytes.len(), 32);
```

### Trusted Setup Ceremony

#### Two-Party Setup (Recommended for Security)

```rust
use commitmentgen::trusted_setup::{TwoPartySetup, SetupResult};
use ark_bn254::Fr;

// Max distance: 10km = 10,000m → (10,000)² = 100,000,000 m²
let max_distance_squared = Fr::from(100_000_000u64);
let mut setup = TwoPartySetup::new(max_distance_squared);

// Party A contributes randomness
let party_a_contribution = setup.party_a_contribute()?;

// Party B contributes randomness
let party_b_contribution = setup.party_b_contribute()?;

// Finalize setup (combines contributions)
let setup_result: SetupResult = setup.finalize_setup()?;

// The setup_result contains:
// - proving_key: Used by server to generate proofs (keep secret)
// - verifying_key: Stored on-chain for proof verification (public)
```

#### Single-Party Setup (Development Only)

```rust
use commitmentgen::trusted_setup::single_party_setup;
use ark_bn254::Fr;

let max_distance_squared = Fr::from(100_000_000u64); // 10km squared in meters
let setup_result = single_party_setup(max_distance_squared)?;
```

#### Serialize/Deserialize Setup Keys

```rust
use commitmentgen::trusted_setup::{serialize_setup_result, deserialize_setup_result};

// Serialize for storage
let (proving_key_bytes, verifying_key_bytes) = serialize_setup_result(&setup_result)?;

// Proving key: ~5-10MB, store securely server-side
// Verifying key: ~328 bytes, publish on-chain

// Deserialize when needed
let loaded_setup = deserialize_setup_result(&proving_key_bytes, &verifying_key_bytes)?;
```

### Proximity Proof Generation

```rust
use commitmentgen::{ProximityProver, Coordinates, create_poseidon_commitment, get_poseidon_config, coord_to_fr};

// Initialize prover with proving key from trusted setup
let prover = ProximityProver::new(proving_key);

// Target location (server secret)
let target_coords = Coordinates { 
    x: 1000, 
    y: 2000, 
    z: 500 
};

// Generate or retrieve the blinding factor used for commitment
let blinding = generate_blinding();

// Compute commitment hash (must match on-chain commitment)
let poseidon_config = get_poseidon_config();
let commitment_hash = create_poseidon_commitment(
    coord_to_fr(target_coords.x),
    coord_to_fr(target_coords.y),
    coord_to_fr(target_coords.z),
    blinding,
    &poseidon_config,
);

// Player location (known to both player and server)
let player_coords = Coordinates { 
    x: 1500, 
    y: 1800, 
    z: 450 
};

// Generate proof that player is within 10km of target
let (proof, public_inputs) = prover.generate_proof(
    &target_coords,
    &blinding,
    &player_coords,
    &commitment_hash,
    10.0, // 10km max distance
)?;

// Public inputs contain: [commitment_hash (32 bytes), max_distance_squared (32 bytes)]
// Total: 64 bytes (2 field elements)

// Serialize for blockchain submission
let proof_bytes = ProximityProver::serialize_proof(&proof);
let inputs_bytes = ProximityProver::serialize_public_inputs(&public_inputs);
```

## Architecture

### zkSNARK Circuit

The `ProximityCircuit` implements two main constraint systems:

1. **Poseidon Commitment Verification** (~150-200 constraints):
   - Proves knowledge of `(x, y, z, r)` such that `C = Poseidon(x, y, z, r)`
   - Validates commitment hash matches public input
   - Provides zero-knowledge hiding with 254-bit blinding factor

2. **Euclidean Distance Constraint**:
   - Computes `distance² = (x_p - x_t)² + (y_p - y_t)² + (z_p - z_t)²`
   - Enforces `distance² ≤ max_distance²` using MSB bit check
   - Ensures player coordinates are within proximity range

### Security Properties

- **Zero-Knowledge**: Coordinates remain private in the proof
- **Soundness**: Cannot forge proofs for coordinates outside proximity range
- **Completeness**: Valid proximity always generates verifiable proofs
- **Hiding**: 254-bit blinding factor prevents offline brute-force attacks
- **Binding**: Poseidon collision resistance prevents commitment forgery
- **Server Authentication**: Canonical verifying key ensures only CCP-generated proofs verify

## Dependencies

- `ark-bn254`: BN254 pairing-friendly elliptic curve
- `ark-groth16`: Groth16 zero-knowledge proof system
- `ark-r1cs-std`: R1CS constraint system gadgets
- `ark-crypto-primitives`: Poseidon hash and cryptographic primitives
- `rand`: Cryptographically secure random number generation (blinding factors)

## System Integration

### Data Flow

1. **Server Setup (One-Time)**:
   ```
   Trusted Setup → Proving Key (server) + Verifying Key (on-chain)
   ```

2. **Commitment Creation (Per SSU)**:
   ```
   Server: (x, y, z) + generate_blinding() → r
   Server: Poseidon(x, y, z, r) → commitment_hash (32 bytes)
   Server: Store (x, y, z, r) securely
   Server: Publish commitment_hash on-chain via create_commitment()
   ```

3. **Proximity Verification (Per Request)**:
   ```
   Player: Provides (x_p, y_p, z_p) to server
   Server: Loads (x_t, y_t, z_t, r) from storage
   Server: generate_proof() → (proof, public_inputs)
   Player: Submits to verify_proximity_proof() on-chain
   Chain: Verifies proof against canonical verifying key
   Chain: Increments nonce if valid
   ```

### Integration with Move Contract

The generated proofs are designed for the Sui Move contract:

```move
// Server publishes canonical verifying key once
proximity::init_verifying_key(&server_cap, vk_bytes, ctx);

// Server creates commitments
proximity::create_commitment(&server_cap, commitment_bytes, owner, ctx);

// Anyone can verify proofs (but only CCP can generate valid ones)
proximity::verify_proximity_proof(&mut commitment, &verifying_key, proof_bytes, public_inputs, ctx);
```

## Building

```bash
# Build the library
cargo build --release

# Build with all features
cargo build --release --all-features

# Build examples
cargo build --release --examples
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
# Basic commitment generation (demonstrates Poseidon hash commitments)
cargo run --example commitment_demo

# Trusted setup ceremony demonstration (single-party and two-party)
cargo run --example trusted_setup_example

# End-to-end test data generation (generates Move contract test data)
cargo run --example e2e_test_setup
```

The `e2e_test_setup` example generates a complete test suite including:
- Valid proximity proofs with correct blinding factors
- Invalid test cases (corrupted proofs, wrong VK, wrong public inputs)
- Multiple coordinate scenarios (within/outside range)
- Negative coordinate handling validation
- Auto-generated Move contract test file

## Security Notes

### Cryptographic Security

- **Poseidon Hash**: Provides collision resistance and preimage resistance with 128-bit security
- **Blinding Factors**: 254-bit entropy prevents offline coordinate guessing attacks (2^254 computational complexity)
- **Canonical Verifying Key**: Must be stored on-chain to ensure only CCP-generated proofs verify
- **Coordinate Privacy**: Neither player nor target coordinates are revealed in proofs or commitments
- **Trusted Setup Security**: Two-party setup provides better security than single-party

### Production Recommendations

1. **Blinding Factor Management**:
   - Generate using cryptographically secure RNG (`generate_blinding()`)
   - Store securely in HSM or encrypted database
   - Never reuse blinding factors across commitments
   - Implement key rotation policies

2. **Trusted Setup**:
   - Use multi-party computation (MPC) protocols with 3+ parties
   - Have parties from different organizations contribute
   - Destroy all randomness after setup completion
   - Independently verify setup correctness

3. **Verifying Key**:
   - Publish canonical verifying key on-chain during initialization
   - Store with `ServerCap` access control
   - All proofs must verify against this canonical key

4. **Key Storage**:
   - Proving key: Store server-side in HSM (~5-10MB)
   - Blinding factors: Encrypted database with backup strategy
   - Verifying key: On-chain storage (~328 bytes)

### Attack Resistance

- **Offline Brute-Force**: Blocked by 254-bit blinding factors
- **Proof Replay**: Blocked by on-chain nonce increment
- **Coordinate Guessing**: Cryptographically infeasible (Poseidon preimage resistance)
- **Adversarial Proofs**: Blocked by canonical verifying key requirement
- **Commitment Forgery**: Prevented by Poseidon collision resistance

## Performance Characteristics

- **Commitment Generation**: < 1ms (Poseidon hash computation)
- **Proof Generation**: 1-5 seconds (~150-200 R1CS constraints)
- **Proof Verification**: < 10ms (Groth16 pairing verification)
- **Proof Size**: ~256 bytes
- **Public Inputs**: 64 bytes (commitment_hash + max_distance_squared)
- **Commitment Storage**: 32 bytes on-chain (single field element)
- **Memory Usage**: ~2-4GB RAM for proof generation

## Testing

The crate includes comprehensive test coverage:

```bash
# Run all tests
cargo test

# Run tests with output
cargo test -- --nocapture

# Run specific test
cargo test test_poseidon_commitment
```

### Test Categories

- **Commitment Properties**: Binding, hiding, determinism, blinding factor effects
- **Circuit Constraints**: Poseidon verification, distance calculations, edge cases
- **Coordinate Handling**: Negative coordinates, large values, modular arithmetic
- **Security Validation**: Offline attack resistance, proof verification, commitment validation
- **Serialization**: Roundtrip tests, format validation, field element encoding

### Key Tests

- `test_poseidon_binding_property`: Validates collision resistance
- `test_commitment_verification_security_flaw`: Ensures commitment verification is enforced
- `test_negative_coordinates_absolute_value_validation`: Tests signed coordinate handling
- `test_proximity_circuit_proof_generation_and_verification`: End-to-end proof flow
- `test_blinding_factor_entropy_requirements`: Validates cryptographic strength

## Cryptographic Guarantees

### What the zkSNARK Proves

The proximity proof cryptographically demonstrates:

1. **Commitment Opening**: Prover knows `(x, y, z, r)` such that `C = Poseidon(x, y, z, r)`
2. **Distance Constraint**: `(x_p - x_t)² + (y_p - y_t)² + (z_p - z_t)² ≤ max_distance²`
3. **Blinding Factor Authenticity**: The proof is bound to the specific blinding factor used in the commitment
4. **Server Authority**: Only proofs generated with CCP's proving key verify against the canonical verifying key

### What is NOT Revealed

- Target coordinates `(x_t, y_t, z_t)` remain hidden
- Player coordinates `(x_p, y_p, z_p)` remain hidden
- Blinding factor `r` remains hidden
- Actual distance between coordinates remains hidden

### What is Publicly Visible

- Commitment hash `C` (32 bytes) - reveals nothing about coordinates due to blinding
- Maximum distance constraint (e.g., 10km)
- Fact that player is within the specified distance
- Nonce value (for replay protection)

## Troubleshooting

### Common Issues

**Issue**: Proof generation is slow (>10 seconds)
- **Solution**: Ensure you're using `--release` mode: `cargo build --release`

**Issue**: "Assignment missing" error during proof generation
- **Solution**: Verify all witness values are `Some(...)` and not `None`

**Issue**: Proof verification fails on-chain
- **Solution**: Check that commitment hash in public inputs matches on-chain commitment
- **Solution**: Ensure using the same verifying key that was used during trusted setup

**Issue**: Coordinate overflow errors
- **Solution**: Coordinates must fit in BN254 field (< 2^254), use modular arithmetic

**Issue**: Blinding factor entropy warning
- **Solution**: Use `generate_blinding()` instead of manual field element creation

## Further Reading

- [Poseidon Hash Paper](https://eprint.iacr.org/2019/458.pdf): "Poseidon: A New Hash Function for Zero-Knowledge Proof Systems"
- [Groth16 Paper](https://eprint.iacr.org/2016/260.pdf): "On the Size of Pairing-based Non-interactive Arguments"
- [arkworks Documentation](https://arkworks.rs/): Rust cryptography library ecosystem
- [SUI Move Documentation](https://docs.sui.io/): Blockchain integration guides

## License

See the main project LICENSE file.