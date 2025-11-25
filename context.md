# Location Proximity Proof System - Context Document

## Project Overview

This system provides cryptographically secure proximity verification between two 3D coordinates while protecting one coordinate (the "target" location) from offline brute-force attacks. It uses Pedersen commitments combined with zkSNARK proofs to achieve both zero-knowledge properties and resistance to coordinate guessing attacks.

## Problem Statement

**Goal:** Prove that two 3D coordinates are within 10km of each other without revealing the obfuscated (target) coordinate.

**Key Security Requirement:** Prevent offline brute-force attacks where an attacker with access to the on-chain commitment and verification code attempts to determine the hidden coordinates by testing candidate values.

**Why Standard Approaches Fail:**
- Simple hash commitments allow offline testing: attacker hashes each candidate coordinate and compares
- zkSNARK proofs alone (without blinding) still allow attackers to generate candidate proofs offline
- The Earth's surface is relatively small (~510M km²), making exhaustive search feasible at moderate resolution

## Solution Architecture

### Core Cryptographic Components

1. **Pedersen Commitment**: `C = g^x · h^y · k^z · m^r`
   - `(x, y, z)`: Target coordinates (private)
   - `r`: 256-bit blinding factor (private, server-controlled)
   - `C`: Commitment (public, stored on-chain)
   - **Critical Property**: Without knowledge of `r`, an attacker cannot determine if a candidate `(x', y', z')` matches `C`

2. **zkSNARK Proximity Proof**
   - **Private Inputs**: `x_target, y_target, z_target, r_target, x_player, y_player, z_player`
   - **Public Inputs**: `C_target` (commitment), `nonce` (replay prevention)
   - **Constraints Proven**:
     - `C_target == Pedersen(x_target, y_target, z_target, r_target)` (commitment opens correctly)
     - `distance²(player, target) ≤ (10km)²` (proximity constraint)
     - `nonce` matches current on-chain nonce (freshness)

3. **Nonce-Based Replay Protection**
   - Each successful verification increments an on-chain nonce
   - Proofs include the nonce as a public input
   - Prevents proof replay and pre-computation attacks

### Why This Prevents Offline Attacks

**Attack Scenario Blocked:**
1. Attacker obtains `C_target` from blockchain
2. Attacker wants to find `(x, y, z)` by testing candidates
3. For each candidate `(x', y', z')`, attacker would need to:
   - Find `r'` such that `C_target == Pedersen(x', y', z', r')`
   - This requires solving discrete logarithm (computationally infeasible)
4. Even if attacker could guess coordinates, they cannot generate a valid zkSNARK proof without knowing `r_target`
5. Server is the only entity that knows `r_target`, so only the server can generate valid proofs

## System Components

### 1. SUI Move Smart Contract

**Purpose:** On-chain storage and verification

**Key Structures:**
```
LocationCommitment {
    commitment: vector<u8>,  // 32-byte Pedersen commitment
    nonce: u64,              // Replay protection counter
    created_at: u64,         // Timestamp
    owner: address           // SSU owner address
}
```

**Key Functions:**
- `create_commitment()`: Publishes a new location commitment (server-only)
- `verify_proximity_proof()`: Verifies zkSNARK proof and increments nonce
- `verify_groth16_proof()`: Internal Groth16 verification logic

**Security Features:**
- ServerCap capability ensures only authorized server can create commitments
- Nonce increment prevents proof replay
- Public input validation ensures commitment and nonce match
- Native Groth16 verifier for cryptographic proof checking

### 2. Rust Server-Side Proof Generator

**Purpose:** Generate commitments and proofs using secret blinding factors

**Key Components:**

**LocationCommitmentGenerator:**
- Generates random 256-bit blinding factors
- Creates Pedersen commitments using secret coordinates and blinding
- Serializes commitments for on-chain publication

**ProximityCircuit (zkSNARK Circuit):**
- Implements R1CS constraints for:
  - Pedersen commitment opening verification
  - Euclidean distance calculation and range check
  - Nonce binding
- Private witness: coordinates and blinding factors
- Public inputs: commitment and nonce

**ProximityProver:**
- Loads proving key from trusted setup
- Generates Groth16 proofs given witness values
- Serializes proofs and public inputs for blockchain submission

### 3. Coordinate System

**Encoding Scheme:**
- Use fixed-point integer representation (e.g., millimeters)
- Earth coordinates: latitude ∈ [-90°, 90°], longitude ∈ [-180°, 180°]
- Altitude: meters above sea level

**Example Encoding:**
```
Latitude 47.6062° → 47,606,200 (in 0.0001° units)
Longitude -122.3321° → -122,332,100 (in 0.0001° units)
Altitude 0m → 0
```

**Why Fixed-Point:**
- zkSNARK circuits require integer arithmetic
- Must fit within field element size (< 2^254 for BN254 curve)
- Provides sufficient precision for distance calculations

## Workflow

### Phase 1: Commitment Creation (One-Time Setup)

1. Server defines SSU location coordinates: `(x, y, z)`
2. Server generates random 256-bit blinding: `r = random()`
3. Server computes commitment: `C = Pedersen(x, y, z, r)`
4. Server serializes `C` to 32 bytes
5. Server calls `create_commitment()` on-chain with ServerCap
6. Server securely stores `(x, y, z, r)` in HSM/encrypted database

**Storage Requirements:**
- On-chain: 32 bytes (commitment) + 8 bytes (nonce) + metadata
- Server-side: 4 × 32 bytes (coordinates + blinding)

### Phase 2: Proximity Verification (Repeated)

1. **Player Request:**
   - Player wants to prove proximity to SSU
   - Sends their coordinates `(x_p, y_p, z_p)` to server
   - Retrieves current `nonce` from blockchain

2. **Server Proof Generation:**
   - Loads secret `(x_target, y_target, z_target, r_target)` from storage
   - Verifies distance: `sqrt((x_p - x_t)² + (y_p - y_t)² + (z_p - z_t)²) ≤ 10km`
   - If valid, generates zkSNARK proof using ProximityCircuit
   - Proof includes current `nonce` as public input
   - Returns serialized proof (~256 bytes) and public inputs (~96 bytes)

3. **On-Chain Verification:**
   - Player submits proof to contract via `verify_proximity_proof()`
   - Contract validates:
     - Proof structure (256 bytes)
     - Public inputs structure (96 bytes)
     - Commitment in public inputs matches stored commitment
     - Nonce in public inputs matches current contract nonce
   - Contract calls native Groth16 verifier
   - If valid: increments nonce, emits event, grants access
   - If invalid: transaction reverts

## Security Properties

### Cryptographic Guarantees

1. **Zero-Knowledge:** Proof reveals nothing about target coordinates beyond distance constraint
2. **Soundness:** Cannot forge proof for coordinates outside 10km radius (computational soundness)
3. **Completeness:** Valid proximity always produces valid proof
4. **Binding:** Cannot change coordinates after commitment published
5. **Hiding:** Commitment reveals nothing about coordinates without blinding factor

### Attack Resistance

**Offline Brute Force:** ✓ Blocked
- Requires guessing 256-bit blinding factor
- 2^256 computational complexity (infeasible)

**Proof Replay:** ✓ Blocked
- Nonce increments after each verification
- Old proofs fail nonce check

**Proof Pre-Computation:** ✓ Blocked
- Proofs tied to specific nonce
- Cannot generate proofs for future nonces

**Server Key Compromise:** Partial
- Compromised blinding factors allow attacker to generate proofs
- Mitigation: HSM storage, key rotation, rate limiting

**Network Analysis:** ✓ Blocked
- On-chain data reveals no coordinate information
- Proof/verification patterns reveal no location data

## Implementation Requirements

### Cryptographic Dependencies

**Rust (Server-Side):**
```
ark-bn254       # BN254 pairing-friendly curve
ark-groth16     # Groth16 proof system
ark-r1cs-std    # R1CS constraint gadgets
ark-crypto-primitives  # Pedersen commitments
```

**SUI Move (On-Chain):**
```
sui::groth16    # Native Groth16 verifier
sui::object     # Object model
sui::transfer   # Object transfers
```

### Trusted Setup

**Required:** Groth16 requires a circuit-specific trusted setup ceremony

**Process:**
1. Define ProximityCircuit constraints
2. Run multi-party computation (MPC) ceremony
3. Generate proving key (PK) and verifying key (VK)
4. Destroy toxic waste (setup randomness)
5. Store PK server-side, publish VK on-chain

**Alternatives:**
- Use universal setup schemes (Marlin, PLONK) to avoid per-circuit setup
- Participate in existing trusted setup ceremonies

### Key Management

**Server-Side Secrets:**
- Blinding factors `r` (256 bits per commitment)
- Proving key PK (~10MB for moderate circuit size)
- Server signing key (if using additional authentication)

**Storage Recommendations:**
- AWS KMS, Google Cloud KMS, or Azure Key Vault
- Hardware Security Module (HSM) for high-value deployments
- Encrypted database with key rotation
- Multi-signature access control

**Backup Strategy:**
- Encrypted offsite backups of blinding factors
- Coordinate recovery procedures
- Key rotation policy (quarterly recommended)

## Performance Characteristics

### Computational Costs

**Commitment Generation:**
- Time: < 1ms (elliptic curve operations)
- Server load: Negligible

**Proof Generation:**
- Time: 1-10 seconds (depends on circuit size)
- Memory: ~4GB RAM
- CPU: Single-threaded, benefits from fast single-core performance

**Proof Verification:**
- Time: < 10ms (pairing-based verification)
- Gas cost: ~300k-500k gas units (SUI equivalent)

### Storage Costs

**Per Commitment:**
- On-chain: ~100 bytes (commitment + metadata)
- Server-side: ~128 bytes (coordinates + blinding)

**Verifying Key:**
- On-chain: ~512 bytes (can be shared across all proofs)

### Scalability

**Throughput:**
- Bottleneck: Server proof generation (1-10 seconds per proof)
- Solution: Horizontal scaling with multiple proof generation servers
- Load balancing: Round-robin or queue-based distribution

**Caching:**
- Cannot cache proofs (nonce-bound)
- Can cache coordinate validations temporarily
- Can pre-validate player coordinates before proof generation

## Testing Requirements

### Unit Tests

1. **Commitment Tests:**
   - Generate commitment with known values
   - Verify serialization/deserialization
   - Test commitment binding property

2. **Circuit Tests:**
   - Valid proximity proofs pass
   - Invalid proximity proofs fail
   - Commitment opening verification
   - Distance calculation accuracy

3. **Contract Tests:**
   - Commitment creation with ServerCap
   - Proof verification success cases
   - Nonce increment behavior
   - Invalid proof rejection

### Integration Tests

1. **End-to-End Flow:**
   - Create commitment → Generate proof → Verify on-chain
   - Multiple verifications with nonce progression

2. **Attack Simulations:**
   - Attempt proof replay (should fail)
   - Submit invalid proofs (should revert)
   - Test boundary conditions (exactly 10km)

3. **Performance Tests:**
   - Measure proof generation time
   - Measure verification gas costs
   - Load test server with concurrent requests

## Production Deployment Checklist

### Pre-Deployment

- [ ] Complete trusted setup ceremony
- [ ] Audit smart contract code
- [ ] Security review of server implementation
- [ ] Set up HSM/KMS for key storage
- [ ] Configure monitoring and alerting
- [ ] Prepare incident response plan

### Deployment

- [ ] Deploy Move contract to SUI testnet
- [ ] Deploy server infrastructure
- [ ] Test end-to-end flow on testnet
- [ ] Deploy to SUI mainnet
- [ ] Initialize ServerCap and transfer to server address
- [ ] Create initial location commitments

### Post-Deployment

- [ ] Monitor proof generation latency
- [ ] Track verification success rates
- [ ] Set up automated backups of blinding factors
- [ ] Implement rate limiting
- [ ] Schedule key rotation
- [ ] Document operational procedures

## Common Pitfalls and Solutions

### Pitfall 1: Weak Blinding Factor
**Problem:** Using small or predictable blinding factors
**Solution:** Always use cryptographically secure random 256-bit values

### Pitfall 2: Nonce Desynchronization
**Problem:** Server and contract nonce get out of sync
**Solution:** Always fetch current nonce before proof generation

### Pitfall 3: Coordinate Overflow
**Problem:** Coordinates exceed field element size
**Solution:** Use modular arithmetic and range checks in circuit

### Pitfall 4: Gas Exhaustion
**Problem:** Proof verification costs too much gas
**Solution:** Use Groth16 (most efficient), optimize verifying key storage

### Pitfall 5: Server Key Loss
**Problem:** Losing blinding factors makes commitments unusable
**Solution:** Implement robust backup and recovery procedures

## Future Enhancements

### Potential Features

1. **Batch Verification:**
   - Verify multiple proofs in single transaction
   - Amortize gas costs across users

2. **Dynamic Distance Thresholds:**
   - Allow different radius constraints per verification
   - Encode threshold in public inputs

3. **Time-Based Proofs:**
   - Prove "I was within 10km at timestamp T"
   - Add timestamp constraints to circuit

4. **Multi-Party Proofs:**
   - Prove "All N parties are within 10km of each other"
   - Aggregate multiple location proofs

5. **Recursive Proofs:**
   - Prove "I generated 5 valid proximity proofs this week"
   - Without revealing individual locations

## References and Resources

### Papers and Documentation

- Pedersen Commitments: "Non-Interactive and Information-Theoretic Secure Verifiable Secret Sharing" (Pedersen, 1992)
- Groth16: "On the Size of Pairing-based Non-interactive Arguments" (Groth, 2016)
- zkSNARKs: "Succinct Non-Interactive Zero Knowledge for a von Neumann Architecture" (Ben-Sasson et al., 2014)

### Libraries and Tools

- arkworks-rs: https://github.com/arkworks-rs
- SUI Documentation: https://docs.sui.io
- Circom (alternative circuit language): https://docs.circom.io

### Learning Resources

- "Why and How zk-SNARK Works" by Maksym Petkus
- "Zero Knowledge Proofs: An Illustrated Primer" by Matthew Green
- SUI Move Programming Guide

## Glossary

**Blinding Factor:** Random value used in Pedersen commitment to hide the committed value

**Commitment:** Cryptographic binding to a value that hides the value until opened

**Discrete Log Problem:** Finding x given g^x, computationally hard in appropriate groups

**Field Element:** Element of a finite field used in elliptic curve arithmetic

**Groth16:** Efficient zkSNARK proof system with small proof size and fast verification

**Nonce:** Number used once, prevents replay attacks

**Pedersen Commitment:** Homomorphic commitment scheme based on discrete logarithm problem

**R1CS:** Rank-1 Constraint System, arithmetic circuit representation for zkSNARKs

**Trusted Setup:** One-time ceremony to generate proving/verifying keys for zkSNARKs

**Verifying Key (VK):** Public key used to verify zkSNARK proofs

**Witness:** Private inputs to a zkSNARK circuit

**Zero-Knowledge:** Proof reveals nothing beyond truth of statement

**zkSNARK:** Zero-Knowledge Succinct Non-Interactive Argument of Knowledge