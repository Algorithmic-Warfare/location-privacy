# Security Properties and Threat Model

## Security Guarantees

### Zero-Knowledge
**Property**: Proofs reveal only proximity constraint satisfaction, not coordinates.

**Attack**: Attacker analyzes proof to extract coordinate information.

**Defense**: Groth16 zkSNARK provides computational zero-knowledge. Proof contains no information about witness (coordinates) beyond constraint satisfaction.

### Commitment Binding
**Property**: Proof is cryptographically bound to specific commitment.

**Attack**: Reuse proof generated for SSU_A with commitment for SSU_B.

**Defense**: Public inputs include `commitment_hash`. Verifier checks proof validates against this specific hash. Different commitments have different hashes due to Poseidon collision resistance.

### Hiding (Offline Attack Resistance)
**Property**: Commitment hides coordinates even with unlimited offline computation.

**Attack**: Attacker with commitment `C` tests all candidate coordinates to find match.

**Defense**: 
- Commitment = `Poseidon(x, y, z, r)` where `r` is 254-bit blinding factor
- Without `r`, attacker must find `(x', y', z', r')` such that `C = Poseidon(x', y', z', r')`
- This requires finding collision in Poseidon hash - computationally infeasible (2^254 search space)

### Soundness
**Property**: Invalid proximity claims cannot produce valid proofs.

**Attack**: Generate proof that verifies but violates distance constraint.

**Defense**: Groth16 soundness guarantee - computationally infeasible to generate accepting proof for false statement without breaking cryptographic assumptions (BN254 pairing hardness).

### Replay Protection
**Property**: Same proof cannot be used twice.

**Attack**: Reuse valid proof multiple times.

**Defense**: On-chain nonce increments after successful verification. Each proof implicitly tied to nonce value.

**Future Enhancement**: Include nonce in public inputs for explicit binding.

## Threat Model

### Trusted Components

**Server (Proof Generator)**
- Knows target coordinates
- Knows blinding factors  
- Generates proofs
- **If compromised**: Can generate false proofs, reveal target coordinates
- **Mitigation**: HSM/KMS for key storage, audit logging, monitoring

**Blockchain**
- Stores commitments and verifying keys
- Executes verification logic
- **If compromised**: System integrity fails (out of scope)

### Untrusted Components

**Players**
- Submit player coordinates
- Receive proofs
- Submit proofs for verification
- **Cannot**: Generate valid proofs without server, learn target coordinates, forge proofs

**On-Chain Observers**
- See commitments, proofs, public inputs
- **Cannot**: Determine target coordinates (blinding), determine player coordinates (not in public inputs)

## Attack Scenarios

### 1. Offline Coordinate Guessing

**Attack**: Download commitment, test all possible coordinates offline.

**Why It Fails**: 
- Commitment = `Poseidon(x, y, z, r)` with 254-bit `r`
- Testing coordinate `(x', y', z')` requires finding `r'` such that commitment matches
- 2^254 search space is computationally infeasible

**Tested**: Yes - commitment binding tests validate different coordinates produce different commitments

### 2. Proof Reuse (Different Commitment)

**Attack**: Use proof from SSU_A with commitment for SSU_B.

**Why It Fails**:
- Public inputs include `commitment_hash_A`
- Verifier checks proof against commitment hash in public inputs
- Proof for hash_A will not verify against hash_B

**Tested**: Yes - `test_commitment_hash_mismatch_fails`

### 3. Proof Manipulation

**Attack**: Modify proof bytes to change verification outcome.

**Why It Fails**: 
- Groth16 proof elements cryptographically linked
- Any modification breaks pairing equations
- Verification fails

**Tested**: Yes - `test_corrupted_proof_fails`

### 4. Wrong Verification Key

**Attack**: Use proof from different trusted setup.

**Why It Fails**:
- Proof and verifying key must match from same setup
- Pairing equations fail with mismatched keys

**Tested**: Yes - `test_wrong_verification_key_fails`

### 5. Public Input Manipulation

**Attack**: Use valid proof but modify public inputs.

**Why It Fails**:
- Public inputs are bound to proof via circuit constraints
- Changing inputs breaks verification

**Tested**: Yes - `test_wrong_public_inputs_fails`

### 6. Replay Attack

**Attack**: Reuse valid proof multiple times.

**Why It Fails**:
- Nonce increments after each successful verification
- Smart contract state changes prevent identical transactions

**Tested**: Implicit - nonce increment validated in tests

**Future**: Include nonce in public inputs for explicit binding

## Key Sizes and Security Levels

- **BN254 Curve**: ~100-bit security level
- **Blinding Factor**: 254 bits (~128-bit security against collision)
- **Poseidon Hash**: Collision-resistant for BN254 field
- **Groth16 Proof**: ~128 bytes (compressed)
- **Public Inputs**: 64 bytes (2 field elements)

## Privacy Guarantees

### What is Hidden

✅ **Target coordinates**: Bound in commitment with 254-bit blinding
✅ **Blinding factor**: Known only to server
✅ **Exact distance**: Only constraint satisfaction revealed
✅ **Player coordinates**: Not included in public inputs or on-chain data

### What is Public

🔓 **Commitment hash**: 32 bytes on-chain (reveals nothing without blinding)
🔓 **Max distance threshold**: In public inputs (e.g., 10km)
🔓 **Verification outcome**: Success/fail visible on-chain
🔓 **Verification count**: Nonce visible (number of successful verifications)

## Operational Security

### Key Management

**Proving Key**: 
- Store in HSM/KMS only
- Never on disk in production
- Quarterly rotation

**Blinding Factors**:
- Encrypted database
- Strict access control
- Daily encrypted backups
- **NEVER rotate** (would break existing commitments)

**ServerCap**:
- Production server only
- Monitor all transactions
- Alert on unexpected usage

### Monitoring

Alert on:
- Proof generation failures
- Unusual proof patterns
- Gas cost spikes
- Nonce desync
- HSM unavailability

### Auditing

- Log all proof requests (player_coords, timestamp)
- Log all proof generations (success/fail)
- Log all verification attempts (on-chain)
- Regular security audits of cryptographic implementation

## Future Enhancements

1. **Nonce in Public Inputs**: Explicit binding to prevent theoretical replay attacks
2. **Timestamp Constraints**: Proof validity window
3. **Rate Limiting**: Per-player proof generation limits
4. **Multi-Party Setup**: Distributed trusted setup ceremony
5. **Recursive Proofs**: Aggregate multiple proximity proofs
