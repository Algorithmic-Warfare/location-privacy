# Testing Guide for Pedersen Commitment Verification

## Overview

This guide explains the testing strategy for implementing proper Pedersen commitment verification in the zkSNARK circuit.

## Test Structure

### 1. Current Behavior Test (PASSING)

**Test Name:** `test_current_simplified_commitment_behavior`

**Purpose:** Documents the current simplified implementation and its limitations.

**Run with:**
```bash
cargo test test_current_simplified_commitment_behavior -- --nocapture
```

**What it validates:**
- ✓ Simplified field equality checks work (commitment_x == x_t, etc.)
- ⚠️ Blinding factor is NOT cryptographically enforced
- ⚠️ No hiding property (commitment reveals coordinates)
- ⚠️ No cryptographic binding (commitment is just coordinates as field elements)

**Expected Result:** PASS (shows current behavior)

### 2. Guiding Test (CURRENTLY IGNORED - SHOULD FAIL)

**Test Name:** `test_proper_poseidon_commitment_verification_guide`

**Purpose:** Validates proper Poseidon hash commitment verification once implemented.

**Run with:**
```bash
# This will fail with current implementation
cargo test test_proper_poseidon_commitment_verification_guide -- --ignored --nocapture
```

**What it validates:**
1. ✓ Valid commitment with matching witness succeeds
2. ✗ Attacker scenario: wrong commitment coordinates fails
3. ✗ Wrong blinding factor fails
4. ✗ Tampered x coordinate fails
5. ✗ Tampered y coordinate fails
6. ✗ Tampered z coordinate fails
7. ✗ Multiple simultaneous tampering fails

**Expected Result:** 
- **Current:** FAIL (simplified implementation doesn't check Poseidon hash)
- **After Implementation:** PASS (proper Poseidon hash verification in place)

## Implementation Roadmap

### Phase 1: Understand Current State ✓

Run the current behavior test to see what's working:
```bash
cargo test test_current_simplified_commitment_behavior -- --nocapture
```

**Output shows:**
```
Test 1: Mismatched commitment coordinates (should fail)...
  ✓ PASS: Mismatched coordinates rejected (field equality check)

Test 3: Blinding factor is not cryptographically enforced...
  ⚠️  WARNING: Proof succeeded with DIFFERENT blinding factor!
```

### Phase 2: Implement Poseidon Hash Verification

Follow the pseudocode in `PEDERSEN_VERIFICATION_PSEUDOCODE.md` (updated for Poseidon):

1. **Add dependencies to Cargo.toml:**
   ```toml
   ark-crypto-primitives = { version = "0.4.0", features = ["r1cs", "sponge"] }
   ```

2. **Import Poseidon gadgets:**
   ```rust
   use ark_crypto_primitives::crh::{
       poseidon::{
           CRH as PoseidonCRH,
           constraints::{CRHGadget as PoseidonCRHGadget, CRHParametersVar},
       },
       CRHScheme, CRHSchemeGadget,
   };
   use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;
   ```

3. **Modify ProximityCircuit struct:**
   ```rust
   pub struct ProximityCircuit {
       // ... witness fields unchanged ...
       
       // Public inputs - CHANGED
       pub commitment_hash: Option<Fr>,  // Changed from commitment_x, commitment_y, commitment_z
       pub max_distance_squared: Fr,
       
       // Configuration - CHANGED
       pub poseidon_config: PoseidonConfig<Fr>,  // Replace pedersen_params
       pub max_coord: Fr,
   }
   ```

4. **Replace Constraint 1 (lines 276-286):**
   ```rust
   // OLD: Simplified field equality (3 constraints)
   commitment_x.enforce_equal(&x_t)?;
   commitment_y.enforce_equal(&y_t)?;
   commitment_z.enforce_equal(&z_t)?;

   // NEW: Poseidon hash verification (~150-200 constraints)
   let commitment = FpVar::new_input(cs.clone(), || {
       self.commitment_hash.ok_or(SynthesisError::AssignmentMissing)
   })?;
   
   let params_var = CRHParametersVar::new_constant(
       cs.clone(), 
       self.poseidon_config.clone()
   )?;
   
   let inputs = vec![x_t, y_t, z_t, r];
   let computed_commitment = PoseidonCRHGadget::evaluate(&params_var, &inputs)?;
   
   computed_commitment.enforce_equal(&commitment)?;
   ```

### Phase 3: Update Test Instantiations

Update all test circuits to use new structure (search for `ProximityCircuit {`):
- Replace `commitment_x`, `commitment_y`, `commitment_z` with single `commitment_hash: Some(Fr)`
- Replace `pedersen_params` with `poseidon_config`
- Update public inputs serialization (2 field elements: hash + max_distance)
- Update Move contract to accept 32-byte hash instead of 96-byte coordinates

### Phase 4: Validate with Guiding Test

Remove `#[ignore]` from the test:
```rust
#[test]
// #[ignore]  <- Remove this line
fn test_proper_poseidon_commitment_verification_guide() {
```

Run the test:
```bash
cargo test test_proper_poseidon_commitment_verification_guide -- --nocapture
```

**Expected output when working:**
```
========================================
POSEIDON COMMITMENT VERIFICATION TEST
========================================

Test 1: Valid commitment with matching witness...
  ✓ PASS: Valid proof generated successfully

Test 2: Commitment mismatch - attacker tries to use wrong coordinates...
  ✓ PASS: Attack correctly rejected (constraint violation)

Test 3: Wrong blinding factor...
  ✓ PASS: Wrong blinding factor correctly rejected

Test 4: Tampered x coordinate in witness...
  ✓ PASS: Tampered x coordinate correctly rejected

Test 5: Tampered y coordinate in witness...
  ✓ PASS: Tampered y coordinate correctly rejected

Test 6: Tampered z coordinate in witness...
  ✓ PASS: Tampered z coordinate correctly rejected

Test 7: Multiple coordinates tampered simultaneously...
  ✓ PASS: Multiple tampering correctly rejected

========================================
ALL TESTS PASSED! ✓
========================================

The circuit properly verifies Poseidon commitment:
  C = Poseidon(x, y, z, r)

Security properties validated:
  ✓ Binding: Cannot change coordinates without changing commitment (collision resistance)
  ✓ Hiding: Random blinding factor hides coordinates (hash preimage resistance)
  ✓ Verification: Circuit enforces cryptographic commitment constraint
  ✓ Completeness: Valid commitments generate valid proofs
  ✓ Soundness: Invalid commitments cannot generate valid proofs

Performance achieved:
  • Constraints: ~150-200 (vs ~3 simplified, ~1000+ EC)
  • Proof time: ~2-3 seconds (practical for production)
  • Security: 128-bit collision resistance
```

## Test Metrics

### Current Simplified Implementation
- **Constraint Count:** ~3-5 constraints
- **Proof Generation Time:** ~1-2 seconds
- **Security Level:** ⚠️ Demo only - not cryptographically secure
- **Blinding Factor Enforcement:** ❌ Not enforced
- **Commitment Size:** 96 bytes (3 field elements)

### Target Poseidon Implementation (RECOMMENDED)
- **Constraint Count:** ~150-200 constraints
- **Proof Generation Time:** ~2-3 seconds
- **Security Level:** ✓ Production-ready (128-bit collision resistance)
- **Blinding Factor Enforcement:** ✓ Cryptographically enforced
- **Commitment Size:** 32 bytes (single field element)

## Success Criteria

The implementation is complete when:

1. ✓ `test_current_simplified_commitment_behavior` still passes (backwards compatibility test)
2. ✓ `test_proper_poseidon_commitment_verification_guide` passes without `#[ignore]`
3. ✓ All existing tests still pass
4. ✓ Performance benchmarks show acceptable proof generation time (2-3 seconds target)
5. ✓ Move contract integration tests pass with new commitment format (32 bytes)

## Debugging Tips

### If guiding test fails on valid proof generation:

**Problem:** Test 1 fails - valid proof doesn't generate
**Solution:** Check that public inputs match the new format (commitment point instead of coordinates)

### If guiding test passes on attack scenarios:

**Problem:** Tests 2-7 pass when they should fail
**Solution:** Poseidon hash constraint is not properly enforced - review CRH gadget implementation and ensure inputs are correctly passed

### If proof generation is too slow:

**Problem:** Proof takes >5 seconds to generate with Poseidon
**Solution:** Check implementation:
- Verify Poseidon parameters are correctly configured (rate=4, capacity=1)
- Ensure you're using CRH (not full sponge) for single hash output
- Profile to identify constraint bottlenecks
- Target: 2-3 seconds for ~150-200 constraints

## Implementation Approaches Comparison

### Option 1: Poseidon Hash Commitment (RECOMMENDED ✓)
- Security: ✓✓✓ Production-ready (128-bit)
- Performance: Fast (~2-3s proofs)
- Complexity: Medium (~150-200 constraints)
- Implementation: See `PEDERSEN_VERIFICATION_PSEUDOCODE.md`
- **Best choice for production**: Optimal balance of security and performance

```rust
// Poseidon implementation
let commitment = FpVar::new_input(cs.clone(), || self.commitment_hash.ok_or(...))?;
let params_var = CRHParametersVar::new_constant(cs.clone(), self.poseidon_config.clone())?;
let inputs = vec![x_t, y_t, z_t, r];
let computed = PoseidonCRHGadget::evaluate(&params_var, &inputs)?;
computed.enforce_equal(&commitment)?;
```

### Option 2: Elliptic Curve Pedersen (Overkill)
- Security: ✓✓✓ Maximum (algebraic)
- Performance: Slow (~5-10s proofs)
- Complexity: High (1000+ constraints)
- Trade-off: 6-7x slower than Poseidon for same security level
- **Not recommended**: Too slow for practical use

### Option 3: Hybrid Development Approach
- Use simplified version for rapid development/testing
- Switch to Poseidon for production
- Feature flag to toggle implementations during development

## Questions?

For detailed implementation guidance, see:
- `PEDERSEN_VERIFICATION_PSEUDOCODE.md` - Step-by-step Poseidon implementation
- `IMPLEMENTATION_SUMMARY.md` - Complete workflow and decision rationale
- `src/lib.rs` lines 276-286 - Current constraint location
- Test files - Search for `ProximityCircuit` to find all instantiations (~8 locations)

## Next Steps

1. Run current behavior test to understand baseline
   ```bash
   cargo test test_current_simplified_commitment_behavior -- --nocapture
   ```

2. Study Poseidon implementation guide
   ```bash
   cat PEDERSEN_VERIFICATION_PSEUDOCODE.md  # Updated for Poseidon
   ```

3. Add ark-crypto-primitives dependency
   ```toml
   ark-crypto-primitives = { version = "0.4.0", features = ["r1cs", "sponge"] }
   ```

4. Implement Poseidon hash constraints (15-20 lines)
   - Replace lines 276-286 in src/lib.rs
   - Update ProximityCircuit struct

5. Update all test instantiations (~8 circuits)
   - Change commitment_x/y/z → commitment_hash
   - Change pedersen_params → poseidon_config

6. Run guiding test (remove `#[ignore]`)
   ```bash
   cargo test test_proper_poseidon_commitment_verification_guide -- --nocapture
   ```

7. Celebrate when all 7 sub-tests pass! 🎉
   - You'll have production-ready commitment verification
   - ~150-200 constraints, 2-3 second proofs
   - 128-bit security, practical performance
