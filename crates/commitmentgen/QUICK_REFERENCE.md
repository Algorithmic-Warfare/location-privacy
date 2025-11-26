# Quick Reference: Pedersen Commitment Verification Testing

## TL;DR

**Goal:** Implement proper Pedersen commitment verification: `C = x*G + y*H + z*K + r*M`

**Guiding Test:** `test_proper_pedersen_commitment_verification_guide` (currently `#[ignore]`d)

**Success:** When guiding test passes, implementation is complete ✓

## Quick Commands

```bash
# 1. See current behavior (shows blinding factor not enforced)
cargo test test_current_simplified_commitment_behavior -- --nocapture

# 2. Try guiding test (will fail until proper EC arithmetic implemented)
cargo test test_proper_pedersen_commitment_verification_guide -- --ignored --nocapture

# 3. After implementation, remove #[ignore] and run:
cargo test test_proper_pedersen_commitment_verification_guide -- --nocapture
```

## Files to Read

1. **`IMPLEMENTATION_SUMMARY.md`** - Start here, complete overview
2. **`PEDERSEN_VERIFICATION_PSEUDOCODE.md`** - Implementation details
3. **`TESTING_GUIDE.md`** - Development workflow

## Key Code Location

**File:** `src/lib.rs` **Lines 276-286**

Replace this:
```rust
// Constraint 1: Verify Pedersen commitment opening C = x*G + y*H + z*K + r*M
commitment_x.enforce_equal(&x_t)?;
commitment_y.enforce_equal(&y_t)?;
commitment_z.enforce_equal(&z_t)?;
```

With proper elliptic curve arithmetic (see `PEDERSEN_VERIFICATION_PSEUDOCODE.md`).

## What the Tests Show

### Current Behavior Test (PASSING)
```
Test 3: Blinding factor is not cryptographically enforced...
  ⚠️  WARNING: Proof succeeded with DIFFERENT blinding factor!
```
**Problem:** Blinding factor doesn't matter - only coordinates checked.

### Guiding Test (CURRENTLY IGNORED)
```
Test 1: Valid commitment with matching witness... ✓
Test 2: Commitment mismatch - should fail... ✗ (currently passes)
Test 3: Wrong blinding factor... ✗ (currently passes)
```
**Goal:** All tests should pass (failures should fail, successes should succeed).

## Expected Timeline

1. **Study phase**: 1-2 hours (read pseudocode, understand EC arithmetic)
2. **Implementation**: 3-5 hours (add constraints, update circuit)
3. **Testing/debugging**: 2-3 hours (fix test instantiations, validate)
4. **Integration**: 1-2 hours (update Move contract for new format)

**Total: ~1 day of focused work**

## Constraint Budget

- **Current:** 3-5 constraints
- **Target:** ~1000-1300 constraints
- **Impact:** 3-5x slower proof generation (~3-10 seconds)
- **Benefit:** Cryptographically secure, production-ready

## Success Checklist

- [ ] Read `IMPLEMENTATION_SUMMARY.md`
- [ ] Run current behavior test (understand baseline)
- [ ] Read `PEDERSEN_VERIFICATION_PSEUDOCODE.md`
- [ ] Implement EC arithmetic in constraint 1
- [ ] Update `ProximityCircuit` struct
- [ ] Update all test instantiations (~8 places)
- [ ] Remove `#[ignore]` from guiding test
- [ ] Run guiding test - ALL PASS ✓
- [ ] Update Move contract (32-byte compressed commitment)
- [ ] Integration tests pass

## When You're Stuck

**Problem:** Don't know where to start
**Solution:** Read `PEDERSEN_VERIFICATION_PSEUDOCODE.md` line by line

**Problem:** Guiding test still failing after implementation
**Solution:** Check `TESTING_GUIDE.md` debugging section

**Problem:** Performance too slow (>30 seconds)
**Solution:** Consider Poseidon hash alternative (see pseudocode)

**Problem:** Move contract integration failing
**Solution:** Update commitment format from 96 bytes → 32 bytes compressed

## Architecture Changes Required

### Circuit Struct (Before)
```rust
pub commitment_x: Option<Fr>,  // 32 bytes
pub commitment_y: Option<Fr>,  // 32 bytes  
pub commitment_z: Option<Fr>,  // 32 bytes
```

### Circuit Struct (After)
```rust
pub commitment: Option<G1Affine>,  // Full EC point
```

### Move Contract (Before)
```move
// 96 bytes: x, y, z coordinates as field elements
commitment_bytes: vector<u8>  // length = 96
```

### Move Contract (After)
```move
// 32 bytes: compressed EC point
commitment_bytes: vector<u8>  // length = 32
```

## The North Star

**The guiding test is your deliverable.**

When this output appears, you're done:

```
========================================
ALL TESTS PASSED! ✓
========================================

The circuit properly verifies Pedersen commitment:
  C = x*G + y*H + z*K + r*M

Security properties validated:
  ✓ Binding: Cannot change coordinates without changing commitment
  ✓ Verification: Circuit enforces cryptographic commitment constraint
  ✓ Completeness: Valid commitments generate valid proofs
  ✓ Soundness: Invalid commitments cannot generate valid proofs
```

---

**Ready to start?** Read `IMPLEMENTATION_SUMMARY.md` first! 🚀
