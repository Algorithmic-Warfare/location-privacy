# Action plan — hardening proximity proofs & Pedersen commitments

Nice — below is a concrete, prioritized, hands-on action plan you can follow to move your Rust/arkworks design from prototype → production-hardened. I’ve grouped tasks by priority (High / Medium / Low), listed concrete deliverables and verification steps for each, and included operational controls (key management, monitoring, incident handling). No timelines or waiting — just a clear checklist of what to *do next* and what each step proves.

---

## Priority: HIGH — Cryptography correctness & secrecy (must do first)

1. [x] **Replace scalar-only "commitment" with a real curve-point Pedersen**

   * Deliverable: `create_commitment` returns a `G1Projective`/`G1Affine` point `C = x*G + y*H + z*K + r*M`.
   * Tasks:

     * Derive `G,H,K,M` using hash-to-curve with domain separation (no reused generator values).
     * Use proper scalar multiplication and group addition APIs in arkworks.
     * Serialize `C` compressed for on-chain storage.
   * Verify:

     * Unit tests that `C` serializes/deserializes and `create_commitment(opening) -> C` is deterministic.
     * Check that changing `r` changes `C`.
   * Why: field-linear combo currently breaks discrete-log hardness; this fixes the fundamental cryptographic assumption.

2. [x] **Include a freshness nonce (contract-provided) in every proof**

   * Deliverable: proof public inputs include `contract_nonce` (and `C_target` or its compressed coordinates).
   * Tasks:

     * Define on-chain API to return a nonce or require submitter to include it.
     * Add `nonce` as public input to SNARK and enforce in circuit.
   * Verify:

     * Proofs generated for an old nonce must not verify against new nonce on-chain.
   * Why: prevents replay/precomputation of proofs.

3. [x] **Fix distance check & bit-decomposition**

   * Deliverable: robust `distance_squared ≤ R^2` gadget using fixed, safe bit-length decomposition.
   * Tasks:

     * Choose `n_bits` such that `2^n_bits > max_possible_distance_squared` (include fixed-point scaling).
     * Decompose `diff = max - dist_sq` into `n_bits` bits; reconstruct to check equality; ensure bits are boolean.
     * Avoid using full-field MSB index.
   * Verify:

     * Unit tests that boundary distances (exactly R, R±1) behave correctly.
   * Why: prevents modular wrap / false positives due to field arithmetic quirks.

---

## Priority: HIGH — Representation & range safety

4. [x] **Use fixed-point integer coordinate representation + explicit range checks**

   * Deliverable: stable mapping (e.g., integer meters or centimeters) with enforced range `[MIN,MAX]`.
   * Tasks:

     * Choose scale (meters recommended) and mapping (signed→unsigned offset or signed gadget).
     * Add range checks in circuit for each coordinate (prove they lie in allowed bounds).
   * Verify:

     * Tests that coordinates near field modulus wrap are rejected.
   * Why: prevents field wrap-around, overflow attacks, and ambiguity.

5. [x] **Set strong blinding parameter size**

   * Deliverable: define blinding entropy `r_bits` (recommend ≧ 256 bits).
   * Tasks:

     * Use a CSPRNG to generate `r` values of desired bit length.
     * Add unit test ensuring uniqueness / lack of duplicates over many draws.
   * Verify:

     * Entropy tests & static review.
   * Why: a small `r` makes brute-force feasible.

---

## Priority: HIGH — Trusted setup & proof system considerations

6. [x] **Revisit SNARK choice & trusted setup**

   * Deliverable: documented decision on Groth16 vs universal SNARK (PLONK, Halo2, etc.).
   * Tasks:

     * If keeping Groth16: perform multi-party MPC setup, store proving key securely (toxic waste caution).
     * If switching to universal (no per-circuit toxic setup): prototype PLONK/Plonky2/Halo2 circuit and measurement.
   * Verify:

     * Successful setup with audit trail and reproducible artifacts.
   * Why: Groth16 has faster verification but requires toxic-key protection; universal SNARKs simplify ceremonies.

---

## Priority: MEDIUM — Circuit design & optimization

7. [x] **Implement Pedersen commitment check inside SNARK efficiently**

   * Deliverable: circuit uses fixed-base scalar multiplication gadgets or Poseidon hash-based commitment (if cheaper).
   * Tasks:

     * Compare cost (R1CS constraints) of fixed-base multi vs using hash (Poseidon) with commitments stored as field elements inside SNARK.
     * Implement the cheaper variant and benchmark proving times.
   * Verify:

     * Benchmarks for proving time and proof size meet operational constraints.
   * Why: on-chain verification cost and prover CPU matter.

8. [x] **Make public inputs and verifier interface consistent**

   * Deliverable: defined wire format for public inputs (e.g., `C_target.x`, `C_target.y`, `nonce`, `max_dist`).
   * Tasks:

     * Implement serialization/deserialization helpers.
     * Align on-chain verifier ABI with proof input format expected by verifier.
   * Verify:

     * End-to-end test: generate proof → on-chain verify succeeds with sample inputs.

90. **Add player commitment option (optional)**

    * Deliverable: support `C_player` + opening in circuit instead of raw `x_player` witness (helps client privacy).
    * Tasks:

      * Add code paths for both witness types.
    * Verify:

      * Tests for both flows.

---

## Priority: MEDIUM — Tests, adversarial & offline brute-force simulation

10. [x] **Simulate offline brute-force attack against your commitments**

    * Deliverable: test harness that tries to recover `(x,r)` for known `C` from an enumerated set of candidate `x` values (e.g., Lagrange points).
    * Tasks:

      * Use your real curve-based Pedersen and realistic `r` sizes.
      * Measure compute required for success (should be infeasible).
    * Verify:

      * Empirical evidence that brute-force against realistic domain fails within practical compute constraints.

11. **Fuzz / property testing of R1CS circuit**

    * Deliverable: randomized tests that generate valid/invalid witnesses and assert proof acceptance/failure.
    * Tasks:

      * Use `arkworks` test harness or `proptest`-style to generate ranges of coordinates and blinds.
    * Verify:

      * Circuit rejects malformed inputs and accepts valid ones.

12. [x] **Unit & integration tests**

    * Deliverable: CI pipeline tests that validate:

      * Commitment correctness,
      * Proof generation and verification (off-chain),
      * On-chain verification against verifier contract (local dev chain).
    * Tasks:

      * Add tests to run in CI (circle/gha) with small circuits and mocked keys.

---

## Priority: MEDIUM — On-chain verifier & gas / costs

13. [x] **Design on-chain verifier & gas budget**

    * Deliverable: on-chain verifier contract that accepts proof + public inputs and verifies.
    * Tasks:

      * If EVM: generate Solidity verifier for Groth16 or PLONK (use standard tools), check gas for verify call.
      * Add caching or batching if many verifications expected.
    * Verify:

      * Measure gas on testnet, ensure cost acceptable for intended UX.
    * Why: an expensive verifier can break UX or be DoS vector.

---

## Priority: LOW — Monitoring, provenance, and auditing

14. **Auditability & logging**

    * Deliverable: tamper-evident logging of proof issuance (signed receipts), with minimal leakage (no coordinates logged).
    * Tasks:

      * Server logs: store proof metadata (timestamp, target id, nonce, proof id) with signature.
      * Ensure logs do not contain raw openings.
    * Verify:

      * Audit that logs contain no secrets and are sufficient for post-mortem.

15. **Third-party security audit**

    * Deliverable: commissioned crypto + smart-contract audit covering:

      * commitment implementation,
      * circuit correctness,
      * on-chain verifier,
      * key management.
    * Tasks:

      * Prepare threat model, deliverables, test corpuses to auditors.
    * Verify:

      * Address findings and re-run tests.

16. **Operational runbook / incident response**

    * Deliverable: quick reference for key compromise scenarios, rollback, revocation, and user notification.
    * Tasks:

      * Create step-by-step guide: revoke keys → rotate commitments → re-issue proofs.
    * Verify:

      * Tabletop exercise with dev & ops.

---

## Minimal acceptance criteria (what to aim for)

* Commitments are proper curve points and stored on-chain as such.
* Prover can generate a proof that verifies on-chain and includes freshness nonce.
* Offline brute-force experiments show infeasibility for realistic parameters.
* CI pipeline contains unit tests, R1CS fuzz tests and an on-chain verification smoke test.
* Security audit completed with issues resolved.

---

## Quick checklist you can copy into a ticket system

* [x] Implement G1Point Pedersen `create_commitment`
* [x] Generate Hash-to-Curve basepoints (`G,H,K,M`)
* [x] Replace Fr serialization with G1 compressed serialization for on-chain
* [x] Add fixed-point & range checks in circuit
* [x] Implement robust `diff` bit-decomposition gadget (n_bits param)
* [x] Add `nonce` public input and wire on-chain API
* [x] Add unit + fuzz tests for circuit & commitments
* [x] Simulate offline brute-force attack against commitments
* [x] Build on-chain verifier & test gas usage
* [ ] Draft key rotation & compromise runbook
* [ ] Commission third-party audit

---

If you want I can:

* rewrite your `create_commitment` in Rust to use `G1Projective`/`G1Affine` and show correct serialization, **and**
* produce the corrected R1CS snippet for the distance check with bit-decomposition and fixed-point mapping.

Which of those two code artifacts should I generate for you next?
