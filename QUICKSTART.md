# Location Privacy - Quick Reference

## Quick Start

```bash
# One-command integration test (generates proofs, tests on-chain)
npm run integration:test

# Start orchestrated local environment
npm run start:local
```

## Common Commands

### Network Operations
```bash
npm run start:sui          # Start local Sui network
npm run fund               # Fund account from faucet
npm run start:local        # Start full orchestrated environment (mprocs)
```

### Move Contract Development
```bash
npm run build:move         # Build Move contracts
npm run test:move          # Run Move tests
npm run publish:local      # Publish to local network
npm run deploy:watch       # Auto-deploy on file changes (simple watcher)
npm run fmt:move           # Format Move code

# Optional: faster file watching (requires: cargo install watchexec-cli)
npm run deploy:watch:watchexec
```

### Rust Development
```bash
npm run test:rust          # Run Rust tests (27 test cases)
npm run generate:e2e       # Generate E2E test data
npm run fmt:rust           # Format Rust code
npm run lint:rust          # Lint with clippy
```

### Proof Server & Client
```bash
npm run server:build       # Build proof server (release mode)
npm run server:start       # Start proof server (port 3001)
npm run server:dev         # Start server with auto-reload (cargo watch)

npm run client:install     # Install client dependencies
npm run client:dev         # Start client dev server (port 3000)
npm run client:build       # Build client for production
```

### Integration Testing
```bash
npm run integration:test   # Full E2E test (Rust → Move)
```

## Test Data Constraints

All security constraints are validated in the integration tests:

1. **Commitment Binding** - Cannot reuse proof with different commitment
2. **Proof Integrity** - Corrupted proofs are rejected
3. **VK Pairing** - Proof must match verifying key
4. **Public Inputs** - Inputs must match proof
5. **Valid Proximity** - Coordinates within 10km succeed
6. **Invalid Coordinates** - Out-of-range coordinates fail

Run specific constraint tests:
```bash
cd packages/location
sui move test --filter test_commitment_hash_mismatch_fails
sui move test --filter test_corrupted_proof_fails
sui move test --filter test_user_within_10km_succeeds
```

## Architecture

```
location-privacy/
├── crates/commitmentgen/     # Rust: Poseidon commitments, zkSNARK proofs
│   ├── src/lib.rs            # Core cryptographic implementation
│   └── examples/             # E2E test setup, trusted setup
├── packages/location/        # Move: On-chain verification
│   ├── sources/              # proximity.move contract
│   └── tests/                # Move contract tests
├── scripts/                  # Deployment and automation
│   ├── start_sui.sh          # Start local network
│   ├── fund_address.sh       # Fund from faucet
│   ├── publish_local.sh      # Deploy contracts
│   └── integration-test.sh   # Full E2E test
├── mprocs.yaml               # Orchestrated development
├── package.json              # npm scripts
└── .env.local                # Environment config
```

## Data Flow

```
1. Server generates commitment:
   C = Poseidon(x, y, z, r) → [32 bytes]

2. Server publishes commitment on-chain:
   create_commitment(C, owner)

3. Player requests proof:
   (player_coords) → Server

4. Server generates proof:
   zkSNARK(target_coords, player_coords, blinding, C, max_distance)
   → (proof, public_inputs)

5. Player verifies on-chain:
   verify_proximity_proof(commitment, vk, proof, public_inputs)
   → Success (nonce incremented) or Fail (revert)
```

## Security Properties

- **Zero-Knowledge:** Proof reveals only proximity constraint satisfaction
- **Binding:** Commitment cannot be changed after publication
- **Hiding:** 254-bit blinding prevents coordinate guessing
- **Soundness:** Invalid proofs cryptographically rejected
- **Replay Protection:** Nonce prevents proof reuse
- **Location Binding:** Proof tied to specific commitment object

## File Structure

### Configuration Files
- `.env.local` - Private key for local development
- `mprocs.yaml` - Multi-process orchestration
- `package.json` - npm scripts and dependencies
- `Move.toml` - Move package configuration

### Build Artifacts (gitignored)
- `build/` - Move compilation output
- `target/` - Rust compilation output
- `.last_publish_output.json` - Deployment records
- `generated_move_tests.move` - Generated test data

### Documentation
- `README.md` - Full project documentation
- `DEPLOYMENT.md` - Deployment guide
- `context.md` - System design and security
- `data_constraints.md` - Privacy expectations

## Environment Variables

### .env.local
```bash
PRIVATE_KEY_FILE=suiprivkey1abc...   # Sui keypair for local dev
```

### packages/location/.env.local (generated)
```bash
PACKAGE_ID=0xabc...                   # Deployed package ID
```

## Troubleshooting

### "Cannot find private key"
- Check `.env.local` exists and has valid PRIVATE_KEY_FILE
- Generate new key: `sui keytool generate ed25519`

### "Faucet request failed"
- Increase FUND_DELAY_SECONDS (default: 3)
- Check local Sui network is running: `ps aux | grep sui`

### "Publish failed"
- Ensure account is funded: `sui client balance`
- Check gas budget is sufficient (default: 30M)

### "Test failed: commitment hash mismatch"
- Regenerate test data: `npm run generate:e2e`
- Copy to tests: `cp crates/commitmentgen/generated_move_tests.move packages/location/tests/location_tests.move`

### "mprocs not found"
- Install: `cargo install mprocs`
- Or run manually without mprocs (see README)

## Performance

- **Commitment Generation:** < 1ms (Poseidon hash)
- **Proof Generation:** 1-5 seconds (zkSNARK with ~150-200 constraints)
- **Proof Verification:** < 10ms on-chain (Groth16 pairing)
- **Storage:** 32 bytes per commitment (Poseidon hash)
- **Gas Cost:** ~300k-500k gas units per verification

## Key Concepts

- **Poseidon Hash:** Cryptographic hash optimized for zkSNARK circuits
- **Commitment:** C = Poseidon(x, y, z, r) - binds to coordinates with 254-bit blinding
- **zkSNARK:** Zero-Knowledge Succinct Non-Interactive Argument of Knowledge
- **Groth16:** Efficient zkSNARK proof system (small proofs, fast verification)
- **ServerCap:** Move capability restricting commitment creation to server
- **Nonce:** Counter preventing proof replay attacks

## Resources

- [Full Documentation](./README.md)
- [Deployment Guide](./DEPLOYMENT.md)
- [System Context](./context.md)
- [Data Constraints](./data_constraints.md)
- [Sui Documentation](https://docs.sui.io)
- [Arkworks Documentation](https://arkworks.rs)

---

**Need help?** Check the [README](./README.md) or [DEPLOYMENT.md](./DEPLOYMENT.md) for detailed instructions.
