# Location Privacy System

Zero-knowledge proximity verification for 3D coordinates using Poseidon commitments and zkSNARK proofs.

## Quick Start

```bash
# One-command integration test
npm run integration:test

# Full local environment (requires: cargo install mprocs). After it starts you may need to
# "restart" scripts to make sure various things execute in order.
# The flow is:
# 1. Start local SUI network
# 2. Fund a wallet address with gas to submit transactions to the blockchain.
# 3. Build and deploy SUI objects
# 4. Run tests against deployed objects
npm run start:local
```

## Overview

Prove two 3D coordinates are within a distance threshold ("<10km" in tests) without revealing the target location.

**Key Features:**
- **Zero-Knowledge**: Proofs reveal only proximity, not coordinates
- **Offline Attack Resistant**: 254-bit blinding prevents coordinate guessing  
- **Efficient**: Poseidon hash optimized for zkSNARK circuits
- **Fast**: 15-20ms proof generation in release mode

## Architecture

```
location-privacy/
├── crates/
│   ├── commitmentgen/     # Rust: Poseidon commitments + zkSNARK proofs
│   └── proof-server/      # HTTP server for proof generation
├── packages/
│   ├── location/          # Move: On-chain verification contracts
│   └── proof-client/      # React: Web UI for proof requests - interacting requires a SUI wallet w/ local network support - I used Surf Wallet chrome extension for testing.
├── docs/                  # Documentation
└── scripts/               # Build and deployment automation
```

## Common Commands

### Development
```bash
npm run start:sui          # Start local Sui network
npm run fund               # Fund account from faucet

npm run build:move         # Build Move contracts
npm run test:move          # Test Move contracts
npm run publish:local      # Deploy contracts locally

npm run test:rust          # Test Rust library (27 tests)
npm run server:start       # Start proof server (port 3001)
npm run client:dev         # Start client UI (port 3000)
```

### Testing
```bash
npm run integration:test   # Full E2E test
npm run generate:e2e       # Generate test data
```

## How It Works

### 1. Commitment Generation
Server creates Poseidon hash commitment binding to target location:
```
C = Poseidon(x, y, z, r)  // r = 254-bit blinding factor
```

### 2. Proof Generation
Player requests proof from server with their coordinates:
```
zkSNARK Proof: distance(player, target) ≤ max_distance
Public Inputs: [commitment_hash, max_distance_squared]
```

### 3. On-Chain Verification
Anyone can verify the proof without learning coordinates:
```move
verify_proximity_proof(commitment, verifying_key, proof, public_inputs)
```

## Security Properties

- **Binding**: Proof cryptographically tied to specific commitment (prevents reuse across SSUs)
- **Hiding**: 254-bit blinding prevents brute-force coordinate guessing (2^254 search space)
- **Soundness**: Invalid proofs are cryptographically rejected (Groth16 guarantees)
- **Replay Protection**: Nonce increments prevent proof reuse

See [docs/SECURITY.md](docs/SECURITY.md) for detailed threat model.

## Performance

| Operation | Time | Notes |
|-----------|------|-------|
| Commitment Generation | < 1ms | Poseidon hash computation |
| Proof Generation | 15-20ms | Release mode, ~150-200 R1CS constraints |
| On-Chain Verification | < 10ms | Groth16 pairing verification |
| Storage | 32 bytes | Single field element per commitment |

**Critical**: Disable `tracing_subscriber` for production (causes 400x slowdown). See [crates/proof-server/PERFORMANCE.md](crates/proof-server/PERFORMANCE.md).

## Documentation

- **[docs/SETUP.md](docs/SETUP.md)** - Full stack setup guide
- **[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)** - Testnet/mainnet deployment
- **[docs/SECURITY.md](docs/SECURITY.md)** - Security properties and threat model
- **[context.md](context.md)** - Detailed system design (technical deep-dive)
- **[data_constraints.md](data_constraints.md)** - Privacy expectations

### Component-Specific Docs
- [crates/commitmentgen/README.md](crates/commitmentgen/README.md) - Rust library API
- [crates/proof-server/PERFORMANCE.md](crates/proof-server/PERFORMANCE.md) - Performance tuning
- [crates/proof-server/AUTO_PUBLISH_GUIDE.md](crates/proof-server/AUTO_PUBLISH_GUIDE.md) - Auto-publish feature
- [packages/proof-client/README.md](packages/proof-client/README.md) - Client UI documentation

## Requirements

- **Rust** 1.70+ (`cargo`, `rustc`)
- **Node.js** 18+ (`npm` or `pnpm`)
- **Sui CLI** (for Move contracts)
- **Sui Wallet** extension (for client UI)

## Testing

The system includes comprehensive test coverage:

**Rust Library** (27 tests):
- Poseidon commitment properties (binding, hiding, determinism)
- Coordinate handling (negative values, large integers)
- Circuit constraints (Poseidon verification, distance calculation)
- Trusted setup validation

**Move Contracts**:
- Valid proximity scenarios
- Security constraints (commitment binding, proof integrity, replay protection)
- Invalid input rejection

**Integration Tests**:
- Full E2E flow (Rust → Move)
- Cross-language verification consistency
- Automated test data generation

Run all tests:
```bash
npm run test:rust && npm run test:move && npm run integration:test
```

## License

See [LICENSE](LICENSE) file.
