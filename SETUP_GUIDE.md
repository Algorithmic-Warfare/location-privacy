# Location Privacy - Full Stack Setup Guide

Complete guide for running the proof server and client application.

## Overview

This system provides zero-knowledge proximity verification:

1. **Proof Server** (Rust/Axum): Generates zkSNARK proofs from player-signed requests
2. **Client App** (React/TypeScript): Web UI for wallet connection and proof requests
3. **Move Contracts**: On-chain verification of proximity proofs

## Prerequisites

- **Rust** (1.70+)
- **Node.js** (18+) and npm/pnpm
- **Sui CLI** (for local network)
- **Sui Wallet** browser extension

## Quick Start

### 1. Install Client Dependencies

```bash
npm run client:install
```

### 2. Start Proof Server

```bash
# Terminal 1: Start proof server (port 3001)
npm run server:start
```

The server will:
- Perform trusted setup for zkSNARK circuit
- Generate target location commitment
- Expose API endpoints for proof generation

### 3. Start Client Development Server

```bash
# Terminal 2: Start client (port 3000)
npm run client:dev
```

### 4. Use the Application

1. Open http://localhost:3000
2. Click "Connect Wallet" to connect Sui wallet
3. Enter player coordinates (X, Y, Z)
4. Set max distance threshold
5. Click "Request Proof" to generate zkSNARK proof

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         Browser Client                          │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  React App (localhost:3000)                              │  │
│  │  - Wallet Integration (@mysten/dapp-kit)                 │  │
│  │  - Message Signing (Ed25519)                             │  │
│  │  - Proof Request UI                                       │  │
│  └───────────────────────────┬──────────────────────────────┘  │
└────────────────────────────────┼───────────────────────────────┘
                                 │ HTTP POST /api/generate-proof
                                 │ (signed coordinates)
                                 ▼
┌─────────────────────────────────────────────────────────────────┐
│                       Proof Server (Rust)                        │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  Axum HTTP Server (localhost:3001)                       │  │
│  │  - Signature Verification                                │  │
│  │  - zkSNARK Proof Generation (Groth16)                    │  │
│  │  - Poseidon Commitment Management                        │  │
│  └────────────────────────┬─────────────────────────────────┘  │
│                            │                                     │
│  ┌────────────────────────▼─────────────────────────────────┐  │
│  │  Commitment Library (commitmentgen)                      │  │
│  │  - Trusted Setup (proving keys, verifying keys)          │  │
│  │  - Circuit: Proximity(target, player, max_dist)          │  │
│  │  - Poseidon Hash: H(x, y, z, blinding)                   │  │
│  └──────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                                 │
                                 │ Returns proof + public inputs
                                 ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Sui Blockchain (Future)                     │
│  - verify_proximity_proof(commitment, vk, proof, inputs)        │
│  - On-chain verification with Move contracts                    │
└─────────────────────────────────────────────────────────────────┘
```

## API Endpoints

### Health Check
```bash
GET http://localhost:3001/health
```

### Server Info
```bash
GET http://localhost:3001/api/info
```

Response:
```json
{
  "status": "ready",
  "commitment_published": false,
  "commitment_id": null,
  "commitment_bytes": "deadbeef..."
}
```

### Generate Proof
```bash
POST http://localhost:3001/api/generate-proof
Content-Type: application/json

{
  "player_x": -23534879266777850000,
  "player_y": -435314932817330100,
  "player_z": -4336253132989267000,
  "max_distance_km": 10,
  "signature": "base64_signature",
  "message": "{...signed_message_json...}"
}
```

Response:
```json
{
  "proof_bytes": "hex_encoded_proof",
  "public_inputs": "hex_encoded_inputs",
  "commitment_id": null,
  "player_coordinates": {
    "x": -23534879266777850000,
    "y": -435314932817330100,
    "z": -4336253132989267000
  },
  "target_info": {
    "commitment_bytes": "deadbeef...",
    "max_distance_km": 10
  }
}
```

## Configuration

### Proof Server (.env or environment)
```bash
SERVER_ADDR=127.0.0.1:3001  # Server bind address
RUST_LOG=info               # Log level
```

### Client (.env.local)
```bash
VITE_PROOF_SERVER_URL=http://localhost:3001
```

## Development Workflow

### Watch Mode

```bash
# Terminal 1: Auto-reload proof server on Rust changes
npm run server:dev

# Terminal 2: Auto-reload client on React changes
npm run client:dev
```

### Testing

```bash
# Test Rust commitment generation
npm run test:rust

# Test Move contracts
npm run test:move

# Full integration test
npm run integration:test
```

## Security Features

### Client-Side
- **Wallet Signing**: All requests signed with user's private key
- **Message Integrity**: Timestamp and coordinates included in signature
- **Address Binding**: Request tied to specific wallet address

### Server-Side
- **Signature Validation**: Verifies player signatures (optional)
- **Zero-Knowledge Proofs**: Groth16 zkSNARK - cryptographically sound
- **Commitment Binding**: Proof tied to specific Poseidon commitment
- **Blinding Factor**: 254-bit random value prevents location guessing

### On-Chain (Future)
- **Nonce Protection**: Prevents proof replay attacks
- **Public Verification**: Anyone can verify proof validity
- **Immutable Commitments**: Target location commitment cannot be changed

## Coordinate System

The system uses 3D coordinates in millimeters:

- **X, Y, Z**: Integer coordinates in millimeters
- **Example**: San Francisco = (-23534879266777860000, -435314932817330200, -4336253132989268000)
- **Distance**: Euclidean distance in 3D space
- **Threshold**: Configurable max distance (e.g., 10km = 10,000,000mm)

## Troubleshooting

### Server won't start
```bash
# Check port availability
lsof -i :3001

# Check Rust installation
cargo --version

# Rebuild from scratch
cd crates/proof-server
cargo clean
cargo build
```

### Client won't start
```bash
# Reinstall dependencies
cd packages/proof-client
rm -rf node_modules
npm install

# Check Node version
node --version  # Should be 18+
```

### Wallet won't connect
- Install Sui Wallet browser extension
- Ensure wallet is unlocked
- Check browser console for errors
- Try refreshing the page

### Proof generation fails
- Verify player coordinates are valid i128 integers
- Check max_distance_km is positive number
- Ensure server is running (check /health endpoint)
- Check browser console and server logs

## Next Steps

1. **Deploy Contracts**: Publish Move contracts to local/testnet
2. **Publish Commitments**: Create on-chain commitment objects
3. **On-Chain Verification**: Submit proofs for verification
4. **UI Enhancement**: Add transaction builder and verification status

## Resources

- [Full Documentation](./README.md)
- [Client README](./packages/proof-client/README.md)
- [Deployment Guide](./DEPLOYMENT.md)
- [Quick Reference](./QUICKSTART.md)
