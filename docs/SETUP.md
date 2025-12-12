# Full Stack Setup Guide

Complete guide for running the proof server and client application.

## Prerequisites

- **Rust** 1.70+
- **Node.js** 18+
- **Sui CLI**
- **Sui Wallet** browser extension

## Quick Setup

```bash
# 1. Install dependencies
npm install
npm run client:install

# 2. Configure environment
cp .env.local.example .env.local
# Edit .env.local with your Sui keypair

# 3. Start everything
npm run start:local  # Requires: cargo install mprocs
```

## Manual Setup

### 1. Start Local Sui Network

```bash
# Terminal 1
npm run start:sui
```

### 2. Fund Your Account

```bash
# Terminal 2 (wait 3-5 seconds after network starts)
npm run fund
```

### 3. Deploy Contracts

```bash
npm run publish:local
```

This automatically updates:
- `packages/location/.env.local` - Package ID reference
- `crates/proof-server/.env` - Server configuration

### 4. Start Proof Server

```bash
# Terminal 3
npm run server:start
```

Server endpoints:
- `GET /health` - Health check
- `GET /api/info` - Server status and commitment info
- `POST /api/generate-proof` - Generate proximity proof

### 5. Start Client

```bash
# Terminal 4
npm run client:dev
```

Open http://localhost:3000

## Using the Application

1. **Connect Wallet** - Click "Connect Wallet"
2. **Enter Coordinates** - Input player X, Y, Z (millimeters)
3. **Set Distance** - Max proximity threshold (e.g., 10km)
4. **Request Proof** - Sign message and generate proof
5. **Verify On-Chain** - Submit proof for blockchain verification

## Configuration

### Server (.env)
```bash
SERVER_ADDR=127.0.0.1:3001
```

### Client (.env.local)
```bash
VITE_PROOF_SERVER_URL=http://localhost:3001
```

## Troubleshooting

### "Cannot find private key"
Generate new keypair:
```bash
sui keytool generate ed25519
# Copy the suiprivkey1... to .env.local
```

### "Faucet failed"
- Check network is running: `ps aux | grep sui`
- Wait 5 seconds for faucet to start
- Increase FUND_DELAY_SECONDS

### "Slow proof generation"
Ensure release mode:
```bash
cd crates/proof-server
cargo build --release
```

Debug mode is 20-100x slower than release (15-20ms).

## Auto-Publish Commitment (Optional)

The server can auto-publish commitments on startup:

```bash
# Build with feature
cargo build --release --features sui-auto-publish

# Configure
cd crates/proof-server
cat > .env <<EOF
SUI_PACKAGE_ID=0x...
SUI_SERVER_CAP_ID=0x...
SUI_RPC_URL=http://127.0.0.1:9000
EOF

# Run
cargo run --release --features sui-auto-publish
```

See [crates/proof-server/AUTO_PUBLISH_GUIDE.md](../crates/proof-server/AUTO_PUBLISH_GUIDE.md) for details.

## Next Steps

- [DEPLOYMENT.md](DEPLOYMENT.md) - Deploy to testnet/mainnet
- [SECURITY.md](SECURITY.md) - Security properties
