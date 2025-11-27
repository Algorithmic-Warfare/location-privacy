# Complete Setup and Verification Guide

This guide walks you through the complete flow: deploying contracts, setting up commitments, requesting proofs, and verifying them on-chain.

## Prerequisites

- Sui wallet browser extension installed
- Local Sui network running (`npm run start:sui`)
- Proof server running (`npm run server:start`)
- Client running (`npm run client:dev`)

## Step 1: Deploy Move Contracts

```bash
# Build and publish the Move contracts
npm run publish:local
```

**Save these values from the output:**
- `Package ID`: 0x... (the deployed package)
- `ServerCap`: Object ID transferred to your address

Example output:
```
Published Package: 0xabc123...
Created Objects:
  - ServerCap (0xdef456...)
```

## Step 2: Configure Server for Auto-Setup (Recommended)

The proof server can automatically publish commitments and verifying keys on startup!

1. Get your ServerCap Object ID:
   ```bash
   sui client objects | grep ServerCap
   ```

2. Configure the server environment:
   ```bash
   cd crates/proof-server
   cp .env.example .env
   ```

3. Edit `.env` and add:
   ```bash
   SUI_PACKAGE_ID=0x...           # From Step 1
   SUI_SERVER_CAP_ID=0x...        # ServerCap object ID
   SUI_RPC_URL=http://127.0.0.1:9000
   SUI_KEYSTORE_PATH=/path/to/.sui/sui_config/sui.keystore
   ```

4. Restart the proof server:
   ```bash
   npm run server:start
   ```

5. **Done!** The server will automatically:
   - Publish the verifying key
   - Publish the location commitment
   - Return object IDs via API

The client will automatically fetch these IDs from `/api/info`.

### Alternative: Manual Setup (Not Recommended)

If you prefer manual setup or auto-setup fails:

```bash
# Run the setup script
npm run setup:commitment

# The script will:
# 1. Generate verifying key
# 2. Publish verifying key on-chain
# 3. Publish location commitment on-chain
# 4. Save IDs to .env file
```

## Step 4: Request Proximity Proof (Player)

1. Open http://localhost:3000
2. Connect your wallet (any Sui wallet)
3. On **"Request Proof"** tab:
   - Enter player coordinates (X, Y, Z in millimeters)
   - Set max distance threshold (e.g., 10 km)
   - Click **"Request Proof"**
4. Sign the message in your wallet
5. Wait for proof generation (~50-200ms in release mode)
6. **Copy the proof details** shown in the response

## Step 5: Verify Proof On-Chain (Player)

1. Switch to **"Verify Proof"** tab
2. Enter:
   - **Package ID**: Same as Step 1
   - **LocationCommitment Object ID**: From Step 2
   - **VerifyingKey Object ID**: From Step 2 (setup script output)
   - **Proof Bytes**: Auto-filled from Step 4 (or paste manually)
   - **Public Inputs**: Auto-filled from Step 4 (or paste manually)
3. Click **"Verify Proof"**
4. Approve the transaction in your wallet
5. ✅ Success! The proof is verified on-chain

## What Each Object Does

### Package
- Contains the Move smart contract code
- Defines `proximity::verify_proximity_proof` function
- Immutable once deployed

### ServerCap
- Capability object for admin operations
- Only holder can create commitments
- Transferred to publisher at deployment

### LocationCommitment
- Shared object containing Poseidon hash commitment
- Binds to specific target location (hidden)
- Tracks nonce to prevent replay attacks
- Created by server using ServerCap

### VerifyingKey
- Shared object containing Groth16 verification key
- Used to verify all proofs cryptographically
- 328 bytes for BN254 curve with 2 public inputs
- Created by server using ServerCap

### Proof
- Generated off-chain by server
- ~128 bytes (Groth16 on BN254)
- Proves player is within max_distance of target
- Does not reveal exact coordinates

### Public Inputs
- 64 bytes total:
  - 32 bytes: commitment_hash (binds proof to commitment)
  - 32 bytes: max_distance_squared (constraint satisfaction)
- Verified on-chain against the proof

## Security Features

### Commitment Binding
- Proof is cryptographically bound to specific commitment
- Cannot reuse proof with different commitment
- Checked in `verify_commitment_binding()`

### Replay Protection
- Nonce incremented after each verification
- Same proof cannot be verified twice
- Prevents replay attacks

### Zero-Knowledge
- Proof reveals only proximity constraint satisfaction
- Target coordinates remain hidden (blinded with 254-bit factor)
- Player coordinates not revealed on-chain

### Signature Verification
- Client signs request with wallet
- Server can validate player identity
- Timestamp prevents stale requests

## Troubleshooting

### "Commitment ID not found"
- Make sure Step 2 (Publish Commitment) succeeded
- Check transaction on Sui explorer
- Look for shared object creation

### "Verification failed"
- Ensure Package ID, Commitment ID, and VerifyingKey ID are correct
- Check that proof bytes and public inputs match
- Verify you're using the correct commitment for this proof

### "ServerCap not found"
- Make sure you're using the wallet that deployed the package
- ServerCap is transferred to tx sender at deployment
- Use `sui client objects` to find it

### "Proof generation takes too long"
- Ensure server is running in release mode: `npm run server:start`
- Debug mode can be 20-100x slower
- Release mode: ~50-200ms, Debug mode: ~20-30s

## Object ID Reference

After completing setup, you'll have these IDs:

```
Package ID:           0xabc123...
ServerCap ID:         0xdef456...
LocationCommitment:   0x789abc...
VerifyingKey:         0x012def...
```

Save these in a `.env` file for easy reference:

```bash
# packages/proof-client/.env.local
VITE_PACKAGE_ID=0xabc123...
VITE_COMMITMENT_ID=0x789abc...
VITE_VERIFYING_KEY_ID=0x012def...
```

## Next Steps

- Generate multiple proofs for different player locations
- Test proximity constraints (within/outside max_distance)
- View verification events on Sui explorer
- Build game logic using verified proximity
