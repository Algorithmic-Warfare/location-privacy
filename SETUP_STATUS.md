# Setup Status

## Current State

The proof server and client are fully functional for **generating and verifying proofs**, but the automatic on-chain publishing feature is currently **disabled**.

## What Works

✅ **Proof Generation**: Rust server generates zkSNARK proofs via API  
✅ **Client Interface**: React app with wallet integration  
✅ **Manual Verification**: Submit proofs to blockchain after manual setup  
✅ **Fast Performance**: Release mode builds generate proofs in <1s

## What's Disabled

❌ **Auto-publish**: Server does NOT automatically publish commitments/verifying keys on startup

### Why?

The Sui SDK packages are not available on crates.io and must be sourced from the Sui GitHub repository (~1GB+). To avoid the large download during development, the Sui dependencies are commented out in `crates/proof-server/Cargo.toml`.

## Workarounds

### Option 1: Manual Setup (Recommended for Development)

1. **Keep** `ServerSetup` component in client (currently removed from tabs)
2. Use the UI to publish commitment and verifying key objects
3. Copy the object IDs to server `.env` file:
   ```bash
   SUI_PACKAGE_ID=0x...
   SUI_SERVER_CAP_ID=0x...
   ```
4. Restart proof server - it will load the IDs and expose them via `/api/info`

### Option 2: Enable Auto-Publish (Production)

1. **Uncomment** Sui dependencies in `crates/proof-server/Cargo.toml`:
   ```toml
   sui-sdk = { git = "https://github.com/MystenLabs/sui.git", rev = "mainnet-v1.37.3", optional = true }
   sui-types = { git = "https://github.com/MystenLabs/sui.git", rev = "mainnet-v1.37.3", optional = true }
   sui-keys = { git = "https://github.com/MystenLabs/sui.git", rev = "mainnet-v1.37.3", optional = true }
   sui-json-rpc-types = { git = "https://github.com/MystenLabs/sui.git", rev = "mainnet-v1.37.3", optional = true }
   ```

2. **Uncomment** the feature flag:
   ```toml
   [features]
   sui-auto-publish = ["sui-sdk", "sui-types", "sui-keys", "sui-json-rpc-types"]
   ```

3. **Build** with the feature enabled (this will clone the Sui repo):
   ```bash
   cargo build --release --features sui-auto-publish
   ```

4. **Configure** environment variables in `.env`:
   ```bash
   SUI_PACKAGE_ID=0x...
   SUI_SERVER_CAP_ID=0x...
   SUI_RPC_URL=http://127.0.0.1:9000
   SUI_KEYSTORE_PATH=/path/to/.sui/sui_config/sui.keystore
   ```

5. **Run** the server - it will auto-publish on startup

## Files Modified

- `crates/proof-server/Cargo.toml` - Sui dependencies commented out
- `crates/proof-server/src/lib.rs` - Auto-publish code wrapped in `#[cfg(feature = "sui-auto-publish")]`
- `packages/proof-client/src/App.tsx` - ServerSetup tab removed from UI
- `packages/proof-client/src/components/VerifyProof.tsx` - Warning message about manual setup

## Next Steps

For production deployment, you'll want to enable auto-publish (Option 2) to streamline the setup process. For local development, manual setup (Option 1) is faster.
