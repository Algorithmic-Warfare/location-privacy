# Auto-Publish Feature Requirements

## Current Status

The auto-publish feature is **disabled** because the Sui SDK Rust API has breaking changes that require code migration.

## What Works (TypeScript Client)

The `ServerSetup.tsx` component successfully publishes commitments using `@mysten/sui` SDK:

```typescript
const tx = new Transaction();
const commitmentBytes = Array.from(Buffer.from(serverInfo.commitment_bytes, "hex"));

tx.moveCall({
  target: `${packageId}::proximity::create_commitment`,
  arguments: [
    tx.object(serverCapId),
    tx.pure.vector("u8", commitmentBytes),
    tx.pure.address(info.address),
  ],
});

const result = await signAndExecuteTransaction({ transaction: tx });
```

## What Needs Fixing (Rust Server)

### 1. Dependencies

**Current** (commented out):
```toml
# sui-sdk = { git = "https://github.com/MystenLabs/sui.git", rev = "mainnet-v1.37.3", optional = true }
# sui-types = { git = "https://github.com/MystenLabs/sui.git", rev = "mainnet-v1.37.3", optional = true }
# sui-keys = { git = "https://github.com/MystenLabs/sui.git", rev = "mainnet-v1.37.3", optional = true }
# sui-json-rpc-types = { git = "https://github.com/MystenLabs/sui.git", rev = "mainnet-v1.37.3", optional = true }
```

**Need to add**:
```toml
shared-crypto = { git = "https://github.com/MystenLabs/sui.git", rev = "mainnet-v1.37.3", optional = true }
```

### 2. Import Changes

**Old code** (line 292, 360):
```rust
use sui_types::crypto::Intent;  // ❌ This is now private
let signature = keystore.sign_secure(&sender_address, &tx_data, Intent::sui_transaction())?;
```

**Fix**:
```rust
use shared_crypto::intent::Intent;  // ✅ Use shared_crypto instead
let signature = keystore.sign_secure(&sender_address, &tx_data, Intent::sui_transaction())?;
```

### 3. Object Reference Issues

**Old code** (line 260, 331):
```rust
let server_cap_arg = ptb.obj(ObjectArg::ImmOrOwnedObject(server_cap_id.into()))?;
// ❌ Error: ObjectID doesn't convert to (ObjectID, SequenceNumber, ObjectDigest)
```

**Fix**: Need to fetch the object info first:
```rust
// Fetch object info to get version and digest
let object_info = sui_client
    .read_api()
    .get_object_with_options(server_cap_id, SuiObjectDataOptions::new())
    .await?;

let object_ref = object_info
    .object_ref()
    .ok_or_else(|| anyhow::anyhow!("Could not get object reference"))?;

let server_cap_arg = ptb.obj(ObjectArg::ImmOrOwnedObject(object_ref))?;
```

### 4. Transaction Execution API Changes

**Old code** (line 296-298):
```rust
let response = sui_client
    .quorum_driver_api()
    .execute_transaction_block(
        sui_types::transaction::Transaction::from_data(tx_data, vec![signature]),
        sui_types::quorum_driver_types::ExecuteTransactionRequestType::WaitForLocalExecution,
        None,
    )
    .await?;
```

**Fix**: Use `SuiTransactionBlockResponseOptions`:
```rust
use sui_sdk::rpc_types::SuiTransactionBlockResponseOptions;

let options = SuiTransactionBlockResponseOptions::new()
    .with_effects()
    .with_object_changes();

let response = sui_client
    .quorum_driver_api()
    .execute_transaction_block(
        sui_types::transaction::Transaction::from_data(tx_data, vec![signature]),
        options,
        None,
    )
    .await?;
```

### 5. Effects Parsing

**Old code** (line 305, 373):
```rust
for created in &effects.created() {
    // ❌ Error: method `created` not found
```

**Fix**: Import the trait:
```rust
use sui_sdk::rpc_types::SuiTransactionBlockEffectsAPI;

// Now .created() method is available
for created in effects.created() {
    info!("Created object: {}", created.reference.object_id);
}
```

### 6. Additional Imports Needed

Add to the `#[cfg(feature = "sui-auto-publish")]` block:
```rust
use sui_sdk::{
    SuiClient, 
    SuiClientBuilder,
    rpc_types::{
        SuiObjectDataOptions,
        SuiTransactionBlockResponseOptions, 
        SuiTransactionBlockEffectsAPI,
    },
};
use sui_types::{
    base_types::{ObjectID, SuiAddress},
    programmable_transaction_builder::ProgrammableTransactionBuilder,
    transaction::{TransactionData, ObjectArg},
};
use sui_keys::keystore::FileBasedKeystore;
use shared_crypto::intent::Intent;
```

## Implementation Effort

### High Priority Changes (Core Functionality)
1. ✅ **Uncomment dependencies** in Cargo.toml (~5 mins)
2. ✅ **Add shared-crypto dependency** (~2 mins)
3. ✅ **Fix Intent imports** (2 locations) (~5 mins)
4. ⚠️ **Fix object reference fetching** (2 functions × 10 mins = ~20 mins)
5. ⚠️ **Fix transaction execution API** (2 functions × 10 mins = ~20 mins)
6. ⚠️ **Add trait imports** (~5 mins)

**Total**: ~1 hour of focused work

### Testing Required
1. Build with `cargo build --release --features sui-auto-publish` (~10 mins first time, ~2GB download)
2. Start local Sui network
3. Test auto-publish on startup with env vars set
4. Verify commitment and verifying key are created
5. Test proof generation and verification with published objects

**Total**: ~30 mins

### Alternative: Bash Script

Instead of fixing Rust auto-publish, we could create a bash script that:
1. Calls the server `/api/info` endpoint to get commitment bytes
2. Uses `sui client call` to publish the commitment
3. Updates the `.env` file with the commitment ID

This would be much simpler (~30 mins) but requires manual execution.

## Recommendation

**Short term**: Use the existing `ServerSetup` TypeScript UI component (already working!)

**Medium term**: Create a bash script for CI/CD automation

**Long term**: Fix the Rust auto-publish for fully automated deployment

## Current Workaround

The system works perfectly with manual setup:

1. ✅ Publish Move package → `npm run publish:local`
2. ✅ Package ID and ServerCap ID auto-written to server `.env`
3. ✅ Start server → Exposes commitment/verifying key bytes via `/api/info`
4. ✅ Use ServerSetup UI → Click "Publish Commitment" button
5. ✅ Commitment ID returned → Use for verification

**No blocker for development or production use!**
