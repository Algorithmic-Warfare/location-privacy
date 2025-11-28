# Auto-Publish Guide

## Quick Start

```bash
# 1. Build with feature
cargo build --release --features sui-auto-publish

# 2. Configure .env
SUI_PACKAGE_ID=0x...
SUI_SERVER_CAP_ID=0x...

# 3. Run
cargo run --release --features sui-auto-publish
```

## Environment Variables

```env
# Required
SUI_PACKAGE_ID=0x...          # Deployed package
SUI_SERVER_CAP_ID=0x...       # Server capability object

# Optional (defaults shown)
SUI_RPC_URL=http://127.0.0.1:9000
SUI_KEYSTORE_PATH=~/.sui/sui_config/sui.keystore
SUI_SENDER_ADDRESS=0x...
```

## What Gets Published

1. **Verifying Key** (328 bytes) → `proximity::init_verifying_key()`
2. **Location Commitment** (32 bytes) → `proximity::create_commitment()`

Both are shared objects readable by anyone for verification.

## Verify Status

```bash
# Check server
curl http://localhost:3001/api/info | jq

# Check on-chain
sui client object $VERIFYING_KEY_ID
sui client object $COMMITMENT_ID
```

## Troubleshooting

| Issue | Check |
|-------|-------|
| Not triggering | Build with `--features sui-auto-publish` |
| Transaction fails | Sender has SUI tokens and owns ServerCap |
| Keystore errors | Path exists and address in keystore |

**Note**: Adds 1-2s to startup, doesn't affect proof performance.
