# Deployment Flow

## Automatic Configuration

The `publish_local.sh` script now automatically extracts and configures deployment information across the project.

### What Happens on Publish

When you run `npm run publish:local` or the deploy watcher triggers:

1. **Publishes** the Move package to the local Sui network
2. **Extracts** from the JSON output:
   - `PACKAGE_ID` - The published package address
   - `SERVER_CAP_ID` - The ServerCap object ID (admin capability)

3. **Updates** two configuration files:
   - `packages/location/.env.local` - Package deployment info (for reference)
   - `crates/proof-server/.env` - Server configuration with package ID and ServerCap ID

### Configuration Files

#### packages/location/.env.local
```bash
PACKAGE_ID=0x944f747cd54eb94e47f9d87940cc6f9cdf0f3ae5f4efce35dbcd448df20daa34
SERVER_CAP_ID=0xf89c9dd8a518f6bfbb4c1f89a25b441a90306928ea2b83b85f386909f17fc691
```
Stored for reference and debugging.

#### crates/proof-server/.env
```bash
# Existing config...
SUI_PACKAGE_ID=0x944f747cd54eb94e47f9d87940cc6f9cdf0f3ae5f4efce35dbcd448df20daa34
SUI_SERVER_CAP_ID=0xf89c9dd8a518f6bfbb4c1f89a25b441a90306928ea2b83b85f386909f17fc691
```
The server reads these on startup and exposes them via `/api/info` endpoint for the client to fetch.

#### packages/proof-client/.env
```bash
VITE_PROOF_SERVER_URL=http://localhost:3001
```
The client **only** stores the server URL. All package and object IDs come from the server's `/api/info` endpoint.

### Workflow

```
┌─────────────────────┐
│  Move Source Change │
└──────────┬──────────┘
           │
           v
┌─────────────────────┐
│   sui move build    │
└──────────┬──────────┘
           │
           v
┌─────────────────────┐
│  sui client publish │
│    (JSON output)    │
└──────────┬──────────┘
           │
           v
┌─────────────────────┐
│  Extract IDs with   │
│        jq           │
└──────────┬──────────┘
           │
           │
           v
┌─────────────────────┐
│  Update Server .env │
│  SUI_PACKAGE_ID     │
│  SUI_SERVER_CAP_ID  │
└──────────┬──────────┘
           │
           v
┌─────────────────────┐
│  Restart Server     │
│  (if running)       │
└──────────┬──────────┘
           │
           v
┌─────────────────────┐
│   Server exposes    │
│   IDs via /api/info │
└──────────┬──────────┘
           │
           v
┌─────────────────────┐
│   Client fetches    │
│   IDs from server   │
└─────────────────────┘
```

### Manual Setup Not Required

With this flow, you **no longer need** to:
- ❌ Manually copy package IDs from terminal output
- ❌ Paste IDs into multiple .env files
- ❌ Use the ServerSetup UI component
- ❌ Run separate CLI commands to publish commitments

### What Still Needs Manual Work

The server still needs to **publish the commitment and verifying key** on-chain. This happens via one of:

1. **Server auto-publish** (currently disabled - needs Sui SDK API updates)
2. **Manual CLI commands** (using `setup_commitment.sh`)
3. **ServerSetup UI component** (can be re-added to client)

Once those are published, their object IDs can be added to the server's `.env`:
```bash
# After manual commitment publish
SUI_COMMITMENT_ID=0x...
SUI_VERIFYING_KEY_ID=0x...
```

## Running the Stack

```bash
# Terminal 1: Start local Sui network
npm run start:sui

# Terminal 2: Fund address
npm run fund

# Terminal 3: Build, publish, and watch for changes
npm run deploy:watch

# Terminal 4: Start proof server
npm run server:start

# Terminal 5: Start client
npm run client:dev
```

Or use mprocs to run everything:
```bash
mprocs
```

The deploy watcher will automatically update all configurations when you modify Move code!
