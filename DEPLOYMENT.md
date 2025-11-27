# Location Privacy - Deployment Guide

## Table of Contents

1. [Local Development Setup](#local-development-setup)
2. [Testing Data Constraints](#testing-data-constraints)
3. [Deploying to Testnet](#deploying-to-testnet)
4. [Deploying to Mainnet](#deploying-to-mainnet)
5. [Operational Procedures](#operational-procedures)

---

## Local Development Setup

### Prerequisites

Install required tools:

```bash
# Install Sui CLI
cargo install --locked --git https://github.com/MystenLabs/sui.git --branch main sui

# Install mprocs for orchestrated development
cargo install mprocs

# Install watchexec for file watching
cargo install watchexec-cli

# Install jq for JSON parsing
brew install jq  # macOS
# or
apt-get install jq  # Ubuntu/Debian
```

### Initial Configuration

1. **Generate a Sui keypair:**
   ```bash
   sui keytool generate ed25519
   ```
   This outputs something like:
   ```
   ╭─────────────────────────────────────────────────────────────────────╮
   │ Created new keypair for address: 0x1234...                          │
   │ Secret Recovery Phrase: word1 word2 word3 ...                       │
   │ Bech32 with flag: suiprivkey1abc...                                 │
   ╰─────────────────────────────────────────────────────────────────────╯
   ```

2. **Configure environment:**
   ```bash
   # Copy the private key to .env.local
   echo "PRIVATE_KEY_FILE=suiprivkey1abc..." > .env.local
   ```

3. **Set up local Sui environment:**
   ```bash
   # Create local environment alias
   sui client new-env --alias local --rpc http://127.0.0.1:9000
   
   # Switch to local environment
   sui client switch --env local
   ```

### Running the Full Stack

**Option 1: Orchestrated (Recommended)**

```bash
npm run start:local
```

This starts all processes in a single terminal using `mprocs`:
- `sui-local`: Local Sui validator with faucet
- `fund`: Account funding with retry logic
- `build_and_publish`: Auto-rebuild and deploy on file changes
- `move-tests`: Run Move tests
- `rust-tests`: Run Rust tests
- `generate-e2e`: Generate E2E test data
- `shell`: Interactive shell for commands

**Option 2: Manual Steps**

```bash
# Terminal 1: Start Sui network
npm run start:sui

# Terminal 2: Fund account (wait 3-5 seconds for network to start)
npm run fund

# Terminal 3: Build and deploy
npm run build:move
npm run publish:local

# Terminal 4: Run tests
npm run test:move
```

---

## Testing Data Constraints

The system includes comprehensive tests for all security constraints:

### Data Constraint Tests

1. **Commitment Binding** (`test_commitment_hash_mismatch_fails`)
   - Ensures proof cannot be used with wrong commitment
   - Validates cryptographic binding between proof and commitment
   - Attack scenario: Try to reuse proof for SSU_A with commitment for SSU_B

2. **Proof Integrity** (`test_corrupted_proof_fails`)
   - Validates cryptographic proof structure
   - Corrupted proofs must be rejected
   - Attack scenario: Modify proof bytes and attempt verification

3. **Verification Key Pairing** (`test_wrong_verification_key_fails`)
   - Ensures proof matches the verifying key
   - Prevents using proofs from different trusted setups
   - Attack scenario: Generate proof with VK_A, verify with VK_B

4. **Public Input Validation** (`test_wrong_public_inputs_fails`)
   - Validates public inputs match proof
   - Prevents public input manipulation
   - Attack scenario: Use valid proof with modified public inputs

5. **Valid Proximity** (`test_user_within_10km_succeeds`)
   - Tests multiple valid scenarios within 10km
   - Different coordinate combinations
   - Boundary testing at distance limits

6. **Coordinate Validation** (`test_invalid_inversed_sign_value_coordinates_fails`)
   - Tests sign handling in coordinates
   - Validates absolute vs negative coordinate handling
   - Prevents coordinate manipulation attacks

### Running Constraint Tests

```bash
# Run all constraint tests
npm run integration:test

# Run specific test
cd packages/location
sui move test --filter test_commitment_hash_mismatch_fails

# Run all security tests
sui move test --filter commitment
sui move test --filter fails
```

### Test Output Validation

Each test validates:
- ✓ Commitment creation succeeds
- ✓ Proof generation succeeds (Rust)
- ✓ Proof verification succeeds (Move)
- ✓ Nonce increments after verification
- ✓ Invalid scenarios fail with correct error codes

---

## Deploying to Testnet

### 1. Prepare for Testnet

```bash
# Switch to testnet
sui client switch --env testnet

# Request testnet tokens from faucet
sui client faucet

# Verify balance
sui client balance
```

### 2. Build and Test

```bash
# Build contracts
npm run build:move

# Run comprehensive tests
npm run test:move
npm run test:rust
npm run integration:test
```

### 3. Deploy to Testnet

```bash
cd packages/location

# Publish package
sui client publish --gas-budget 100000000 --skip-dependency-verification

# Save the output - you'll need:
# - PACKAGE_ID (the published package)
# - ServerCap object ID
# - Other created objects
```

### 4. Initialize On-Chain State

```bash
# The init function automatically transfers ServerCap to deployer
# You should see a ServerCap object created

# List objects owned by your address
sui client objects

# Find the ServerCap object ID and save it securely
```

### 5. Test on Testnet

```bash
# Generate test commitments and proofs
npm run generate:e2e

# Use the generated data to test on-chain verification
# You'll need to create custom transactions to:
# 1. Initialize VerifyingKey (using ServerCap)
# 2. Create LocationCommitment (using ServerCap)
# 3. Verify proximity proof (public call)
```

---

## Deploying to Mainnet

### Prerequisites Checklist

Before mainnet deployment:

- [ ] Complete security audit of contracts
- [ ] Complete security audit of Rust library
- [ ] Test thoroughly on testnet (minimum 1 week)
- [ ] Perform trusted setup ceremony
- [ ] Set up HSM/KMS for key storage
- [ ] Prepare monitoring and alerting
- [ ] Document operational procedures
- [ ] Prepare incident response plan
- [ ] Set up backup and recovery procedures

### 1. Trusted Setup Ceremony

```bash
cd crates/commitmentgen

# Run trusted setup (single party for dev, multi-party for prod)
cargo run --example trusted_setup_example

# This generates:
# - proving_key.bin (CRITICAL SECRET - store in HSM)
# - verifying_key.bin (public - deploy on-chain)

# Store proving key in HSM/KMS
# NEVER commit proving keys to git
```

### 2. Deploy to Mainnet

```bash
# Switch to mainnet
sui client switch --env mainnet

# Verify you have sufficient gas
sui client balance

# Build contracts one final time
cd packages/location
sui move build

# Deploy to mainnet (NO --skip-dependency-verification in production!)
sui client publish --gas-budget 100000000

# CRITICAL: Save all output including:
# - PACKAGE_ID
# - ServerCap object ID
# - Transaction digest
# - All created object IDs
```

### 3. Initialize Production State

```bash
# 1. Initialize VerifyingKey object (using verifying_key.bin from trusted setup)
# This requires a custom transaction that calls:
# proximity::init_verifying_key(&server_cap, vk_bytes, ctx)

# 2. Transfer ServerCap to production server address
# This is critical - only the server should hold ServerCap

# 3. Create initial location commitments for your SSUs
# This requires:
# - Server generates commitments: C = Poseidon(x, y, z, r)
# - Server calls: proximity::create_commitment(&server_cap, commitment_bytes, owner, ctx)
```

### 4. Production Server Setup

```bash
# On production server:

# 1. Configure environment
cat > /secure/location-privacy/.env.production <<EOF
PACKAGE_ID=0xYOUR_PACKAGE_ID
SERVER_CAP_ID=0xYOUR_SERVER_CAP_ID
VERIFYING_KEY_ID=0xYOUR_VERIFYING_KEY_ID
SUI_RPC_URL=https://fullnode.mainnet.sui.io:443
PRIVATE_KEY_PATH=/secure/keys/server.pem
PROVING_KEY_PATH=/secure/keys/proving_key.bin
EOF

# 2. Load keys from HSM/KMS
# Use your organization's key management system

# 3. Start proof generation service
# This should be a separate service that:
# - Loads proving key from HSM
# - Accepts (player_coords, target_coords, blinding) requests
# - Generates zkSNARK proofs
# - Returns (proof_bytes, public_inputs)
```

---

## Operational Procedures

### Daily Operations

1. **Monitor Proof Generation:**
   - Track proof generation latency
   - Alert if latency > threshold (e.g., 10 seconds)
   - Monitor success rate (should be >99%)

2. **Monitor On-Chain Verification:**
   - Track gas costs per verification
   - Alert if gas cost spikes
   - Monitor nonce synchronization

3. **Key Management:**
   - Daily backup of blinding factors database
   - Weekly backup verification
   - Quarterly key rotation planning

### Incident Response

**Scenario: ServerCap Compromised**

1. Immediately revoke old ServerCap if possible
2. Deploy new package with fresh ServerCap
3. Migrate existing commitments (if needed)
4. Rotate all proving keys
5. Audit all proofs generated during compromise window

**Scenario: Proving Key Exposed**

1. Immediate key rotation
2. Deploy new verifying key on-chain
3. Audit all generated proofs
4. Notify affected users
5. Post-incident review

**Scenario: Nonce Desynchronization**

1. Query current on-chain nonce
2. Update server-side nonce tracker
3. Retry failed proofs
4. Add nonce verification to monitoring

### Monitoring Metrics

Track these metrics in your monitoring system:

```bash
# Proof generation metrics
proof_generation_latency_seconds (histogram)
proof_generation_success_rate (gauge)
proof_generation_errors_total (counter)

# On-chain verification metrics
verification_gas_cost_sui (histogram)
verification_success_rate (gauge)
verification_errors_total (counter)
nonce_value (gauge)

# System health metrics
server_cap_balance (gauge)
proving_key_load_time_seconds (histogram)
hsm_availability (gauge)
```

### Backup and Recovery

**Daily Backups:**
```bash
# Backup blinding factors database
pg_dump blinding_factors > backup-$(date +%Y%m%d).sql

# Encrypt backup
gpg --encrypt --recipient ops@company.com backup-$(date +%Y%m%d).sql

# Upload to secure storage
aws s3 cp backup-$(date +%Y%m%d).sql.gpg s3://company-backups/location-privacy/
```

**Recovery Testing (Monthly):**
```bash
# 1. Restore from backup
# 2. Verify blinding factors integrity
# 3. Generate test proof
# 4. Verify proof on testnet
# 5. Document recovery time
```

---

## Troubleshooting

### Common Issues

**Issue: Proof generation fails with "constraint not satisfied"**
- **Cause:** Player coordinates too far from target (>10km)
- **Solution:** Verify distance calculation before proof generation

**Issue: On-chain verification fails with error code 4**
- **Cause:** Invalid proof or wrong verifying key
- **Solution:** Verify proof was generated with matching proving key

**Issue: On-chain verification fails with error code 8**
- **Cause:** Commitment hash in public inputs doesn't match stored commitment
- **Solution:** Ensure proof was generated for the correct target location

**Issue: Fund script timeout**
- **Cause:** Faucet slow or unavailable
- **Solution:** Increase MAX_FAUCET_ATTEMPTS or MAX_BALANCE_WAIT in environment

**Issue: Publish fails with "insufficient gas"**
- **Cause:** Not enough SUI tokens
- **Solution:** Request more from faucet or transfer from another account

---

## Security Best Practices

1. **Never commit secrets to git:**
   - .env.local is in .gitignore
   - Proving keys should NEVER be in repo
   - Blinding factors are SERVER-SIDE ONLY

2. **Key rotation schedule:**
   - Proving keys: Quarterly rotation
   - Blinding factors: NO rotation (breaks commitments)
   - Server credentials: Monthly rotation

3. **Access control:**
   - ServerCap: Only production server
   - Proving keys: Only in HSM, never on disk
   - Blinding factors: Encrypted database with strict access control

4. **Monitoring and alerting:**
   - Alert on all proof generation failures
   - Alert on gas cost spikes
   - Alert on unusual proof patterns
   - Alert on HSM unavailability

---

## Support and Resources

- **Documentation:** [README.md](./README.md)
- **Context:** [context.md](./context.md)
- **Data Constraints:** [data_constraints.md](./data_constraints.md)
- **Codebase:** [GitHub Repository](#)

For production support, contact the engineering team.
