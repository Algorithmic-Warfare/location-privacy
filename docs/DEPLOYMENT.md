# Deployment Guide

## Local Development

See [SETUP.md](SETUP.md) for local development setup.

## Testnet Deployment

### 1. Switch to Testnet

```bash
sui client switch --env testnet
sui client faucet              # Get testnet SUI
sui client balance             # Verify balance
```

### 2. Build and Test

```bash
npm run build:move
npm run test:move
npm run integration:test
```

### 3. Deploy

```bash
cd packages/location
sui client publish --gas-budget 100000000

# Save these from output:
# - PACKAGE_ID
# - ServerCap object ID
```

### 4. Initialize State

```bash
# List your objects to find ServerCap
sui client objects

# The ServerCap is automatically transferred to deployer
# Save the object ID for server configuration
```

## Mainnet Deployment

### Prerequisites Checklist

- [ ] Security audit completed
- [ ] Testnet testing (minimum 1 week)
- [ ] Trusted setup ceremony performed
- [ ] HSM/KMS configured for keys
- [ ] Monitoring and alerting ready
- [ ] Incident response plan documented
- [ ] Backup procedures tested

### 1. Trusted Setup

```bash
cd crates/commitmentgen
cargo run --example trusted_setup_example

# Outputs:
# - proving_key.bin (CRITICAL SECRET - store in HSM)
# - verifying_key.bin (public - deploy on-chain)
```

**NEVER commit proving keys to git!**

### 2. Deploy to Mainnet

```bash
sui client switch --env mainnet
sui client balance  # Ensure sufficient gas

cd packages/location
sui client publish --gas-budget 100000000

# Save all output:
# - PACKAGE_ID
# - ServerCap ID
# - Transaction digest
```

### 3. Configure Production Server

```bash
# Production .env
cat > /secure/location-privacy/.env <<EOF
SUI_PACKAGE_ID=0x...
SUI_SERVER_CAP_ID=0x...
SUI_RPC_URL=https://fullnode.mainnet.sui.io:443
SERVER_ADDR=0.0.0.0:3001
EOF

# Load proving key from HSM
# Start server with proper monitoring
```

## Security Operations

### Key Management

**Proving Key**: Store in HSM/KMS only
**Blinding Factors**: Encrypted database, strict access control
**ServerCap**: Production server address only

### Monitoring

Track these metrics:
- `proof_generation_latency_seconds`
- `proof_generation_success_rate`
- `verification_gas_cost_sui`
- `nonce_value`

### Backups

```bash
# Daily: Backup blinding factors
pg_dump blinding_factors > backup-$(date +%Y%m%d).sql
gpg --encrypt backup-$(date +%Y%m%d).sql
aws s3 cp backup-$(date +%Y%m%d).sql.gpg s3://backups/
```

### Incident Response

**ServerCap Compromised:**
1. Deploy new package
2. Rotate proving keys
3. Audit generated proofs
4. Notify users

**Proving Key Exposed:**
1. Immediate key rotation
2. Deploy new verifying key
3. Audit proofs
4. Post-incident review

## Troubleshooting

### "Proof generation > 1s"
- Check: Running in release mode?
- Check: `tracing_subscriber` disabled?
- See [crates/proof-server/PERFORMANCE.md](../crates/proof-server/PERFORMANCE.md)

### "Verification failed"
- Verify package/commitment/VK IDs are correct
- Check proof bytes and public inputs match
- Ensure using correct commitment

### "ServerCap not found"
- ServerCap transferred to deployer at init
- Use `sui client objects` to find it
