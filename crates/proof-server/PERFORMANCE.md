# Performance Guide

## Quick Reference
- **Expected proof time**: 15-20ms (release mode)
- **Build command**: `cargo build --release`
- **Test command**: `cargo run --release --example performance_test`

## Performance Issues

### 1. Slow Proofs (>1 second)
**Cause**: Debug mode or missing optimizations  
**Solution**: Build with `--release` flag

### 2. Very Slow Proofs (>5 seconds)
**Cause**: `tracing_subscriber` enabled with Rayon  
**Solution**: Comment out tracing_subscriber in `main.rs` (lines 12-17)

```rust
// CRITICAL: tracing_subscriber causes 400x performance regression!
// tracing_subscriber::fmt().init(); // ← Keep this disabled
```

### 3. Missing CPU Optimizations
**Cause**: No native CPU features enabled  
**Solution**: Add `.cargo/config.toml`:

```toml
[target.aarch64-apple-darwin]
rustflags = ["-C", "target-cpu=native"]

[target.x86_64-apple-darwin]
rustflags = ["-C", "target-cpu=native"]
```

## Optimization Checklist

- ✅ Build with `--release`
- ✅ Disable `tracing_subscriber` for production
- ✅ Enable `parallel` feature in Cargo.toml (already configured)
- ✅ Use `target-cpu=native` for SIMD instructions

## Testing Performance

```bash
# Quick test
cargo run --release --example performance_test

# Full server test
cargo run --release
curl -X POST http://localhost:3001/api/generate-proof \
  -H 'Content-Type: application/json' \
  -d '{"player_x":-23534879266777859500,"player_y":-435314932817328400,"player_z":-4336253132989267550}'
```

## Auto-Publish Feature

Enable on-chain publishing during startup:

```bash
# Build with feature
cargo build --release --features sui-auto-publish

# Set environment variables
SUI_PACKAGE_ID=0x...
SUI_SERVER_CAP_ID=0x...

# Run server
cargo run --release --features sui-auto-publish
```

**Note**: Auto-publish adds ~1-2 seconds to startup but doesn't affect proof generation.

## Troubleshooting

| Symptom | Time | Cause | Fix |
|---------|------|-------|-----|
| Slow startup | >5s | Debug mode | Use `--release` |
| Slow proofs | >1s | Tracing enabled | Disable tracing_subscriber |
| CPU not utilized | Any | Missing native flags | Add .cargo/config.toml |
| Server crash | N/A | Out of memory | Reduce worker_threads in main.rs |
