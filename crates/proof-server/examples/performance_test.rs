// Comprehensive performance testing example for proof generation
use commitmentgen::{
    coord_to_fr, create_poseidon_commitment, generate_blinding, get_poseidon_config,
    trusted_setup, Coordinates, ProximityProver,
};
use std::sync::Arc;
use std::time::Instant;

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() {
    println!("🔬 Proof Generation Performance Test\n");

    // Setup
    let max_distance_squared = ark_bn254::Fr::from(100_000_000u64);
    let setup_result = trusted_setup::single_party_setup(max_distance_squared).unwrap();
    let prover = Arc::new(ProximityProver::new(setup_result.proving_key.clone()));

    // Test data
    let target_location = Coordinates {
        x: -23534879266777860000i128,
        y: -435314932817330200i128,
        z: -4336253132989268000i128,
    };

    let player_location = Coordinates {
        x: -23534879266777859500i128,
        y: -435314932817328400i128,
        z: -4336253132989267550i128,
    };

    let blinding = generate_blinding();
    let poseidon_config = get_poseidon_config();
    let commitment_hash = create_poseidon_commitment(
        coord_to_fr(target_location.x),
        coord_to_fr(target_location.y),
        coord_to_fr(target_location.z),
        blinding,
        &poseidon_config,
    );

    println!("=== Performance Benchmark ===");
    let start = Instant::now();
    
    let result = prover.generate_proof(
        &target_location,
        &blinding,
        &player_location,
        &commitment_hash,
        10.0,
    );
    
    let duration = start.elapsed();
    
    match result {
        Ok((proof, _public_inputs)) => {
            println!("✓ Proof generated");
            println!("  Time: {:.3}s ({:.0}ms)", duration.as_secs_f64(), duration.as_millis());
            println!("  Size: {} bytes", ProximityProver::serialize_proof(&proof).len());
        }
        Err(e) => {
            println!("❌ Failed: {}", e);
        }
    }
}
