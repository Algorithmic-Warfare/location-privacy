// tokio_blocking_proof.rs
use commitmentgen::{
    coord_to_fr, create_poseidon_commitment, generate_blinding, get_poseidon_config,
    trusted_setup, Coordinates, ProximityProver,
};
use std::sync::Arc;
use std::time::Instant;

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() {
    println!("🔬 Proof Generation Performance Benchmark\n");

    // Setup
    println!("Setting up zkSNARK circuit...");
    let max_distance_squared = ark_bn254::Fr::from(100_000_000u64); // (10km)^2
    let setup_result = trusted_setup::single_party_setup(max_distance_squared).unwrap();
    let prover = Arc::new(ProximityProver::new(setup_result.proving_key.clone()));
    println!("✓ Setup complete\n");
    println!("Proving key a_query: {}", setup_result.proving_key.a_query.len());
    println!("Circuit info: {}", prover.circuit_info());
    println!();

    // Test data (ensure Coordinates implements Clone; if not, move ownership)
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

    // Move owned data / clones into the blocking task
    let prover_cloned = prover.clone();
    let target = target_location;
    let player = player_location;
    let commitment = commitment_hash;
    let blind = blinding;

    println!("Generating proof (spawn_blocking)...");
    let start = Instant::now();

    // Run heavy, blocking proof generation on Tokio's blocking pool.
    let result = tokio::task::spawn_blocking(move || {
        // Call the sync generate_proof here
        prover_cloned.generate_proof(&target, &blind, &player, &commitment, 10.0)
    })
    .await
    .expect("blocking task panicked");

    let duration = start.elapsed();

    match result {
        Ok((proof, public_inputs)) => {
            println!("✓ Proof generated successfully");
            println!("  Proof size: {} bytes", ProximityProver::serialize_proof(&proof).len());
            println!("  Public inputs size: {} bytes", ProximityProver::serialize_public_inputs(&public_inputs).len());
            println!("\n⏱️  Time taken: {:.3}s", duration.as_secs_f64());

            if duration.as_secs_f64() < 1.0 {
                println!("✅ Performance is GOOD (< 1 second)");
            } else {
                println!("⚠️  Performance needs improvement (>= 1 second)");
            }
        }
        Err(e) => {
            println!("❌ Proof generation failed: {}", e);
        }
    }
}
