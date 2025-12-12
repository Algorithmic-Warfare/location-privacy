// Direct test without tokio to see if it's a tokio interaction issue
use commitmentgen::{
    coord_to_fr, create_poseidon_commitment, generate_blinding, get_poseidon_config,
    trusted_setup, Coordinates, ProximityProver,
};
use std::time::Instant;

fn main() {
    println!("🔬 Direct Proof Generation Test (No Tokio)\n");

    // Setup
    println!("Setting up...");
    let max_distance_squared = ark_bn254::Fr::from(100_000_000u64);
    let setup_result = trusted_setup::single_party_setup(max_distance_squared).unwrap();
    let prover = ProximityProver::new(setup_result.proving_key.clone());
    println!("✓ Setup complete\n");

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

    // Run 3 tests
    for i in 1..=3 {
        println!("Test {}: Generating proof...", i);
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
            Ok((proof, _)) => {
                println!("✓ Proof generated: {} bytes in {:.3}s\n", 
                         commitmentgen::ProximityProver::serialize_proof(&proof).len(),
                         duration.as_secs_f64());
            }
            Err(e) => {
                println!("❌ Failed: {}\n", e);
            }
        }
    }
}
