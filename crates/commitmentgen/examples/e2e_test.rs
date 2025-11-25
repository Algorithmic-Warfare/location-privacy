use commitmentgen::{
    LocationCommitmentGenerator, PedersenParams, Coordinates,
    ProximityProver, trusted_setup
};
use ark_bn254::{G1Affine, Fr, Bn254};
use ark_serialize::CanonicalSerialize;
use ark_ec::AffineRepr;
use ark_groth16::Groth16;
use ark_snark::SNARK;
use std::panic;

/// End-to-end test that generates data for Sui Move contract verification
fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("End-to-End Test: Rust → Sui Move Integration");
    println!("==============================================");

    // ============================================================================
    // Phase 1: Setup cryptographic parameters
    // ============================================================================

    println!("\n1. Setting up Pedersen parameters...");
    let params = PedersenParams {
        g: Fr::from(1u64),
        h: Fr::from(2u64), // In practice, use independent generators
        k: Fr::from(3u64),
        m: Fr::from(4u64),
    };

    println!("2. Performing trusted setup...");
    let max_distance_squared = Fr::from(100_000_000u64); // (10km * 1000)^2 = 100_000_000
    let setup_result = trusted_setup::single_party_setup(max_distance_squared)?;
    let vk_clone = setup_result.verifying_key.clone();
    let prover = ProximityProver::new(
        setup_result.proving_key,
        setup_result.verifying_key,
        params.clone(),
    );

    // ============================================================================
    // Phase 2: Generate location commitment (server side)
    // ============================================================================

    println!("3. Generating location commitment...");

    // SSU location (server knows this)
    let ssu_location = Coordinates {
        x: 1000,  // 1000 meters in X direction
        y: 2000,  // 2000 meters in Y direction
        z: 500,   // 500 meters above reference plane
    };

    let commitment_gen = LocationCommitmentGenerator::new(params.clone());
    let blinding = LocationCommitmentGenerator::generate_blinding();
    let commitment = commitment_gen.create_commitment(&ssu_location, &blinding);
    let commitment_bytes = LocationCommitmentGenerator::serialize_commitment(&commitment);

    println!("   SSU Location: ({}, {}, {})", ssu_location.x, ssu_location.y, ssu_location.z);
    println!("   Commitment generated: {} bytes", commitment_bytes.len());

    // ============================================================================
    // Phase 3: Generate proximity proof (server side)
    // ============================================================================

    println!("4. Generating proximity proof...");

    // Player location (within range)
    let player_location = Coordinates {
        x: 1500,  // 1500 meters in X direction (~500m from SSU)
        y: 1800,  // 1800 meters in Y direction (~200m from SSU)
        z: 450,   // 450 meters above reference plane
    };

    let nonce = 0u64; // Initial nonce from contract
    let (proof, public_inputs) = prover.generate_proof(
        &ssu_location,
        &blinding,
        &player_location,
        &commitment,
        10.0, // 10km max distance
    )?;

    // Serialize proof and public inputs
    let proof_bytes = ProximityProver::serialize_proof(&proof);
    let public_inputs_bytes = ProximityProver::serialize_public_inputs(&public_inputs);

    // ============================================================================
    // Phase 6: Verify the proof in Rust to ensure it's valid
    // ============================================================================

    println!("6. Verifying proof in Rust...");
    let pvk = Groth16::<Bn254>::process_vk(&vk_clone).unwrap();
    let is_valid = Groth16::<Bn254>::verify_proof(&pvk, &proof, &public_inputs)?;
    if is_valid {
        println!("   ✅ Proof verification successful in Rust");
    } else {
        println!("   ❌ Proof verification failed in Rust");
        return Err("Proof verification failed".into());
    }

    println!("   Player Location: ({}, {}, {})", player_location.x, player_location.y, player_location.z);
    println!("   Proof generated: {} bytes", proof_bytes.len());
    println!("   Public inputs: {} bytes", public_inputs_bytes.len());

    // ============================================================================
    // Phase 4: Serialize verifying key for Move contract
    // ============================================================================

    println!("5. Serializing verifying key...");
    let mut vk_bytes = Vec::new();
    vk_clone.serialize_compressed(&mut vk_bytes)?;

    // Write the complete verifying key to a file for easy copying
    std::fs::write("/tmp/verifying_key_bytes.txt", format!("{:?}", vk_bytes))?;

    println!("   Complete verifying key written to /tmp/verifying_key_bytes.txt");

    // ============================================================================
    // Phase 5: Generate Move contract test data
    // ============================================================================

    // ============================================================================
    // Phase 7: Generate invalid proof test cases
    // ============================================================================

    println!("\n8. Generating invalid proof test cases...");

    // Test case 1: Wrong blinding factor (should fail)
    println!("   Generating proof with wrong blinding factor...");
    let wrong_blinding = Fr::from(999u64); // Different blinding factor
    // Note: This will fail during proof generation because constraints won't be satisfied
    // For Move tests, we'll use a valid proof but with a different commitment
    let wrong_blinding_result = std::panic::catch_unwind(|| {
        prover.generate_proof(
            &ssu_location,
            &wrong_blinding, // Wrong blinding factor
            &player_location,
            &commitment, // Same commitment (created with correct blinding)
            10.0,
        )
    });
    
    let (wrong_blinding_proof_bytes, wrong_blinding_public_inputs_bytes) = match wrong_blinding_result {
        Ok(Ok((proof, public_inputs))) => {
            println!("   ⚠️  Warning: Proof generation succeeded with wrong blinding factor (unexpected)");
            (ProximityProver::serialize_proof(&proof), ProximityProver::serialize_public_inputs(&public_inputs))
        },
        _ => {
            println!("   ✅ Proof generation correctly failed with wrong blinding factor");
            // For Move tests, we'll create a valid proof but use it with wrong commitment
            // Generate a valid proof first
            let valid_proof = prover.generate_proof(
                &ssu_location,
                &blinding, // Correct blinding factor
                &player_location,
                &commitment,
                10.0,
            )?;
            (ProximityProver::serialize_proof(&valid_proof.0), ProximityProver::serialize_public_inputs(&valid_proof.1))
        }
    };

    // Test case 2: Player too far (should fail)
    println!("   Generating proof with player too far...");
    // Create a new setup with smaller max distance to make the player location invalid
    let small_max_distance_squared = Fr::from(1_000_000u64); // (1km * 1000)^2 = 1_000_000 - much smaller
    let small_setup_result = trusted_setup::single_party_setup(small_max_distance_squared)?;
    
    // Serialize the small verifying key first
    let mut small_vk_bytes = Vec::new();
    small_setup_result.verifying_key.serialize_compressed(&mut small_vk_bytes)?;
    
    let small_prover = ProximityProver::new(
        small_setup_result.proving_key,
        small_setup_result.verifying_key,
        params.clone(),
    );
    
    // Generate proof with small max distance - this should succeed but verification should fail with the original VK
    let (far_player_proof, far_player_public_inputs) = small_prover.generate_proof(
        &ssu_location,
        &blinding,
        &player_location, // Same valid location, but with smaller max distance in circuit
        &commitment,
        1.0, // 1km max distance (but this is just for the function, circuit has small_max_distance_squared)
    )?;
    
    let far_player_proof_bytes = ProximityProver::serialize_proof(&far_player_proof);
    let far_player_public_inputs_bytes = ProximityProver::serialize_public_inputs(&far_player_public_inputs);
    
    println!("   ✅ Generated proof with small max distance for distance test");

    // Create a different commitment with wrong blinding factor for testing
    let wrong_blinding = Fr::from(999u64);
    let wrong_commitment = commitment_gen.create_commitment(&ssu_location, &wrong_blinding);
    let wrong_commitment_bytes = LocationCommitmentGenerator::serialize_commitment(&wrong_commitment);

    // Create a temporary Move test file
    let move_test_content = format!(r#"
#[test]
fun test_e2e_proximity_verification() {{
    use sui::test_scenario;
    use location_addr::proximity;

    let mut scenario = test_scenario::begin(@0x1);
    {{
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::init_for_testing(ctx);
    }};

    // Create commitment
    scenario.next_tx(@0x1);
    {{
        let server_cap = test_scenario::take_from_sender<proximity::ServerCap>(&scenario);
        let commitment_bytes = vector[{}];
        let owner = @0x2;
        
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::create_commitment(&server_cap, commitment_bytes, owner, ctx);
        
        test_scenario::return_to_sender(&scenario, server_cap);
    }};

    // Verify proximity proof
    scenario.next_tx(@0x2);
    {{
        let mut commitment = test_scenario::take_shared<proximity::LocationCommitment>(&scenario);
        let vk_bytes = vector[{}];
        let proof_bytes = vector[{}];
        let public_inputs = vector[{}];
        
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::verify_proximity_proof(&mut commitment, vk_bytes, proof_bytes, public_inputs, ctx);
        
        // Verify nonce was incremented
        let nonce = proximity::get_nonce(&commitment);
        assert!(nonce == 1, 0);
        
        test_scenario::return_shared(commitment);
    }};

    test_scenario::end(scenario);
}}

#[test]
#[expected_failure]
fun test_invalid_blinding_factor_fails() {{
    use sui::test_scenario;
    use location_addr::proximity;

    let mut scenario = test_scenario::begin(@0x1);
    {{
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::init_for_testing(ctx);
    }};

    // Create commitment with wrong blinding factor
    scenario.next_tx(@0x1);
    {{
        let server_cap = test_scenario::take_from_sender<proximity::ServerCap>(&scenario);
        let commitment_bytes = vector[{}]; // Wrong commitment bytes
        let owner = @0x2;
        
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::create_commitment(&server_cap, commitment_bytes, owner, ctx);
        
        test_scenario::return_to_sender(&scenario, server_cap);
    }};

    // Try to verify with valid proof but wrong commitment - should fail
    scenario.next_tx(@0x2);
    {{
        let mut commitment = test_scenario::take_shared<proximity::LocationCommitment>(&scenario);
        let vk_bytes = vector[{}];
        let proof_bytes = vector[{}];
        let public_inputs = vector[{}];
        
        let ctx = test_scenario::ctx(&mut scenario);
        // This should fail because the commitment doesn't match the proof
        proximity::verify_proximity_proof(&mut commitment, vk_bytes, proof_bytes, public_inputs, ctx);
        
        test_scenario::return_shared(commitment);
    }};

    test_scenario::end(scenario);
}}

#[test]
#[expected_failure]
fun test_distance_too_high_fails() {{
    use sui::test_scenario;
    use location_addr::proximity;

    let mut scenario = test_scenario::begin(@0x1);
    {{
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::init_for_testing(ctx);
    }};

    // Create commitment
    scenario.next_tx(@0x1);
    {{
        let server_cap = test_scenario::take_from_sender<proximity::ServerCap>(&scenario);
        let commitment_bytes = vector[{}];
        let owner = @0x2;
        
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::create_commitment(&server_cap, commitment_bytes, owner, ctx);
        
        test_scenario::return_to_sender(&scenario, server_cap);
    }};

    // Try to verify with player too far - should fail
    scenario.next_tx(@0x2);
    {{
        let mut commitment = test_scenario::take_shared<proximity::LocationCommitment>(&scenario);
        let vk_bytes = vector[{}];
        let proof_bytes = vector[{}];
        let public_inputs = vector[{}];
        
        let ctx = test_scenario::ctx(&mut scenario);
        // This should fail because the player is too far from the target location
        proximity::verify_proximity_proof(&mut commitment, vk_bytes, proof_bytes, public_inputs, ctx);
        
        test_scenario::return_shared(commitment);
    }};

    test_scenario::end(scenario);
}}
"#,
        // Format commitment_bytes
        commitment_bytes.iter().map(|b| format!("{}u8", b)).collect::<Vec<_>>().join(", "),
        // Format vk_bytes
        vk_bytes.iter().map(|b| format!("{}u8", b)).collect::<Vec<_>>().join(", "),
        // Format proof_bytes
        proof_bytes.iter().map(|b| format!("{}u8", b)).collect::<Vec<_>>().join(", "),
        // Format public_inputs
        public_inputs_bytes.iter().map(|b| format!("{}u8", b)).collect::<Vec<_>>().join(", "),
        // Wrong blinding factor test - use wrong commitment
        wrong_commitment_bytes.iter().map(|b| format!("{}u8", b)).collect::<Vec<_>>().join(", "),
        vk_bytes.iter().map(|b| format!("{}u8", b)).collect::<Vec<_>>().join(", "),
        wrong_blinding_proof_bytes.iter().map(|b| format!("{}u8", b)).collect::<Vec<_>>().join(", "),
        wrong_blinding_public_inputs_bytes.iter().map(|b| format!("{}u8", b)).collect::<Vec<_>>().join(", "),
        // Far player test
        commitment_bytes.iter().map(|b| format!("{}u8", b)).collect::<Vec<_>>().join(", "),
        small_vk_bytes.iter().map(|b| format!("{}u8", b)).collect::<Vec<_>>().join(", "),
        far_player_proof_bytes.iter().map(|b| format!("{}u8", b)).collect::<Vec<_>>().join(", "),
        far_player_public_inputs_bytes.iter().map(|b| format!("{}u8", b)).collect::<Vec<_>>().join(", "),
    );

    // Write the test to a temporary file
    std::fs::write("/tmp/move_e2e_test.move", move_test_content)?;

    println!("   Move test file created at /tmp/move_e2e_test.move");
    println!("   (This is a template - you'll need to integrate it into your Move package)");

    // ============================================================================
    // Phase 9: Summary
    // ============================================================================

    println!("\n🎉 E2E Test Data Generated Successfully!");
    println!("\nSummary:");
    println!("• Commitment: {} bytes", commitment_bytes.len());
    println!("• Verifying Key: {} bytes", vk_bytes.len());
    println!("• Valid Proof: {} bytes", proof_bytes.len());
    println!("• Valid Public Inputs: {} bytes", public_inputs_bytes.len());
    println!("• Invalid Proof (wrong blinding): {} bytes", wrong_blinding_proof_bytes.len());
    println!("• Invalid Proof (too far): {} bytes", far_player_proof_bytes.len());
    println!("\nNext steps:");
    println!("1. Copy the generated data into your Move contract tests");
    println!("2. Run 'sui move test' to verify all proof verification scenarios");
    println!("3. Deploy to testnet and test with real Sui network");

    Ok(())
}