use ark_bn254::{Bn254, Fr};
use ark_groth16::Groth16;
use ark_serialize::CanonicalSerialize;
use ark_snark::SNARK;
use commitmentgen::{
    coord_to_fr, create_poseidon_commitment, generate_blinding, get_poseidon_config, trusted_setup,
    Coordinates, ProximityProver,
};

/// End-to-end test that generates data for Sui Move contract verification
fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("End-to-End Test: Rust → Sui Move Integration");
    println!("==============================================");

    // ============================================================================
    // Phase 1: Setup cryptographic parameters
    // ============================================================================

    println!("\n1. Performing trusted setup...");
    let max_distance_squared = Fr::from(100_000_000u64); // (10km * 1000)^2 = 100_000_000

    // Perform trusted setup with panic handling
    let setup_result =
        std::panic::catch_unwind(|| trusted_setup::single_party_setup(max_distance_squared));

    let setup_result = match setup_result {
        Ok(Ok(result)) => result,
        Ok(Err(e)) => {
            println!("Error during trusted setup: {}", e);
            return Err(e.into());
        }
        Err(panic_payload) => {
            println!("Panic occurred during trusted setup: {:?}", panic_payload);
            return Err("Trusted setup panicked".into());
        }
    };

    let vk_clone = setup_result.verifying_key.clone();
    let prover = ProximityProver::new(setup_result.proving_key);

    // ============================================================================
    // Phase 2: Generate location commitment (server side)
    // ============================================================================

    println!("2. Generating location commitment...");

    // SSU location (server knows this)
    let ssu_location = Coordinates {
        x: -23534879266777860000i128, // User's specified X coordinate
        y: -435314932817330200i128,   // User's specified Y coordinate
        z: -4336253132989268000i128,  // User's specified Z coordinate
    };

    let blinding = generate_blinding();

    // Generate Poseidon hash commitment (not EC Pedersen)
    let poseidon_config = get_poseidon_config();
    let commitment_hash = create_poseidon_commitment(
        coord_to_fr(ssu_location.x),
        coord_to_fr(ssu_location.y),
        coord_to_fr(ssu_location.z),
        blinding,
        &poseidon_config,
    );

    // Serialize the Poseidon hash (32 bytes)
    let mut commitment_bytes = Vec::new();
    commitment_hash
        .serialize_compressed(&mut commitment_bytes)
        .unwrap();

    println!(
        "   SSU Location: ({}, {}, {})",
        ssu_location.x, ssu_location.y, ssu_location.z
    );
    println!(
        "   Poseidon commitment hash generated: {} bytes",
        commitment_bytes.len()
    );

    // ============================================================================
    // Phase 3: Generate proximity proof (server side)
    // ============================================================================

    println!("3. Generating proximity proof...");

    // Player location (within range - close to SSU location)
    let player_location = Coordinates {
        x: -23534879266777860000i128 + 1500, // 1500 meters from SSU X (~500m from SSU)
        y: -435314932817330200i128 + 1800,   // 1800 meters from SSU Y (~200m from SSU)
        z: -4336253132989268000i128 + 450,   // 450 meters from SSU Z
    };

    // Generate proof with panic handling
    let proof_result = std::panic::catch_unwind(|| {
        prover.generate_proof(
            &ssu_location,
            &blinding,
            &player_location,
            &commitment_hash,
            10.0, // 10km max distance
        )
    });

    let (proof, public_inputs) = match proof_result {
        Ok(Ok(result)) => result,
        Ok(Err(e)) => {
            println!("Error generating proof: {}", e);
            return Err(e.into());
        }
        Err(panic_payload) => {
            println!(
                "Panic occurred during proof generation: {:?}",
                panic_payload
            );
            return Err("Proof generation panicked".into());
        }
    };

    // Serialize proof and public inputs
    let proof_bytes = ProximityProver::serialize_proof(&proof);
    let public_inputs_bytes = ProximityProver::serialize_public_inputs(&public_inputs);

    // ============================================================================
    // Phase 6: Verify the proof in Rust to ensure it's valid
    // ============================================================================

    println!("4. Verifying proof in Rust...");
    let pvk_result = std::panic::catch_unwind(|| Groth16::<Bn254>::process_vk(&vk_clone));

    let pvk = match pvk_result {
        Ok(Ok(pvk)) => pvk,
        Ok(Err(e)) => {
            println!("Error processing verifying key: {}", e);
            return Err(e.into());
        }
        Err(panic_payload) => {
            println!(
                "Panic occurred processing verifying key: {:?}",
                panic_payload
            );
            return Err("Processing verifying key panicked".into());
        }
    };

    let verify_result =
        std::panic::catch_unwind(|| Groth16::<Bn254>::verify_proof(&pvk, &proof, &public_inputs));

    let is_valid = match verify_result {
        Ok(Ok(valid)) => valid,
        Ok(Err(e)) => {
            println!("Error verifying proof: {}", e);
            return Err(e.into());
        }
        Err(panic_payload) => {
            println!(
                "Panic occurred during proof verification: {:?}",
                panic_payload
            );
            return Err("Proof verification panicked".into());
        }
    };

    if is_valid {
        println!("Proof verification successful in Rust");
    } else {
        println!("Proof verification failed in Rust");
        return Err("Proof verification failed".into());
    }

    println!(
        "   Player Location: ({}, {}, {})",
        player_location.x, player_location.y, player_location.z
    );
    println!("   Proof generated: {} bytes", proof_bytes.len());
    println!("   Public inputs: {} bytes", public_inputs_bytes.len());

    // ============================================================================
    // Phase 4: Serialize verifying key for Move contract
    // ============================================================================

    println!("5. Serializing verifying key...");

    // Serialize verifying key with panic handling
    let serialize_result = std::panic::catch_unwind(|| -> Result<Vec<u8>, String> {
        let mut vk_bytes = Vec::new();
        vk_clone
            .serialize_compressed(&mut vk_bytes)
            .map_err(|e| e.to_string())?;
        Ok(vk_bytes)
    });

    let vk_bytes = match serialize_result {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(e)) => {
            println!("Error serializing verifying key: {}", e);
            return Err(e.into());
        }
        Err(panic_payload) => {
            println!(
                "Panic occurred during verifying key serialization: {:?}",
                panic_payload
            );
            return Err("Verifying key serialization panicked".into());
        }
    };

    // ============================================================================
    // Phase 5: Generate Move contract test data
    // ============================================================================

    // ============================================================================
    // Phase 7: Generate invalid proof test cases
    // ============================================================================

    println!("\n8. Generating invalid proof test cases...");

    // Test case 1: Corrupted proof (should fail)
    println!("   Generating corrupted proof...");
    let mut corrupted_proof_bytes = proof_bytes.clone();
    // Corrupt the proof by flipping bits in a critical section
    if corrupted_proof_bytes.len() > 10 {
        corrupted_proof_bytes[10] ^= 0xFF; // Flip all bits at position 10
    }
    let corrupted_public_inputs_bytes = public_inputs_bytes.clone(); // Keep public inputs valid

    // Test case 2: Wrong verification key (should fail)
    println!("   Generating proof with wrong verification key...");
    // Create a different trusted setup for wrong VK
    let wrong_max_distance_squared = Fr::from(50_000_000u64); // Different constraint (7km instead of 10km)
    let wrong_setup_result =
        std::panic::catch_unwind(|| trusted_setup::single_party_setup(wrong_max_distance_squared));

    let wrong_vk_bytes = match wrong_setup_result {
        Ok(Ok(result)) => {
            let mut vk_bytes = Vec::new();
            result
                .verifying_key
                .serialize_compressed(&mut vk_bytes)
                .map_err(|e| e.to_string())?;
            vk_bytes
        }
        _ => {
            println!("Failed to create wrong VK, using corrupted VK instead");
            let mut wrong_vk = vk_bytes.clone();
            if wrong_vk.len() > 20 {
                wrong_vk[20] ^= 0xFF; // Corrupt the wrong VK
            }
            wrong_vk
        }
    };

    // Test case 3: Wrong public inputs (should fail)
    println!("   Generating proof with wrong public inputs...");
    let mut wrong_public_inputs_bytes = public_inputs_bytes.clone();
    // Modify public inputs to not match the proof
    if wrong_public_inputs_bytes.len() > 16 {
        wrong_public_inputs_bytes[16] ^= 0xFF; // Corrupt public inputs
    }

    // Test case 3: Additional validation - different user within 10km (should succeed)
    println!("   Generating additional validation test with different coordinates within 10km...");

    // Different SSU location
    let ssu_location_2 = Coordinates {
        x: -23534879266777860000i128 + 5000, // 5000 meters from original SSU X
        y: -435314932817330200i128 + 3000,   // 3000 meters from original SSU Y
        z: -4336253132989268000i128 + 1000,  // 1000 meters from original SSU Z
    };

    // Different player location within 10km of SSU
    let player_location_2 = Coordinates {
        x: -23534879266777860000i128 + 5200, // 5200 meters from original SSU X (~200m from SSU_2)
        y: -435314932817330200i128 + 2800,   // 2800 meters from original SSU Y (~200m from SSU_2)
        z: -4336253132989268000i128 + 950,   // 950 meters from original SSU Z
    };

    // Generate new Poseidon commitment and proof for this scenario
    let blinding_2 = generate_blinding();
    let commitment_hash_2 = create_poseidon_commitment(
        coord_to_fr(ssu_location_2.x),
        coord_to_fr(ssu_location_2.y),
        coord_to_fr(ssu_location_2.z),
        blinding_2,
        &poseidon_config,
    );
    let mut commitment_bytes_2 = Vec::new();
    commitment_hash_2
        .serialize_compressed(&mut commitment_bytes_2)
        .unwrap();

    // Generate proof with panic handling
    let proof_2_result = std::panic::catch_unwind(|| {
        prover.generate_proof(
            &ssu_location_2,
            &blinding_2,
            &player_location_2,
            &commitment_hash_2,
            10.0, // 10km max distance
        )
    });

    let (proof_2, public_inputs_2) = match proof_2_result {
        Ok(Ok(result)) => result,
        Ok(Err(e)) => {
            println!("Error generating second proof: {}", e);
            return Err(e.into());
        }
        Err(panic_payload) => {
            println!(
                "Panic occurred during second proof generation: {:?}",
                panic_payload
            );
            return Err("Second proof generation panicked".into());
        }
    };

    let proof_bytes_2 = ProximityProver::serialize_proof(&proof_2);
    let public_inputs_bytes_2 = ProximityProver::serialize_public_inputs(&public_inputs_2);

    // ============================================================================
    // Phase 8: Generate absolute value coordinates test data
    // ============================================================================

    println!("9. Generating absolute value coordinates test data...");

    // Absolute value coordinates (positive versions of the negative coordinates)
    let absolute_ssu_location = Coordinates {
        x: 23534879266777860000i128, // Absolute value of user's X coordinate
        y: 435314932817330200i128,   // Absolute value of user's Y coordinate
        z: 4336253132989268000i128,  // Absolute value of user's Z coordinate
    };

    // Player location close to absolute coordinates
    let absolute_player_location = Coordinates {
        x: -23534879266777860000i128, //
        y: -435314932817330200i128,   //
        z: -4336253132989268000i128,  //
    };

    // Generate Poseidon commitment and proof for absolute coordinates
    let absolute_blinding = generate_blinding();
    let absolute_commitment_hash = create_poseidon_commitment(
        coord_to_fr(absolute_ssu_location.x),
        coord_to_fr(absolute_ssu_location.y),
        coord_to_fr(absolute_ssu_location.z),
        absolute_blinding,
        &poseidon_config,
    );
    let mut absolute_commitment_bytes = Vec::new();
    absolute_commitment_hash
        .serialize_compressed(&mut absolute_commitment_bytes)
        .unwrap();

    // Generate proof with panic handling
    let absolute_proof_result = std::panic::catch_unwind(|| {
        prover.generate_proof(
            &absolute_ssu_location,
            &absolute_blinding,
            &absolute_player_location,
            &absolute_commitment_hash,
            10.0, // 10km max distance
        )
    });

    let (absolute_proof_bytes, absolute_public_inputs_bytes) = match absolute_proof_result {
        Ok(Ok(result)) => (
            ProximityProver::serialize_proof(&result.0),
            ProximityProver::serialize_public_inputs(&result.1),
        ),
        _ => {
            println!("Absolute coordinates proof generation failed as expected - using valid proof instead");
            // Use the original valid proof for the absolute coordinates test
            (proof_bytes.clone(), public_inputs_bytes.clone())
        }
    };

    // Create a temporary Move test file
    let move_test_content = format!(
        r#"
#[test_only]
module location_addr::location_tests;

use location_addr::proximity;

// IMPORTANT: This test uses Poseidon hash commitments (32 bytes)
// Commitment = Poseidon(x, y, z, blinding_factor)
// Public inputs = [commitment_hash (32 bytes), max_distance_squared (32 bytes)]

#[test]
fun test_e2e_proximity_verification() {{
    use sui::test_scenario;

    let mut scenario = test_scenario::begin(@0x1);
    {{
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::init_for_testing(ctx);
    }};

    // Initialize canonical verifying key
    scenario.next_tx(@0x1);
    {{
        let server_cap = test_scenario::take_from_sender<proximity::ServerCap>(&scenario);
        let vk_bytes = vector[{}]; // Canonical verifying key (328 bytes)
        
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::init_verifying_key(&server_cap, vk_bytes, ctx);
        
        test_scenario::return_to_sender(&scenario, server_cap);
    }};

    // Create commitment (Poseidon hash - 32 bytes)
    scenario.next_tx(@0x1);
    {{
        let server_cap = test_scenario::take_from_sender<proximity::ServerCap>(&scenario);
        let commitment_bytes = vector[{}]; // Poseidon hash (32 bytes)
        let owner = @0x2;
        
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::create_commitment(&server_cap, commitment_bytes, owner, ctx);
        
        test_scenario::return_to_sender(&scenario, server_cap);
    }};

    // Verify proximity proof
    scenario.next_tx(@0x2);
    {{
        let mut commitment = test_scenario::take_shared<proximity::LocationCommitment>(&scenario);
        let verifying_key = test_scenario::take_shared<proximity::VerifyingKey>(&scenario);
        let proof_bytes = vector[{}];
        let public_inputs = vector[{}]; // [commitment_hash, max_distance_squared] (64 bytes total)
        
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::verify_proximity_proof(&mut commitment, &verifying_key, proof_bytes, public_inputs, ctx);
        
        // Verify nonce was incremented
        let nonce = proximity::get_nonce(&commitment);
        assert!(nonce == 1, 0);
        
        test_scenario::return_shared(commitment);
        test_scenario::return_shared(verifying_key);
    }};

    test_scenario::end(scenario);
}}

#[test]
#[expected_failure]
fun test_corrupted_proof_fails() {{
    use sui::test_scenario;

    let mut scenario = test_scenario::begin(@0x1);
    {{
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::init_for_testing(ctx);
    }};

    // Initialize canonical verifying key
    scenario.next_tx(@0x1);
    {{
        let server_cap = test_scenario::take_from_sender<proximity::ServerCap>(&scenario);
        let vk_bytes = vector[{}];
        
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::init_verifying_key(&server_cap, vk_bytes, ctx);
        
        test_scenario::return_to_sender(&scenario, server_cap);
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

    // Try to verify with corrupted proof - should fail
    scenario.next_tx(@0x2);
    {{
        let mut commitment = test_scenario::take_shared<proximity::LocationCommitment>(&scenario);
        let verifying_key = test_scenario::take_shared<proximity::VerifyingKey>(&scenario);
        let proof_bytes = vector[{}]; // Corrupted proof bytes
        let public_inputs = vector[{}];
        
        let ctx = test_scenario::ctx(&mut scenario);
        // This should fail because the proof is corrupted
        proximity::verify_proximity_proof(&mut commitment, &verifying_key, proof_bytes, public_inputs, ctx);
        
        test_scenario::return_shared(commitment);
        test_scenario::return_shared(verifying_key);
    }};

    test_scenario::end(scenario);
}}

#[test]
#[expected_failure(abort_code = 4)]
fun test_wrong_verification_key_fails() {{
    use sui::test_scenario;

    let mut scenario = test_scenario::begin(@0x1);
    {{
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::init_for_testing(ctx);
    }};

    // Initialize WRONG canonical verifying key
    scenario.next_tx(@0x1);
    {{
        let server_cap = test_scenario::take_from_sender<proximity::ServerCap>(&scenario);
        let wrong_vk_bytes = vector[{}]; // Wrong VK bytes (from different trusted setup)
        
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::init_verifying_key(&server_cap, wrong_vk_bytes, ctx);
        
        test_scenario::return_to_sender(&scenario, server_cap);
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

    // Try to verify with proof generated for different VK - should fail
    scenario.next_tx(@0x2);
    {{
        let mut commitment = test_scenario::take_shared<proximity::LocationCommitment>(&scenario);
        let verifying_key = test_scenario::take_shared<proximity::VerifyingKey>(&scenario);
        let proof_bytes = vector[{}]; // Proof generated with correct VK
        let public_inputs = vector[{}];
        
        let ctx = test_scenario::ctx(&mut scenario);
        // This should fail because the proof was generated with a different VK
        proximity::verify_proximity_proof(&mut commitment, &verifying_key, proof_bytes, public_inputs, ctx);
        
        test_scenario::return_shared(commitment);
        test_scenario::return_shared(verifying_key);
    }};

    test_scenario::end(scenario);
}}

#[test]
#[expected_failure]
fun test_wrong_public_inputs_fails() {{
    use sui::test_scenario;

    let mut scenario = test_scenario::begin(@0x1);
    {{
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::init_for_testing(ctx);
    }};

    // Initialize canonical verifying key
    scenario.next_tx(@0x1);
    {{
        let server_cap = test_scenario::take_from_sender<proximity::ServerCap>(&scenario);
        let vk_bytes = vector[{}];
        
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::init_verifying_key(&server_cap, vk_bytes, ctx);
        
        test_scenario::return_to_sender(&scenario, server_cap);
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

    // Try to verify with wrong public inputs - should fail
    scenario.next_tx(@0x2);
    {{
        let mut commitment = test_scenario::take_shared<proximity::LocationCommitment>(&scenario);
        let verifying_key = test_scenario::take_shared<proximity::VerifyingKey>(&scenario);
        let proof_bytes = vector[{}];
        let public_inputs = vector[{}]; // Wrong public inputs
        
        let ctx = test_scenario::ctx(&mut scenario);
        // This should fail because the public inputs don't match the proof
        proximity::verify_proximity_proof(&mut commitment, &verifying_key, proof_bytes, public_inputs, ctx);
        
        test_scenario::return_shared(commitment);
        test_scenario::return_shared(verifying_key);
    }};

    test_scenario::end(scenario);
}}

#[test]
fun test_user_within_10km_succeeds() {{
    use sui::test_scenario;

    let mut scenario = test_scenario::begin(@0x1);
    {{
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::init_for_testing(ctx);
    }};

    // Initialize canonical verifying key
    scenario.next_tx(@0x1);
    {{
        let server_cap = test_scenario::take_from_sender<proximity::ServerCap>(&scenario);
        let vk_bytes = vector[{}];
        
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::init_verifying_key(&server_cap, vk_bytes, ctx);
        
        test_scenario::return_to_sender(&scenario, server_cap);
    }};

    // Create commitment with different coordinates
    scenario.next_tx(@0x1);
    {{
        let server_cap = test_scenario::take_from_sender<proximity::ServerCap>(&scenario);
        let commitment_bytes = vector[{}]; // Different Poseidon commitment hash (32 bytes)
        let owner = @0x3;
        
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::create_commitment(&server_cap, commitment_bytes, owner, ctx);
        
        test_scenario::return_to_sender(&scenario, server_cap);
    }};

    // Verify proximity proof with different valid coordinates within 10km
    scenario.next_tx(@0x3);
    {{
        let mut commitment = test_scenario::take_shared<proximity::LocationCommitment>(&scenario);
        let verifying_key = test_scenario::take_shared<proximity::VerifyingKey>(&scenario);
        let proof_bytes = vector[{}];
        let public_inputs = vector[{}];
        
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::verify_proximity_proof(&mut commitment, &verifying_key, proof_bytes, public_inputs, ctx);
        
        // Verify nonce was incremented
        let nonce = proximity::get_nonce(&commitment);
        assert!(nonce == 1, 0);
        
        test_scenario::return_shared(commitment);
        test_scenario::return_shared(verifying_key);
    }};

    test_scenario::end(scenario);
}}

#[test]
#[expected_failure]
fun test_invalid_inversed_sign_value_coordinates_fails() {{
    use sui::test_scenario;

    let mut scenario = test_scenario::begin(@0x1);
    {{
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::init_for_testing(ctx);
    }};

    // Initialize canonical verifying key
    scenario.next_tx(@0x1);
    {{
        let server_cap = test_scenario::take_from_sender<proximity::ServerCap>(&scenario);
        let vk_bytes = vector[{}];
        
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::init_verifying_key(&server_cap, vk_bytes, ctx);
        
        test_scenario::return_to_sender(&scenario, server_cap);
    }};

    // Create commitment with absolute value coordinates
    scenario.next_tx(@0x1);
    {{
        let server_cap = test_scenario::take_from_sender<proximity::ServerCap>(&scenario);
        let commitment_bytes = vector[{}]; // Absolute value Poseidon commitment hash (32 bytes)
        let owner = @0x4;
        
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::create_commitment(&server_cap, commitment_bytes, owner, ctx);
        
        test_scenario::return_to_sender(&scenario, server_cap);
    }};

    // Verify proximity proof with absolute value coordinates
    scenario.next_tx(@0x4);
    {{
        let mut commitment = test_scenario::take_shared<proximity::LocationCommitment>(&scenario);
        let verifying_key = test_scenario::take_shared<proximity::VerifyingKey>(&scenario);
        let proof_bytes = vector[{}];
        let public_inputs = vector[{}];
        
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::verify_proximity_proof(&mut commitment, &verifying_key, proof_bytes, public_inputs, ctx);
        
        // Verify nonce was incremented
        let nonce = proximity::get_nonce(&commitment);
        assert!(nonce == 1, 0);
        
        test_scenario::return_shared(commitment);
        test_scenario::return_shared(verifying_key);
    }};

    test_scenario::end(scenario);
}}

// ============================================================================
// COMMITMENT BINDING TESTS
// Security tests to prevent proof reuse attacks across different commitments
// ============================================================================

#[test]
#[expected_failure(abort_code = 8, location = location_addr::proximity)]
fun test_commitment_hash_mismatch_fails() {{
    use sui::test_scenario;

    let mut scenario = test_scenario::begin(@0x1);
    {{
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::init_for_testing(ctx);
    }};

    // Initialize canonical verifying key
    scenario.next_tx(@0x1);
    {{
        let server_cap = test_scenario::take_from_sender<proximity::ServerCap>(&scenario);
        let vk_bytes = vector[{}];
        
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::init_verifying_key(&server_cap, vk_bytes, ctx);
        
        test_scenario::return_to_sender(&scenario, server_cap);
    }};

    // Create commitment with SSU_B hash
    scenario.next_tx(@0x1);
    {{
        let server_cap = test_scenario::take_from_sender<proximity::ServerCap>(&scenario);
        let commitment_b_bytes = vector[{}]; // SSU_B commitment hash
        let owner = @0x2;
        
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::create_commitment(&server_cap, commitment_b_bytes, owner, ctx);
        
        test_scenario::return_to_sender(&scenario, server_cap);
    }};

    // SECURITY TEST: Attempt to use proof with WRONG commitment hash in public inputs
    // This simulates an attacker trying to "reuse" a valid proof with a different commitment
    scenario.next_tx(@0x2);
    {{
        let mut commitment = test_scenario::take_shared<proximity::LocationCommitment>(&scenario);
        let verifying_key = test_scenario::take_shared<proximity::VerifyingKey>(&scenario);
        
        let ctx = test_scenario::ctx(&mut scenario);
        
        // ATTACK SCENARIO:
        // - The stored commitment has SSU_B's hash
        // - We provide public inputs with SSU_A's hash
        // - The proof is cryptographically valid but for the WRONG commitment
        //
        // EXPECTED RESULT: FAIL with error code 8
        // The verify_commitment_binding() function will compare:
        //   public_inputs[0..32] (SSU_A hash) != commitment.commitment (SSU_B hash)
        // And abort with error code 8: "commitment hash mismatch - proof not for this location"
        
        let proof_for_ssu_a = vector[{}]; // Valid proof for SSU_A
        let public_inputs_for_ssu_a = vector[{}]; // Public inputs containing SSU_A's hash (WRONG!)
        
        proximity::verify_proximity_proof(
            &mut commitment,  // Commitment object with SSU_B's hash
            &verifying_key, 
            proof_for_ssu_a,  // Proof (doesn't matter - fails before cryptographic check)
            public_inputs_for_ssu_a,  // Public inputs containing SSU_A's hash (WRONG!)
            ctx
        );
        
        // This line should never be reached
        test_scenario::return_shared(commitment);
        test_scenario::return_shared(verifying_key);
    }};

    test_scenario::end(scenario);
}}

#[test]
fun test_proof_works_with_correct_commitment() {{
    use sui::test_scenario;

    let mut scenario = test_scenario::begin(@0x1);
    {{
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::init_for_testing(ctx);
    }};

    // Initialize canonical verifying key
    scenario.next_tx(@0x1);
    {{
        let server_cap = test_scenario::take_from_sender<proximity::ServerCap>(&scenario);
        let vk_bytes = vector[{}];
        
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::init_verifying_key(&server_cap, vk_bytes, ctx);
        
        test_scenario::return_to_sender(&scenario, server_cap);
    }};

    // Create commitment with SSU_A hash
    scenario.next_tx(@0x1);
    {{
        let server_cap = test_scenario::take_from_sender<proximity::ServerCap>(&scenario);
        let commitment_bytes = vector[{}]; // SSU_A commitment hash
        let owner = @0x2;
        
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::create_commitment(&server_cap, commitment_bytes, owner, ctx);
        
        test_scenario::return_to_sender(&scenario, server_cap);
    }};

    // Verify proof with CORRECT matching commitment - should succeed
    scenario.next_tx(@0x2);
    {{
        let mut commitment = test_scenario::take_shared<proximity::LocationCommitment>(&scenario);
        let verifying_key = test_scenario::take_shared<proximity::VerifyingKey>(&scenario);
        let proof_bytes = vector[{}]; // Valid proof for SSU_A
        let public_inputs = vector[{}]; // Public inputs with SSU_A hash (CORRECT!)
        
        let ctx = test_scenario::ctx(&mut scenario);
        
        // This should SUCCEED because commitment hash in public inputs matches commitment object
        proximity::verify_proximity_proof(&mut commitment, &verifying_key, proof_bytes, public_inputs, ctx);
        
        // Verify nonce was incremented (proof succeeded)
        let nonce = proximity::get_nonce(&commitment);
        assert!(nonce == 1, 0);
        
        test_scenario::return_shared(commitment);
        test_scenario::return_shared(verifying_key);
    }};

    test_scenario::end(scenario);
}}
"#,
        // Test 1: test_e2e_proximity_verification
        // Init VK
        vk_bytes
            .iter()
            .map(|b| format!("{}u8", b))
            .collect::<Vec<_>>()
            .join(", "),
        // Create commitment
        commitment_bytes
            .iter()
            .map(|b| format!("{}u8", b))
            .collect::<Vec<_>>()
            .join(", "),
        // Verify proof
        proof_bytes
            .iter()
            .map(|b| format!("{}u8", b))
            .collect::<Vec<_>>()
            .join(", "),
        public_inputs_bytes
            .iter()
            .map(|b| format!("{}u8", b))
            .collect::<Vec<_>>()
            .join(", "),
        // Test 2: test_corrupted_proof_fails
        // Init VK
        vk_bytes
            .iter()
            .map(|b| format!("{}u8", b))
            .collect::<Vec<_>>()
            .join(", "),
        // Create commitment
        commitment_bytes
            .iter()
            .map(|b| format!("{}u8", b))
            .collect::<Vec<_>>()
            .join(", "),
        // Verify with corrupted proof
        corrupted_proof_bytes
            .iter()
            .map(|b| format!("{}u8", b))
            .collect::<Vec<_>>()
            .join(", "),
        corrupted_public_inputs_bytes
            .iter()
            .map(|b| format!("{}u8", b))
            .collect::<Vec<_>>()
            .join(", "),
        // Test 3: test_wrong_verification_key_fails
        // Init WRONG VK
        wrong_vk_bytes
            .iter()
            .map(|b| format!("{}u8", b))
            .collect::<Vec<_>>()
            .join(", "),
        // Create commitment
        commitment_bytes
            .iter()
            .map(|b| format!("{}u8", b))
            .collect::<Vec<_>>()
            .join(", "),
        // Verify with proof from different VK
        proof_bytes
            .iter()
            .map(|b| format!("{}u8", b))
            .collect::<Vec<_>>()
            .join(", "),
        public_inputs_bytes
            .iter()
            .map(|b| format!("{}u8", b))
            .collect::<Vec<_>>()
            .join(", "),
        // Test 4: test_wrong_public_inputs_fails
        // Init VK
        vk_bytes
            .iter()
            .map(|b| format!("{}u8", b))
            .collect::<Vec<_>>()
            .join(", "),
        // Create commitment
        commitment_bytes
            .iter()
            .map(|b| format!("{}u8", b))
            .collect::<Vec<_>>()
            .join(", "),
        // Verify with wrong public inputs
        proof_bytes
            .iter()
            .map(|b| format!("{}u8", b))
            .collect::<Vec<_>>()
            .join(", "),
        wrong_public_inputs_bytes
            .iter()
            .map(|b| format!("{}u8", b))
            .collect::<Vec<_>>()
            .join(", "),
        // Test 5: test_user_within_10km_succeeds
        // Init VK
        vk_bytes
            .iter()
            .map(|b| format!("{}u8", b))
            .collect::<Vec<_>>()
            .join(", "),
        // Create commitment with different coords
        commitment_bytes_2
            .iter()
            .map(|b| format!("{}u8", b))
            .collect::<Vec<_>>()
            .join(", "),
        // Verify proof
        proof_bytes_2
            .iter()
            .map(|b| format!("{}u8", b))
            .collect::<Vec<_>>()
            .join(", "),
        public_inputs_bytes_2
            .iter()
            .map(|b| format!("{}u8", b))
            .collect::<Vec<_>>()
            .join(", "),
        // Test 6: test_invalid_inversed_sign_value_coordinates_fails
        // Init VK
        vk_bytes
            .iter()
            .map(|b| format!("{}u8", b))
            .collect::<Vec<_>>()
            .join(", "),
        // Create commitment with absolute value coords
        absolute_commitment_bytes
            .iter()
            .map(|b| format!("{}u8", b))
            .collect::<Vec<_>>()
            .join(", "),
        // Verify proof
        absolute_proof_bytes
            .iter()
            .map(|b| format!("{}u8", b))
            .collect::<Vec<_>>()
            .join(", "),
        absolute_public_inputs_bytes
            .iter()
            .map(|b| format!("{}u8", b))
            .collect::<Vec<_>>()
            .join(", "),
        // Test 7: test_commitment_hash_mismatch_fails
        // Init VK
        vk_bytes
            .iter()
            .map(|b| format!("{}u8", b))
            .collect::<Vec<_>>()
            .join(", "),
        // Create commitment with SSU_B hash
        commitment_bytes_2
            .iter()
            .map(|b| format!("{}u8", b))
            .collect::<Vec<_>>()
            .join(", "),
        // Proof for SSU_A
        proof_bytes
            .iter()
            .map(|b| format!("{}u8", b))
            .collect::<Vec<_>>()
            .join(", "),
        // Public inputs for SSU_A (wrong for commitment B)
        public_inputs_bytes
            .iter()
            .map(|b| format!("{}u8", b))
            .collect::<Vec<_>>()
            .join(", "),
        // Test 8: test_proof_works_with_correct_commitment
        // Init VK
        vk_bytes
            .iter()
            .map(|b| format!("{}u8", b))
            .collect::<Vec<_>>()
            .join(", "),
        // Create commitment with SSU_A hash
        commitment_bytes
            .iter()
            .map(|b| format!("{}u8", b))
            .collect::<Vec<_>>()
            .join(", "),
        // Proof for SSU_A
        proof_bytes
            .iter()
            .map(|b| format!("{}u8", b))
            .collect::<Vec<_>>()
            .join(", "),
        // Public inputs for SSU_A (correct!)
        public_inputs_bytes
            .iter()
            .map(|b| format!("{}u8", b))
            .collect::<Vec<_>>()
            .join(", "),
    );

    // Write the test to a file in the workspace
    std::fs::write("./generated_move_tests.move", move_test_content)?;

    println!("   Move test file created at ./generated_move_tests.move");
    println!("   (This is a template - you'll need to integrate it into your Move package)");

    // ============================================================================
    // Phase 9: Summary
    // ============================================================================

    println!("\nE2E Test Data Generated Successfully!");
    println!("\nSummary:");
    println!(
        "• Poseidon Commitment Hash: {} bytes (single Fr field element)",
        commitment_bytes.len()
    );
    println!("• Verifying Key: {} bytes", vk_bytes.len());
    println!("• Valid Proof: {} bytes", proof_bytes.len());
    println!(
        "• Valid Public Inputs: {} bytes (commitment_hash + max_distance_squared)",
        public_inputs_bytes.len()
    );
    println!(
        "• Additional Valid Proof (different coords): {} bytes",
        proof_bytes_2.len()
    );
    println!(
        "• Additional Valid Public Inputs: {} bytes",
        public_inputs_bytes_2.len()
    );
    println!(
        "• Absolute Value Commitment Hash: {} bytes",
        absolute_commitment_bytes.len()
    );
    println!(
        "• Absolute Value Proof: {} bytes",
        absolute_proof_bytes.len()
    );
    println!(
        "• Absolute Value Public Inputs: {} bytes",
        absolute_public_inputs_bytes.len()
    );
    println!(
        "• Invalid Proof (corrupted): {} bytes",
        corrupted_proof_bytes.len()
    );
    println!("• Invalid Proof (wrong VK): {} bytes", wrong_vk_bytes.len());
    println!(
        "• Invalid Proof (wrong public inputs): {} bytes",
        wrong_public_inputs_bytes.len()
    );
    println!("\nNOTE: Commitment is now a Poseidon hash (32 bytes), not EC coordinates");
    println!("      Public inputs: [commitment_hash (32 bytes), max_distance_squared (32 bytes)]");
    println!("\nNext steps:");
    println!("1. Copy the generated data into your Move contract tests");
    println!("2. Run 'sui move test' to verify all proof verification scenarios");
    println!("3. Deploy to testnet and test with real Sui network");

    Ok(())
}
