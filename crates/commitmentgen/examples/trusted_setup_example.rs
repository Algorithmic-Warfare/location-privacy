use ark_bn254::Fr;
use commitmentgen::trusted_setup::{serialize_setup_result, single_party_setup, TwoPartySetup};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("CommitmentGen Trusted Setup Example");
    println!("=====================================");

    // Define maximum distance (10km squared in millimeters)
    let max_distance_squared = Fr::from(10_000_000_000u64);

    println!("\n Single-Party Setup (Development Only)");
    println!("---------------------------------------");

    // Single-party setup (not secure for production)
    let single_setup = single_party_setup(max_distance_squared)?;
    println!("Single-party setup completed");
    println!(
        "   Proving key size: {} queries",
        single_setup.proving_key.a_query.len()
    );

    // Serialize the keys
    let (pk_bytes, vk_bytes) = serialize_setup_result(&single_setup)?;
    println!("   Serialized proving key: {} bytes", pk_bytes.len());
    println!("   Serialized verifying key: {} bytes", vk_bytes.len());

    println!("\nTwo-Party Setup (Production Ready)");
    println!("------------------------------------");

    // Two-party setup ceremony
    let mut two_party_setup = TwoPartySetup::new(max_distance_squared);

    // Party A contributes
    let party_a_contribution = two_party_setup.party_a_contribute()?;
    println!("Party A contributed: {} bytes", party_a_contribution.len());

    // Party B contributes
    let party_b_contribution = two_party_setup.party_b_contribute()?;
    println!("Party B contributed: {} bytes", party_b_contribution.len());

    // Check setup completeness
    println!("Setup complete: {}", two_party_setup.is_complete());

    // Finalize setup
    let two_party_result = two_party_setup.finalize_setup()?;
    println!("Two-party setup finalized!");
    println!(
        "   Proving key size: {} queries",
        two_party_result.proving_key.a_query.len()
    );

    println!("\nTrusted setup ceremony completed successfully!");
    println!("\nNext steps:");
    println!("1. Store proving key securely on server");
    println!("2. Deploy verifying key to blockchain");
    println!("3. Use setup for generating proximity proofs");

    Ok(())
}
