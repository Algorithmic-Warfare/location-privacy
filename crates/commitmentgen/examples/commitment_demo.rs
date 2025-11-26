use ark_serialize::CanonicalSerialize;
use commitmentgen::{
    coord_to_fr, create_poseidon_commitment, generate_blinding, get_poseidon_config, Coordinates,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Location Commitment Generation Demo");
    println!("=====================================");

    // Setup Poseidon configuration
    let poseidon_config = get_poseidon_config();

    // Example coordinates: Seattle, WA (47.6062°N, -122.3321°W)
    // Converted to millimeters for precision
    let seattle_coords = Coordinates {
        x: 47606200i128,   // 47.6062° * 10^4 (fixed-point)
        y: -122332100i128, // -122.3321° * 10^4 (fixed-point)
        z: 0i128,          // Sea level
    };

    println!("Target Location: Seattle, WA");
    println!(
        "   Coordinates: ({}, {}, {})",
        seattle_coords.x, seattle_coords.y, seattle_coords.z
    );

    // Generate blinding factor
    let blinding = generate_blinding();
    println!("Generated blinding factor");

    // Create Poseidon commitment
    let commitment = create_poseidon_commitment(
        coord_to_fr(seattle_coords.x),
        coord_to_fr(seattle_coords.y),
        coord_to_fr(seattle_coords.z),
        blinding,
        &poseidon_config,
    );
    println!("Created Poseidon commitment");

    // Serialize for on-chain storage
    let mut commitment_bytes = Vec::new();
    commitment.serialize_compressed(&mut commitment_bytes)?;
    println!("Serialized commitment: {} bytes", commitment_bytes.len());

    // Display first few bytes for verification
    println!(
        "Commitment bytes (first 32): {:?}",
        &commitment_bytes[..32.min(commitment_bytes.len())]
    );

    // Demonstrate that different blinding factors create different commitments
    let blinding2 = generate_blinding();
    let commitment2 = create_poseidon_commitment(
        coord_to_fr(seattle_coords.x),
        coord_to_fr(seattle_coords.y),
        coord_to_fr(seattle_coords.z),
        blinding2,
        &poseidon_config,
    );
    let mut commitment_bytes2 = Vec::new();
    commitment2.serialize_compressed(&mut commitment_bytes2)?;

    println!("\nSame coordinates, different blinding:");
    println!("Commitment 1: {:?}", &commitment_bytes[..16]);
    println!("Commitment 2: {:?}", &commitment_bytes2[..16]);
    println!("   Different: {}", commitment_bytes != commitment_bytes2);

    println!("\nCommitment generation demo completed!");
    println!("\nIn production:");
    println!("1. Use Poseidon hash for efficient commitment generation");
    println!("2. Store blinding factors securely (never reveal them)");
    println!("3. Publish commitment_bytes on-chain");

    Ok(())
}
