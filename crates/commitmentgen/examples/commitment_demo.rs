use commitmentgen::{LocationCommitmentGenerator, PedersenParams, Coordinates};
use ark_bn254::Fr;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Location Commitment Generation Demo");
    println!("=====================================");

    // Setup Pedersen parameters (in production, use independent generators)
    let params = PedersenParams {
        g: Fr::from(1u64),
        h: Fr::from(2u64), // Different generator in production
        k: Fr::from(3u64), // Different generator in production
        m: Fr::from(4u64), // Different generator in production
    };

    let commitment_gen = LocationCommitmentGenerator::new(params);

    // Example coordinates: Seattle, WA (47.6062°N, -122.3321°W)
    // Converted to millimeters for precision
    let seattle_coords = Coordinates {
        x: 47_606_200,  // 47.6062° * 10^4 (fixed-point)
        y: -122_332_100, // -122.3321° * 10^4 (fixed-point)
        z: 0,           // Sea level
    };

    println!("Target Location: Seattle, WA");
    println!("   Coordinates: ({}, {}, {})", seattle_coords.x, seattle_coords.y, seattle_coords.z);

    // Generate blinding factor
    let blinding = LocationCommitmentGenerator::generate_blinding();
    println!("Generated blinding factor");

    // Create commitment
    let commitment = commitment_gen.create_commitment(&seattle_coords, &blinding);
    println!("Created Pedersen commitment");

    // Serialize for on-chain storage
    let commitment_bytes = LocationCommitmentGenerator::serialize_commitment(&commitment);
    println!("Serialized commitment: {} bytes", commitment_bytes.len());

    // Display first few bytes for verification
    println!("Commitment bytes (first 32): {:?}", &commitment_bytes[..32.min(commitment_bytes.len())]);

    // Demonstrate that different blinding factors create different commitments
    let blinding2 = LocationCommitmentGenerator::generate_blinding();
    let commitment2 = commitment_gen.create_commitment(&seattle_coords, &blinding2);
    let commitment_bytes2 = LocationCommitmentGenerator::serialize_commitment(&commitment2);

    println!("\nSame coordinates, different blinding:");
    println!("Commitment 1: {:?}", &commitment_bytes[..16]);
    println!("Commitment 2: {:?}", &commitment_bytes2[..16]);
    println!("   Different: {}", commitment_bytes != commitment_bytes2);

    println!("\nCommitment generation demo completed!");
    println!("\nIn production:");
    println!("1. Use cryptographically secure independent generators");
    println!("2. Store blinding factors securely (never reveal them)");
    println!("3. Publish commitment_bytes on-chain");

    Ok(())
}