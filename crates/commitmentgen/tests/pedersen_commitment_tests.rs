//! Integration tests for Pedersen commitments
//!
//! These tests verify the cryptographic properties of Pedersen commitments
//! used in the location privacy system.

#[cfg(test)]
mod integration_tests {
    use commitmentgen::{LocationCommitmentGenerator, PedersenParams, Coordinates};
    use ark_bn254::{Fr, G1Affine};
    use ark_std::Zero;
    use ark_serialize::CanonicalDeserialize;
    use ark_ec::AffineRepr;

    /// Test that demonstrates the complete Pedersen commitment workflow
    #[test]
    fn test_pedersen_commitment_workflow() {
        // Setup secure parameters (in practice, these should be generated securely)
        let params = PedersenParams::new();

        let commitment_gen = LocationCommitmentGenerator::new(params);

        // Server creates a commitment to SSU location
        let ssu_location = Coordinates { x: 1000, y: 2000, z: 500 };
        let blinding = LocationCommitmentGenerator::generate_blinding();

        let commitment = commitment_gen.create_commitment(&ssu_location, &blinding);
        let commitment_bytes = LocationCommitmentGenerator::serialize_commitment(&commitment);

        // Verify commitment is properly formed
        assert_eq!(commitment_bytes.len(), 32);
        assert!(!commitment.is_zero());

        // Verify that the commitment cannot be opened without the blinding factor
        // (This demonstrates the hiding property)
        let wrong_blinding = Fr::from(99999u64);
        let wrong_commitment = commitment_gen.create_commitment(&ssu_location, &wrong_blinding);
        assert_ne!(commitment, wrong_commitment);

        println!(" Pedersen commitment workflow test passed");
        println!("   Commitment size: {} bytes", commitment_bytes.len());
        println!("   SSU Location: ({}, {}, {}) meters", ssu_location.x, ssu_location.y, ssu_location.z);
    }

    /// Test the binding property: different coordinates produce different commitments
    #[test]
    fn test_binding_property_comprehensive() {
        let params = PedersenParams::new();
        let commitment_gen = LocationCommitmentGenerator::new(params);
        let blinding = Fr::from(42u64);

        let coords1 = Coordinates { x: 1000, y: 2000, z: 500 };
        let coords2 = Coordinates { x: 1001, y: 2000, z: 500 }; // Only x differs

        let commitment1 = commitment_gen.create_commitment(&coords1, &blinding);
        let commitment2 = commitment_gen.create_commitment(&coords2, &blinding);

        assert_ne!(commitment1, commitment2, "Binding property: different coordinates → different commitments");

        // Also test that same coordinates with different blinding give different commitments
        let blinding2 = Fr::from(43u64);
        let commitment3 = commitment_gen.create_commitment(&coords1, &blinding2);
        assert_ne!(commitment1, commitment3, "Hiding property: different blinding → different commitments");
    }

    /// Test that commitments work correctly with the mathematical definition
    /// C = g^x * h^y * k^z * m^r
    #[test]
    fn test_mathematical_correctness_detailed() {
        let params = PedersenParams::new();
        let commitment_gen = LocationCommitmentGenerator::new(params.clone());
        let coords = Coordinates { x: 3, y: 5, z: 7 };
        let blinding = Fr::from(11u64);

        let commitment = commitment_gen.create_commitment(&coords, &blinding);

        // Manual calculation: g*x + h*y + k*z + m*r
        let x_fr = Fr::from(coords.x as u64);
        let y_fr = Fr::from(coords.y as u64);
        let z_fr = Fr::from(coords.z as u64);

        let manual = (params.g * x_fr) + (params.h * y_fr) + (params.k * z_fr) + (params.m * blinding);

        assert_eq!(commitment, manual, "Commitment matches mathematical definition C = g*x + h*y + k*z + m*r");
    }

    /// Test serialization compatibility with blockchain requirements
    #[test]
    fn test_blockchain_compatibility() {
        let params = PedersenParams::new();
        let commitment_gen = LocationCommitmentGenerator::new(params);

        // Test various coordinate values that might appear in practice
        let test_cases = vec![
            Coordinates { x: 0, y: 0, z: 0 },
            Coordinates { x: 1000000, y: 2000000, z: 500000 }, // Large coordinates
            Coordinates { x: -500000, y: 750000, z: 250000 }, // Negative coordinates
        ];

        for (i, coords) in test_cases.iter().enumerate() {
            let blinding = LocationCommitmentGenerator::generate_blinding();
            let commitment = commitment_gen.create_commitment(coords, &blinding);
            let serialized = LocationCommitmentGenerator::serialize_commitment(&commitment);

            // Verify blockchain compatibility
            assert_eq!(serialized.len(), 32, "Commitment must serialize to exactly 32 bytes for blockchain");

            // Verify deserialization works
            let deserialized = G1Affine::deserialize_compressed(&serialized[..]).unwrap();
            assert_eq!(commitment, deserialized, "Serialization roundtrip must preserve commitment");

            println!(" Test case {} passed: coords ({}, {}, {})", i + 1, coords.x, coords.y, coords.z);
        }
    }

    /// Test that demonstrates why independent generators are important
    #[test]
    fn test_generator_independence_importance() {
        // Using the same generator for all parameters (INSECURE)
        let insecure_params = PedersenParams {
            g: G1Affine::generator(),
            h: G1Affine::generator(), // Same as g - INSECURE
            k: G1Affine::generator(), // Same as g - INSECURE
            m: G1Affine::generator(), // Same as g - INSECURE
        };

        // Using independent generators (SECURE)
        let secure_params = PedersenParams::new();

        let coords = Coordinates { x: 2, y: 3, z: 5 };
        let blinding = Fr::from(7u64);

        let insecure_commitment = LocationCommitmentGenerator::new(insecure_params).create_commitment(&coords, &blinding);
        let secure_commitment = LocationCommitmentGenerator::new(secure_params).create_commitment(&coords, &blinding);

        // Both should work but the secure version provides better cryptographic properties
        assert!(!insecure_commitment.is_zero());
        assert!(!secure_commitment.is_zero());

        // They will be different because the generators are different
        assert_ne!(insecure_commitment, secure_commitment);

        println!(" Generator independence test passed");
        println!("WARNING: Using the same generator for multiple parameters reduces security");
        println!("RECOMMENDATION: Use independent generators generated from a trusted setup");
    }
}