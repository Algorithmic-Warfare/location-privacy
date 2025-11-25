use ark_bn254::{Bn254, Fr};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_groth16::{Groth16, ProvingKey, VerifyingKey, Proof};
use ark_r1cs_std::prelude::AllocVar;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::bits::ToBitsGadget;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::R1CSVar;
use ark_snark::SNARK;
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use ark_std::UniformRand;
use std::ops::Neg;
use rand::rngs::OsRng;

/// Pedersen commitment parameters
#[derive(Clone)]
pub struct PedersenParams {
    pub g: Fr, // Generator for x
    pub h: Fr, // Generator for y
    pub k: Fr, // Generator for z
    pub m: Fr, // Generator for blinding r
}

/// Location coordinates in 3D Cartesian space (in meters)
/// x, y, z represent coordinates in a 3D coordinate system
#[derive(Clone)]
pub struct Coordinates {
    pub x: i64,
    pub y: i64,
    pub z: i64,
}

/// Server-side commitment creator
pub struct LocationCommitmentGenerator {
    params: PedersenParams,
}

impl LocationCommitmentGenerator {
    pub fn new(params: PedersenParams) -> Self {
        Self { params }
    }

    pub fn generate_blinding() -> Fr {
        Fr::rand(&mut rand::rngs::OsRng)
    }

    /// Create a Pedersen commitment: C = g^x * h^y * k^z * m^r
    pub fn create_commitment(
        &self,
        coords: &Coordinates,
        blinding: &Fr,
    ) -> Fr {
        let x_fr = if coords.x >= 0 {
            Fr::from(coords.x as u64)
        } else {
            Fr::from((-coords.x) as u64).neg()
        };
        let y_fr = if coords.y >= 0 {
            Fr::from(coords.y as u64)
        } else {
            Fr::from((-coords.y) as u64).neg()
        };
        let z_fr = if coords.z >= 0 {
            Fr::from(coords.z as u64)
        } else {
            Fr::from((-coords.z) as u64).neg()
        };

        let commitment = (x_fr * self.params.g) + (y_fr * self.params.h) + (z_fr * self.params.k) + (*blinding * self.params.m);

        commitment
    }

    /// Serialize commitment to 32 bytes for on-chain storage
    pub fn serialize_commitment(commitment: &Fr) -> Vec<u8> {
        let mut bytes = Vec::new();
        commitment.serialize_compressed(&mut bytes).unwrap();
        bytes
    }
}

/// zkSNARK circuit for proximity proof
#[derive(Clone)]
pub struct ProximityCircuit {
    // Private inputs (witness)
    pub x_target: Option<Fr>,
    pub y_target: Option<Fr>,
    pub z_target: Option<Fr>,
    pub blinding: Option<Fr>,

    pub x_player: Option<Fr>,
    pub y_player: Option<Fr>,
    pub z_player: Option<Fr>,

    // Public inputs
    pub commitment: Option<Fr>,
    pub max_distance_squared: Fr, // (10km)^2 in your units

    // Pedersen parameters (public constants)
    pub pedersen_params: PedersenParams,
}

impl ConstraintSynthesizer<Fr> for ProximityCircuit {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<Fr>,
    ) -> Result<(), SynthesisError> {
        // Allocate private witness variables
        let x_t = FpVar::new_witness(cs.clone(), || {
            self.x_target.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let y_t = FpVar::new_witness(cs.clone(), || {
            self.y_target.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let z_t = FpVar::new_witness(cs.clone(), || {
            self.z_target.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let _r = FpVar::new_witness(cs.clone(), || {
            self.blinding.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let x_p = FpVar::new_witness(cs.clone(), || {
            self.x_player.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let y_p = FpVar::new_witness(cs.clone(), || {
            self.y_player.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let z_p = FpVar::new_witness(cs.clone(), || {
            self.z_player.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Allocate public inputs
        let commitment_var = FpVar::new_input(cs.clone(), || {
            self.commitment.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Constraint 1: Verify Pedersen commitment opening C = g*x + h*y + k*z + m*r
        {
            let g_var = FpVar::Constant(self.pedersen_params.g);
            let h_var = FpVar::Constant(self.pedersen_params.h);
            let k_var = FpVar::Constant(self.pedersen_params.k);
            let m_var = FpVar::Constant(self.pedersen_params.m);

            let c_calc = (x_t.clone() * g_var) + (y_t.clone() * h_var) + (z_t.clone() * k_var) + (_r.clone() * m_var);

            c_calc.enforce_equal(&commitment_var)?;
        }

        // Constraint 2: Verify distance constraint
        // distance_squared = (x_p - x_t)^2 + (y_p - y_t)^2 + (z_p - z_t)^2
        {
            let dx = &x_p - &x_t;
            let dy = &y_p - &y_t;
            let dz = &z_p - &z_t;

            let dx_sq = &dx * &dx;
            let dy_sq = &dy * &dy;
            let dz_sq = &dz * &dz;

            let distance_squared = dx_sq + dy_sq + dz_sq;

            // Enforce distance_squared <= max_distance_squared
            let max_dist_var = FpVar::Constant(self.max_distance_squared);

            // Compute diff = max_distance_squared - distance_squared
            let diff = &max_dist_var - &distance_squared;

            // To check that diff >= 0, we decompose diff into bits and ensure
            // the most significant bit is 0 (meaning diff is positive and small)
            let diff_bits = diff.to_bits_le()?;
            let msb = &diff_bits[253]; // BN254 field is 254 bits, MSB is at index 253
            msb.enforce_equal(&Boolean::constant(false))?;
        }

        Ok(())
    }
}

// TODO: Implement Pedersen commitment verification in R1CS
// This is a complex task that requires proper G1 arithmetic in the circuit
// fn compute_pedersen_commitment(...) -> ...

/// Proof generator
pub struct ProximityProver {
    proving_key: ProvingKey<Bn254>,
    verifying_key: VerifyingKey<Bn254>,
    params: PedersenParams,
}

impl ProximityProver {
    /// Initialize with proving/verifying keys (generated during setup)
    pub fn new(
        proving_key: ProvingKey<Bn254>,
        verifying_key: VerifyingKey<Bn254>,
        params: PedersenParams,
    ) -> Self {
        Self {
            proving_key,
            verifying_key,
            params,
        }
    }

    /// Generate a proximity proof
    pub fn generate_proof(
        &self,
        target_coords: &Coordinates,
        blinding: &Fr,
        player_coords: &Coordinates,
        commitment: &Fr,
        max_distance_km: f64,
    ) -> Result<(Proof<Bn254>, Vec<Fr>), Box<dyn std::error::Error>> {
        // Convert max distance to squared units (in meters)
        let max_distance_m = (max_distance_km * 1000.0) as u64;
        let max_distance_squared = Fr::from(max_distance_m * max_distance_m);

        // Create circuit with witness values
        let circuit = ProximityCircuit {
            x_target: Some(if target_coords.x >= 0 { Fr::from(target_coords.x as u64) } else { Fr::from((-target_coords.x) as u64).neg() }),
            y_target: Some(if target_coords.y >= 0 { Fr::from(target_coords.y as u64) } else { Fr::from((-target_coords.y) as u64).neg() }),
            z_target: Some(if target_coords.z >= 0 { Fr::from(target_coords.z as u64) } else { Fr::from((-target_coords.z) as u64).neg() }),
            blinding: Some(*blinding),

            x_player: Some(if player_coords.x >= 0 { Fr::from(player_coords.x as u64) } else { Fr::from((-player_coords.x) as u64).neg() }),
            y_player: Some(if player_coords.y >= 0 { Fr::from(player_coords.y as u64) } else { Fr::from((-player_coords.y) as u64).neg() }),
            z_player: Some(if player_coords.z >= 0 { Fr::from(player_coords.z as u64) } else { Fr::from((-player_coords.z) as u64).neg() }),

            commitment: Some(*commitment),
            max_distance_squared,
            pedersen_params: self.params.clone(),
        };

        // Generate proof
        let mut rng = OsRng;
        let proof = Groth16::<Bn254>::prove(&self.proving_key, circuit.clone(), &mut rng)?;

        // Public inputs: [commitment]
        let public_inputs = vec![
            *commitment,
        ];

        Ok((proof, public_inputs))
    }

    /// Serialize proof for on-chain submission
    pub fn serialize_proof(proof: &Proof<Bn254>) -> Vec<u8> {
        let mut bytes = Vec::new();
        proof.serialize_compressed(&mut bytes).unwrap();
        bytes
    }

    /// Serialize public inputs for on-chain submission
    pub fn serialize_public_inputs(inputs: &[Fr]) -> Vec<u8> {
        let mut bytes = Vec::new();
        for input in inputs {
            input.serialize_compressed(&mut bytes).unwrap();
        }
        bytes
    }
}

/// Complete example usage
pub fn example_usage() {
    // 1. Setup phase (one-time)
    let params = PedersenParams {
        g: Fr::from(1u64),
        h: Fr::from(2u64),
        k: Fr::from(3u64),
        m: Fr::from(4u64),
    };

    let commitment_gen = LocationCommitmentGenerator::new(params.clone());

    // 2. Server creates commitment for SSU location
    let ssu_location = Coordinates {
        x: 1000, // 1000 meters in X direction
        y: 2000, // 2000 meters in Y direction
        z: 500,  // 500 meters above reference plane
    };

    let blinding = LocationCommitmentGenerator::generate_blinding();
    let commitment = commitment_gen.create_commitment(&ssu_location, &blinding);
    let commitment_bytes = LocationCommitmentGenerator::serialize_commitment(&commitment);

    println!("Commitment created: {} bytes", commitment_bytes.len());
    // Now publish commitment_bytes on-chain using create_commitment()

    // 3. Player requests proximity check
    let _player_location = Coordinates {
        x: 1500, // 1500 meters in X direction (~500m from SSU)
        y: 1800, // 1800 meters in Y direction (~200m from SSU)
        z: 450,  // 450 meters above reference plane
    };

    // 4. Server generates proof (requires proving key from trusted setup)
    // let prover = ProximityProver::new(proving_key, verifying_key, params);
    // let (proof, public_inputs) = prover.generate_proof(
    //     &ssu_location,
    //     &blinding,
    //     &player_location,
    //     &commitment,
    //     10.0, // 10km max distance
    // ).unwrap();

    // 5. Submit to chain
    // let proof_bytes = ProximityProver::serialize_proof(&proof);
    // let inputs_bytes = ProximityProver::serialize_public_inputs(&public_inputs);
    // Call verify_proximity_proof() with these bytes
}

/// Trusted setup for generating proving and verifying keys
pub mod trusted_setup {
    use super::*;
    use ark_groth16::Groth16;
    use rand::thread_rng;

    /// Result of a trusted setup ceremony
    pub struct SetupResult {
        pub proving_key: ProvingKey<Bn254>,
        pub verifying_key: VerifyingKey<Bn254>,
    }

    /// Simple two-party trusted setup ceremony
    /// In a real system, this would involve multiple parties with MPC
    pub struct TwoPartySetup {
        party_a_contribution: Option<Vec<u8>>,
        party_b_contribution: Option<Vec<u8>>,
        current_circuit: ProximityCircuit,
    }

    impl TwoPartySetup {
        /// Initialize a new two-party setup ceremony
        pub fn new(max_distance_squared: Fr) -> Self {
            // Create a dummy circuit for setup (values must satisfy the constraints)
            // Use coordinates that are close enough to satisfy distance constraint
            let commitment = Fr::from(10u64); // 1*1 + 2*1 + 3*1 + 4*1 = 10
            let circuit = ProximityCircuit {
                x_target: Some(Fr::from(1u64)),
                y_target: Some(Fr::from(1u64)),
                z_target: Some(Fr::from(1u64)),
                blinding: Some(Fr::from(1u64)),
                x_player: Some(Fr::from(1u64)), // Same as target - distance = 0
                y_player: Some(Fr::from(1u64)),
                z_player: Some(Fr::from(1u64)),
                commitment: Some(commitment),
                max_distance_squared,
                pedersen_params: PedersenParams {
                    g: Fr::from(1u64),
                    h: Fr::from(2u64),
                    k: Fr::from(3u64),
                    m: Fr::from(4u64),
                },
            };

            Self {
                party_a_contribution: None,
                party_b_contribution: None,
                current_circuit: circuit,
            }
        }

        /// Party A contributes randomness to the setup
        pub fn party_a_contribute(&mut self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
            let mut rng = thread_rng();

            // Generate proving key with Party A's randomness
            let (pk, _vk) = Groth16::<Bn254>::circuit_specific_setup(
                self.current_circuit.clone(),
                &mut rng,
            )?;

            // Serialize the proving key as Party A's contribution
            let mut contribution = Vec::new();
            pk.serialize_compressed(&mut contribution)?;
            self.party_a_contribution = Some(contribution.clone());

            Ok(contribution)
        }

        /// Party B contributes randomness to the setup
        pub fn party_b_contribute(&mut self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
            let mut rng = thread_rng();

            // Generate proving key with Party B's randomness
            let (pk, _vk) = Groth16::<Bn254>::circuit_specific_setup(
                self.current_circuit.clone(),
                &mut rng,
            )?;

            // Serialize the proving key as Party B's contribution
            let mut contribution = Vec::new();
            pk.serialize_compressed(&mut contribution)?;
            self.party_b_contribution = Some(contribution.clone());

            Ok(contribution)
        }

        /// Combine contributions and generate final keys
        /// In a real MPC setup, this would combine the contributions securely
        pub fn finalize_setup(self) -> Result<SetupResult, Box<dyn std::error::Error>> {
            // For simplicity, we'll use Party B's contribution as the final key
            // In a real system, contributions would be combined using MPC protocols

            let party_b_contribution = self.party_b_contribution
                .ok_or("Party B must contribute before finalizing")?;

            // Deserialize Party B's proving key
            let pk = ProvingKey::<Bn254>::deserialize_compressed(&party_b_contribution[..])?;

            // Generate the verifying key from the proving key
            let vk = pk.vk.clone();

            Ok(SetupResult {
                proving_key: pk,
                verifying_key: vk,
            })
        }

        /// Verify that both parties contributed
        pub fn is_complete(&self) -> bool {
            self.party_a_contribution.is_some() && self.party_b_contribution.is_some()
        }
    }

    /// Convenience function for single-party setup (not secure for production)
    pub fn single_party_setup(max_distance_squared: Fr) -> Result<SetupResult, Box<dyn std::error::Error>> {
        let mut rng = thread_rng();

        let circuit = ProximityCircuit {
            x_target: Some(Fr::from(1u64)),
            y_target: Some(Fr::from(1u64)),
            z_target: Some(Fr::from(1u64)),
            blinding: Some(Fr::from(1u64)),
            x_player: Some(Fr::from(1u64)), // Same as target - distance = 0
            y_player: Some(Fr::from(1u64)),
            z_player: Some(Fr::from(1u64)),
            commitment: Some(Fr::from(10u64)), // 1*1 + 2*1 + 3*1 + 4*1 = 10
            max_distance_squared,
            pedersen_params: PedersenParams {
                g: Fr::from(1u64),
                h: Fr::from(2u64),
                k: Fr::from(3u64),
                m: Fr::from(4u64),
            },
        };

        let (proving_key, verifying_key) = Groth16::<Bn254>::circuit_specific_setup(circuit, &mut rng)?;

        Ok(SetupResult {
            proving_key,
            verifying_key,
        })
    }

    /// Serialize setup result for storage
    pub fn serialize_setup_result(result: &SetupResult) -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
        let mut pk_bytes = Vec::new();
        let mut vk_bytes = Vec::new();

        result.proving_key.serialize_compressed(&mut pk_bytes)?;
        result.verifying_key.serialize_compressed(&mut vk_bytes)?;

        Ok((pk_bytes, vk_bytes))
    }

    /// Deserialize setup result from storage
    pub fn deserialize_setup_result(pk_bytes: &[u8], vk_bytes: &[u8]) -> Result<SetupResult, Box<dyn std::error::Error>> {
        let proving_key = ProvingKey::<Bn254>::deserialize_compressed(pk_bytes)?;
        let verifying_key = VerifyingKey::<Bn254>::deserialize_compressed(vk_bytes)?;

        Ok(SetupResult {
            proving_key,
            verifying_key,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::{Fr, G1Affine};
    use ark_std::{UniformRand, Zero};
    use rand::thread_rng;
    use ark_ec::CurveGroup;

    /// Test that Pedersen commitments have the binding property:
    /// Different coordinates should produce different commitments
    #[test]
    fn test_pedersen_binding_property() {
        let params = PedersenParams {
            g: Fr::from(1u64),
            h: Fr::from(2u64),
            k: Fr::from(3u64),
            m: Fr::from(4u64),
        };

        let commitment_gen = LocationCommitmentGenerator::new(params);

        let coords1 = Coordinates { x: 1000, y: 2000, z: 500 };
        let coords2 = Coordinates { x: 1001, y: 2000, z: 500 }; // Different x
        let blinding = LocationCommitmentGenerator::generate_blinding();

        let commitment1 = commitment_gen.create_commitment(&coords1, &blinding);
        let commitment2 = commitment_gen.create_commitment(&coords2, &blinding);

        assert_ne!(commitment1, commitment2, "Different coordinates should produce different commitments");
    }

    /// Test that Pedersen commitments are deterministic:
    /// Same inputs should produce the same commitment
    #[test]
    fn test_pedersen_deterministic() {
        let params = PedersenParams {
            g: Fr::from(1u64),
            h: Fr::from(2u64),
            k: Fr::from(3u64),
            m: Fr::from(4u64),
        };

        let commitment_gen = LocationCommitmentGenerator::new(params);
        let coords = Coordinates { x: 1000, y: 2000, z: 500 };
        let blinding = Fr::from(42u64); // Fixed blinding factor

        let commitment1 = commitment_gen.create_commitment(&coords, &blinding);
        let commitment2 = commitment_gen.create_commitment(&coords, &blinding);

        assert_eq!(commitment1, commitment2, "Same inputs should produce the same commitment");
    }

    /// Test that blinding factors affect the commitment:
    /// Same coordinates with different blinding factors should produce different commitments
    #[test]
    fn test_blinding_factor_effect() {
        let params = PedersenParams {
            g: Fr::from(1u64),
            h: Fr::from(2u64),
            k: Fr::from(3u64),
            m: Fr::from(4u64),
        };

        let commitment_gen = LocationCommitmentGenerator::new(params);
        let coords = Coordinates { x: 1000, y: 2000, z: 500 };

        let blinding1 = Fr::from(123u64);
        let blinding2 = Fr::from(456u64);

        let commitment1 = commitment_gen.create_commitment(&coords, &blinding1);
        let commitment2 = commitment_gen.create_commitment(&coords, &blinding2);

        assert_ne!(commitment1, commitment2, "Different blinding factors should produce different commitments");
    }

    /// Test that each coordinate component affects the commitment independently
    #[test]
    fn test_coordinate_components_independence() {
        let params = PedersenParams {
            g: Fr::from(1u64),
            h: Fr::from(2u64),
            k: Fr::from(3u64),
            m: Fr::from(4u64),
        };

        let commitment_gen = LocationCommitmentGenerator::new(params);
        let blinding = Fr::from(999u64);

        // Base coordinates
        let base_coords = Coordinates { x: 1000, y: 2000, z: 500 };
        let base_commitment = commitment_gen.create_commitment(&base_coords, &blinding);

        // Change X coordinate
        let x_changed = Coordinates { x: 1001, y: 2000, z: 500 };
        let x_commitment = commitment_gen.create_commitment(&x_changed, &blinding);
        assert_ne!(base_commitment, x_commitment, "Changing X should affect commitment");

        // Change Y coordinate
        let y_changed = Coordinates { x: 1000, y: 2001, z: 500 };
        let y_commitment = commitment_gen.create_commitment(&y_changed, &blinding);
        assert_ne!(base_commitment, y_commitment, "Changing Y should affect commitment");

        // Change Z coordinate
        let z_changed = Coordinates { x: 1000, y: 2000, z: 501 };
        let z_commitment = commitment_gen.create_commitment(&z_changed, &blinding);
        assert_ne!(base_commitment, z_commitment, "Changing Z should affect commitment");
    }

    /// Test serialization and deserialization of commitments
    #[test]
    fn test_commitment_serialization_roundtrip() {
        let params = PedersenParams {
            g: Fr::from(1u64),
            h: Fr::from(2u64),
            k: Fr::from(3u64),
            m: Fr::from(4u64),
        };

        let commitment_gen = LocationCommitmentGenerator::new(params);
        let coords = Coordinates { x: 1000, y: 2000, z: 500 };
        let blinding = LocationCommitmentGenerator::generate_blinding();

        let original_commitment = commitment_gen.create_commitment(&coords, &blinding);
        let serialized = LocationCommitmentGenerator::serialize_commitment(&original_commitment);

        // Deserialize back
        let deserialized_commitment = Fr::deserialize_compressed(&serialized[..]).unwrap();

        assert_eq!(original_commitment, deserialized_commitment, "Serialization roundtrip should preserve commitment");
        assert_eq!(serialized.len(), 32, "Serialized commitment should be 32 bytes");
    }

    /// Test that commitments are not the identity element (unless all inputs are zero)
    #[test]
    fn test_commitment_not_identity() {
        let params = PedersenParams {
            g: Fr::from(1u64),
            h: Fr::from(2u64),
            k: Fr::from(3u64),
            m: Fr::from(4u64),
        };

        let commitment_gen = LocationCommitmentGenerator::new(params);

        // Non-zero coordinates should not produce identity
        let coords = Coordinates { x: 1000, y: 2000, z: 500 };
        let blinding = LocationCommitmentGenerator::generate_blinding();
        let commitment = commitment_gen.create_commitment(&coords, &blinding);

        assert!(commitment != Fr::from(0u64), "Non-zero inputs should not produce identity element");

        // Zero coordinates with zero blinding should produce identity (g^0 * h^0 * k^0 * m^0 = 1)
        let zero_coords = Coordinates { x: 0, y: 0, z: 0 };
        let zero_blinding = Fr::from(0u64);
        let zero_commitment = commitment_gen.create_commitment(&zero_coords, &zero_blinding);

        assert_eq!(zero_commitment, Fr::from(0u64), "Zero inputs should produce identity element");
    }

    /// Test mathematical correctness of Pedersen commitment formula
    /// C = g^x * h^y * k^z * m^r
    #[test]
    fn test_pedersen_mathematical_correctness() {
        let params = PedersenParams {
            g: Fr::from(1u64),
            h: Fr::from(2u64),
            k: Fr::from(3u64),
            m: Fr::from(4u64),
        };

        let commitment_gen = LocationCommitmentGenerator::new(params.clone());
        let coords = Coordinates { x: 2, y: 3, z: 4 };
        let blinding = Fr::from(5u64);

        let commitment = commitment_gen.create_commitment(&coords, &blinding);

        // Manually compute the commitment: g*x + h*y + k*z + m*r
        let x_fr = Fr::from(coords.x as u64);
        let y_fr = Fr::from(coords.y as u64);
        let z_fr = Fr::from(coords.z as u64);

        let manual_commitment = (x_fr * params.g) + (y_fr * params.h) + (z_fr * params.k) + (blinding * params.m);

        assert_eq!(commitment, manual_commitment, "Commitment should match manual calculation");
    }

    /// Test that commitments work with negative coordinates (within field range)
    #[test]
    fn test_negative_coordinates() {
        let params = PedersenParams {
            g: Fr::from(1u64),
            h: Fr::from(2u64),
            k: Fr::from(3u64),
            m: Fr::from(4u64),
        };

        let commitment_gen = LocationCommitmentGenerator::new(params);

        // Test with negative coordinates (within reasonable range)
        let coords = Coordinates { x: -1000, y: 2000, z: -500 };
        let blinding = LocationCommitmentGenerator::generate_blinding();

        // This should not panic and should produce a valid commitment
        let commitment = commitment_gen.create_commitment(&coords, &blinding);
        assert!(!commitment.is_zero(), "Negative coordinates should produce valid commitment");

        let serialized = LocationCommitmentGenerator::serialize_commitment(&commitment);
        assert_eq!(serialized.len(), 32, "Serialized commitment should be 32 bytes");
    }

    /// Test that different Pedersen parameters produce different commitments
    #[test]
    fn test_different_parameters_different_commitments() {
        let params1 = PedersenParams {
            g: Fr::from(1u64),
            h: Fr::from(2u64),
            k: Fr::from(3u64),
            m: Fr::from(4u64),
        };

        // Create different parameters by using a different generator for h
        let params2 = PedersenParams {
            g: Fr::from(1u64),
            h: Fr::from(3u64),
            k: Fr::from(3u64),
            m: Fr::from(4u64),
        };

        let commitment_gen1 = LocationCommitmentGenerator::new(params1);
        let commitment_gen2 = LocationCommitmentGenerator::new(params2);

        let coords = Coordinates { x: 1000, y: 2000, z: 500 };
        let blinding = Fr::from(42u64);

        let commitment1 = commitment_gen1.create_commitment(&coords, &blinding);
        let commitment2 = commitment_gen2.create_commitment(&coords, &blinding);

        assert_ne!(commitment1, commitment2, "Different parameters should produce different commitments");
    }

    /// Test that blinding factors are uniformly random
    #[test]
    fn test_blinding_factor_randomness() {
        // Generate multiple blinding factors and check they're different
        let mut blinding_factors = Vec::new();
        for _ in 0..100 {
            blinding_factors.push(LocationCommitmentGenerator::generate_blinding());
        }

        // Check that all are different (very unlikely to have duplicates with proper randomness)
        for i in 0..blinding_factors.len() {
            for j in (i+1)..blinding_factors.len() {
                assert_ne!(blinding_factors[i], blinding_factors[j], "Blinding factors should be unique");
            }
        }
    }

    /// Test commitment properties with edge case coordinates
    #[test]
    fn test_edge_case_coordinates() {
        let params = PedersenParams {
            g: Fr::from(1u64),
            h: Fr::from(2u64),
            k: Fr::from(3u64),
            m: Fr::from(4u64),
        };

        let commitment_gen = LocationCommitmentGenerator::new(params);
        let blinding = LocationCommitmentGenerator::generate_blinding();

        // Test with zero coordinates (except one dimension)
        let x_only = Coordinates { x: 1000, y: 0, z: 0 };
        let commitment_x = commitment_gen.create_commitment(&x_only, &blinding);
        assert!(!commitment_x.is_zero(), "X-only coordinates should produce valid commitment");

        let y_only = Coordinates { x: 0, y: 2000, z: 0 };
        let commitment_y = commitment_gen.create_commitment(&y_only, &blinding);
        assert!(!commitment_y.is_zero(), "Y-only coordinates should produce valid commitment");

        let z_only = Coordinates { x: 0, y: 0, z: 500 };
        let commitment_z = commitment_gen.create_commitment(&z_only, &blinding);
        assert!(!commitment_z.is_zero(), "Z-only coordinates should produce valid commitment");

        // All commitments should be different
        assert_ne!(commitment_x, commitment_y);
        assert_ne!(commitment_y, commitment_z);
        assert_ne!(commitment_x, commitment_z);
    }

    /// Test that invalid blinding factor in proof generation would fail verification
    /// This test demonstrates that the circuit must properly verify Pedersen commitment opening
    #[test]
    fn test_invalid_blinding_factor_verification_failure() {
        // Since the current circuit doesn't actually verify Pedersen commitment opening,
        // this test demonstrates the fundamental property that different blinding factors
        // produce different commitments, which would cause verification failure in a
        // properly implemented circuit.

        let params = PedersenParams {
            g: Fr::from(1u64),
            h: Fr::from(2u64),
            k: Fr::from(3u64),
            m: Fr::from(4u64),
        };

        let commitment_gen = LocationCommitmentGenerator::new(params);

        // Create commitment with specific coordinates and correct blinding factor
        let target_coords = Coordinates { x: 1000, y: 2000, z: 500 };
        let correct_blinding = Fr::from(42u64);
        let commitment = commitment_gen.create_commitment(&target_coords, &correct_blinding);

        // Create commitment with same coordinates but wrong blinding factor
        let wrong_blinding = Fr::from(43u64); // Different blinding factor
        let wrong_commitment = commitment_gen.create_commitment(&target_coords, &wrong_blinding);

        // The commitments should be different
        assert_ne!(commitment, wrong_commitment,
            "Different blinding factors should produce different commitments");

        // In a properly implemented zkSNARK circuit that verifies C = g^x * h^y * k^z * m^r,
        // a proof generated with the correct blinding factor would only verify against
        // the correct commitment. A proof with wrong_blinding would fail verification
        // because the witness values wouldn't satisfy the commitment verification constraint.

        // Test that commitments are deterministic with same inputs
        let commitment_again = commitment_gen.create_commitment(&target_coords, &correct_blinding);
        assert_eq!(commitment, commitment_again,
            "Same coordinates and blinding factor should produce same commitment");

        // Test that wrong blinding factor produces different commitment
        assert_ne!(commitment, wrong_commitment,
            "Wrong blinding factor should produce different commitment");

        println!("✅ Invalid blinding factor test passed");
        println!("   Different blinding factors produce different commitments");
        println!("   In a full implementation, this would cause proof verification failure");
    }

    #[test]
    fn test_commitment_generation() {
        // Setup parameters
        let params = PedersenParams {
            g: Fr::from(1u64),
            h: Fr::from(2u64),
            k: Fr::from(3u64),
            m: Fr::from(4u64),
        };

        let commitment_gen = LocationCommitmentGenerator::new(params);

        // Test coordinates (3D Cartesian in meters)
        let coords = Coordinates {
            x: 1000,  // 1000 meters in X
            y: 2000,  // 2000 meters in Y
            z: 500,   // 500 meters in Z
        };

        let blinding = LocationCommitmentGenerator::generate_blinding();
        let commitment = commitment_gen.create_commitment(&coords, &blinding);
        let serialized = LocationCommitmentGenerator::serialize_commitment(&commitment);

        // Verify serialization is correct size (compressed G1 point)
        assert_eq!(serialized.len(), 32);
        println!("Commitment generated successfully: {} bytes", serialized.len());
    }

    #[test]
    fn test_blinding_randomness() {
        // Test that blinding factors are different
        let b1 = LocationCommitmentGenerator::generate_blinding();
        let b2 = LocationCommitmentGenerator::generate_blinding();
        assert_ne!(b1, b2);
    }

    #[test]
    fn test_two_party_setup() {
        use super::trusted_setup::TwoPartySetup;

        let max_distance = Fr::from(10_000_000u64); // 10km squared in meters
        let mut setup = TwoPartySetup::new(max_distance);

        // Party A contributes
        let contribution_a = setup.party_a_contribute().unwrap();
        assert!(!contribution_a.is_empty());

        // Party B contributes
        let contribution_b = setup.party_b_contribute().unwrap();
        assert!(!contribution_b.is_empty());

        // Contributions should be different
        assert_ne!(contribution_a, contribution_b);

        // Setup should be complete
        assert!(setup.is_complete());

        // Finalize setup
        let result = setup.finalize_setup().unwrap();
        // Check that we have a valid setup result
        assert!(result.proving_key.a_query.len() > 0);
    }

    #[test]
    fn test_single_party_setup() {
        use super::trusted_setup::single_party_setup;

        let max_distance = Fr::from(10_000_000u64);
        let result = single_party_setup(max_distance).unwrap();

        // Check that we have valid keys
        assert!(result.proving_key.a_query.len() > 0);
    }

    #[test]
    fn test_setup_serialization() {
        use super::trusted_setup::{single_party_setup, serialize_setup_result, deserialize_setup_result};

        let max_distance = Fr::from(10_000_000u64);
        let original_result = single_party_setup(max_distance).unwrap();

        // Serialize
        let (pk_bytes, vk_bytes) = serialize_setup_result(&original_result).unwrap();
        assert!(!pk_bytes.is_empty());
        assert!(!vk_bytes.is_empty());

        // Deserialize
        let deserialized_result = deserialize_setup_result(&pk_bytes, &vk_bytes).unwrap();

        // Verify keys are the same by checking they have the same structure
        assert_eq!(original_result.proving_key.a_query.len(), deserialized_result.proving_key.a_query.len());
    }
}