use anyhow::{Context, Result};
use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use commitmentgen::{
    coord_to_fr, create_poseidon_commitment, generate_blinding, get_poseidon_config,
    trusted_setup, Coordinates, ProximityProver,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use tower_http::cors::CorsLayer;
use tracing::{info, warn};

#[cfg(feature = "sui-auto-publish")]
use sui_sdk::{
    SuiClient, SuiClientBuilder,
    rpc_types::{
        SuiObjectDataOptions,
        SuiTransactionBlockResponseOptions,
        SuiTransactionBlockEffectsAPI,
    },
};
#[cfg(feature = "sui-auto-publish")]
use sui_types::{base_types::{ObjectID, SuiAddress}, transaction::TransactionData};
#[cfg(feature = "sui-auto-publish")]
use sui_keys::keystore::{AccountKeystore, FileBasedKeystore};
#[cfg(feature = "sui-auto-publish")]
use shared_crypto::intent::Intent;
#[cfg(feature = "sui-auto-publish")]
use std::path::PathBuf;
#[cfg(feature = "sui-auto-publish")]
use std::str::FromStr;

// ============================================================================
// State Management
// ============================================================================

#[derive(Clone)]
pub struct AppState {
    pub prover: Arc<ProximityProver>,
    pub server_data: Arc<RwLock<ServerData>>,
}

pub struct ServerData {
    pub target_location: Coordinates,
    pub blinding: ark_bn254::Fr,
    pub commitment_bytes: Vec<u8>,
    pub verifying_key_bytes: Vec<u8>,
    pub commitment_id: Option<String>,
    pub verifying_key_id: Option<String>,
    pub package_id: Option<String>,
}

// ============================================================================
// API Request/Response Types
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct GenerateProofRequest {
    pub player_x: i128,
    pub player_y: i128,
    pub player_z: i128,
    #[serde(default = "default_max_distance")]
    pub max_distance_km: f64,
    pub signature: Option<String>, // Player's signature
    pub message: Option<String>,   // Signed message containing request details
}

fn default_max_distance() -> f64 {
    10.0
}

#[derive(Debug, Serialize)]
pub struct GenerateProofResponse {
    pub proof_bytes: String,         // hex-encoded
    pub public_inputs: String,        // hex-encoded
    pub commitment_id: Option<String>, // On-chain commitment object ID
    pub player_coordinates: PlayerCoordinates,
    pub target_info: TargetInfo,
}

#[derive(Debug, Serialize)]
pub struct PlayerCoordinates {
    pub x: i128,
    pub y: i128,
    pub z: i128,
}

#[derive(Debug, Serialize)]
pub struct TargetInfo {
    pub commitment_bytes: String, // hex-encoded
    pub max_distance_km: f64,
}

#[derive(Debug, Serialize)]
pub struct ServerInfoResponse {
    pub status: String,
    pub commitment_published: bool,
    pub commitment_id: Option<String>,
    pub package_id: Option<String>,
    pub verifying_key_id: Option<String>,
    pub commitment_bytes: String,
    pub verifying_key_bytes: String,
    pub setup_complete: bool,
}

#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
}

// ============================================================================
// Error Handling
// ============================================================================

pub struct AppError(anyhow::Error);

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        warn!("Request failed: {:?}", self.0);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": self.0.to_string()
            })),
        )
            .into_response()
    }
}

impl<E> From<E> for AppError
where
    E: Into<anyhow::Error>,
{
    fn from(err: E) -> Self {
        Self(err.into())
    }
}

// ============================================================================
// API Handlers
// ============================================================================

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "healthy".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}

async fn server_info(State(state): State<AppState>) -> Result<Json<ServerInfoResponse>, AppError> {
    let data = state.server_data.read().await;
    
    let setup_complete = data.commitment_id.is_some() && data.verifying_key_id.is_some();
    
    Ok(Json(ServerInfoResponse {
        status: if setup_complete { "ready" } else { "setup_required" }.to_string(),
        commitment_published: data.commitment_id.is_some(),
        commitment_id: data.commitment_id.clone(),
        package_id: data.package_id.clone(),
        verifying_key_id: data.verifying_key_id.clone(),
        commitment_bytes: hex::encode(&data.commitment_bytes),
        verifying_key_bytes: hex::encode(&data.verifying_key_bytes),
        setup_complete,
    }))
}

async fn generate_proof(
    State(state): State<AppState>,
    Json(req): Json<GenerateProofRequest>,
) -> Result<Json<GenerateProofResponse>, AppError> {
    info!(
        "Generating proof for player coordinates: ({}, {}, {})",
        req.player_x, req.player_y, req.player_z
    );

    let data = state.server_data.read().await;

    // Get Poseidon config
    let poseidon_config = get_poseidon_config();

    // Create player coordinates
    let player_coords = Coordinates {
        x: req.player_x,
        y: req.player_y,
        z: req.player_z,
    };

    // Generate commitment hash for the target location
    let commitment_hash = create_poseidon_commitment(
        coord_to_fr(data.target_location.x),
        coord_to_fr(data.target_location.y),
        coord_to_fr(data.target_location.z),
        data.blinding,
        &poseidon_config,
    );

    // Generate proof
    let (proof, public_inputs) = state.prover.generate_proof(
        &data.target_location,
        &data.blinding,
        &player_coords,
        &commitment_hash,
        req.max_distance_km,
    )?;

    // Serialize proof and public inputs
    let proof_bytes = ProximityProver::serialize_proof(&proof);
    let public_inputs_bytes = ProximityProver::serialize_public_inputs(&public_inputs);

    info!(
        "Proof generated successfully: {} bytes, public inputs: {} bytes",
        proof_bytes.len(),
        public_inputs_bytes.len()
    );

    Ok(Json(GenerateProofResponse {
        proof_bytes: hex::encode(proof_bytes),
        public_inputs: hex::encode(public_inputs_bytes),
        commitment_id: data.commitment_id.clone(),
        player_coordinates: PlayerCoordinates {
            x: player_coords.x,
            y: player_coords.y,
            z: player_coords.z,
        },
        target_info: TargetInfo {
            commitment_bytes: hex::encode(&data.commitment_bytes),
            max_distance_km: req.max_distance_km,
        },
    }))
}

// ============================================================================
// Server Initialization
// ============================================================================

pub async fn create_app(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/api/info", get(server_info))
        .route("/api/generate-proof", post(generate_proof))
        .layer(CorsLayer::permissive())
        .with_state(state)
}

#[cfg(feature = "sui-auto-publish")]
async fn publish_commitment_on_chain(
    sui_client: &SuiClient,
    keystore: &FileBasedKeystore,
    package_id: ObjectID,
    server_cap_id: ObjectID,
    commitment_bytes: &[u8],
    sender_address: sui_types::base_types::SuiAddress,
) -> Result<String> {
    use sui_types::programmable_transaction_builder::ProgrammableTransactionBuilder;
    use sui_types::transaction::{Argument, CallArg, ObjectArg};
    
    info!("Publishing commitment on-chain...");
    
    let mut ptb = ProgrammableTransactionBuilder::new();
    
    // Fetch ServerCap object info to get version and digest
    let server_cap_obj = sui_client
        .read_api()
        .get_object_with_options(server_cap_id, SuiObjectDataOptions::new())
        .await?;
    
    let server_cap_data = server_cap_obj
        .data
        .ok_or_else(|| anyhow::anyhow!("Could not get ServerCap object data"))?;
    
    let server_cap_ref = server_cap_data.object_ref();
    
    // Add ServerCap as input
    let server_cap_arg = ptb.obj(ObjectArg::ImmOrOwnedObject(server_cap_ref))?;
    
    // Add commitment bytes as pure input
    let commitment_arg = ptb.pure(commitment_bytes)?;
    
    // Add owner address as pure input
    let owner_arg = ptb.pure(sender_address)?;
    
    // Call create_commitment(ServerCap, vector<u8>, address)
    ptb.programmable_move_call(
        package_id,
        "proximity".parse()?,
        "create_commitment".parse()?,
        vec![],
        vec![server_cap_arg, commitment_arg, owner_arg],
    );
    
    let pt = ptb.finish();
    
    // Build transaction with gas payment
    let gas_budget = 30_000_000;
    let gas_price = sui_client.read_api().get_reference_gas_price().await?;
    
    // Get gas coins for the sender
    use sui_types::base_types::SuiAddress;
    let coins = sui_client
        .coin_read_api()
        .get_coins(SuiAddress::from(sender_address), None, None, None)
        .await?;
    
    if coins.data.is_empty() {
        anyhow::bail!("No gas coins available for address {}", sender_address);
    }
    
    // Use the first coin as gas payment
    let gas_coin = coins.data[0].object_ref();
    
    let tx_data = TransactionData::new_programmable(
        sender_address,
        vec![gas_coin],
        pt,
        gas_budget,
        gas_price,
    );
    
    // Sign and execute
    let signature = keystore.sign_secure(&sender_address, &tx_data, Intent::sui_transaction())?;
    
    let options = SuiTransactionBlockResponseOptions::new()
        .with_effects()
        .with_object_changes();
    
    let response = sui_client
        .quorum_driver_api()
        .execute_transaction_block(
            sui_types::transaction::Transaction::from_data(tx_data, vec![signature]),
            options,
            None,
        )
        .await?;
    
    // Extract created object ID (LocationCommitment)
    if let Some(effects) = &response.effects {
        for created in effects.created() {
            info!("Created commitment object: {}", created.reference.object_id);
            return Ok(created.reference.object_id.to_string());
        }
    }
    
    anyhow::bail!("No commitment object created")
}

#[cfg(feature = "sui-auto-publish")]
async fn publish_verifying_key_on_chain(
    sui_client: &SuiClient,
    keystore: &FileBasedKeystore,
    package_id: ObjectID,
    server_cap_id: ObjectID,
    vk_bytes: &[u8],
    sender_address: sui_types::base_types::SuiAddress,
) -> Result<String> {
    use sui_types::programmable_transaction_builder::ProgrammableTransactionBuilder;
    use sui_types::transaction::{Argument, CallArg, ObjectArg};
    
    info!("Publishing verifying key on-chain...");
    
    let mut ptb = ProgrammableTransactionBuilder::new();
    
    // Fetch ServerCap object info to get version and digest
    let server_cap_obj = sui_client
        .read_api()
        .get_object_with_options(server_cap_id, SuiObjectDataOptions::new())
        .await?;
    
    let server_cap_data = server_cap_obj
        .data
        .ok_or_else(|| anyhow::anyhow!("Could not get ServerCap object data"))?;
    
    let server_cap_ref = server_cap_data.object_ref();
    
    // Add ServerCap as input
    let server_cap_arg = ptb.obj(ObjectArg::ImmOrOwnedObject(server_cap_ref))?;
    
    // Add verifying key bytes as pure input
    let vk_arg = ptb.pure(vk_bytes)?;
    
    // Call init_verifying_key(ServerCap, vector<u8>)
    ptb.programmable_move_call(
        package_id,
        "proximity".parse()?,
        "init_verifying_key".parse()?,
        vec![],
        vec![server_cap_arg, vk_arg],
    );
    
    let pt = ptb.finish();
    
    // Build transaction with gas payment
    let gas_budget = 30_000_000;
    let gas_price = sui_client.read_api().get_reference_gas_price().await?;
    
    // Get gas coins for the sender
    use sui_types::base_types::SuiAddress;
    let coins = sui_client
        .coin_read_api()
        .get_coins(SuiAddress::from(sender_address), None, None, None)
        .await?;
    
    if coins.data.is_empty() {
        anyhow::bail!("No gas coins available for address {}", sender_address);
    }
    
    // Use the first coin as gas payment
    let gas_coin = coins.data[0].object_ref();
    
    let tx_data = TransactionData::new_programmable(
        sender_address,
        vec![gas_coin],
        pt,
        gas_budget,
        gas_price,
    );
    
    // Sign and execute
    let signature = keystore.sign_secure(&sender_address, &tx_data, Intent::sui_transaction())?;
    
    let options = SuiTransactionBlockResponseOptions::new()
        .with_effects()
        .with_object_changes();
    
    let response = sui_client
        .quorum_driver_api()
        .execute_transaction_block(
            sui_types::transaction::Transaction::from_data(tx_data, vec![signature]),
            options,
            None,
        )
        .await?;
    
    // Extract created object ID (VerifyingKey)
    if let Some(effects) = &response.effects {
        for created in effects.created() {
            info!("Created verifying key object: {}", created.reference.object_id);
            return Ok(created.reference.object_id.to_string());
        }
    }
    
    anyhow::bail!("No verifying key object created")
}

pub async fn initialize_server() -> Result<AppState> {
    info!("Initializing proof server...");

    // Perform trusted setup
    info!("Performing trusted setup...");
    let max_distance_squared = ark_bn254::Fr::from(100_000_000u64); // (10km)^2
    let setup_result = trusted_setup::single_party_setup(max_distance_squared)?;
    
    let prover = ProximityProver::new(setup_result.proving_key.clone());
    info!("Trusted setup complete");

    // Serialize verifying key
    use ark_serialize::CanonicalSerialize;
    let mut verifying_key_bytes = Vec::new();
    setup_result.verifying_key.serialize_compressed(&mut verifying_key_bytes)?;
    info!("Verifying key serialized: {} bytes", verifying_key_bytes.len());

    // Create example target location
    let target_location = Coordinates {
        x: -23534879266777860000i128,
        y: -435314932817330200i128,
        z: -4336253132989268000i128,
    };

    // Generate blinding factor
    let blinding = generate_blinding();
    info!("Generated blinding factor");

    // Create Poseidon commitment
    let poseidon_config = get_poseidon_config();
    let commitment_hash = create_poseidon_commitment(
        coord_to_fr(target_location.x),
        coord_to_fr(target_location.y),
        coord_to_fr(target_location.z),
        blinding,
        &poseidon_config,
    );

    // Serialize commitment
    let mut commitment_bytes = Vec::new();
    commitment_hash.serialize_compressed(&mut commitment_bytes)?;
    
    info!(
        "Generated commitment: {} bytes (hex: {})",
        commitment_bytes.len(),
        hex::encode(&commitment_bytes)
    );

    // Read package ID and ServerCap ID from environment (always available)
    let package_id_opt = std::env::var("SUI_PACKAGE_ID").ok();
    
    // Check if auto-publish is enabled via environment variables
    #[cfg(feature = "sui-auto-publish")]
    let mut commitment_id = None;
    #[cfg(feature = "sui-auto-publish")]
    let mut verifying_key_id = None;

    #[cfg(not(feature = "sui-auto-publish"))]
    let commitment_id: Option<String> = None;
    #[cfg(not(feature = "sui-auto-publish"))]
    let verifying_key_id: Option<String> = None;

    #[cfg(feature = "sui-auto-publish")]
    {
        let server_cap_str = std::env::var("SUI_SERVER_CAP_ID").ok();
        let sui_rpc_url = std::env::var("SUI_RPC_URL").unwrap_or_else(|_| "http://127.0.0.1:9000".to_string());
        let keystore_path = std::env::var("SUI_KEYSTORE_PATH")
            .unwrap_or_else(|_| dirs::home_dir().unwrap().join(".sui/sui_config/sui.keystore").to_string_lossy().to_string());

        // Attempt auto-publish if configured
        if let (Some(pkg_id), Some(cap_id)) = (package_id_opt.as_ref(), server_cap_str.as_ref()) {
            info!("Auto-publish configuration detected");
            
            match (ObjectID::from_str(&pkg_id), ObjectID::from_str(&cap_id)) {
                (Ok(package_id), Ok(server_cap_id)) => {
                    info!("Connecting to Sui RPC: {}", sui_rpc_url);
                    
                    match SuiClientBuilder::default().build(&sui_rpc_url).await {
                        Ok(sui_client) => {
                            match FileBasedKeystore::new(&PathBuf::from(&keystore_path)) {
                                Ok(keystore) => {
                                    // Use SUI_SENDER_ADDRESS if set, otherwise use active address
                                    let sender = if let Ok(sender_str) = std::env::var("SUI_SENDER_ADDRESS") {
                                        match SuiAddress::from_str(&sender_str) {
                                            Ok(addr) => {
                                                info!("Using configured sender address: {}", addr);
                                                addr
                                            }
                                            Err(e) => {
                                                warn!("Invalid SUI_SENDER_ADDRESS: {}. Using first keystore address.", e);
                                                keystore.addresses().first().copied().unwrap()
                                            }
                                        }
                                    } else {
                                        keystore.addresses().first().copied().unwrap()
                                    };
                                    
                                    info!("Using sender address: {}", sender);
                                    
                                    // Publish verifying key
                                        match publish_verifying_key_on_chain(
                                            &sui_client,
                                            &keystore,
                                            package_id,
                                            server_cap_id,
                                            &verifying_key_bytes,
                                            sender,
                                        ).await {
                                            Ok(vk_id) => {
                                                info!("✓ Verifying key published: {}", vk_id);
                                                verifying_key_id = Some(vk_id);
                                            }
                                            Err(e) => warn!("Failed to publish verifying key: {}", e),
                                        }
                                        
                                        // Publish commitment
                                        match publish_commitment_on_chain(
                                            &sui_client,
                                            &keystore,
                                            package_id,
                                            server_cap_id,
                                            &commitment_bytes,
                                            sender,
                                        ).await {
                                            Ok(comm_id) => {
                                                info!("✓ Commitment published: {}", comm_id);
                                                commitment_id = Some(comm_id);
                                            }
                                            Err(e) => warn!("Failed to publish commitment: {}", e),
                                        }
                                }
                                Err(e) => warn!("Failed to load keystore: {}", e),
                            }
                        }
                        Err(e) => warn!("Failed to connect to Sui: {}", e),
                    }
                }
                _ => warn!("Invalid Package ID or ServerCap ID format"),
            }
        } else {
            info!("Auto-publish disabled. Set SUI_PACKAGE_ID and SUI_SERVER_CAP_ID to enable.");
        }
    }

    #[cfg(not(feature = "sui-auto-publish"))]
    {
        info!("Auto-publish feature not enabled. Build with --features sui-auto-publish to enable on-chain publishing.");
    }

    let server_data = ServerData {
        target_location,
        blinding,
        commitment_bytes,
        verifying_key_bytes,
        commitment_id,
        verifying_key_id,
        package_id: package_id_opt,
    };

    Ok(AppState {
        prover: Arc::new(prover),
        server_data: Arc::new(RwLock::new(server_data)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_server_initialization() {
        let state = initialize_server().await.unwrap();
        let data = state.server_data.read().await;
        assert_eq!(data.commitment_bytes.len(), 32);
        assert!(data.verifying_key_bytes.len() > 0);
    }
}
