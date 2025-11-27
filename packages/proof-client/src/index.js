import { SuiClient, getFullnodeUrl } from '@mysten/sui.js/client';
import { Ed25519Keypair } from '@mysten/sui.js/keypairs/ed25519';
import { TransactionBlock } from '@mysten/sui.js/transactions';
import { fromB64 } from '@mysten/sui.js/utils';
import { config } from 'dotenv';

config();

// ============================================================================
// Configuration
// ============================================================================

const API_SERVER_URL = process.env.API_SERVER_URL || 'http://127.0.0.1:3000';
const SUI_NETWORK = process.env.SUI_NETWORK || 'local';
const PRIVATE_KEY = process.env.PRIVATE_KEY || '';

// ============================================================================
// ProofClient Class
// ============================================================================

export class ProofClient {
    constructor() {
        this.apiUrl = API_SERVER_URL;
        this.suiClient = new SuiClient({ url: getFullnodeUrl(SUI_NETWORK) });
        
        // Initialize keypair from env
        if (PRIVATE_KEY) {
            const keyPair = Ed25519Keypair.fromSecretKey(fromB64(PRIVATE_KEY));
            this.signer = keyPair;
            this.address = keyPair.getPublicKey().toSuiAddress();
        }
    }

    /**
     * Get server info including commitment details
     */
    async getServerInfo() {
        const response = await fetch(`${this.apiUrl}/api/info`);
        if (!response.ok) {
            throw new Error(`Server info failed: ${response.statusText}`);
        }
        return await response.json();
    }

    /**
     * Request proof generation from server
     */
    async generateProof(playerCoords, maxDistanceKm = 10.0) {
        console.log('🔐 Requesting proof from server...');
        console.log(`   Player coordinates: (${playerCoords.x}, ${playerCoords.y}, ${playerCoords.z})`);
        console.log(`   Max distance: ${maxDistanceKm}km`);

        const response = await fetch(`${this.apiUrl}/api/generate-proof`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                player_x: playerCoords.x.toString(),
                player_y: playerCoords.y.toString(),
                player_z: playerCoords.z.toString(),
                max_distance_km: maxDistanceKm,
            }),
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(`Proof generation failed: ${error.error || response.statusText}`);
        }

        const data = await response.json();
        console.log('✅ Proof generated successfully');
        console.log(`   Proof size: ${Math.floor(data.proof_bytes.length / 2)} bytes`);
        console.log(`   Public inputs size: ${Math.floor(data.public_inputs.length / 2)} bytes`);
        
        return data;
    }

    /**
     * Verify proof on-chain
     */
    async verifyProofOnChain(proofData, packageId, commitmentId, verifyingKeyId) {
        if (!this.signer) {
            throw new Error('No signer configured. Set PRIVATE_KEY environment variable.');
        }

        console.log('📡 Submitting proof to blockchain...');
        console.log(`   Package ID: ${packageId}`);
        console.log(`   Commitment ID: ${commitmentId}`);

        const tx = new TransactionBlock();

        // Convert hex strings to Uint8Array
        const proofBytes = Array.from(Buffer.from(proofData.proof_bytes, 'hex'));
        const publicInputs = Array.from(Buffer.from(proofData.public_inputs, 'hex'));

        // Call verify_proximity_proof
        tx.moveCall({
            target: `${packageId}::proximity::verify_proximity_proof`,
            arguments: [
                tx.object(commitmentId),
                tx.object(verifyingKeyId),
                tx.pure(proofBytes),
                tx.pure(publicInputs),
            ],
        });

        // Execute transaction
        const result = await this.suiClient.signAndExecuteTransactionBlock({
            transactionBlock: tx,
            signer: this.signer,
            options: {
                showEffects: true,
                showEvents: true,
            },
        });

        console.log('✅ Proof verified on-chain!');
        console.log(`   Transaction digest: ${result.digest}`);
        console.log(`   Status: ${result.effects?.status?.status}`);

        return result;
    }

    /**
     * Run full E2E test flow
     */
    async runE2EFlow(playerCoords) {
        console.log('\n============================================');
        console.log('Location Privacy E2E Test Flow');
        console.log('============================================\n');

        try {
            // Step 1: Get server info
            console.log('Step 1: Getting server info...');
            const serverInfo = await this.getServerInfo();
            console.log('   Server status:', serverInfo.status);
            console.log('   Commitment published:', serverInfo.commitment_published);
            console.log('   Commitment bytes:', serverInfo.commitment_bytes);
            
            if (!serverInfo.commitment_published) {
                console.warn('⚠️  Commitment not yet published on-chain');
                console.log('   Run the on-chain setup first with: npm run setup:commitment');
            }

            // Step 2: Generate proof
            console.log('\nStep 2: Generating proof...');
            const proofData = await this.generateProof(playerCoords);

            // Step 3: Verify on-chain (if commitment is published)
            if (serverInfo.commitment_published && serverInfo.package_id) {
                console.log('\nStep 3: Verifying proof on-chain...');
                await this.verifyProofOnChain(
                    proofData,
                    serverInfo.package_id,
                    serverInfo.commitment_id,
                    serverInfo.verifying_key_id
                );
            } else {
                console.log('\nStep 3: Skipping on-chain verification (not yet deployed)');
                console.log('   Proof generated successfully and can be verified manually');
            }

            console.log('\n============================================');
            console.log('E2E Test Flow Complete! ✅');
            console.log('============================================\n');

            return {
                success: true,
                proofData,
                serverInfo,
            };

        } catch (error) {
            console.error('\n❌ E2E Test Flow Failed:');
            console.error('   ', error.message);
            throw error;
        }
    }
}

// ============================================================================
// Example Usage
// ============================================================================

if (import.meta.url === `file://${process.argv[1]}`) {
    const client = new ProofClient();

    // Example: Player coordinates within 10km of target
    const playerCoords = {
        x: BigInt('-23534879266777860000') + BigInt(1500),
        y: BigInt('-435314932817330200') + BigInt(1800),
        z: BigInt('-4336253132989268000') + BigInt(450),
    };

    client.runE2EFlow(playerCoords)
        .then(() => process.exit(0))
        .catch((error) => {
            console.error(error);
            process.exit(1);
        });
}
