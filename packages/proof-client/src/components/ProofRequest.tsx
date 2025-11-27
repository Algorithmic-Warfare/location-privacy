import React, { useState } from "react";
import { useWallet } from "../contexts/WalletContext";
import { Button } from "../components/ui/Button";
import { useSignPersonalMessage } from "@mysten/dapp-kit";

interface ProofResponse {
  proof_bytes: string;
  public_inputs: string;
  commitment_id: string | null;
  player_coordinates: {
    x: number;
    y: number;
    z: number;
  };
  target_info: {
    commitment_bytes: string;
    max_distance_km: number;
  };
}

const PROOF_SERVER_URL = import.meta.env.VITE_PROOF_SERVER_URL || "http://localhost:3001";

interface ProofRequestProps {
  onProofGenerated?: (data: {
    proof_bytes: string;
    public_inputs: string;
    commitment_id: string | null;
  }) => void;
}

export const ProofRequest: React.FC<ProofRequestProps> = ({ onProofGenerated }) => {
  const { isConnected, info } = useWallet();
  const { mutateAsync: signMessage } = useSignPersonalMessage();
  
  const [playerX, setPlayerX] = useState("-23534879266777860000");
  const [playerY, setPlayerY] = useState("-435314932817330200");
  const [playerZ, setPlayerZ] = useState("-4336253132989268000");
  const [maxDistance, setMaxDistance] = useState("10");
  
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [proofResponse, setProofResponse] = useState<ProofResponse | null>(null);

  const handleRequestProof = async () => {
    if (!isConnected || !info.address) {
      setError("Please connect your wallet first");
      return;
    }

    setLoading(true);
    setError(null);
    setProofResponse(null);

    try {
      // Create message to sign with player coordinates
      const message = JSON.stringify({
        player_x: playerX,
        player_y: playerY,
        player_z: playerZ,
        max_distance_km: parseFloat(maxDistance),
        timestamp: Date.now(),
        address: info.address,
      });

      // Sign the message
      const { signature } = await signMessage({
        message: new TextEncoder().encode(message),
      });

      // Request proof from server
      const response = await fetch(`${PROOF_SERVER_URL}/api/generate-proof`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          player_x: parseInt(playerX),
          player_y: parseInt(playerY),
          player_z: parseInt(playerZ),
          max_distance_km: parseFloat(maxDistance),
          signature: signature,
          message: message,
        }),
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || "Failed to generate proof");
      }

      const data: ProofResponse = await response.json();
      setProofResponse(data);
      
      // Auto-transmit proof data to the verify tab
      if (onProofGenerated) {
        onProofGenerated({
          proof_bytes: data.proof_bytes,
          public_inputs: data.public_inputs,
          commitment_id: data.commitment_id,
        });
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown error occurred");
    } finally {
      setLoading(false);
    }
  };

  if (!isConnected) {
    return null;
  }

  return (
    <div className="w-full max-w-2xl mx-auto p-6 space-y-6">
      <div className="bg-gray-900 rounded-lg border border-gray-700 p-6 space-y-4">
        <h2 className="text-xl font-bold text-white">Request Proximity Proof</h2>
        
        <div className="space-y-3">
          <div>
            <label className="block text-sm text-gray-400 mb-1">Player X Coordinate</label>
            <input
              type="text"
              value={playerX}
              onChange={(e) => setPlayerX(e.target.value)}
              className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded text-white"
              placeholder="Enter X coordinate"
            />
          </div>
          
          <div>
            <label className="block text-sm text-gray-400 mb-1">Player Y Coordinate</label>
            <input
              type="text"
              value={playerY}
              onChange={(e) => setPlayerY(e.target.value)}
              className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded text-white"
              placeholder="Enter Y coordinate"
            />
          </div>
          
          <div>
            <label className="block text-sm text-gray-400 mb-1">Player Z Coordinate</label>
            <input
              type="text"
              value={playerZ}
              onChange={(e) => setPlayerZ(e.target.value)}
              className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded text-white"
              placeholder="Enter Z coordinate"
            />
          </div>
          
          <div>
            <label className="block text-sm text-gray-400 mb-1">Max Distance (km)</label>
            <input
              type="text"
              value={maxDistance}
              onChange={(e) => setMaxDistance(e.target.value)}
              className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded text-white"
              placeholder="Maximum distance in kilometers"
            />
          </div>
        </div>

        <Button
          onClick={handleRequestProof}
          disabled={loading}
          className="w-full"
        >
          {loading ? "Generating Proof..." : "Request Proof"}
        </Button>

        {error && (
          <div className="p-3 bg-red-900/50 border border-red-700 rounded text-red-200 text-sm">
            {error}
          </div>
        )}
      </div>

      {proofResponse && (
        <div className="bg-gray-900 rounded-lg border border-gray-700 p-6 space-y-4">
          <h3 className="text-lg font-bold text-green-400">✓ Proof Generated Successfully</h3>
          
          <div className="space-y-2 text-sm">
            <div>
              <span className="text-gray-400">Commitment ID:</span>
              <div className="text-white font-mono text-xs break-all bg-gray-800 p-2 rounded mt-1">
                {proofResponse.commitment_id || "Not published yet"}
              </div>
            </div>
            
            <div>
              <span className="text-gray-400">Proof Bytes ({proofResponse.proof_bytes.length / 2} bytes):</span>
              <div className="text-white font-mono text-xs break-all bg-gray-800 p-2 rounded mt-1 max-h-24 overflow-auto">
                {proofResponse.proof_bytes}
              </div>
            </div>
            
            <div>
              <span className="text-gray-400">Public Inputs ({proofResponse.public_inputs.length / 2} bytes):</span>
              <div className="text-white font-mono text-xs break-all bg-gray-800 p-2 rounded mt-1 max-h-24 overflow-auto">
                {proofResponse.public_inputs}
              </div>
            </div>
            
            <div>
              <span className="text-gray-400">Max Distance:</span>
              <span className="text-white ml-2">{proofResponse.target_info.max_distance_km} km</span>
            </div>
          </div>

          <div className="text-xs text-gray-500 pt-2 border-t border-gray-800">
            You can now submit this proof on-chain to verify proximity without revealing your exact location.
          </div>
        </div>
      )}
    </div>
  );
};
