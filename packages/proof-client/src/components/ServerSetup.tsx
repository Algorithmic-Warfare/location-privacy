import React, { useState } from "react";
import { useWallet } from "../contexts/WalletContext";
import { Button } from "../components/ui/Button";
import { Transaction } from "@mysten/sui/transactions";
import { useSignAndExecuteTransaction } from "@mysten/dapp-kit";

interface SetupResponse {
  commitment_bytes: string;
  verifying_key_bytes?: string;
  package_id: string | null;
}

const PROOF_SERVER_URL = import.meta.env.VITE_PROOF_SERVER_URL || "http://localhost:3001";

export const ServerSetup: React.FC = () => {
  const { isConnected, info, client } = useWallet();
  const { mutateAsync: signAndExecuteTransaction } = useSignAndExecuteTransaction();
  
  const [packageId, setPackageId] = useState("");
  const [serverCapId, setServerCapId] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [status, setStatus] = useState<string | null>(null);
  const [commitmentId, setCommitmentId] = useState<string | null>(null);
  const [verifyingKeyId, setVerifyingKeyId] = useState<string | null>(null);

  const fetchServerInfo = async () => {
    try {
      const response = await fetch(`${PROOF_SERVER_URL}/api/info`);
      const data: SetupResponse = await response.json();
      return data;
    } catch (err) {
      throw new Error("Failed to fetch server info");
    }
  };

  const handlePublishVerifyingKey = async () => {
    if (!isConnected || !info.address || !packageId || !serverCapId) {
      setError("Please connect wallet and enter Package ID and ServerCap ID");
      return;
    }

    setLoading(true);
    setError(null);
    setStatus("Fetching verifying key from server...");

    try {
      // TODO: Get verifying key from server (needs to be exported)
      // For now, we'll need to manually get it from the trusted setup
      setError("Verifying key export not yet implemented in server. Use scripts/setup_commitment.sh");
      
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown error");
    } finally {
      setLoading(false);
      setStatus(null);
    }
  };

  const handlePublishCommitment = async () => {
    if (!isConnected || !info.address || !packageId || !serverCapId) {
      setError("Please connect wallet and enter Package ID and ServerCap ID");
      return;
    }

    setLoading(true);
    setError(null);
    setStatus("Fetching commitment from server...");

    try {
      const serverInfo = await fetchServerInfo();
      
      setStatus("Publishing commitment on-chain...");

      const tx = new Transaction();
      
      // Convert hex commitment bytes to number array
      const commitmentBytes = Array.from(
        Buffer.from(serverInfo.commitment_bytes, "hex")
      );

      tx.moveCall({
        target: `${packageId}::proximity::create_commitment`,
        arguments: [
          tx.object(serverCapId),
          tx.pure.vector("u8", commitmentBytes),
          tx.pure.address(info.address),
        ],
      });

      const result = await signAndExecuteTransaction({
        transaction: tx,
      });

      setStatus("Commitment published! Extracting commitment ID...");

      // Get the shared object ID from created objects
      const createdObjects = result.effects?.created;
      if (createdObjects && createdObjects.length > 0) {
        const commitmentObj = createdObjects.find((obj: any) => 
          obj.owner && typeof obj.owner === 'object' && 'Shared' in obj.owner
        );
        
        if (commitmentObj) {
          setCommitmentId(commitmentObj.reference.objectId);
          setStatus(`✓ Commitment published: ${commitmentObj.reference.objectId}`);
        }
      }

    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown error");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="w-full max-w-2xl mx-auto p-6 space-y-6">
      <div className="bg-gray-900 rounded-lg border border-gray-700 p-6 space-y-4">
        <h2 className="text-xl font-bold text-white">Server Setup (Admin Only)</h2>
        <p className="text-sm text-gray-400">
          Publish the server's commitment and verifying key on-chain. Requires ServerCap.
        </p>
        
        <div className="space-y-3">
          <div>
            <label className="block text-sm text-gray-400 mb-1">Package ID</label>
            <input
              type="text"
              value={packageId}
              onChange={(e) => setPackageId(e.target.value)}
              className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded text-white font-mono text-sm"
              placeholder="0x..."
            />
          </div>
          
          <div>
            <label className="block text-sm text-gray-400 mb-1">ServerCap Object ID</label>
            <input
              type="text"
              value={serverCapId}
              onChange={(e) => setServerCapId(e.target.value)}
              className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded text-white font-mono text-sm"
              placeholder="0x..."
            />
            <p className="text-xs text-gray-500 mt-1">
              ServerCap was transferred to the publisher address when the package was published.
            </p>
          </div>
        </div>

        <div className="flex gap-2">
          <Button
            onClick={handlePublishCommitment}
            disabled={loading || !packageId || !serverCapId}
            className="flex-1"
          >
            Publish Commitment
          </Button>
          
          <Button
            onClick={handlePublishVerifyingKey}
            disabled={loading || !packageId || !serverCapId}
            variant="secondary"
            className="flex-1"
          >
            Publish Verifying Key
          </Button>
        </div>

        {status && (
          <div className="p-3 bg-blue-900/50 border border-blue-700 rounded text-blue-200 text-sm">
            {status}
          </div>
        )}

        {error && (
          <div className="p-3 bg-red-900/50 border border-red-700 rounded text-red-200 text-sm">
            {error}
          </div>
        )}

        {commitmentId && (
          <div className="p-3 bg-green-900/50 border border-green-700 rounded">
            <p className="text-sm text-green-200 font-medium mb-2">✓ Commitment Published</p>
            <p className="text-xs text-gray-400">Commitment ID:</p>
            <code className="text-xs text-green-300 font-mono break-all">{commitmentId}</code>
          </div>
        )}

        {verifyingKeyId && (
          <div className="p-3 bg-green-900/50 border border-green-700 rounded">
            <p className="text-sm text-green-200 font-medium mb-2">✓ Verifying Key Published</p>
            <p className="text-xs text-gray-400">VerifyingKey ID:</p>
            <code className="text-xs text-green-300 font-mono break-all">{verifyingKeyId}</code>
          </div>
        )}
      </div>

      <div className="bg-gray-800 rounded-lg border border-gray-600 p-4">
        <h3 className="text-sm font-bold text-white mb-2">📖 Setup Instructions</h3>
        <ol className="text-xs text-gray-300 space-y-2 list-decimal list-inside">
          <li>Deploy the Move contract: <code className="text-blue-400">npm run publish:local</code></li>
          <li>Note the Package ID from the deployment output</li>
          <li>Find the ServerCap object ID (sent to publisher address)</li>
          <li>Enter both IDs above and click "Publish Commitment"</li>
          <li>Use the Commitment ID in the proof verification form</li>
        </ol>
      </div>
    </div>
  );
};
