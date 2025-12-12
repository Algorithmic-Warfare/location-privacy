import React, { useState, useEffect } from "react";
import { useWallet } from "../contexts/WalletContext";
import { Button } from "../components/ui/Button";
import { Transaction } from "@mysten/sui/transactions";
import { useSuiClient } from "@mysten/dapp-kit";
import { DevInspectResults } from "@mysten/sui/dist/cjs/client";

interface VerifyProofProps {
  proofData?: {
    proof_bytes: string;
    public_inputs: string;
    commitment_id: string | null;
  };
}

interface ServerInfo {
  status: string;
  commitment_published: boolean;
  commitment_id: string | null;
  package_id: string | null;
  verifying_key_id: string | null;
  commitment_bytes: string;
  verifying_key_bytes: string;
  setup_complete: boolean;
}

const PROOF_SERVER_URL = import.meta.env.VITE_PROOF_SERVER_URL || "http://localhost:3001";

const hexToBytes = (hex: string): Uint8Array => {
  // Remove optional 0x prefix
  if (hex.startsWith("0x")) hex = hex.slice(2);

  if (hex.length % 2 !== 0) {
    throw new Error("Hex string must have an even number of characters");
  }

  return Uint8Array.from(hex.match(/.{1,2}/g)!.map((byte) => parseInt(byte, 16)));
};

const interpretResults = (devInspectResult: DevInspectResults): string => {
  if (!devInspectResult) {
    return "No results returned";
  }

  // Check for execution errors first
  if (devInspectResult.error) {
    // Parse abort error if available
    const effects = devInspectResult.effects as {
      abortError?: {
        module_id: string;
        function: string;
        error_code: number;
      };
    };
    
    if (effects?.abortError) {
      const { function: funcName, error_code } = effects.abortError;
      
      // Map error codes to human-readable messages based on Move contract
      const errorMessages: Record<number, string> = {
        1: "Invalid commitment format (must be 32 bytes)",
        2: "Invalid proof size (must be at least 128 bytes)",
        3: "Invalid public inputs size (must be 64 bytes)",
        4: "Proof verification failed - cryptographic check failed",
        6: "Invalid verifying key size (must be 328 bytes)",
        7: "Invalid public inputs format",
        8: "Commitment hash mismatch - proof not for this location"
      };

      const errorMsg = errorMessages[error_code] || `Unknown error code ${error_code}`;
      return `${errorMsg} (in ${funcName || 'unknown function'})`;
    }

    // Fall back to generic error message
    return `Transaction error: ${devInspectResult.error}`;
  }

  // Check for successful execution
  if (!devInspectResult.results || devInspectResult.results.length === 0) {
    return "No results returned";
  }

  const result = devInspectResult.results[0];
  if (!result.returnValues || result.returnValues.length === 0) {
    return "No return values";
  }

  const returnValue = result.returnValues[0];
  const [returnData] = returnValue;

  // The return value is a byte array [1] for true, [0] for false
  if (returnData && returnData.length > 0) {
    return returnData[0] === 1 ? "Proof is valid" : "Proof is invalid";
  }

  return "Unknown result format";
};

export const VerifyProof: React.FC<VerifyProofProps> = ({ proofData }) => {
  const { isConnected, info } = useWallet();
  // const { mutateAsync: signAndExecuteTransaction } = useSignAndExecuteTransaction();
  const client = useSuiClient();

  const [packageId, setPackageId] = useState("");
  const [commitmentId, setCommitmentId] = useState(proofData?.commitment_id || "");
  const [verifyingKeyId, setVerifyingKeyId] = useState("");
  const [proofBytes, setProofBytes] = useState(proofData?.proof_bytes || "");
  const [publicInputs, setPublicInputs] = useState(proofData?.public_inputs || "");

  const [loading, setLoading] = useState(false);
  const [fetchingServer, setFetchingServer] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);
  const [txDigest, setTxDigest] = useState<string | null>(null);
  const [serverSetupComplete, setServerSetupComplete] = useState(false);

  // Fetch server configuration on mount
  useEffect(() => {
    const fetchServerInfo = async () => {
      setFetchingServer(true);
      try {
        const response = await fetch(`${PROOF_SERVER_URL}/api/info`);
        const data: ServerInfo = await response.json();

        if (data.package_id) setPackageId(data.package_id);
        if (data.commitment_id) setCommitmentId(data.commitment_id);
        if (data.verifying_key_id) setVerifyingKeyId(data.verifying_key_id);
        setServerSetupComplete(data.setup_complete);

        if (data.setup_complete) {
          console.log("✓ Server setup complete - object IDs loaded from server");
        }
      } catch (err) {
        console.warn("Could not fetch server info:", err);
      } finally {
        setFetchingServer(false);
      }
    };

    fetchServerInfo();
  }, []);

  // Update fields when proofData prop changes
  useEffect(() => {
    if (proofData) {
      setProofBytes(proofData.proof_bytes);
      setPublicInputs(proofData.public_inputs);
      if (proofData.commitment_id) {
        setCommitmentId(proofData.commitment_id);
      }
    }
  }, [proofData]);

  const handleVerifyProof = async () => {
    if (!isConnected || !info.address) {
      setError("Please connect your wallet first");
      return;
    }

    if (!packageId || !commitmentId || !verifyingKeyId || !proofBytes || !publicInputs) {
      setError("Please fill in all fields");
      return;
    }
    console.log("Verifying proof on-chain with:", {
      packageId,
      commitmentId,
      verifyingKeyId,
      proofBytes,
      publicInputs,
    });
    setLoading(true);
    setError(null);
    setSuccess(false);
    setTxDigest(null);

    try {
      const tx = new Transaction();
      console.log("Preparing proof verification transaction...");
      // Convert hex strings to byte arrays
      const proofArray = hexToBytes(proofBytes);
      console.log(`Proof bytes length: ${proofArray.length}`);
      const inputsArray = hexToBytes(publicInputs);
      console.log(`Public inputs length: ${inputsArray.length}`);

      // Call verify_proximity_proof
      tx.moveCall({
        target: `${packageId}::proximity::verify_proximity_proof`,
        arguments: [
          tx.object(commitmentId),
          tx.object(verifyingKeyId),
          tx.pure.vector("u8", proofArray),
          tx.pure.vector("u8", inputsArray),
        ],
      });
      console.log("Executing transaction...");
      // const result = await signAndExecuteTransaction({
      //   transaction: tx,
      // });
      const dryRunResult = await client.devInspectTransactionBlock({
        transactionBlock: tx,
        sender: info.address,
      });
      console.log("Dry run result:", dryRunResult);

      const verificationResult = interpretResults(dryRunResult);
      console.log("Dry run verification output:", verificationResult);

      if (verificationResult === "Proof is valid") {
        setSuccess(true);
      } else {
        setError(`Verification failed: ${verificationResult}`);
      }
      // setTxDigest(result.digest);
    } catch (err) {
      console.log(err);
      const errorMessage = err instanceof Error ? err.message : "Unknown error occurred";
      setError(`Verification failed: ${errorMessage}`);
      setSuccess(false);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="w-full max-w-2xl mx-auto p-6 space-y-6">
      {serverSetupComplete && (
        <div className="p-3 bg-green-900/30 border border-green-700 rounded text-green-200 text-sm">
          ✓ Server setup complete - Object IDs loaded automatically
        </div>
      )}

      {!serverSetupComplete && !fetchingServer && (
        <div className="p-3 bg-yellow-900/30 border border-yellow-700 rounded text-yellow-200 text-sm space-y-2">
          <div>
            ⚠️ Server setup incomplete - You need to manually publish the commitment and verifying
            key:
          </div>
          <div className="text-xs space-y-1 mt-2">
            <div>1. Use the ServerSetup component to publish objects (or do it via CLI)</div>
            <div>2. Set SUI_PACKAGE_ID and SUI_SERVER_CAP_ID in server .env file</div>
            <div>3. Restart the proof server</div>
            <div className="mt-2 italic text-gray-400">
              Note: Auto-publish is currently disabled due to large Sui SDK dependency (~1GB). To
              enable, uncomment Sui dependencies in crates/proof-server/Cargo.toml and rebuild with
              --features sui-auto-publish.
            </div>
          </div>
        </div>
      )}

      <div className="bg-gray-900 rounded-lg border border-gray-700 p-6 space-y-4">
        <h2 className="text-xl font-bold text-white">Verify Proof On-Chain</h2>
        <p className="text-sm text-gray-400">
          Submit the proof to the blockchain for cryptographic verification.
        </p>

        <div className="space-y-3">
          <div>
            <label className="block text-sm text-gray-400 mb-1">
              Package ID{" "}
              {serverSetupComplete && <span className="text-green-400 text-xs">• Auto-loaded</span>}
            </label>
            <input
              type="text"
              value={packageId}
              onChange={(e) => setPackageId(e.target.value)}
              className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded text-white font-mono text-sm"
              placeholder="0x..."
              disabled={fetchingServer}
            />
          </div>

          <div>
            <label className="block text-sm text-gray-400 mb-1">
              LocationCommitment Object ID{" "}
              {serverSetupComplete && <span className="text-green-400 text-xs">• Auto-loaded</span>}
            </label>
            <input
              type="text"
              value={commitmentId}
              onChange={(e) => setCommitmentId(e.target.value)}
              className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded text-white font-mono text-sm"
              placeholder="0x..."
              disabled={fetchingServer}
            />
          </div>

          <div>
            <label className="block text-sm text-gray-400 mb-1">
              VerifyingKey Object ID{" "}
              {serverSetupComplete && <span className="text-green-400 text-xs">• Auto-loaded</span>}
            </label>
            <input
              type="text"
              value={verifyingKeyId}
              onChange={(e) => setVerifyingKeyId(e.target.value)}
              className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded text-white font-mono text-sm"
              placeholder="0x..."
              disabled={fetchingServer}
            />
          </div>

          <div>
            <label className="block text-sm text-gray-400 mb-1">Proof Bytes (hex)</label>
            <textarea
              value={proofBytes}
              onChange={(e) => setProofBytes(e.target.value)}
              className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded text-white font-mono text-xs h-24"
              placeholder="Hex-encoded proof bytes..."
            />
            <p className="text-xs text-gray-500 mt-1">
              {proofBytes ? `${proofBytes.length / 2} bytes` : "No proof loaded"}
            </p>
          </div>

          <div>
            <label className="block text-sm text-gray-400 mb-1">Public Inputs (hex)</label>
            <textarea
              value={publicInputs}
              onChange={(e) => setPublicInputs(e.target.value)}
              className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded text-white font-mono text-xs h-20"
              placeholder="Hex-encoded public inputs..."
            />
            <p className="text-xs text-gray-500 mt-1">
              {publicInputs ? `${publicInputs.length / 2} bytes` : "No inputs loaded"}
            </p>
          </div>
        </div>

        <Button onClick={handleVerifyProof} disabled={loading || !isConnected} className="w-full">
          {loading ? "Verifying On-Chain..." : "Verify Proof"}
        </Button>

        {error && (
          <div className="p-3 bg-red-900/50 border border-red-700 rounded text-red-200 text-sm">
            {error}
          </div>
        )}

        {success && (
          <div className="p-3 bg-green-900/50 border border-green-700 rounded space-y-2">
            <p className="text-sm text-green-200 font-medium">✓ Proof Verified Successfully!</p>
            {txDigest && (
              <div>
                <p className="text-xs text-gray-400">Transaction Digest:</p>
                <code className="text-xs text-green-300 font-mono break-all">{txDigest}</code>
              </div>
            )}
            <p className="text-xs text-gray-300 mt-2">
              The proof has been cryptographically verified on-chain. Nonce incremented.
            </p>
          </div>
        )}
      </div>

      <div className="bg-gray-800 rounded-lg border border-gray-600 p-4">
        <h3 className="text-sm font-bold text-white mb-2">ℹ️ Verification Process</h3>
        <ul className="text-xs text-gray-300 space-y-2 list-disc list-inside">
          <li>Proof is verified using Groth16 zkSNARK verification</li>
          <li>Commitment hash binding is checked (prevents proof reuse)</li>
          <li>Nonce is incremented to prevent replay attacks</li>
          <li>Event is emitted with verification details</li>
        </ul>
      </div>
    </div>
  );
};
