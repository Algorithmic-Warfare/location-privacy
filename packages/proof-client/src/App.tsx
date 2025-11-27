import { BrowserRouter, Routes, Route, Link } from "react-router-dom";
import { useWallet, useDisplayAddress } from "./contexts/WalletContext";
import { ConnectWalletButton } from "./components/ui/ConnectWalletButton";
import { ConnectWalletPanel } from "./components/wallet/ConnectWalletPanel";
import { ProofRequest } from "./components/ProofRequest";
import { VerifyProof } from "./components/VerifyProof";
import { ServerSetup } from "./components/ServerSetup";
import { useState } from "react";

interface ProofData {
  proof_bytes: string;
  public_inputs: string;
  commitment_id: string | null;
}

function Dashboard() {
  const { status, info, isConnected } = useWallet();
  const displayAddress = useDisplayAddress();
  const [activeTab, setActiveTab] = useState("request");
  const [proofData, setProofData] = useState<ProofData | null>(null);

  const tabs = [
    { id: "request", label: "Request Proof" },
    { id: "verify", label: "Verify Proof" },
    { id: "setup", label: "Server Setup" },
  ];

  const handleProofGenerated = (data: ProofData) => {
    setProofData(data);
    setActiveTab("verify");
  };

  return (
    <div className="min-h-screen bg-black text-white p-4">
      <div className="max-w-6xl mx-auto space-y-6">
        <div className="border-b border-gray-800 pb-4">
          <h1 className="text-3xl font-bold tracking-tight">Location Privacy - Proof Client</h1>
          <p className="text-sm text-gray-400 mt-1">
            Request zero-knowledge proximity proofs from the server by connecting your SUI wallet and signing a message.
          </p>
        </div>

        <div className="bg-gray-900 rounded-lg border border-gray-800 p-4">
          <div className="text-xs text-gray-400">
            Status: <span className="text-gray-300">{status}</span>
            {isConnected && displayAddress && (
              <>
                {" "}
                • Address: <span className="text-gray-300 font-mono">{displayAddress}</span>
                {info.walletName && <> • Wallet: {info.walletName}</>}
              </>
            )}
          </div>
        </div>

        {isConnected && (
          <>
            <div className="flex gap-2 border-b border-gray-800">
              {tabs.map((tab) => (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`px-4 py-2 text-sm font-medium transition-colors ${
                    activeTab === tab.id
                      ? "text-white border-b-2 border-blue-500"
                      : "text-gray-400 hover:text-gray-300"
                  }`}
                >
                  {tab.label}
                </button>
              ))}
            </div>

            {activeTab === "request" && <ProofRequest onProofGenerated={handleProofGenerated} />}
            {activeTab === "verify" && <VerifyProof proofData={proofData || undefined} />}
            {activeTab === "setup" && <ServerSetup />}
          </>
        )}
      </div>
    </div>
  );
}

export function App() {
  const { isConnected } = useWallet();

  if (!isConnected) {
    return <ConnectWalletPanel />;
  }

  return (
    <BrowserRouter>
      <nav className="bg-gray-900 border-b border-gray-800 p-4">
        <div className="max-w-6xl mx-auto flex justify-between items-center">
          <div className="space-x-4">
            <Link to="/" className="text-gray-300 hover:text-white transition-colors">
              Home
            </Link>
          </div>
          <ConnectWalletButton />
        </div>
      </nav>
      <Routes>
        <Route path="/" element={<Dashboard />} />
      </Routes>
    </BrowserRouter>
  );
}

export default App;
