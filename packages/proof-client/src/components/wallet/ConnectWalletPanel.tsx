import React, { useEffect } from "react";
import { useWallet, WalletStatus } from "../../contexts/WalletContext";
import { Button } from "../ui/Button";
import { WalletWithRequiredFeatures } from "@mysten/wallet-standard";

export const ConnectWalletPanel: React.FC = () => {
  const { wallets, isConnected, connectWallet, status } = useWallet();

  const deriveBtnText = (
    status: WalletStatus,
    isConnected: boolean,
    wallets: WalletWithRequiredFeatures[]
  ): { buttonText: string; buttonDisabled: boolean } => {
    if (wallets.length === 0) {
      return { buttonText: "Please install a SUI Wallet", buttonDisabled: true };
    }
    switch (`${status}-${isConnected}`) {
      case "connecting-false":
        return { buttonText: "Connecting...", buttonDisabled: true };
      case "idle-false":
        return { buttonText: "Connect with SUI wallet", buttonDisabled: false };
      case "connected-true":
        return { buttonText: "Connected", buttonDisabled: true };
      default:
        return { buttonText: "Connect Wallet", buttonDisabled: false };
    }
  };

  return (
    <div className="mx-auto flex w-full max-w-sm flex-col items-center justify-center">
      <div className="relative mx-auto flex h-screen max-w-[560px] flex-col items-center justify-center">
        <div className="flex flex-col items-center gap-6 p-8 rounded-lg border border-gray-700 bg-gray-900">
          <h1 className="text-2xl font-bold text-white">Location Privacy Client</h1>
          <p className="text-gray-400 text-center">
            Connect your wallet to request proximity proofs
          </p>
          <Button
            className="w-full uppercase"
            id="connect-sui-wallet"
            variant="secondary"
            onClick={() => connectWallet(wallets[0])}
            disabled={deriveBtnText(status, isConnected, wallets).buttonDisabled}
          >
            {deriveBtnText(status, isConnected, wallets).buttonText}
          </Button>
        </div>
      </div>
    </div>
  );
};
