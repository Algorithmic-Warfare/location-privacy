import React from "react";
import { useWallet, useDisplayAddress } from "../../contexts/WalletContext";
import { Button } from "./Button";

export const ConnectWalletButton: React.FC = () => {
  const { isConnected, connect, disconnect, status, error, wallets } = useWallet();
  const display = useDisplayAddress();

  const onClick = async () => {
    if (isConnected) {
      disconnect();
    } else {
      await connect();
    }
  };

  let label: string;
  if (status === "connecting") label = "Connecting...";
  else if (isConnected && display) label = display;
  else label = "Connect Wallet";

  return (
    <div className="flex flex-col gap-1 items-start">
      <Button
        onClick={onClick}
        disabled={status === "connecting" || status === "error"}
        variant={isConnected ? "secondary" : "primary"}
        aria-live="polite"
      >
        {label}
      </Button>
      {status === "error" && error && (
        <div role="alert" className="text-xs text-red-500">
          {error}
        </div>
      )}
      {!isConnected && wallets.length === 0 && status !== "error" && (
        <div className="text-xs text-orange-400" role="status">
          No wallet extension found
        </div>
      )}
    </div>
  );
};
