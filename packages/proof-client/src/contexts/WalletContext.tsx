import React, { createContext, useContext, useMemo, useState } from "react";
import {
  useCurrentAccount,
  useSuiClient,
  useConnectWallet,
  useDisconnectWallet,
  useWallets,
} from "@mysten/dapp-kit";
import { QueryClient, useQueryClient } from "@tanstack/react-query";

export type WalletStatus = "idle" | "connecting" | "connected" | "error";

export interface WalletInfo {
  address?: string;
  walletName?: string;
}

export interface WalletContextShape {
  status: WalletStatus;
  info: WalletInfo;
  error?: string;
  client: ReturnType<typeof useSuiClient>;
  connect: () => Promise<void>;
  connectWallet: (wallet: ReturnType<typeof useWallets>[number]) => Promise<void>;
  disconnect: () => void;
  isConnected: boolean;
  queryClient: QueryClient;
  wallets: ReturnType<typeof useWallets>;
  clearError: () => void;
}

const WalletContext = createContext<WalletContextShape | undefined>(undefined);

interface AppWalletProviderProps {
  children: React.ReactNode;
}

function truncateAddress(addr: string | undefined, size = 4) {
  if (!addr) return "";
  if (addr.length <= size * 2) return addr;
  return `${addr.slice(0, size)}…${addr.slice(-size)}`;
}

export const AppWalletProvider: React.FC<AppWalletProviderProps> = ({ children }) => {
  const account = useCurrentAccount();
  const client = useSuiClient();
  const queryClient = useQueryClient();
  const connectHook = useConnectWallet?.();
  const disconnectHook = useDisconnectWallet?.();
  const { mutateAsync: connectAsync, isPending: isConnecting } = connectHook || ({} as any);
  const { mutate: disconnectMutate } = disconnectHook || ({} as any);

  const wallets = useWallets?.() || [];
  const [error, setError] = useState<string | undefined>();
  const clearError = () => setError(undefined);

  const connect = async () => {
    clearError();
    if (!connectAsync) {
      setError("Wallet connect function unavailable.");
      return;
    }
    if (!wallets.length) {
      setError("No wallet providers detected.");
      return;
    }
    const target = wallets[0];
    try {
      await connectAsync({ wallet: target });
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to connect wallet.");
    }
  };

  const connectWallet = async (wallet: ReturnType<typeof useWallets>[number]) => {
    clearError();
    if (!connectAsync) {
      setError("Wallet connect function unavailable.");
      return;
    }
    if (!wallet) {
      setError("Invalid wallet selection.");
      return;
    }
    try {
      await connectAsync({ wallet });
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to connect wallet.");
    }
  };

  const disconnect = () => {
    if (disconnectMutate) disconnectMutate();
    clearError();
  };

  const status: WalletStatus = error
    ? "error"
    : isConnecting
      ? "connecting"
      : account?.address
        ? "connected"
        : "idle";

  const info: WalletInfo = useMemo(
    () => ({
      address: account?.address,
      walletName: account?.publicKey ? "SUI Wallet" : undefined,
    }),
    [account?.address, account?.publicKey]
  );

  const value: WalletContextShape = {
    status,
    info,
    error,
    client,
    connect,
    connectWallet,
    disconnect,
    isConnected: status === "connected",
    queryClient,
    wallets,
    clearError,
  };

  return <WalletContext.Provider value={value}>{children}</WalletContext.Provider>;
};

export function useWallet() {
  const ctx = useContext(WalletContext);
  if (!ctx) throw new Error("useWallet must be used within AppWalletProvider");
  return ctx;
}

export function useDisplayAddress(size = 4) {
  const { info } = useWallet();
  return info.address ? truncateAddress(info.address, size) : undefined;
}
