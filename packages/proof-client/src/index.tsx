import { createRoot } from "react-dom/client";
import { App } from "./App";
import { AppWalletProvider } from "./contexts/WalletContext";
import { createNetworkConfig, SuiClientProvider, WalletProvider } from "@mysten/dapp-kit";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { getFullnodeUrl } from "@mysten/sui/client";
import "./global.css";

const container = document.getElementById("root");
if (!container) throw new Error("Root container #root not found");
const root = createRoot(container);

const { networkConfig } = createNetworkConfig({
  localnet: { url: "http://127.0.0.1:9000" },
  devnet: { url: getFullnodeUrl("devnet") },
  testnet: { url: getFullnodeUrl("testnet") },
  mainnet: { url: getFullnodeUrl("mainnet") },
});

const queryClient = new QueryClient();

root.render(
  <QueryClientProvider client={queryClient}>
    <SuiClientProvider networks={networkConfig} defaultNetwork="localnet">
      <WalletProvider>
        <AppWalletProvider>
          <App />
        </AppWalletProvider>
      </WalletProvider>
    </SuiClientProvider>
  </QueryClientProvider>
);
