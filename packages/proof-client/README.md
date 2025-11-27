# Proof Client

React-based web client for requesting zero-knowledge proximity proofs from the proof server.

## Features

- **Wallet Integration**: Connect Sui wallet using @mysten/dapp-kit
- **Message Signing**: Sign requests with wallet for authentication
- **Proof Requests**: Submit player coordinates to generate proximity proofs
- **Zero-Knowledge**: Proofs verify proximity without revealing exact location

## Quick Start

```bash
# Install dependencies
npm install

# Start development server
npm run dev

# Build for production
npm run build
```

## Configuration

Create `.env.local`:

```bash
VITE_PROOF_SERVER_URL=http://localhost:3001
```

## Usage

1. **Connect Wallet**: Click "Connect Wallet" to connect your Sui wallet
2. **Enter Coordinates**: Input player X, Y, Z coordinates
3. **Set Max Distance**: Specify maximum distance threshold (default: 10km)
4. **Request Proof**: Click "Request Proof" to generate a zkSNARK proof

The client will:
- Create a signed message with your coordinates
- Send request to proof server
- Display generated proof bytes and public inputs
- Show commitment ID for on-chain verification

## Architecture

```
src/
├── App.tsx                    # Main app component & routing
├── index.tsx                  # App entry point with providers
├── contexts/
│   └── WalletContext.tsx      # Wallet state management
├── components/
│   ├── ui/
│   │   ├── Button.tsx         # Reusable button component
│   │   └── ConnectWalletButton.tsx  # Wallet connection button
│   ├── wallet/
│   │   └── ConnectWalletPanel.tsx   # Wallet connection UI
│   └── ProofRequest.tsx       # Proof request form & display
└── global.css                 # Tailwind styles
```

## API Integration

The client communicates with the proof server:

**POST /api/generate-proof**
```json
{
  "player_x": -23534879266777850000,
  "player_y": -435314932817330100,
  "player_z": -4336253132989267000,
  "max_distance_km": 10,
  "signature": "...",  // Wallet signature
  "message": "{...}"   // Signed message
}
```

**Response**
```json
{
  "proof_bytes": "...",        // Hex-encoded proof
  "public_inputs": "...",      // Hex-encoded public inputs
  "commitment_id": "0x...",    // On-chain commitment object ID
  "player_coordinates": {...},
  "target_info": {...}
}
```

## Development

```bash
# Run type checking
npm run typecheck

# Run linter
npm run lint

# Format code
npm run format
```

## Tech Stack

- **React 18** - UI framework
- **TypeScript** - Type safety
- **Vite** - Build tool
- **Tailwind CSS** - Styling
- **@mysten/dapp-kit** - Sui wallet integration
- **@tanstack/react-query** - Data fetching

## Security

- All requests are signed with wallet private key
- Signatures verify player identity
- Server validates signatures before proof generation
- Proofs reveal only proximity constraint satisfaction

## Next Steps

- Add on-chain proof verification UI
- Display commitment details
- Show verification status
- Transaction builder for proof submission
