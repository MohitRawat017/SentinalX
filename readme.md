# 🛡️ SentinelX — Web3 Adaptive Security Platform

> Passwordless wallet login · AI anomaly detection · LLM data guardrails · Ethereum audit trails

---

## 🚀 Quick Start

### Prerequisites
- **Python 3.10+** (backend)
- **Node.js 18+** (frontend, contracts, SDK)
- **MetaMask** browser extension (optional, has demo mode)

### 1. Backend (FastAPI)

```bash
cd backend

# Create virtual environment
python -m venv venv

# Activate (Windows)
venv\Scripts\activate
# Activate (macOS/Linux)
# source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Copy environment file
copy .env.example .env
# Edit .env with your API keys (optional for demo mode)

# Run server
uvicorn main:app --reload --port 8000
```

The backend starts at **http://localhost:8000** with API docs at **/docs**.

### 2. Frontend (React + Vite)

```bash
cd frontend
npm install
npm run dev
```

The dashboard opens at **http://localhost:5173**.

### 3. Smart Contracts (Hardhat — Optional)

```bash
cd contracts
npm install
npx hardhat compile
# Deploy to Sepolia:
# npx hardhat run scripts/deploy.js --network sepolia
```

### 4. SDK

```bash
cd sdk
npm install
npm run build
```

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                   FRONTEND (React + Vite + Tailwind)        │
│  ┌────────────┐ ┌────────────┐ ┌──────────┐ ┌───────────┐  │
│  │ Wallet Auth│ │ Dashboard  │ │GuardLayer│ │ Simulation│  │
│  │ (MetaMask) │ │ (Charts,   │ │ Scanner  │ │   Lab     │  │
│  │            │ │  Map)      │ │          │ │           │  │
│  └─────┬──────┘ └─────┬──────┘ └────┬─────┘ └─────┬─────┘  │
└────────┼──────────────┼─────────────┼──────────────┼────────┘
         │   REST API   │            │              │
         ▼              ▼            ▼              ▼
┌─────────────────────────────────────────────────────────────┐
│                     BACKEND (FastAPI + Python)               │
│  ┌──────────┐ ┌────────────┐ ┌──────────┐ ┌──────────────┐ │
│  │ SIWE Auth│ │ Risk Engine│ │GuardLayer│ │ Merkle Batch │ │
│  │ + JWT    │ │ Isolation  │ │ Regex+LLM│ │ + Audit      │ │
│  │          │ │ Forest+SHAP│ │          │ │              │ │
│  └──────────┘ └────────────┘ └──────────┘ └──────┬───────┘ │
└──────────────────────────────────────────────────┼──────────┘
                                                   │
         ┌─────────────────────────────────────────▼──────────┐
         │           ETHEREUM (Sepolia Testnet)                │
         │   AuditProofBatch.sol                               │
         │   ├─ storeBatch(bytes32 root)                       │
         │   └─ verifyInclusion(bytes32 leaf, bytes32[] proof) │
         └─────────────────────────────────────────────────────┘
```

---

## 📦 Modules

| Module | Description | Status |
|--------|-------------|--------|
| **SIWE Wallet Auth** | Passwordless login with MetaMask/WalletConnect | ✅ Complete |
| **AI Risk Engine** | IsolationForest anomaly detection (5 features) | ✅ Complete |
| **GuardLayer DLP** | Regex + LLM dual-layer content scanning | ✅ Complete |
| **Merkle Batching** | Keccak256 Merkle tree, on-chain root storage | ✅ Complete |
| **React Dashboard** | Risk timeline, world map, event logs | ✅ Complete |
| **Attack Simulation** | Live demo scenarios (suspicious login, data leak, burst) | ✅ Complete |
| **Security Report** | AI-generated session security summary | ✅ Complete |
| **JavaScript SDK** | Drop-in auth + guard for 3rd party apps | ✅ Complete |

---

## 🎮 Demo Script

1. Open **http://localhost:5173** → Click **"Demo Mode"** (no MetaMask needed)
2. Go to **Dashboard** → Click **"Seed Demo Data"** to generate simulation data
3. View the **Risk Timeline** chart and **Login Origin Map**
4. Navigate to **GuardLayer** → Try scanning sensitive text (credit cards, passwords)
5. Open **Simulation Lab** → Run **"Full Demo"** scenario
6. Check **Audit Trail** → View Merkle batches and verify event inclusion
7. Click **"Security Report"** for AI-generated threat analysis

---

## 🔑 API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/auth/nonce` | GET | Generate SIWE nonce |
| `/auth/verify` | POST | Verify wallet signature + risk scoring |
| `/auth/session` | GET | Check JWT session |
| `/risk/score` | POST | Compute risk score for features |
| `/risk/timeline` | GET | Risk score history |
| `/risk/map` | GET | Login origin coordinates |
| `/guard/scan` | POST | Scan text for sensitive data |
| `/guard/override` | POST | Record user override |
| `/audit/batches` | GET | List Merkle batches |
| `/audit/batch` | POST | Force create a batch |
| `/audit/verify` | POST | Verify Merkle inclusion |
| `/simulation/run` | POST | Run attack simulation |
| `/dashboard/overview` | GET | Aggregated dashboard data |
| `/dashboard/security-report` | GET | AI security report |

---

## 🧠 Tech Stack

- **Backend**: Python, FastAPI, scikit-learn, OpenAI, SQLAlchemy
- **Frontend**: React 18, Vite, TailwindCSS, Recharts, Leaflet
- **Blockchain**: Solidity, Hardhat, Sepolia Testnet
- **SDK**: Vanilla JavaScript, esbuild

---

## 📄 License

MIT License — open for remix, reuse, or startup ideas 🔓
