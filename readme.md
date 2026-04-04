<p align="center">
  <img src="https://img.shields.io/badge/SentinelX-Web3_Security-10b981?style=for-the-badge&logo=ethereum&logoColor=white" alt="SentinelX" />
</p>

<h1 align="center">🛡️ SentinelX</h1>

<p align="center">
  <strong>Adaptive Security Platform for Web3</strong><br/>
  <em>Passwordless wallet authentication · AI anomaly detection · LLM data guardrails · Ethereum audit trails</em>
</p>

<p align="center">
  <a href="#-features"><img src="https://img.shields.io/badge/Features-8-emerald?style=flat-square" alt="Features" /></a>
  <a href="#-quick-start"><img src="https://img.shields.io/badge/Quick_Start-5_min-blue?style=flat-square" alt="Quick Start" /></a>
  <a href="https://sepolia.etherscan.io"><img src="https://img.shields.io/badge/Network-Sepolia-purple?style=flat-square" alt="Sepolia" /></a>
  <a href="#-license"><img src="https://img.shields.io/badge/License-MIT-green?style=flat-square" alt="License" /></a>
</p>

<p align="center">
  <a href="https://github.com/MohitRawat017/SentinalX">
    <img src="https://img.shields.io/github/stars/MohitRawat017/SentinalX?style=social" alt="GitHub Stars" />
  </a>
</p>

---

## 🎯 What is SentinelX?

**SentinelX** is a next-generation security layer for modern web applications. It combines:

- 🔐 **Passwordless Authentication** — Sign in with Ethereum wallets (MetaMask, WalletConnect)
- 🧠 **AI-Powered Risk Detection** — Real-time anomaly scoring using machine learning
- 🛡️ **Data Leak Prevention** — LLM + regex-based content scanning (GuardLayer)
- ⛓️ **Blockchain Audit Trail** — Immutable, Merkle-batched proofs on Ethereum

> *SentinelX doesn't just verify who you are — it protects **what** you do.*

---

## ✨ Features

<table>
<tr>
<td width="50%">

### 🔑 SIWE Wallet Authentication
Passwordless login with **Sign-In with Ethereum (EIP-4361)**. No passwords, no emails — just your wallet.

- MetaMask & WalletConnect support
- Session management with JWT
- Automatic geo-location tracking

</td>
<td width="50%">

### 🧠 AI Risk Engine
Real-time behavioral analysis using **IsolationForest** anomaly detection with 5 key features:

- IP location entropy
- Time-of-day deviation
- Device fingerprinting
- Login velocity analysis
- Trust score calculation

</td>
</tr>
<tr>
<td width="50%">

### 🛡️ GuardLayer DLP
Dual-layer content scanning to prevent data leaks:

- **Regex Layer**: Credit cards, passwords, API keys
- **LLM Layer**: Context-aware PII detection
- User override tracking for audit

</td>
<td width="50%">

### ⛓️ On-Chain Audit Trail
Every security event is recorded on **Ethereum Sepolia**:

- Merkle tree batching (gas-efficient)
- Verifiable inclusion proofs
- Immutable, transparent logs

</td>
</tr>
<tr>
<td width="50%">

### 📊 Security Dashboard
Beautiful, real-time visualization of your security posture:

- Risk score timeline charts
- World map of login origins
- Recent security events feed
- Trust score indicators

</td>
<td width="50%">

### 🚨 Step-Up Authentication
Adaptive challenges when risk is detected:

- Secondary wallet signature
- Trust score boosting
- Configurable thresholds
- Skip option with restricted access

</td>
</tr>
<tr>
<td width="50%">

### 🎮 Attack Simulation Lab
Test your security with built-in attack scenarios:

- Suspicious login simulation
- Data leak attempts
- Burst attack patterns
- Full demo mode

</td>
<td width="50%">

### 📦 JavaScript SDK
Drop-in integration for any web app:

- One-line authentication
- GuardLayer DOM injection
- Configurable security policies
- Event callbacks

</td>
</tr>
</table>

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                    FRONTEND (React + Vite + TailwindCSS)            │
│  ┌────────────┐ ┌────────────┐ ┌───────────┐ ┌─────────────────┐   │
│  │   Wallet   │ │  Security  │ │ GuardLayer│ │   Simulation    │   │
│  │    Auth    │ │  Dashboard │ │  Scanner  │ │      Lab        │   │
│  └─────┬──────┘ └─────┬──────┘ └─────┬─────┘ └───────┬─────────┘   │
└────────┼──────────────┼──────────────┼───────────────┼──────────────┘
         │              │              │               │
         ▼              ▼              ▼               ▼
┌─────────────────────────────────────────────────────────────────────┐
│                      BACKEND (FastAPI + Python)                      │
│  ┌──────────┐ ┌─────────────┐ ┌───────────┐ ┌──────────────────┐   │
│  │   SIWE   │ │    Risk     │ │ GuardLayer│ │  Merkle Batching │   │
│  │ + JWT    │ │   Engine    │ │ Regex+LLM │ │  + Audit Trail   │   │
│  │          │ │(IsoForest)  │ │           │ │                  │   │
│  └──────────┘ └─────────────┘ └───────────┘ └────────┬─────────┘   │
└──────────────────────────────────────────────────────┼──────────────┘
                                                       │
                                                       ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    ETHEREUM (Sepolia Testnet)                        │
│                                                                      │
│   AuditProofBatch.sol                                               │
│   ├─ storeBatch(bytes32 root)         → Store Merkle root on-chain  │
│   └─ verifyInclusion(leaf, proof[])   → Verify event inclusion      │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 🚀 Quick Start

### Prerequisites

| Requirement | Version |
|-------------|---------|
| Python | 3.10+ |
| Node.js | 18+ |
| MetaMask | Latest (optional) |

### 1️⃣ Clone the Repository

```bash
git clone https://github.com/MohitRawat017/SentinalX.git
cd SentinalX
```

### 2️⃣ Backend Setup

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

# Configure environment
copy .env.example .env
# Edit .env with your API keys (optional for demo mode)

# Start server
uvicorn main:app --reload --port 8000
```

> 📍 Backend runs at **http://localhost:8000** | API docs at **http://localhost:8000/docs**

### 3️⃣ Frontend Setup

```bash
cd frontend
npm install
npm run dev
```

> 📍 Dashboard opens at **http://localhost:5174**
>
> For deployed frontend builds, set `VITE_API_URL` to your FastAPI backend before running `npm run build` or deploying to Vercel.

### 4️⃣ Smart Contracts (Optional)

```bash
cd contracts
npm install
npx hardhat compile

# Deploy to Sepolia
npx hardhat run scripts/deploy.js --network sepolia
```

### 5️⃣ SDK

```bash
cd sdk
npm install
npm run build
```

---

## 🎮 Demo Walkthrough

1. **Open** → http://localhost:5174
2. **Click** → "Get Started" on the landing page
3. **Login** → Use MetaMask or "Login with Google" for demo mode
4. **Dashboard** → Click "Seed Demo Data" to generate sample data
5. **Explore** → View Risk Timeline, Login Map, and Recent Events
6. **Chat** → Test secure messaging with GuardLayer protection
7. **Simulation** → Run attack scenarios in the Simulation Lab
8. **Audit** → Verify Merkle proofs in the Audit Trail

---

## 🔌 API Reference

### Authentication

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/auth/nonce` | GET | Generate SIWE nonce |
| `/auth/verify` | POST | Verify wallet signature + risk scoring |
| `/auth/session` | GET | Check JWT session validity |
| `/auth/challenge` | POST | Request step-up challenge |
| `/auth/step-up/verify` | POST | Verify step-up signature |

### Risk Intelligence

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/risk/score` | POST | Compute risk score for features |
| `/risk/timeline` | GET | Get risk score history |
| `/risk/map` | GET | Get login origin coordinates |

### GuardLayer

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/guard/scan` | POST | Scan text for sensitive data |
| `/guard/override` | POST | Record user override decision |

### Audit Trail

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/audit/batches` | GET | List Merkle batches |
| `/audit/batch` | POST | Force create a batch |
| `/audit/verify` | POST | Verify Merkle inclusion proof |
| `/audit/pending` | GET | Get pending events |

### Dashboard

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/dashboard/overview` | GET | Aggregated dashboard data |
| `/dashboard/security-report` | GET | AI-generated security report |
| `/dashboard/seed` | POST | Seed demo data |

### Simulation

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/simulation/scenarios` | GET | List available scenarios |
| `/simulation/run` | POST | Execute attack simulation |

---

## 🛠️ Tech Stack

<table>
<tr>
<td align="center" width="25%">

**Backend**

Python 3.10+<br/>
FastAPI<br/>
SQLAlchemy<br/>
scikit-learn<br/>
OpenAI API

</td>
<td align="center" width="25%">

**Frontend**

React 18<br/>
Vite<br/>
TailwindCSS<br/>
Recharts<br/>
React-Leaflet

</td>
<td align="center" width="25%">

**Blockchain**

Solidity<br/>
Hardhat<br/>
Ethers.js<br/>
Sepolia Testnet

</td>
<td align="center" width="25%">

**SDK**

Vanilla JavaScript<br/>
esbuild<br/>
DOM Injection<br/>
Event System

</td>
</tr>
</table>

---

## 🔐 Security & Privacy

| Category | Approach |
|----------|----------|
| **Data Hashing** | SHA256/Keccak256 before storage |
| **Content Scanning** | Local regex first, LLM fallback with opt-in |
| **Blockchain Data** | Merkle roots only — no raw data on-chain |
| **Explainability** | SHAP values for all flagged events |
| **Session Security** | JWT with expiration + nonce validation |

---

## 📁 Project Structure

```
SentinalX/
├── backend/                 # FastAPI backend
│   ├── app/
│   │   ├── routes/         # API endpoints
│   │   ├── models/         # Database models
│   │   ├── services/       # Business logic
│   │   └── utils/          # Helpers
│   ├── main.py             # App entry point
│   └── requirements.txt
│
├── frontend/               # React frontend
│   ├── src/
│   │   ├── components/     # UI components
│   │   ├── pages/          # Route pages
│   │   ├── api/            # API client
│   │   └── store/          # State management
│   └── package.json
│
├── contracts/              # Solidity smart contracts
│   ├── contracts/
│   │   └── AuditProofBatch.sol
│   └── scripts/
│       └── deploy.js
│
├── sdk/                    # JavaScript SDK
│   ├── src/
│   │   ├── auth.js
│   │   └── guard.js
│   └── package.json
│
└── README.md
```

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

<p align="center">
  <strong>Built with ❤️ for the Web3 community</strong><br/>
  <a href="https://github.com/MohitRawat017/SentinalX">⭐ Star this repo</a> · 
  <a href="https://github.com/MohitRawat017/SentinalX/issues">🐛 Report Bug</a> · 
  <a href="https://github.com/MohitRawat017/SentinalX/issues">💡 Request Feature</a>
</p>

---

<p align="center">
  <img src="https://img.shields.io/badge/Made_with-FastAPI-009688?style=flat-square&logo=fastapi" alt="FastAPI" />
  <img src="https://img.shields.io/badge/Made_with-React-61DAFB?style=flat-square&logo=react" alt="React" />
  <img src="https://img.shields.io/badge/Made_with-Ethereum-3C3C3D?style=flat-square&logo=ethereum" alt="Ethereum" />
  <img src="https://img.shields.io/badge/Made_with-TailwindCSS-38B2AC?style=flat-square&logo=tailwind-css" alt="TailwindCSS" />
</p>
