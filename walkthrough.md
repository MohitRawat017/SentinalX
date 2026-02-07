# 🛡️ SentinelX — Project Walkthrough

> A step-by-step guide for judges and reviewers to understand, run, and evaluate every part of the SentinelX Web3 Adaptive Security Platform.

---

## 📌 Table of Contents

1. [What is SentinelX?](#-what-is-sentinelx)
2. [Project Structure](#-project-structure)
3. [Setup & Launch](#-setup--launch)
4. [Live Demo Walkthrough](#-live-demo-walkthrough)
5. [Module Deep Dive](#-module-deep-dive)
6. [API Reference](#-api-reference)
7. [Smart Contract](#-smart-contract)
8. [JavaScript SDK](#-javascript-sdk)
9. [Tech Stack Summary](#-tech-stack-summary)
10. [Design Decisions & Trade-offs](#-design-decisions--trade-offs)

---

## 🎯 What is SentinelX?

SentinelX is a **pluggable Web3 security layer** that any web application can integrate. It combines four defense layers into one platform:

| Layer | What It Does | Why It Matters |
|-------|-------------|----------------|
| **SIWE Wallet Auth** | Passwordless login via Ethereum wallet signature | No passwords to steal, phishing-resistant |
| **AI Risk Engine** | Scores every login with an IsolationForest model | Catches suspicious behavior automatically |
| **GuardLayer DLP** | Scans outbound text for sensitive data (regex + LLM) | Prevents accidental data leaks in real time |
| **Merkle Audit Trail** | Batches event hashes into a Merkle tree, stores root on-chain | Tamper-proof records at ~$0.05 per 1000 events |

> **One-liner pitch**: SentinelX doesn't just verify who you are — it protects *what you do*, and proves it on-chain.

---

## 📁 Project Structure

```
hackthehills/
├── backend/                    # FastAPI Python backend
│   ├── main.py                 # Application entry point + lifespan
│   ├── requirements.txt        # Python dependencies
│   ├── .env                    # Environment config (API keys, secrets)
│   └── app/
│       ├── config.py           # Pydantic Settings (all env variables)
│       ├── database.py         # Async SQLAlchemy + SQLite session
│       ├── models/
│       │   └── models.py       # User, LoginEvent, GuardEvent, AuditBatch, Nonce
│       ├── services/
│       │   ├── jwt_utils.py    # JWT token create / verify / extract wallet
│       │   ├── risk_engine.py  # IsolationForest anomaly detection (5 features)
│       │   ├── guard_layer.py  # Regex + LLM dual-layer content scanner
│       │   └── merkle.py       # MerkleTree + MerkleBatcher (background batching)
│       └── routers/
│           ├── auth.py         # /auth/* — SIWE login, nonce, session, challenge
│           ├── risk.py         # /risk/* — score, timeline, map, stats
│           ├── guard.py        # /guard/* — scan, override, events
│           ├── audit.py        # /audit/* — batches, verify, proof, pending
│           ├── simulation.py   # /simulation/* — 6 attack scenarios
│           └── dashboard.py    # /dashboard/* — overview, security report
│
├── frontend/                   # React + Vite + TailwindCSS dashboard
│   ├── vite.config.js          # Dev server + API proxy config
│   ├── tailwind.config.js      # Custom sentinel color palette + glow animations
│   └── src/
│       ├── main.jsx            # React root with BrowserRouter
│       ├── App.jsx             # Route definitions (5 pages)
│       ├── api.js              # Axios client with auth interceptor + all API calls
│       ├── store.js            # Zustand global state (auth, dashboard, notifications)
│       ├── index.css           # Custom styles (glass-card, glow, animated gradients)
│       ├── pages/
│       │   ├── LoginPage.jsx       # MetaMask + Demo Mode login
│       │   ├── Dashboard.jsx       # Stats, timeline, map, events, security report
│       │   ├── GuardLayerPage.jsx  # Text scanner with quick-fill samples
│       │   ├── AuditPage.jsx       # Merkle batches + inclusion verification
│       │   └── SimulationPage.jsx  # 6 attack scenario cards
│       └── components/
│           ├── Navbar.jsx          # Top nav with wallet display + risk badge
│           ├── Notifications.jsx   # Toast notification system
│           ├── StatsCards.jsx      # 6 animated stat cards with loading skeletons
│           ├── RiskTimeline.jsx    # Recharts area chart with risk thresholds
│           ├── LoginMap.jsx        # react-leaflet world map with risk markers
│           ├── RecentEvents.jsx    # Login + guard event list
│           └── SecurityReport.jsx  # Markdown-rendered threat report
│
├── contracts/                  # Solidity + Hardhat
│   ├── contracts/
│   │   └── AuditProofBatch.sol # On-chain Merkle root storage + verification
│   ├── scripts/
│   │   └── deploy.js           # Deployment script (Sepolia testnet)
│   ├── hardhat.config.js       # Network config (localhost + Sepolia)
│   └── package.json
│
├── sdk/                        # JavaScript SDK for third-party integration
│   └── src/
│       ├── auth.js             # SentinelXAuth — wallet login class
│       ├── guardlayer.js       # GuardLayer — DOM scanner + warning modal
│       └── index.js            # Main SentinelX class (composes auth + guard)
│
├── readme.md                   # Quick start + architecture + API table
├── project_discription.md      # Original hackathon spec
└── walkthrough.md              # ← You are here
```

---

## ⚡ Setup & Launch

### Prerequisites

- **Python 3.10+**
- **Node.js 18+**
- **MetaMask** browser extension *(optional — the app has a built-in Demo Mode)*

### Step 1 — Start the Backend

```bash
cd backend

# Create & activate virtual environment
python -m venv venv
# Windows:
venv\Scripts\activate
# macOS/Linux:
# source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Start server
uvicorn main:app --reload --port 8000
```

You should see:

```
🛡️  SentinelX Backend is running
INFO:     Uvicorn running on http://127.0.0.1:8000
```

The database (`sentinelx.db`) is auto-created on first run. No external database setup needed.

### Step 2 — Start the Frontend

```bash
cd frontend
npm install
npm run dev
```

Opens at **http://localhost:5173**.

### Step 3 — Open in Browser

Navigate to **http://localhost:5173**. You'll land on the login page.

> **No MetaMask?** No problem — click **"🔬 Demo Mode"** to skip wallet signing and get a simulated wallet session with a real risk score.

---

## 🎮 Live Demo Walkthrough

Follow these steps in order for the most impressive demo:

### Step 1 — Login (Demo Mode)

1. Open **http://localhost:5173**
2. Click the **"🔬 Demo Mode"** button (or connect MetaMask for real SIWE flow)
3. The backend instantly:
   - Verifies the wallet signature (or demo mock)
   - Runs **IsolationForest anomaly detection** on 5 features
   - Returns a JWT token + risk score + risk level
   - Adds the event hash to the **Merkle batcher**
4. You'll see a toast notification with your risk score, then redirect to the Dashboard

### Step 2 — Seed Demo Data

1. On the **Dashboard** page, click the **"🎲 Seed Demo Data"** button in the top-right
2. This triggers the `full_demo` simulation which creates **16 events** across 4 attack phases:
   - **Phase 1** — 3 normal logins (San Francisco, London, New York)
   - **Phase 2** — 2 suspicious logins (Tehran, Beijing — unknown devices)
   - **Phase 3** — 3 data leak attempts (credit card, password+email, SSN)
   - **Phase 4** — 8 burst attack logins (rapid-fire from Moscow, Lagos, Beijing, São Paulo)
3. The dashboard populates with:
   - **Stats Cards** — total logins, average risk, threats blocked, on-chain batches
   - **Risk Timeline** — area chart showing risk spikes over time
   - **Login Origin Map** — world map with color-coded risk markers
   - **Recent Events** — scrollable event feed
   - **Security Report** — auto-generated markdown threat analysis

### Step 3 — GuardLayer Scanner

1. Navigate to the **GuardLayer** page from the navbar
2. Use the **quick-fill buttons** to load sample sensitive text:
   - 💳 Credit Card → `"My card number is 4532015112830366"`
   - 🔑 Password → `"Password: SuperSecret123!"`
   - 🆔 SSN → `"SSN: 123-45-6789"`
   - 🔐 API Key → `"api_key_abc123def456ghi789"`
   - ⚠️ Confidential → `"CONFIDENTIAL: Q3 revenue was $2.3M"`
   - ✅ Clean → `"Let's schedule a meeting for next Tuesday"`
3. Click **"🔍 Scan Content"**
4. The result shows:
   - **Risk detected / No risk** status
   - **Matched regex categories** (e.g., `credit_card`, `ssn`)
   - **Severity level** (critical / medium / low)
5. If risk is found, you can click **"⚠️ Override & Send Anyway"** — this records the user's override decision with an audit hash
6. The **Event Log** at the bottom shows all past scans

### Step 4 — Attack Simulation Lab

1. Navigate to **Simulation** from the navbar
2. You'll see **6 scenario cards**, each with a different attack type:
   - 🔴 **Suspicious Login** — login from a high-risk IP with unknown device
   - 🟢 **Normal Login** — baseline safe login
   - 🟡 **Data Leak Attempt** — text containing credit card / SSN
   - ✅ **Clean Text** — benign text that passes all checks
   - ⚡ **Burst Attack** — 8 rapid logins from rotating IPs (brute force sim)
   - 🔬 **Full Demo** — runs all 4 phases end-to-end
3. Click **"▶ Run"** on any scenario
4. Results show each phase with risk scores, feature breakdowns, geo data, and event hashes

### Step 5 — Audit Trail & Merkle Verification

1. Navigate to **Audit Trail** from the navbar
2. You'll see:
   - **Merkle Batches** — each batch has a root hash, event count, and timestamp
   - **Pending Events** — events waiting to be included in the next batch
3. Click **"📦 Create Batch Now"** to force-batch pending events
4. In the **Verify Inclusion** section:
   - Pick a batch from the dropdown
   - Enter an event hash (copy one from the event log)
   - Click **"✓ Verify"** — the backend computes the Merkle proof and confirms inclusion
5. In production, the Merkle root would be posted to Ethereum Sepolia (~$0.05 per batch of 1000 events)

### Step 6 — Security Report

1. Back on the **Dashboard**, scroll to the **Security Report** card
2. It shows an auto-generated markdown report with:
   - Threat level assessment (LOW / MEDIUM / HIGH / CRITICAL)
   - Total events analyzed
   - Key findings (suspicious logins, data leak attempts, burst attacks)
   - Recommendations
3. The report border color matches the threat level (green → yellow → red)

---

## 🔬 Module Deep Dive

### Module 1: SIWE Wallet Authentication

**Files**: `backend/app/routers/auth.py`, `frontend/src/pages/LoginPage.jsx`

**Flow**:
1. Frontend requests a **nonce** from `GET /auth/nonce`
2. Constructs an EIP-4361 SIWE message with wallet address, nonce, chain ID, and timestamp
3. User signs the message via MetaMask (`personal_sign`)
4. Signed message + signature sent to `POST /auth/verify`
5. Backend verifies signature, runs risk scoring, issues a **JWT token**
6. Token stored in `localStorage` and attached to all subsequent API calls via axios interceptor

**Demo Mode**: When MetaMask isn't available, a mock wallet (`0x742d35Cc...`) and dummy signature are used. The backend accepts any signature > 20 characters in demo mode.

---

### Module 2: AI Risk Engine (IsolationForest)

**File**: `backend/app/services/risk_engine.py`

**How it works**:
- **Model**: `sklearn.ensemble.IsolationForest` with `contamination=0.1`
- **Training**: Pre-seeded with 200 synthetic "normal" logins + 20 anomalous samples on startup
- **5 Features** per login event:

| Feature | Range | What It Measures |
|---------|-------|-----------------|
| `ip_entropy` | 0.0–1.0 | How unusual the IP address pattern is |
| `time_deviation` | 0.0–1.0 | How far the login time deviates from user's typical pattern |
| `device_fingerprint` | 0.0–1.0 | How recognized the device/browser is |
| `login_velocity` | 0.0–1.0 | How rapidly logins are occurring (brute force indicator) |
| `wallet_age_score` | 0.0–1.0 | How established the wallet is on-chain |

**Scoring**:
- Raw IsolationForest anomaly score is normalized to **0.0–1.0**
- `< 0.3` → **Low risk** (green badge)
- `0.3–0.7` → **Medium risk** (yellow badge)
- `> 0.7` → **High risk** (red badge, step-up auth triggered)

**Explainability**: Instead of full SHAP (too heavy for a hackathon), we compute lightweight feature importance by measuring each feature's deviation from the training mean, weighted by the IsolationForest's learned feature importances.

---

### Module 3: GuardLayer DLP (Dual-Layer Content Scanner)

**File**: `backend/app/services/guard_layer.py`

**Layer 1 — Regex** (instant, always runs):
10 regex patterns covering credit cards, SSNs, emails, phone numbers, API keys, private keys, passwords, confidential keywords, IP addresses, and wallet seed phrases.

**Layer 2 — LLM** (optional, runs when OpenAI key is configured):
Sends the text to GPT-3.5-Turbo with a system prompt asking it to classify whether the content contains PII, credentials, or sensitive data. Returns structured findings.

**Why dual-layer?**
- Regex is fast and works offline — catches obvious patterns
- LLM catches contextual leaks that regex misses (e.g., *"tell Bob the server password is on the sticky note"*)
- If no OpenAI key is set, the system gracefully falls back to regex-only mode

---

### Module 4: Merkle Batching & On-Chain Audit Trail

**Files**: `backend/app/services/merkle.py`, `contracts/contracts/AuditProofBatch.sol`

**How batching works**:
1. Every login event and guard event generates a **SHA-256 event hash** from `{event_id, wallet, timestamp, data}`
2. Events accumulate in the `MerkleBatcher` singleton
3. When the batch reaches 10 events (configurable) or a manual batch is triggered:
   - A **Merkle tree** is built from all pending event hashes using keccak256
   - The **Merkle root** is stored in the database (and optionally posted to Ethereum)
   - Individual events can be verified using their **Merkle proof** (array of sibling hashes)
4. The `MerkleBatcher` also runs a **background task** every 60 seconds to auto-flush pending events

**Gas efficiency**: Only the 32-byte Merkle root goes on-chain. 1000 events = 1 transaction ≈ $0.05 on Sepolia.

**Verification**: Given an event hash and a batch's Merkle root, the backend walks the proof path, hashing pairs until it either matches the root (✅ verified) or doesn't (❌ not found).

---

### Module 5: React Dashboard

**Files**: `frontend/src/pages/Dashboard.jsx` + 6 components

| Component | Library | What It Shows |
|-----------|---------|--------------|
| `StatsCards.jsx` | — | 6 metric cards: Total Logins, Avg Risk, High Risk %, Guard Scans, Threats Blocked, On-Chain Batches |
| `RiskTimeline.jsx` | Recharts | Area chart with risk score over time; reference lines at 0.3 (low) and 0.7 (high) thresholds; color-coded dots |
| `LoginMap.jsx` | react-leaflet | Dark-themed world map with circle markers sized & colored by risk score; CARTO dark tiles |
| `RecentEvents.jsx` | — | Scrollable list of recent login + guard events with risk indicators |
| `SecurityReport.jsx` | react-markdown | Auto-generated markdown threat report with color-coded border |

---

### Module 6: Attack Simulation Lab

**File**: `backend/app/routers/simulation.py`

6 pre-built scenarios for demo purposes:

| Scenario | What Happens | Events Generated |
|----------|-------------|-----------------|
| `suspicious_login` | Login from Tehran/Beijing with unknown device | 2 login events |
| `normal_login` | Login from San Francisco with known Chrome browser | 3 login events |
| `data_leak` | Scans text containing credit card, password+email, SSN | 3 guard events |
| `clean_text` | Scans benign text — passes all checks | 1 guard event |
| `burst_attack` | 8 rapid logins from rotating IPs (Moscow, Lagos, Beijing, São Paulo) | 8 login events |
| `full_demo` | Runs all four phases in sequence | 16 events total |

Each scenario writes real events to the database, computes real risk scores, and adds event hashes to the Merkle batcher.

---

## 🔑 API Reference

All endpoints are served from **http://localhost:8000**. Interactive Swagger docs available at **/docs**.

### Authentication

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/auth/nonce` | Generate a fresh nonce for SIWE signing |
| `POST` | `/auth/verify` | Verify signed SIWE message → JWT + risk score |
| `GET` | `/auth/session` | Check if current JWT is valid |
| `POST` | `/auth/challenge` | Trigger step-up authentication |
| `POST` | `/auth/logout` | Invalidate session |

### Risk Engine

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/risk/score` | Compute risk score for given features |
| `GET` | `/risk/timeline?wallet_address=` | Risk score history for a wallet |
| `GET` | `/risk/map?wallet_address=` | Login origin coordinates + risk |
| `GET` | `/risk/stats?wallet_address=` | Aggregated risk statistics |

### GuardLayer

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/guard/scan` | Scan text for sensitive data |
| `POST` | `/guard/override` | Record user override of a blocked action |
| `GET` | `/guard/events?wallet_address=` | List all guard events |
| `GET` | `/guard/stats?wallet_address=` | Guard scan statistics |

### Audit Trail

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/audit/stats` | Batch count + event count |
| `GET` | `/audit/batches` | List all Merkle batches |
| `POST` | `/audit/batch` | Force-create a batch from pending events |
| `GET` | `/audit/proof/{root}/{hash}` | Get Merkle proof for an event |
| `POST` | `/audit/verify` | Verify event inclusion in a batch |
| `GET` | `/audit/pending` | List events not yet batched |

### Simulation

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/simulation/scenarios` | List available attack scenarios |
| `POST` | `/simulation/run` | Execute a simulation scenario |

### Dashboard

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/dashboard/overview` | Aggregated stats, timeline, map, events |
| `GET` | `/dashboard/security-report` | Generated markdown threat report |

---

## ⛓️ Smart Contract

**File**: `contracts/contracts/AuditProofBatch.sol` — Solidity 0.8.19

### Key Functions

```solidity
// Store a Merkle root on-chain (owner only)
function storeBatch(bytes32 _merkleRoot, uint256 _eventCount) external onlyOwner

// Verify that a leaf is included in a stored Merkle root
function verifyInclusion(
    bytes32 _leaf,
    bytes32[] calldata _proof,
    bytes32 _root
) external returns (bool)

// Query functions
function getBatch(uint256 _batchId) external view returns (Batch memory)
function isRootStored(bytes32 _root) external view returns (bool)
```

### Storage Layout

| Mapping | Purpose |
|---------|---------|
| `batches[batchId]` | Stores `{merkleRoot, eventCount, timestamp, submitter}` |
| `rootExists[root]` | Quick lookup: has this root been stored? |
| `rootToBatchId[root]` | Reverse lookup: root → batch ID |

### Deployment

```bash
cd contracts
npm install
npx hardhat compile
# Deploy to Sepolia (requires SEPOLIA_RPC_URL + PRIVATE_KEY in .env):
npx hardhat run scripts/deploy.js --network sepolia
```

---

## 📦 JavaScript SDK

**Directory**: `sdk/src/`

The SDK lets any third-party web app integrate SentinelX with minimal code:

```javascript
import SentinelX from '@sentinelx/sdk';

const sx = new SentinelX({
  apiUrl: 'https://your-sentinelx-backend.com',
  appId: 'your-app-id',
});

// Wallet login
const session = await sx.connect();
console.log(session.riskScore); // 0.34

// Enable GuardLayer on all inputs
sx.guard.init();
// → Automatically scans text fields via MutationObserver
// → Shows warning modal when sensitive data is detected
```

### SDK Classes

| Class | File | Purpose |
|-------|------|---------|
| `SentinelXAuth` | `auth.js` | Handles MetaMask connection, SIWE message signing, session management |
| `GuardLayer` | `guardlayer.js` | Attaches MutationObserver to DOM, scans inputs on blur/submit, injects warning modal |
| `SentinelX` | `index.js` | Main entry point — composes auth + guard into one object |

### Build

```bash
cd sdk
npm install
npm run build
# Outputs: dist/sentinelx.esm.js (ES module) + dist/sentinelx.umd.js (browser global)
```

---

## 🧠 Tech Stack Summary

| Layer | Technology | Why |
|-------|-----------|-----|
| **Backend** | Python 3.10+, FastAPI, Uvicorn | Async-first, auto-generated OpenAPI docs, excellent for rapid prototyping |
| **Database** | SQLite + SQLAlchemy (async) | Zero setup, perfect for hackathon — swap to PostgreSQL for production |
| **AI/ML** | scikit-learn (IsolationForest), NumPy, Pandas | Lightweight, well-understood anomaly detection — no GPU needed |
| **LLM** | OpenAI GPT-3.5-Turbo (optional) | Contextual content scanning; graceful fallback to regex-only if no API key |
| **Frontend** | React 18, Vite 5, TailwindCSS 3.4 | Fast HMR, utility-first styling, modern React patterns |
| **Charts** | Recharts | Composable React chart library — area charts, line charts, custom tooltips |
| **Maps** | react-leaflet + Leaflet.js | Open-source map tiles (CARTO dark theme), circle markers for risk visualization |
| **State** | Zustand | Minimal boilerplate global state — simpler than Redux for hackathon scope |
| **Wallet** | wagmi v2, RainbowKit, ethers.js | Industry-standard Web3 wallet connection |
| **Blockchain** | Solidity 0.8.19, Hardhat, Sepolia testnet | Battle-tested smart contract tooling, free testnet |
| **SDK** | Vanilla JS, esbuild | Zero dependencies, fast bundling, works in any framework |

---

## 🤔 Design Decisions & Trade-offs

| Decision | Rationale |
|----------|-----------|
| **SQLite instead of PostgreSQL** | Zero setup for hackathon judges. The async SQLAlchemy layer means swapping to Postgres is a one-line config change. |
| **Synthetic training data** | Real user data isn't available at a hackathon. The 220-sample synthetic dataset demonstrates the model works; in production, it would retrain on actual login patterns. |
| **Demo mode fallback** | Not every judge has MetaMask. Demo mode lets anyone experience the full flow without any wallet setup. |
| **Regex-first, LLM-second** | Regex is instant and works offline. LLM adds contextual understanding but requires an API key and has latency. The dual-layer approach gives the best of both worlds. |
| **Merkle batching (not per-event)** | Posting every event on-chain would cost ~$0.50 each. Batching 1000 events into one Merkle root costs ~$0.05 total — a 10,000× gas reduction. |
| **Feature importance over SHAP** | Full SHAP explainability adds ~500ms per prediction and requires extra dependencies. Our lightweight deviation-based approach gives similar interpretability at zero cost. |
| **Zustand over Redux** | For 3 state slices (auth, dashboard, notifications), Zustand's 30-line store is dramatically simpler than Redux boilerplate. |
| **Singleton services** | `RiskEngine`, `GuardLayer`, and `MerkleBatcher` use the singleton pattern so the ML model is trained once and the Merkle batcher accumulates events across requests. |

---

## ✅ Checklist — What's Working

- [x] SIWE wallet login (MetaMask + Demo Mode)
- [x] JWT session management with auth-gated routes
- [x] IsolationForest risk scoring (5 features, 0–1 normalized, explainable)
- [x] GuardLayer regex scanning (10 patterns, 3 severity levels)
- [x] GuardLayer LLM scanning (OpenAI GPT-3.5, optional)
- [x] Merkle tree construction + proof generation + verification
- [x] Background Merkle batcher (auto-flush every 60s or 10 events)
- [x] Full React dashboard (stats, timeline chart, world map, events, report)
- [x] 6 attack simulation scenarios with real data generation
- [x] Auto-generated security report with threat level classification
- [x] Solidity smart contract for on-chain Merkle root storage
- [x] JavaScript SDK with auth + DOM-scanning GuardLayer
- [x] Interactive API docs at `/docs` (Swagger UI)
- [x] Complete demo flow without any external dependencies (no MetaMask, no OpenAI key, no Ethereum node required)

---

*Built for Hack the Hills hackathon — February 2026*
