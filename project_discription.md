# 🛡️ SentinelX (Enhanced)

> **Web3 Adaptive Security Platform** — Passwordless login with AI-powered anomaly detection, LLM-based data guardrails, and Ethereum-based audit trails.

![Status](https://img.shields.io/badge/status-In%20Development-yellow)
![Blockchain](https://img.shields.io/badge/network-Sepolia%20Testnet-blue)
![License](https://img.shields.io/badge/license-MIT-green)

---

## 🎯 What is SentinelX?

**SentinelX** is a pluggable authentication and security intelligence layer for modern web apps. It augments login with **wallet-based authentication**, flags risky behavior using **AI-powered anomaly detection**, and protects outbound user actions via **LLM-based data leak prevention** — all recorded on **Ethereum** for verifiable proof.

> SentinelX doesn't just verify who you are — it protects *what* you do.

---

## 🔐 Core Feature Stack

| Layer                       | Feature                                  | Tech Stack                                                                   |
| --------------------------- | ---------------------------------------- | ---------------------------------------------------------------------------- |
| Auth Layer                  | SIWE (Sign-In with Ethereum)             | EIP-4361, ethers.js, MetaMask, WalletConnect                                 |
| Risk Intelligence           | AI-based login anomaly detection         | Python, FastAPI, `scikit-learn` (IsolationForest), `shap` for explainability |
| Runtime Behavior Protection | Outbound data scanning using LLM & regex | OpenAI API, regex NLP, `langchain` (optional)                                |
| On-Chain Audit Trail        | Immutable login and behavior proofs      | Solidity (Sepolia), Merkle tree batching, keccak256, Ethers.js               |
| Dashboard                   | Visual risk + security feed per user/app | React, Vite, TailwindCSS, recharts.js                                        |
| Integrator SDK              | Drop-in SentinelX auth + scanner package | JavaScript SDK, SecureIframe / GuardLayer plugin                             |

---

## 🧩 Usage Model

### "How SentinelX Works for a 3rd Party Web App"

1. Developer integrates **SentinelX Login** alongside Google, GitHub, etc.
2. End-user logs in with wallet (MetaMask or WalletConnect).
3. SentinelX:

   * Verifies wallet signature
   * Runs anomaly detection
   * Stores audit hash on-chain (Merkle batched)
4. User gets a **SentinelX Dashboard**:

   * Risk timeline
   * Last login map
   * AI warnings
5. In web app text inputs, SentinelX runs GuardLayer:

   * Flags PII or credential leakage
   * Warns user → "Are you sure you want to send this?"
   * Stores outbound risk audit hash on-chain

---

## 🏗️ Detailed Implementation Plan (Modular & Thorough)

### 📦 Module 1: SIWE Wallet Auth (Passwordless Login)

* **Frontend**:

  * MetaMask login via `wagmi`, `rainbowkit`, or `ethers.js`
  * SIWE message generation + signing

* **Backend**:

  * `FastAPI` endpoint: `/auth/siwe`
  * Libraries: `siwe`, `eth_account` (for signature verification)

* **Security**:

  * Nonce validation + expiration
  * Store session in JWT or server memory

---

### 📦 Module 2: AI-Based Risk Engine (Login Anomaly Detection)

* **Model**: `IsolationForest` with ~5 features

  * IP location entropy (geo mismatch)
  * Time-of-day deviation (based on user history)
  * Device fingerprint (user-agent, screen size)
  * Login velocity (frequency over window)
  * Known vs unknown wallet behavior

* **Stack**:

  * `scikit-learn`, `pandas`, `uvicorn`, `FastAPI`

* **Explainability**:

  * Use `shap.Explainer(model, X_train)` to return top contributing features
  * Store feature contribution logs

* **Thresholds**:

  * Score < 0.3 → Low risk
  * Score 0.3–0.7 → Medium risk
  * Score > 0.7 → Trigger Step-Up + store audit

---

### 📦 Module 3: Step-Up Authentication (Adaptive Challenge)

* When high risk is detected:

  * Show modal: "This login seems unusual. Please confirm."
  * Trigger secondary wallet signature (new nonce)
  * Or trigger push to a secondary wallet/email (mocked with modal)

* **FastAPI endpoint**:

  * `/auth/challenge`
  * Stores challenge result in DB

---

### 📦 Module 4: Runtime GuardLayer (LLM-Based Leak Protection)

* **Injected Plugin (Frontend)**:

  * Scans all textareas & inputs using MutationObserver
  * On input blur or submit, triggers content check

* **Scanning Logic**:

  * Regex rules:

    * Email, password, credit card, internal keywords ("confidential", "secret")
  * LLM rules:

    * API: OpenAI (`gpt-3.5`)
    * Prompt:

      > "Does this message contain sensitive information (PII, passwords, tokens, secrets)? Answer yes/no and list reasons."

* **Confirm Modal UI**:

  * If risk found → block submission + show warning
  * User clicks "Yes, send anyway" to override

* **On-chain Proof**:

  * Create event hash: `SHA256({uid, content_hash, timestamp, override_flag})`
  * Add to Merkle batch

---

### 📦 Module 5: Merkle Batching + On-Chain Proof

* **Backend Service**:

  * Collect login & behavior events
  * Every N minutes or N events:

    * Build Merkle Tree of event hashes (use keccak256)
    * Post root on-chain via `AuditProofBatch.sol`

* **Contract**:

  * `function storeBatch(bytes32 root) external`
  * `mapping(bytes32 => bool)` → verify inclusion

* **Frontend**:

  * Show "Verify on Etherscan" link
  * Let user input a past event → verify Merkle proof

---

### 📦 Module 6: SentinelX Dashboard (User-Side)

* **Pages**:

  * Risk Timeline (graph of login scores)
  * Map view of login origins (leaflet.js or Google Maps)
  * Guard Event Logs ("You blocked a message at 2:32AM")
  * Ethereum Audit Trail Table (tx hashes, Merkle root links)

* **Stack**:

  * `React`, `TailwindCSS`, `Recharts`, `react-leaflet`
  * Backend via FastAPI: `/events`, `/risk-timeline`, `/map` APIs

---

### 📦 Module 7: JavaScript SDK for Integrators

* **Purpose**:

  * Let 3rd party apps import SentinelX auth + GuardLayer with 1 line

* **Files**:

  * `auth.js` → handles login/init
  * `GuardLayer.js` → attaches to DOM
  * `sentinelx.config.js` → appId, wallet config, optional LLM key

---

## 🔒 Privacy & Ethics

| Category       | Approach                                          |
| -------------- | ------------------------------------------------- |
| IP/Data        | SHA256 before storage                             |
| Text Scanning  | Done locally first, LLM fallback only with opt-in |
| Blockchain     | Merkle root only; no raw data ever on-chain       |
| Explainability | Show top model features for all flagged events    |

---

## 🚀 Quick Dev Setup

```bash
# 1. Backend
cd backend
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload

# 2. Frontend
cd frontend
npm install
npm run dev

# 3. Contract
cd contracts
npm install
npx hardhat compile
deploy to Sepolia using private key

# 4. SDK
cd sdk
npm install && npm link
```

---

## 🎥 Suggested Demo Script

1. **Login** into fake web app with SentinelX → AI risk score shown
2. **Try** sending a confidential message → Guard blocks + explains
3. **Override**, send anyway → audit stored on blockchain
4. **Go** to Dashboard → see risk graph, IP map, and audit tx
5. **Verify** event inclusion with Merkle proof
6. **Explain** Ethereum gas cost per batch (~$0.05 for 1000 events)

---

## 🏁 Next Steps (for Hackathon Sprint)

1. ✅ SIWE wallet login (core flow)
2. ✅ Risk engine (IsolationForest)
3. 🔄 GuardLayer input scanner (regex + LLM fallback)
4. 🔄 Merkle tree & on-chain batching
5. 🔄 Admin/Dashboard polish
6. 🔄 End-to-end demo video + Etherscan links

---

## 🧠 Positioning for Judges

> SentinelX is Auth0 + Cloudflare Zero Trust + OpenAI, merged into one trust layer. It verifies identity, analyzes behavior, protects your data — and records every decision on-chain. It’s privacy-first, AI-driven, and Ethereum-anchored.

---

## 📄 License

MIT License – open for remix, reuse, or startup ideas 🔓
