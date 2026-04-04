# SentinelX Backend - Learning Flow Guide

## 📚 How to Read This Codebase

This guide will help you understand the SentinelX backend by following a logical reading order. Start from the basics and work your way up to the complex AI/security components.

---

## 🎯 Recommended Reading Order

### Phase 1: Foundation (Start Here)
*These files establish the core infrastructure. Read them first.*

| Order | File | Purpose | Key Concepts |
|-------|------|---------|--------------|
| 1 | `app/config.py` | Configuration & Environment Variables | Pydantic Settings, SECRET_KEY, JWT config, Database URL |
| 2 | `app/database.py` | Database Connection | Async SQLAlchemy, Connection Pool, Session Factory, `get_db()` |
| 3 | `app/models/models.py` | Database Tables | ORM Models, UUID primary keys, JSON columns, Relationships |

**After Phase 1, you should understand:**
- How configuration is loaded from environment variables
- How async database connections work
- What tables exist and what data they store

---

### Phase 2: Application Entry Point
*Understand how the FastAPI app starts and handles requests*

| Order | File | Purpose | Key Concepts |
|-------|------|---------|--------------|
| 4 | `main.py` | FastAPI Application | Lifespan, CORS, Routers, Background Tasks, Startup/Shutdown |

**After Phase 2, you should understand:**
- How the app initializes on startup
- What background tasks run (Merkle batching, Message cleanup)
- How CORS enables frontend communication
- Which routers handle which API paths

---

### Phase 3: Authentication Layer
*Understand how users log in with their wallets*

| Order | File | Purpose | Key Concepts |
|-------|------|---------|--------------|
| 5 | `services/jwt_utils.py` | JWT Token Management | create_access_token(), verify_token(), HS256 signing |
| 6 | `routers/auth.py` | Auth Endpoints | SIWE (Sign-In with Ethereum), Nonce generation, Step-up verification |

**After Phase 3, you should understand:**
- How wallet-based authentication works (no passwords!)
- What a JWT token contains and how it's verified
- How step-up verification works for sensitive actions

---

### Phase 4: AI Risk Engine (Core Security)
*This is the heart of the security system*

| Order | File | Purpose | Key Concepts |
|-------|------|---------|--------------|
| 7 | `services/risk_engine.py` | Login Risk Scoring | Weighted factors, Graduated scoring, History analysis |
| 8 | `routers/risk.py` | Risk Endpoints | /risk/login, /risk/timeline, Risk assessment API |

**After Phase 4, you should understand:**
- Why rule-based AI instead of neural networks
- How risk_score is computed (formula: weighted sum / max_score)
- What factors are analyzed: device, country, rapid attempts, time
- Why graduated scoring (0.0-1.0) instead of binary (yes/no)

---

### Phase 5: GuardLayer DLP (Data Loss Prevention)
*LLM + Regex dual-layer content scanning*

| Order | File | Purpose | Key Concepts |
|-------|------|---------|--------------|
| 9 | `services/guard_layer.py` | DLP Scanning Engine | Regex patterns, LLM analysis, Escalation rules, Redaction |
| 10 | `routers/guard.py` | DLP Endpoints | /guard/scan, /guard/redact, Content analysis API |

**After Phase 5, you should understand:**
- Why both Regex AND LLM layers (defense in depth)
- What patterns are detected (credit cards, SSN, API keys, etc.)
- How risk scores accumulate (80 for critical, 50 for sensitive, 25 for contextual)
- How escalation rules catch dangerous combinations

---

### Phase 6: Trust Score & Enforcement
*Adaptive security based on user behavior*

| Order | File | Purpose | Key Concepts |
|-------|------|---------|--------------|
| 11 | `services/enforcement.py` | Trust Score System | Trust computation, Security statuses, Step-up bonus, Recency decay |
| 12 | `routers/dashboard.py` | Dashboard Endpoints | /dashboard/overview, Trust score display, Security reports |

**After Phase 6, you should understand:**
- How trust score is computed (100 - penalties + bonus)
- Security statuses: active → step_up_required → restricted → locked
- How recency decay works (older events have less impact)
- How step-up verification restores trust

---

### Phase 7: Transaction Risk
*ETH transfer protection against scams*

| Order | File | Purpose | Key Concepts |
|-------|------|---------|--------------|
| 13 | `services/transaction_risk.py` | Transfer Risk Scoring | Amount deviation, Frequency, First-time recipient, Urgency language |
| 14 | `routers/transactions.py` | Transaction Endpoints | /transactions/evaluate, Transfer risk API |

**After Phase 7, you should understand:**
- Why log scale for amount deviation (handles 0.001 to 100+ ETH)
- How social engineering phrases are detected in chat context
- What cooldown mechanism does (prevents rapid retry attacks)
- Why only completed transactions are used for history baseline

---

### Phase 8: Blockchain Audit Trail
*Merkle tree batching for on-chain verification*

| Order | File | Purpose | Key Concepts |
|-------|------|---------|--------------|
| 15 | `services/merkle.py` | Merkle Batching | Merkle tree, Root hash, Background task, Ethereum submission |
| 16 | `routers/audit.py` | Audit Endpoints | /audit/verify, Merkle proof verification |
| 17 | `contracts/AuditProofBatch.sol` | Smart Contract | submitRoot(), on-chain storage |

**After Phase 8, you should understand:**
- Why Merkle trees (50x cost reduction vs storing each event)
- How batches are created and submitted to Ethereum
- What a Merkle proof is and how verification works
- How the smart contract stores root hashes

---

### Phase 9: Real-time Communication
*WebSocket chat with DLP integration*

| Order | File | Purpose | Key Concepts |
|-------|------|---------|--------------|
| 18 | `routers/chat.py` | WebSocket Chat | Connection manager, Message scanning, Ephemeral messaging |

**After Phase 9, you should understand:**
- How WebSocket connections are managed
- How messages are scanned by GuardLayer before delivery
- Why ephemeral messaging (24-hour TTL for privacy)

---

### Phase 10: Supporting Components
*Additional features and utilities*

| Order | File | Purpose | Key Concepts |
|-------|------|---------|--------------|
| 19 | `routers/simulation.py` | Attack Simulation | Demo/testing endpoints, Simulate risk scenarios |
| 20 | `INTERVIEW_PREP.md` | Interview Guide | Common questions, Key concepts, Resume points |

---

## 🔄 Data Flow Diagrams

### Login Authentication Flow
```
1. Frontend: Request nonce → GET /auth/nonce
2. Backend: Generate nonce → Store in DB → Return to frontend
3. Frontend: User signs message with MetaMask
4. Frontend: POST /auth/verify → {message, signature}
5. Backend: Verify signature → Create JWT → Return token
6. Risk Engine: Compute risk_score for this login
7. Backend: Store LoginEvent → Add to Merkle batch
8. Frontend: Use JWT for subsequent requests
```

### Risk Assessment Flow
```
1. User attempts action (login, transfer, etc.)
2. Fetch user's history from database
3. Compute each risk factor:
   - new_device: 0.0-1.0 (graduated)
   - new_country: 0.0-1.0 (graduated)
   - rapid_attempts: 0.0-1.0 (graduated)
   - abnormal_time: 0.0-1.0 (graduated)
4. Apply weights:
   raw = (device×0.4 + country×0.4 + rapid×0.6 + time×0.2)
5. Normalize: risk_score = raw / 1.6
6. Determine level: low (<0.4), medium (0.4-0.7), high (>0.7)
7. Take action: allow, step-up, or block
```

### DLP Scanning Flow
```
1. User sends message/enters text
2. Layer 1: Regex scan (instant)
   - Check HIGH_CRITICAL patterns → +80 each
   - Check SENSITIVE patterns → +50 each
   - Check CONTEXTUAL patterns → +25 each
   - Check ESCALATION rules → +30 for combinations
   - Reduce if false positive context detected
3. Layer 2: LLM scan (if text > 50 chars)
   - Send to OpenRouter/Llama 3.2 3B
   - Parse JSON response
4. Merge results → Determine severity
5. Return: is_risky, risk_score, categories, redacted_text
```

### Trust Score Computation
```
Base Score: 100
├── Login Penalties (max -40)
│   └── For each login event:
│       risk_level = high → -10 × severity × recency
│       risk_level = medium → -4 × severity × recency
├── Guard Penalties (max -30)
│   └── For each guard event:
│       risk_detected → -5 × recency
│       user_override → -2 × recency
├── Transaction Penalties (max -30)
│   └── For each transaction:
│       status = blocked → -12 × severity × recency
│       cooldown_until set → -6 × severity × recency
└── Trust Bonus (max +40)
    └── From step-up verifications: +20 per verification

Final Score = max(0, min(100, computed_score))
```

### Merkle Batching Flow
```
1. Event occurs (login, DLP scan, transaction)
2. Compute event_hash = SHA256(event_data)
3. Add to MerkleBatcher.queue
4. Background task runs every 300 seconds:
   a. If queue has events:
      - Build Merkle tree from event_hashes
      - Compute merkle_root
      - Store batch in database
      - Submit root to Ethereum smart contract
      - Clear queue
5. Later: Anyone can verify with Merkle proof
```

---

## 📖 Quick Reference: File Dependencies

```
main.py
├── config.py (settings)
├── database.py (init_db, AsyncSessionLocal)
└── routers/
    ├── auth.py → services/jwt_utils.py, services/risk_engine.py
    ├── risk.py → services/risk_engine.py, services/enforcement.py
    ├── guard.py → services/guard_layer.py
    ├── transactions.py → services/transaction_risk.py
    ├── audit.py → services/merkle.py
    ├── chat.py → services/guard_layer.py
    └── dashboard.py → services/enforcement.py

services/
├── jwt_utils.py → config.py
├── risk_engine.py → models/models.py (LoginEvent)
├── guard_layer.py → config.py (OPENROUTER_API_KEY)
├── enforcement.py → models/models.py (SecurityState, events)
├── transaction_risk.py → models/models.py (TransactionEvent)
└── merkle.py → config.py, database.py
```

---

## 🎯 What to Focus On for Interviews

### Must Know (Critical)
1. **Risk Engine Formula** - How risk_score is computed
2. **Trust Score System** - How penalties and bonus work
3. **DLP Dual-Layer** - Why Regex + LLM
4. **Merkle Trees** - Why for audit trails, cost reduction

### Should Know (Important)
5. **Async Architecture** - Why async, connection pooling
6. **JWT Authentication** - How SIWE works, token structure
7. **Singleton Pattern** - Why used for engines

### Nice to Know (Bonus)
8. **Background Tasks** - Merkle batching, message cleanup
9. **CORS Configuration** - Why needed, security considerations
10. **Database Models** - JSON columns, UUID vs auto-increment

---

## 📝 Study Checklist

- [ ] Read all Phase 1-3 files (Foundation)
- [ ] Understand risk scoring formula
- [ ] Understand trust score computation
- [ ] Understand DLP scanning flow
- [ ] Understand Merkle tree purpose
- [ ] Review INTERVIEW_PREP.md
- [ ] Practice explaining trade-offs out loud
- [ ] Be ready to draw architecture diagram

---

**Good luck with your preparation! 🚀**