# SentinelX Backend - Interview Preparation Guide

## 🎯 Project Overview for Resume

**Project Title:** SentinelX - Web3 Adaptive Security Platform

**Description:** A comprehensive security platform for Web3 applications featuring AI-powered anomaly detection, LLM-based data loss prevention, and blockchain-backed audit trails.

**My Role:** Backend Development + AI Integration

**Tech Stack:** Python, FastAPI, PostgreSQL, SQLAlchemy (Async), OpenRouter/Llama LLM, Ethereum/Solidity, WebSockets

---

## 📚 Core Technical Concepts

### 1. Async Architecture (FastAPI + AsyncPG)

**Question:** Why did you choose async architecture?

**Answer:**
- FastAPI is built on Starlette (async framework)
- AsyncPG provides non-blocking database operations
- Single worker can handle thousands of concurrent connections
- Perfect for I/O-bound operations (database, external APIs, WebSockets)
- Lower resource consumption compared to sync frameworks like Flask

**Follow-up:** What's the difference between sync and async?

```
Sync: Request → Block on DB → Response (other requests wait)
Async: Request → Yield on DB → Handle other requests → Resume when DB ready
```

---

### 2. AI Risk Engine (Rule-Based ML)

**Question:** Why use rule-based AI instead of neural networks?

**Answer:**
1. **Explainability:** "Your login was flagged because: New device + New country"
2. **Auditability:** Financial systems require clear reasoning
3. **No Training Data:** Don't need labeled dataset of fraudulent logins
4. **Real-time:** No inference latency from model loading
5. **Tunable:** Weights can be adjusted without retraining

**The Formula:**
```
risk_score = min(
    (device_factor × 0.4 + 
     country_factor × 0.4 + 
     rapid_factor × 0.6 + 
     time_factor × 0.2) / 1.6,
    1.0
)
```

**Why Graduated Scoring?**
- Binary: "New device? Yes/No" → 1 or 0
- Graduated: "New device? User has 5 known devices" → 0.4
- Users with many devices are more likely to legitimately use a new one

---

### 3. GuardLayer DLP (LLM + Regex)

**Question:** Why use both LLM and Regex for DLP?

**Answer:**

| Aspect | Regex | LLM |
|--------|-------|-----|
| Speed | Instant (~ms) | Slower (~1-3s) |
| Cost | Free | ~$0.0001/request |
| Context | None | Understands "my SSN is" vs "SSN format is" |
| Obfuscation | Can't detect "one two three" | Can detect obfuscated data |
| Consistency | 100% deterministic | May vary slightly |

**Defense in Depth:** If one layer misses, the other might catch.

**Model Choice:** Llama 3.2 3B via OpenRouter
- Free tier available
- Fast enough for real-time
- Good at structured output (JSON)

---

### 4. Trust Score System

**Question:** Why trust score instead of binary block/allow?

**Answer:**

| Trust Score | Status | Actions |
|-------------|--------|---------|
| 80-100 | ACTIVE | All actions allowed |
| 50-79 | STEP_UP_REQUIRED | Need wallet re-sign for sensitive actions |
| <50 | RESTRICTED/LOCKED | Sensitive actions disabled |

**Benefits:**
1. Better UX - not locked out for one mistake
2. Path to recovery - step-up verification restores trust
3. Context awareness - considers behavior patterns over time
4. Adaptive security - response matches risk level

**Recency Decay:**
```
recency_factor = max(0.5, 1.0 - index × 0.015)
```
- Recent events have more impact
- Users can recover over time
- Old mistakes don't haunt forever

---

### 5. Merkle Tree Audit Trail

**Question:** Why use Merkle trees for audit trails?

**Answer:**

**Problem:** Storing every event on-chain is expensive (gas costs)

**Solution:** Batch events into Merkle trees
1. Hash each event → leaf node
2. Build tree from leaves → root hash
3. Submit only root hash on-chain (one transaction for many events)

**Benefits:**
- Gas efficient: One tx for 50 events
- Tamper-evident: Changing any event changes root
- Provable: Can prove an event is in a batch without revealing all events

---

### 6. SIWE Authentication (Sign-In with Ethereum)

**Question:** How does wallet authentication work?

**Answer:**

**Flow:**
1. Frontend requests nonce from backend
2. User signs message with wallet (MetaMask)
3. Backend verifies signature cryptographically
4. Backend issues JWT token

**Why SIWE (EIP-4361)?**
- No passwords to store/leak
- User controls identity via wallet
- Cryptographic proof of ownership
- Standard protocol (interoperable)

---

## 🔧 Common Interview Questions

### Database & SQLAlchemy

**Q: What's the difference between `nullable=True` and `default=None`?**
```
nullable=True: Database allows NULL values (schema level)
default=None: SQLAlchemy sets None if no value provided (Python level)
```

**Q: Why `expire_on_commit=False`?**
```
By default, SQLAlchemy "expires" objects after commit.
Accessing attributes triggers new database query.
Setting False keeps objects usable after commit.
Important in web apps where we return object data in response.
```

**Q: How do you handle N+1 problem?**
```
Problem: Fetching N records, making N additional queries for related data.
Solution: Use joinedload() or selectinload()
Example: session.query(User).options(joinedload(User.posts)).all()
```

### FastAPI

**Q: Why lifespan context manager instead of `@app.on_event`?**
```
@app.on_event("startup") is deprecated in FastAPI 0.93+
Lifespan provides:
- Better control over startup/shutdown sequence
- Proper async resource cleanup
- Support for yielding control after startup
```

**Q: How does CORS work?**
```
Browsers enforce Same-Origin Policy.
Frontend (port 5173) calling Backend (port 8000) gets blocked.
CORS middleware tells browser "this backend accepts requests from these origins."

SECURITY: Never use allow_origins=["*"] with credentials=True!
Browsers reject this - would allow any site to make authenticated requests.
```

### Security

**Q: How do you handle secrets in production?**
```
NEVER use .env files in production!
Instead:
- Use secrets manager (AWS Secrets Manager, HashiCorp Vault)
- Inject as environment variables at runtime
- Kubernetes secrets for containerized deployments
- Rotate secrets regularly
```

**Q: JWT HS256 vs RS256?**
```
HS256 (HMAC): Single secret key, faster, simpler. Good for monoliths.
RS256 (RSA): Public/private key pair. Slower but allows token verification
without sharing the signing key. Better for microservices.
```

**Q: Why store content_hash instead of content?**
```
- If database breached, sensitive data not exposed
- GDPR "data minimization" compliance
- Hash proves what was scanned without storing evidence
- Can still verify/audit without raw content
```

---

## 🎨 System Design Questions

**Q: How would you scale this for millions of users?**

**Answer:**
1. **Database:**
   - Read replicas for dashboard queries
   - Connection pooling (PgBouncer)
   - Partitioning by wallet_address

2. **Caching:**
   - Redis for security state (trust score)
   - Cache DLP results by content_hash
   - Session storage in Redis

3. **LLM:**
   - Local LLM deployment (Llama.cpp)
   - Request batching
   - Async processing queue

4. **Background Tasks:**
   - Celery + Redis for job queue
   - Separate worker processes
   - Horizontal scaling

**Q: What would you improve with more time?**

1. **ML Enhancement:**
   - Anomaly detection for behavioral biometrics
   - User-specific baseline (not global thresholds)
   - Timezone-aware scoring

2. **Security:**
   - Device fingerprinting (beyond user agent)
   - VPN/proxy detection
   - Rate limiting per endpoint

3. **Observability:**
   - OpenTelemetry tracing
   - Prometheus metrics
   - Alerting on risk score anomalies

---

## 📊 Key Metrics to Mention

- **Risk Engine:** 4 weighted factors, graduated scoring (0-1)
- **DLP:** 20+ regex patterns, LLM fallback, <100ms regex scan
- **Trust Score:** 0-100 scale, 3 status levels, recency decay
- **Merkle:** 50 events per batch, reduces gas by ~50x
- **Database:** Async with connection pooling (5 + 10 overflow)

---

## 🚀 Quick Reference

### File Structure
```
backend/
├── main.py              # FastAPI app, CORS, routers
├── app/
│   ├── config.py        # Pydantic settings from env vars
│   ├── database.py      # Async engine, session factory
│   ├── models/          # SQLAlchemy ORM models
│   ├── routers/         # API endpoints by domain
│   └── services/        # Business logic (AI, DLP, enforcement)
```

### Key Services
- `risk_engine.py` - Weighted login risk scoring
- `guard_layer.py` - DLP with regex + LLM
- `enforcement.py` - Trust score system
- `merkle.py` - Blockchain audit batching
- `transaction_risk.py` - ETH transfer risk analysis

### API Endpoints
- `/auth/*` - SIWE authentication, JWT tokens
- `/risk/*` - Login risk assessment
- `/guard/*` - Content scanning, redaction
- `/transactions/*` - ETH transfer risk
- `/audit/*` - Merkle proof verification
- `/dashboard/*` - Security overview

---

## 💡 Tips for the Interview

1. **Be Honest:** "I vibe coded this" → "I used AI assistance to rapidly prototype, then studied and refined the code"

2. **Explain Trade-offs:** Every architectural decision has pros/cons. Show you understand them.

3. **Use Concrete Examples:** "For instance, a user logging in from a new country with their usual device..."

4. **Connect to Business Value:** "This reduces false positives by 40%, improving user experience while maintaining security"

5. **Know Your Limits:** "I would use a proper ML model if we had labeled training data and needed higher accuracy"

---

## 📝 Code Snippets to Remember

### Async Database Session
```python
async def get_db():
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()  # Always close!
```

### Risk Score Calculation
```python
raw_score = (
    new_device * WEIGHT_NEW_DEVICE +
    new_country * WEIGHT_NEW_COUNTRY +
    rapid_attempts * WEIGHT_RAPID_ATTEMPTS +
    abnormal_time * WEIGHT_ABNORMAL_TIME
)
risk_score = min(raw_score / MAX_RAW_SCORE, 1.0)
```

### Trust Score with Recency
```python
for i, event in enumerate(events):
    recency = max(0.5, 1.0 - i * 0.015)
    penalty += severity * recency
```

---

**Good luck with your interview! 🎯**