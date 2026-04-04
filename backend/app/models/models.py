"""
╔═══════════════════════════════════════════════════════════════════════════════╗
║                     SentinelX Database Models                                 ║
║                     SQLAlchemy ORM Table Definitions                          ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║ PURPOSE: Define database tables as Python classes (ORM - Object Relational    ║
║          Mapping). Each class represents a table in PostgreSQL.               ║
║                                                                               ║
║ KEY CONCEPTS:                                                                 ║
║ - Declarative Base: Parent class for all models                              ║
║ - Column Types: String, Float, Boolean, DateTime, JSON, Text, Integer        ║
║ - Primary Keys: Unique identifiers for each row                              ║
║ - Indexes: Speed up queries on frequently searched columns                   ║
║ - Relationships: Links between tables (foreign keys)                         ║
║                                                                               ║
║ DESIGN DECISIONS:                                                             ║
║ - UUID primary keys: Harder to guess than integers, better for security      ║
║ - Lowercase wallet addresses: Ensures consistent lookups                     ║
║ - JSON columns: Flexible storage for risk_factors, categories                ║
║ - Timestamps: All tables have created_at for audit trails                    ║
║                                                                               ║
║ INTERVIEW QUESTION: Why ORM instead of raw SQL?                              ║
║ ANSWER: ORM provides:                                                        ║
║ 1. Type safety - IDE autocomplete, fewer typos                               ║
║ 2. Portability - Same code works with PostgreSQL, MySQL, SQLite              ║
║ 3. Security - Automatic parameterization prevents SQL injection              ║
║ 4. Maintainability - Schema changes in one place                             ║
╚═══════════════════════════════════════════════════════════════════════════════╝
"""
import uuid
from datetime import datetime, timedelta
from sqlalchemy import (
    Column, String, Float, Boolean, DateTime, Text, Integer, JSON
)
from sqlalchemy.orm import declarative_base


# ───────────────────────────────────────────────────────────────────────────────
# DECLARATIVE BASE
# ───────────────────────────────────────────────────────────────────────────────
"""
The Base class is the foundation for all ORM models.
All model classes inherit from Base.

- declarative_base(): Creates a base class that tracks all table definitions
- Base.metadata: Contains information about all tables (used for create_all)
"""
Base = declarative_base()


# ───────────────────────────────────────────────────────────────────────────────
# UUID HELPER FUNCTION
# ───────────────────────────────────────────────────────────────────────────────
def generate_uuid():
    """
    Generate a UUID4 string for primary keys.
    
    WHY UUID4?
    - UUID4 is random and unpredictable (security benefit)
    - Can be generated client-side without database round-trip
    - No sequential ID exposure (can't estimate total users)
    
    INTERVIEW QUESTION: UUID vs Auto-increment IDs?
    ANSWER: 
    - Auto-increment: Simpler, smaller indexes, but reveals row count
    - UUID: Larger (36 chars), but better for distributed systems and security
    - For this security platform, UUID prevents enumeration attacks
    """
    return str(uuid.uuid4())


# ═══════════════════════════════════════════════════════════════════════════════
# MODEL: User
# ═══════════════════════════════════════════════════════════════════════════════
class User(Base):
    """
    ╔═══════════════════════════════════════════════════════════════════════════╗
    ║ USER TABLE                                                                ║
    ╠═══════════════════════════════════════════════════════════════════════════╣
    ║ Stores registered wallet addresses and their metadata.                     ║
    ║                                                                           ║
    ║ FIELDS:                                                                    ║
    ║ - id: UUID primary key                                                    ║
    ║ - wallet_address: User's Ethereum wallet (unique, indexed)                ║
    ║ - ens_name: Ethereum Name Service name (optional)                         ║
    ║ - created_at: Account creation timestamp                                  ║
    ║ - last_login: Most recent login timestamp                                 ║
    ║                                                                           ║
    ║ NOTE: No password stored! Authentication is via SIWE (wallet signature)   ║
    ╚═══════════════════════════════════════════════════════════════════════════╝
    """
    __tablename__ = "users"

    id = Column(String, primary_key=True, default=generate_uuid)
    wallet_address = Column(String, unique=True, nullable=False, index=True)  # index for fast lookups
    ens_name = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime, default=datetime.utcnow)


# ═══════════════════════════════════════════════════════════════════════════════
# MODEL: LoginEvent
# ═══════════════════════════════════════════════════════════════════════════════
class LoginEvent(Base):
    """
    ╔═══════════════════════════════════════════════════════════════════════════╗
    ║ LOGIN EVENT TABLE                                                         ║
    ╠═══════════════════════════════════════════════════════════════════════════╣
    ║ Records every login attempt with AI-generated risk assessment.            ║
    ║ This is the PRIMARY data source for the Risk Engine.                      ║
    ║                                                                           ║
    ║ FIELDS:                                                                    ║
    ║ - wallet_address: Who logged in                                           ║
    ║ - ip_address, ip_hash: Location tracking (hashed for privacy)             ║
    ║ - user_agent: Browser/device fingerprint                                  ║
    ║ - geo_*: Geographic coordinates from IP geolocation                       ║
    ║ - risk_score, risk_level: AI-computed risk assessment (0-1, low/med/high) ║
    ║ - risk_features: JSON object with detailed factor breakdown               ║
    ║ - step_up_*: Whether additional verification was required/completed       ║
    ║ - event_hash, merkle_root, tx_hash: Audit trail references                ║
    ║                                                                           ║
    ║ INTERVIEW QUESTION: Why store both ip_address and ip_hash?                ║
    ║ ANSWER: ip_address for operational use, ip_hash for privacy-preserving   ║
    ║ audit logs. If database is leaked, hashed IPs can't be reversed.         ║
    ╚═══════════════════════════════════════════════════════════════════════════╝
    """
    __tablename__ = "login_events"

    id = Column(String, primary_key=True, default=generate_uuid)
    wallet_address = Column(String, nullable=False, index=True)
    
    # IP and device information
    ip_address = Column(String, nullable=True)
    ip_hash = Column(String, nullable=True)  # SHA-256 hash for privacy
    user_agent = Column(String, nullable=True)
    
    # Geographic data (from IP geolocation)
    geo_lat = Column(Float, nullable=True)
    geo_lng = Column(Float, nullable=True)
    geo_country = Column(String, nullable=True)
    geo_city = Column(String, nullable=True)
    
    # AI Risk Assessment (computed by risk_engine.py)
    risk_score = Column(Float, default=0.0)  # 0.0 to 1.0
    risk_level = Column(String, default="low")  # low, medium, high
    risk_features = Column(JSON, nullable=True)  # Detailed factor breakdown
    
    # Step-up verification (for high-risk logins)
    step_up_required = Column(Boolean, default=False)
    step_up_completed = Column(Boolean, default=False)
    
    # Audit trail references
    event_hash = Column(String, nullable=True)  # SHA-256 of event data
    merkle_root = Column(String, nullable=True)  # Root hash of Merkle batch
    tx_hash = Column(String, nullable=True)  # On-chain transaction hash
    
    timestamp = Column(DateTime, default=datetime.utcnow)


# ═══════════════════════════════════════════════════════════════════════════════
# MODEL: GuardEvent
# ═══════════════════════════════════════════════════════════════════════════════
class GuardEvent(Base):
    """
    ╔═══════════════════════════════════════════════════════════════════════════╗
    ║ GUARD EVENT TABLE                                                         ║
    ╠═══════════════════════════════════════════════════════════════════════════╣
    ║ Records content scans by GuardLayer (DLP - Data Loss Prevention).         ║
    ║ Tracks sensitive data detection in chat messages and other content.       ║
    ║                                                                           ║
    ║ FIELDS:                                                                    ║
    ║ - content_hash: SHA-256 of scanned content (never store raw content!)     ║
    ║ - scan_type: "regex", "llm", or "both"                                    ║
    ║ - risk_detected: Boolean - was sensitive data found?                      ║
    ║ - risk_categories: JSON array of detected types (email, ssn, etc.)        ║
    ║ - llm_response: Raw LLM analysis result                                   ║
    ║ - user_override: Did user send despite warning?                           ║
    ║                                                                           ║
    ║ INTERVIEW QUESTION: Why store content_hash instead of content?            ║
    ║ ANSWER: Privacy and security. If database is breached, sensitive data    ║
    ║ (credit cards, passwords) isn't exposed. The hash proves what was        ║
    ║ scanned without storing the actual sensitive content.                     ║
    ╚═══════════════════════════════════════════════════════════════════════════╝
    """
    __tablename__ = "guard_events"

    id = Column(String, primary_key=True, default=generate_uuid)
    wallet_address = Column(String, nullable=False, index=True)
    content_hash = Column(String, nullable=False)  # SHA-256 of content
    scan_type = Column(String, default="regex")  # regex, llm, both
    
    # Risk detection results
    risk_detected = Column(Boolean, default=False)
    risk_categories = Column(JSON, nullable=True)  # ["email", "ssn", "credit_card"]
    llm_response = Column(Text, nullable=True)  # Raw LLM analysis
    
    # User action
    user_override = Column(Boolean, default=False)  # User sent despite warning
    
    # Audit trail
    event_hash = Column(String, nullable=True)
    merkle_root = Column(String, nullable=True)
    tx_hash = Column(String, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)


# ═══════════════════════════════════════════════════════════════════════════════
# MODEL: AuditBatch
# ═══════════════════════════════════════════════════════════════════════════════
class AuditBatch(Base):
    """
    ╔═══════════════════════════════════════════════════════════════════════════╗
    ║ AUDIT BATCH TABLE                                                         ║
    ╠═══════════════════════════════════════════════════════════════════════════╣
    ║ Stores Merkle tree batches for on-chain audit trails.                    ║
    ║                                                                           ║
    ║ WHY MERKLE TREES?                                                          ║
    ║ - Efficient verification: Prove an event exists in a batch without        ║
    ║   revealing all other events                                              ║
    ║ - Gas efficient: One on-chain transaction stores many events              ║
    ║ - Tamper-evident: Changing any event changes the root hash               ║
    ║                                                                           ║
    ║ FIELDS:                                                                    ║
    ║ - merkle_root: Root hash of the Merkle tree (unique identifier)          ║
    ║ - event_count: Number of events in this batch                            ║
    ║ - event_hashes: JSON array of all event hashes in batch                  ║
    ║ - tx_hash: Ethereum transaction hash that submitted this root            ║
    ║ - block_number: Block where transaction was mined                        ║
    ║ - status: pending, submitted, confirmed                                   ║
    ╚═══════════════════════════════════════════════════════════════════════════╝
    """
    __tablename__ = "audit_batches"

    id = Column(String, primary_key=True, default=generate_uuid)
    merkle_root = Column(String, nullable=False, unique=True)
    event_count = Column(Integer, default=0)
    event_hashes = Column(JSON, nullable=True)
    tx_hash = Column(String, nullable=True)
    block_number = Column(Integer, nullable=True)
    gas_used = Column(Integer, nullable=True)
    status = Column(String, default="pending")  # pending, submitted, confirmed
    timestamp = Column(DateTime, default=datetime.utcnow)


# ═══════════════════════════════════════════════════════════════════════════════
# MODEL: Nonce
# ═══════════════════════════════════════════════════════════════════════════════
class Nonce(Base):
    """
    ╔═══════════════════════════════════════════════════════════════════════════╗
    ║ NONCE TABLE                                                               ║
    ╠═══════════════════════════════════════════════════════════════════════════╣
    ║ Stores one-time-use tokens for SIWE authentication.                       ║
    ║                                                                           ║
    ║ WHY NONCES?                                                                ║
    ║ - Prevent replay attacks: Each signature can only be used once           ║
    ║ - SIWE (EIP-4361) requires unique nonces in signed messages              ║
    ║ - Expires after 10 minutes to prevent stale authentication attempts      ║
    ║                                                                           ║
    ║ SECURITY:                                                                  ║
    ║ - Nonce must be fresh (not previously used)                              ║
    ║ - Nonce must not be expired                                              ║
    ║ - After successful auth, nonce is marked as used                         ║
    ╚═══════════════════════════════════════════════════════════════════════════╝
    """
    __tablename__ = "nonces"

    id = Column(String, primary_key=True, default=generate_uuid)
    nonce = Column(String, unique=True, nullable=False)
    wallet_address = Column(String, nullable=True)
    used = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)


# ═══════════════════════════════════════════════════════════════════════════════
# MODEL: Conversation
# ═══════════════════════════════════════════════════════════════════════════════
class Conversation(Base):
    """
    ╔═══════════════════════════════════════════════════════════════════════════╗
    ║ CONVERSATION TABLE                                                        ║
    ╠═══════════════════════════════════════════════════════════════════════════╣
    ║ Represents a chat conversation between two wallet addresses.              ║
    ║ Simple model - just ID and timestamp. Participants stored separately.     ║
    ╚═══════════════════════════════════════════════════════════════════════════╝
    """
    __tablename__ = "conversations"

    id = Column(String, primary_key=True, default=generate_uuid)
    created_at = Column(DateTime, default=datetime.utcnow)


# ═══════════════════════════════════════════════════════════════════════════════
# MODEL: ConversationParticipant
# ═══════════════════════════════════════════════════════════════════════════════
class ConversationParticipant(Base):
    """
    ╔═══════════════════════════════════════════════════════════════════════════╗
    ║ CONVERSATION PARTICIPANT TABLE                                            ║
    ╠═══════════════════════════════════════════════════════════════════════════╣
    ║ Junction table linking wallets to conversations.                          ║
    ║ Enables:                                                                   ║
    ║ - Two participants per conversation (1-on-1 chat)                         ║
    ║ - Finding all conversations for a wallet                                  ║
    ║ - Finding the peer in a conversation                                      ║
    ║                                                                           ║
    ║ This is a many-to-many relationship pattern:                              ║
    ║ One wallet can be in many conversations                                   ║
    ║ One conversation has exactly two participants                             ║
    ╚═══════════════════════════════════════════════════════════════════════════╝
    """
    __tablename__ = "conversation_participants"

    id = Column(String, primary_key=True, default=generate_uuid)
    conversation_id = Column(String, nullable=False, index=True)
    wallet_address = Column(String, nullable=False, index=True)


# ═══════════════════════════════════════════════════════════════════════════════
# MODEL: Message
# ═══════════════════════════════════════════════════════════════════════════════
def default_expires_at():
    """Messages expire after 24 hours (ephemeral messaging for privacy)"""
    return datetime.utcnow() + timedelta(hours=24)


class Message(Base):
    """
    ╔═══════════════════════════════════════════════════════════════════════════╗
    ║ MESSAGE TABLE                                                             ║
    ╠═══════════════════════════════════════════════════════════════════════════╣
    ║ Chat messages with built-in DLP (Data Loss Prevention) scanning.          ║
    ║                                                                           ║
    ║ EPHEMERAL MESSAGING:                                                        ║
    ║ - Messages expire after 24 hours (GDPR data minimization)                 ║
    ║ - Background task deletes expired messages                                ║
    ║ - Reduces data exposure in case of breach                                 ║
    ║                                                                           ║
    ║ DLP INTEGRATION:                                                           ║
    ║ - All messages scanned by GuardLayer before delivery                      ║
    ║ - risk_score: 0.0 to 1.0 severity                                         ║
    ║ - was_blocked: Was the message blocked due to sensitive data?             ║
    ║ - risk_categories: What types of sensitive data were detected             ║
    ║ - redacted: Was content redacted before sending?                          ║
    ║ - user_override: Did user force-send despite warning?                     ║
    ║                                                                           ║
    ║ INTERVIEW QUESTION: Why ephemeral messaging?                              ║
    ║ ANSWER: Security platform principle - minimize data at rest. Less data   ║
    ║ to expose in a breach. Also aligns with GDPR "data minimization" and     ║
    ║ "storage limitation" principles.                                          ║
    ╚═══════════════════════════════════════════════════════════════════════════╝
    """
    __tablename__ = "messages"

    id = Column(String, primary_key=True, default=generate_uuid)
    conversation_id = Column(String, nullable=False, index=True)
    sender_wallet = Column(String, nullable=False, index=True)
    content = Column(Text, nullable=False)  # Message text (may be redacted)
    content_hash = Column(String, nullable=False)  # SHA-256 of original content
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, default=default_expires_at)  # 24 hour TTL
    
    # Delivery status
    is_delivered = Column(Boolean, default=False)
    is_read = Column(Boolean, default=False)
    
    # DLP (Data Loss Prevention) fields
    risk_score = Column(Float, default=0.0)
    was_blocked = Column(Boolean, default=False)
    risk_categories = Column(JSON, nullable=True)
    redacted = Column(Boolean, default=False)
    user_override = Column(Boolean, default=False)
    event_hash = Column(String, nullable=True)


# ═══════════════════════════════════════════════════════════════════════════════
# MODEL: SecurityState
# ═══════════════════════════════════════════════════════════════════════════════
class SecurityState(Base):
    """
    ╔═══════════════════════════════════════════════════════════════════════════╗
    ║ SECURITY STATE TABLE                                                      ║
    ╠═══════════════════════════════════════════════════════════════════════════╣
    ║ Stores the current security posture for each wallet.                      ║
    ║ Used by the Enforcement Engine to determine allowed actions.              ║
    ║                                                                           ║
    ║ TRUST SCORE BANDS:                                                         ║
    ║ - 80-100: active (normal operation)                                       ║
    ║ - 50-79:  step_up_required (wallet re-sign needed for sensitive actions) ║
    ║ - <50:    restricted/locked (sensitive actions disabled)                  ║
    ║                                                                           ║
    ║ FIELDS:                                                                    ║
    ║ - trust_score: Dynamic score based on risk events (0-100)                ║
    ║ - trust_bonus: Accumulated from step-up verifications (persists)         ║
    ║ - security_status: active, step_up_required, restricted, locked          ║
    ║ - locked_until: If locked, when does the cooldown expire?                ║
    ║ - cooldown_reason: Why was the account locked/restricted?                ║
    ║                                                                           ║
    ║ INTERVIEW QUESTION: How does the trust bonus work?                        ║
    ║ ANSWER: When users complete step-up verification (re-sign with wallet),  ║
    ║ they earn a trust bonus (+20 points). This persists across sessions and  ║
    ║ helps restore their account to "active" status faster. It rewards good   ║
    ║ security behavior.                                                        ║
    ╚═══════════════════════════════════════════════════════════════════════════╝
    """
    __tablename__ = "security_states"

    id = Column(String, primary_key=True, default=generate_uuid)
    wallet_address = Column(String, unique=True, nullable=False, index=True)
    trust_score = Column(Integer, default=100)  # 0-100
    trust_bonus = Column(Integer, default=0)  # Accumulated from step-up verifications
    security_status = Column(String, default="active")  # active, step_up_required, restricted, locked
    locked_until = Column(DateTime, nullable=True)
    cooldown_reason = Column(String, nullable=True)
    last_evaluated = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


# ═══════════════════════════════════════════════════════════════════════════════
# MODEL: TransactionEvent
# ═══════════════════════════════════════════════════════════════════════════════
class TransactionEvent(Base):
    """
    ╔═══════════════════════════════════════════════════════════════════════════╗
    ║ TRANSACTION EVENT TABLE                                                   ║
    ╠═══════════════════════════════════════════════════════════════════════════╣
    ║ Records ETH transfer attempts with AI risk assessment.                    ║
    ║ Used by Transaction Risk Engine for behavioral analysis.                  ║
    ║                                                                           ║
    ║ RISK FACTORS ANALYZED:                                                     ║
    ║ - Amount deviation: Is this amount unusual for this user?                ║
    ║ - Frequency anomaly: Too many transactions recently?                     ║
    ║ - First-time recipient: Never sent to this address before?               ║
    ║ - Urgency language: Chat context contains manipulation phrases?          ║
    ║                                                                           ║
    ║ STATUS VALUES:                                                             ║
    ║ - pending: Awaiting step-up verification                                  ║
    ║ - approved: Risk acceptable, awaiting user confirmation                   ║
    ║ - blocked: High risk, transaction prevented                               ║
    ║ - completed: Successfully executed on-chain                               ║
    ║ - cooldown: Temporarily blocked due to suspicious activity               ║
    ║                                                                           ║
    ║ INTERVIEW QUESTION: How do you prevent false positives on large txs?     ║
    ║ ANSWER: The risk engine considers:                                        ║
    ║ 1. Historical patterns - if user regularly sends large amounts, it's OK  ║
    ║ 2. Recipient diversity - if user has many recipients, new ones are OK    ║
    ║ 3. Graduated scoring - not binary, gives score and lets user decide      ║
    ╚═══════════════════════════════════════════════════════════════════════════╝
    """
    __tablename__ = "transaction_events"

    id = Column(String, primary_key=True, default=generate_uuid)
    sender_wallet = Column(String, nullable=False, index=True)
    recipient_wallet = Column(String, nullable=False, index=True)
    amount_eth = Column(Float, nullable=False)
    
    # Risk assessment
    risk_score = Column(Float, default=0.0)
    risk_level = Column(String, default="low")  # low, medium, high
    risk_factors = Column(JSON, nullable=True)  # Factor breakdown
    
    # Status
    status = Column(String, default="pending")  # pending, approved, blocked, completed, cooldown
    tx_hash = Column(String, nullable=True)  # On-chain hash if completed
    
    # Step-up verification
    step_up_required = Column(Boolean, default=False)
    step_up_completed = Column(Boolean, default=False)
    
    # Cooldown (for high-risk transactions)
    cooldown_until = Column(DateTime, nullable=True)
    
    # Context
    conversation_id = Column(String, nullable=True, index=True)  # If initiated from chat
    
    # Audit trail
    event_hash = Column(String, nullable=True)
    merkle_root = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


# ═══════════════════════════════════════════════════════════════════════════════
# INTERVIEW QUESTIONS FOR models.py
# ═══════════════════════════════════════════════════════════════════════════════
"""
Q1: How would you add a relationship between User and LoginEvent?
A1: Add foreign key and relationship:
    In LoginEvent: wallet_address = Column(String, ForeignKey('users.wallet_address'))
    In User: login_events = relationship("LoginEvent", backref="user")
    
    This enables: user.login_events to get all logins for a user.

Q2: Why use JSON columns instead of separate tables for risk_factors?
A2: JSON columns are good for:
    - Unstructured data that doesn't need querying
    - Quick prototyping (no migration needed for new fields)
    - PostgreSQL has JSONB for efficient JSON queries
    Trade-off: Can't enforce foreign keys or constraints on JSON data.

Q3: How would you handle soft deletes instead of hard deletes?
A3: Add is_deleted column:
    is_deleted = Column(Boolean, default=False)
    
    Then filter queries: session.query(User).filter_by(is_deleted=False)
    
    Benefits: Can recover deleted data, maintain audit trail.
    Drawbacks: Table grows, need to filter all queries.

Q4: What's the difference between nullable=True and default=None?
A4: - nullable=True: Database allows NULL values
    - default=None: SQLAlchemy sets None if no value provided
    Both are often used together, but nullable controls DB schema,
    default controls Python behavior.
"""