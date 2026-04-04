"""
╔═══════════════════════════════════════════════════════════════════════════════╗
║                     SentinelX GuardLayer Router                              ║
║                     LLM + Regex Data Leak Prevention API                      ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║ PURPOSE: Expose GuardLayer DLP functionality via REST API endpoints           ║
║                                                                               ║
║ ═════════════════════════════════════════════════════════════════════════════║
║ WHAT IS DLP (Data Loss Prevention)?                                          ║
║ ═════════════════════════════════════════════════════════════════════════════║
║                                                                               ║
║ DLP prevents sensitive data from leaving an organization:                    ║
║ - Credit card numbers                                                        ║
║ - Social Security numbers                                                    ║
║ - API keys and secrets                                                       ║
║ - Private keys (crypto wallets)                                              ║
║ - Personal identifiable information (PII)                                    ║
║                                                                               ║
║ ═════════════════════════════════════════════════════════════════════════════║
║ ENDPOINTS PROVIDED:                                                           ║
║ ═════════════════════════════════════════════════════════════════════════════║
║                                                                               ║
║ POST /guard/scan     - Scan text for sensitive data (Regex + LLM)            ║
║ POST /guard/override - User overrides a warning (audit logged)               ║
║ GET  /guard/events   - Get scan history                                      ║
║ GET  /guard/stats    - Get aggregate statistics                              ║
║                                                                               ║
║ INTERVIEW QUESTION: Why would users override a DLP warning?                  ║
║ ANSWER: False positives happen. Example:                                     ║
║ - Developer pasting test credit card "4111-1111-1111-1111"                   ║
║ - Support agent discussing a customer's email legitimately                   ║
║ - QA testing with fake SSN "123-45-6789"                                     ║
║ Override records the decision for audit trail.                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
"""
import uuid
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.models import GuardEvent
from app.services.guard_layer import GuardLayer
from app.services.merkle import MerkleBatcher


# ───────────────────────────────────────────────────────────────────────────────
# ROUTER SETUP
# ───────────────────────────────────────────────────────────────────────────────
router = APIRouter()

# Initialize GuardLayer instance
# This is the service that does the actual scanning
guard = GuardLayer()


# ───────────────────────────────────────────────────────────────────────────────
# REQUEST/RESPONSE MODELS
# ───────────────────────────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    """
    Request to scan text for sensitive data.
    
    @param text: The text content to scan
    @param wallet_address: Optional user wallet for tracking
    @param use_llm: Whether to use LLM layer (default True)
    @param source: Where the scan came from (web, sdk, api)
    """
    text: str
    wallet_address: Optional[str] = None
    use_llm: bool = True
    source: str = "web"  # web, sdk, api


class ScanResponse(BaseModel):
    """
    Response from a content scan.
    
    @param is_risky: Whether sensitive data was detected
    @param severity: Risk level (none, low, medium, high, critical)
    @param risk_score: Numerical score (0-100+)
    @param categories: Types of sensitive data found
    @param regex_findings: Detailed regex match results
    @param llm_result: LLM analysis result (if enabled)
    @param content_hash: Hash of scanned content
    @param event_hash: Unique identifier for this scan
    @param scan_type: What type of scan was performed
    @param message: Human-readable result message
    """
    is_risky: bool
    severity: str
    risk_score: int = 0
    categories: list
    regex_findings: list
    llm_result: Optional[dict] = None
    content_hash: str
    event_hash: str
    scan_type: str
    message: str


class OverrideRequest(BaseModel):
    """
    Request to override a guard warning.
    
    Users can choose to send content even after a warning.
    This is recorded for audit purposes.
    """
    event_hash: str
    wallet_address: str
    confirmed: bool = True


# ═══════════════════════════════════════════════════════════════════════════════
# ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════════

@router.post("/scan", response_model=ScanResponse)
async def scan_content(req: ScanRequest, db: AsyncSession = Depends(get_db)):
    """
    ╔═══════════════════════════════════════════════════════════════════════════╗
    ║ SCAN TEXT CONTENT FOR SENSITIVE DATA LEAKS                                 ║
    ╠═══════════════════════════════════════════════════════════════════════════╣
    ║                                                                           ║
    ║ LAYER 1: REGEX PATTERN MATCHING (Fast, ~1ms)                              ║
    ║ - Checks against predefined patterns                                      ║
    ║ - Credit cards, SSN, API keys, private keys, etc.                        ║
    ║ - High precision for known formats                                        ║
    ║                                                                           ║
    ║ LAYER 2: LLM ANALYSIS (Deep, ~500ms)                                      ║
    ║ - Understands context                                                     ║
    ║ - Detects novel patterns                                                  ║
    ║ - Explains why content is risky                                          ║
    ║                                                                           ║
    ║ INTERVIEW QUESTION: Why use both layers?                                  ║
    ║ ANSWER: Defense in depth:                                                 ║
    ║ - Regex catches known patterns instantly                                  ║
    ║ - LLM catches context-specific leaks                                      ║
    ║ - Together, they cover each other's blind spots                          ║
    ╚═══════════════════════════════════════════════════════════════════════════╝
    """
    # Call GuardLayer service to scan the content
    result = await guard.scan(req.text, use_llm=req.use_llm)

    # ─── STORE GUARD EVENT ─────────────────────────────────────────────
    # Every scan is recorded for:
    # 1. Audit trail (compliance)
    # 2. Pattern analysis (improve detection)
    # 3. User behavior tracking (risk assessment)
    guard_event = GuardEvent(
        id=str(uuid.uuid4()),
        wallet_address=(req.wallet_address or "anonymous").lower(),
        content_hash=result["content_hash"],
        scan_type=result["scan_type"],
        risk_detected=result["is_risky"],
        risk_categories=result["categories"],
        llm_response=str(result.get("llm_result")),
        user_override=False,  # Will be updated if user overrides
        event_hash=result["event_hash"],
        timestamp=datetime.utcnow(),
    )
    db.add(guard_event)
    await db.commit()

    # ─── ADD TO MERKLE BATCH ───────────────────────────────────────────
    # This event will be included in the next blockchain batch
    batcher = MerkleBatcher.get_instance()
    batcher.add_event(result["event_hash"], event_type="guard", metadata={
        "wallet": req.wallet_address or "anonymous",
        "is_risky": result["is_risky"],
        "severity": result["severity"],
    })

    # Build user-friendly message
    message = ""
    if result["is_risky"]:
        message = f"⚠️ Sensitive data detected ({result['severity']}): {', '.join(result['categories'])}. Are you sure you want to send this?"
    else:
        message = "✅ Content looks clean. No sensitive data detected."

    return ScanResponse(
        is_risky=result["is_risky"],
        severity=result["severity"],
        risk_score=result.get("risk_score", 0),
        categories=result["categories"],
        regex_findings=result["regex_findings"],
        llm_result=result.get("llm_result"),
        content_hash=result["content_hash"],
        event_hash=result["event_hash"],
        scan_type=result["scan_type"],
        message=message,
    )


@router.post("/override")
async def override_guard(req: OverrideRequest, db: AsyncSession = Depends(get_db)):
    """
    ╔═══════════════════════════════════════════════════════════════════════════╗
    ║ USER OVERRIDES A GUARD WARNING                                             ║
    ╠═══════════════════════════════════════════════════════════════════════════╣
    ║                                                                           ║
    ║ WHY ALLOW OVERRIDES?                                                       ║
    ║ - False positives happen (legitimate use of test data)                    ║
    ║ - User autonomy (they own their data)                                      ║
    ║ - Business needs (support agents need to discuss sensitive info)          ║
    ║                                                                           ║
    ║ WHAT HAPPENS:                                                               ║
    ║ 1. Original event is updated with override flag                            ║
    ║ 2. Override is logged to Merkle batch (immutable audit)                   ║
    ║ 3. Trust score may be affected (enforcement service)                      ║
    ║                                                                           ║
    ║ SECURITY IMPLICATION:                                                      ║
    ║ - Override is PERMANENTLY recorded                                         ║
    ║ - Can't be deleted or modified                                             ║
    ║ - Used for compliance audits                                               ║
    ╚═══════════════════════════════════════════════════════════════════════════╝
    """
    # Find the original guard event
    result = await db.execute(
        select(GuardEvent).where(GuardEvent.event_hash == req.event_hash)
    )
    event = result.scalar_one_or_none()

    if event:
        # Update the event to mark it as overridden
        event.user_override = req.confirmed
        await db.commit()

    # Log override to Merkle batch (separate event for audit trail)
    batcher = MerkleBatcher.get_instance()
    import hashlib, json
    override_data = json.dumps({
        "original_event": req.event_hash,
        "wallet": req.wallet_address,
        "override": req.confirmed,
        "timestamp": datetime.utcnow().isoformat(),
    }, sort_keys=True)
    override_hash = hashlib.sha256(override_data.encode()).hexdigest()
    batcher.add_event(override_hash, event_type="guard_override")

    return {
        "success": True,
        "event_hash": req.event_hash,
        "override_recorded": True,
        "audit_hash": override_hash,
        "message": "Override recorded. This action has been logged to the audit trail.",
    }


@router.get("/events")
async def get_guard_events(
    wallet_address: Optional[str] = None,
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
):
    """
    Get guard event history.
    
    Used by dashboard to show recent scans and their results.
    Filter by wallet_address to see a specific user's history.
    """
    query = select(GuardEvent).order_by(desc(GuardEvent.timestamp)).limit(limit)
    if wallet_address:
        query = query.where(GuardEvent.wallet_address == wallet_address.lower())

    result = await db.execute(query)
    events = result.scalars().all()

    return {
        "events": [
            {
                "id": e.id,
                "content_hash": e.content_hash,
                "scan_type": e.scan_type,
                "risk_detected": e.risk_detected,
                "risk_categories": e.risk_categories,
                "user_override": e.user_override,
                "event_hash": e.event_hash,
                "timestamp": e.timestamp.isoformat() + "Z" if e.timestamp else None,
            }
            for e in events
        ],
        "count": len(events),
    }


@router.get("/stats")
async def get_guard_stats(
    wallet_address: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    """
    Get aggregate guard statistics.
    
    Used by dashboard cards to show:
    - Total scans performed
    - Threats detected
    - User overrides
    - Blocked content
    """
    query = select(GuardEvent)
    if wallet_address:
        query = query.where(GuardEvent.wallet_address == wallet_address.lower())

    result = await db.execute(query)
    events = result.scalars().all()

    return {
        "total_scans": len(events),
        "threats_detected": sum(1 for e in events if e.risk_detected),
        "overrides": sum(1 for e in events if e.user_override),
        "blocked": sum(1 for e in events if e.risk_detected and not e.user_override),
    }


# ═══════════════════════════════════════════════════════════════════════════════
# INTERVIEW QUESTIONS FOR guard.py
# ═══════════════════════════════════════════════════════════════════════════════
"""
Q1: How does the dual-layer scanning work?
A1: Layer 1 (Regex):
    - Instant pattern matching (~1ms)
    - Checks credit cards, SSN, API keys, private keys
    - Returns risk score based on matches
    
    Layer 2 (LLM):
    - Slower deep analysis (~500ms)
    - Understands context (is this a test card?)
    - Detects novel patterns not in regex
    
    Flow: Regex runs first, if score > threshold OR use_llm=True, run LLM

Q2: What happens when both layers disagree?
A2: We take the MORE conservative result:
    - If either flags as risky, it's risky
    - Use the higher risk score
    - Combine all detected categories
    This prevents false negatives (missing real threats).

Q3: How does this integrate with the chat system?
A3: Before any message is sent:
    1. Chat endpoint calls guard.scan()
    2. If risky, warning is shown to user
    3. User can override (recorded for audit)
    4. Message is delivered or blocked based on decision
    
    See routers/chat.py for the WebSocket implementation.

Q4: What's the performance impact of LLM scanning?
A4: Considerations:
    - Adds ~500ms latency per message
    - Costs API calls to OpenRouter
    - Not needed for short messages (< 50 chars)
    
    Optimization:
    - Only run LLM if regex finds potential issues
    - Cache similar content hashes
    - Batch process for non-urgent scans

Q5: How would you handle images and files?
A5: Extensions for multi-modal:
    1. Images: OCR to extract text, then scan
    2. PDFs: Extract text with pdfplumber
    3. Screenshots: OCR + image recognition for QR codes
    4. Audio: Speech-to-text, then scan transcript
    
    Storage consideration: Don't store the actual files,
    only the extracted text hash and scan results.
"""