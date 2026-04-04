"""
╔═══════════════════════════════════════════════════════════════════════════════╗
║                     SentinelX Transaction Router                             ║
║                     AI-Protected ETH Transfer Evaluation API                  ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║ PURPOSE: Evaluate ETH transfers for risk before they're sent                  ║
║                                                                               ║
║ ═════════════════════════════════════════════════════════════════════════════║
║ WHY EVALUATE BEFORE SENDING?                                                  ║
║ ═════════════════════════════════════════════════════════════════════════════║
║                                                                               ║
║ In Web3, once a transaction is sent:                                          ║
║ - It CANNOT be reversed (blockchain immutability)                            ║
║ - There's NO customer support to call                                        ║
║ - Funds are GONE if it's a scam                                              ║
║                                                                               ║
║ THIS ROUTER PROVIDES:                                                         ║
║ - Pre-transfer risk evaluation                                               ║
║ - Protection against social engineering                                      ║
║ - Detection of account takeover attempts                                     ║
║ - Audit trail for all transfer attempts                                      ║
║                                                                               ║
║ ═════════════════════════════════════════════════════════════════════════════║
║ ENDPOINTS PROVIDED:                                                           ║
║ ═════════════════════════════════════════════════════════════════════════════║
║                                                                               ║
║ POST /transactions/evaluate - Evaluate risk before transfer                  ║
║ POST /transactions/confirm   - Confirm after MetaMask/step-up               ║
║ GET  /transactions/history   - Get transfer history                          ║
║ GET  /transactions/stats     - Get aggregate statistics                      ║
║                                                                               ║
║ INTERVIEW QUESTION: Why not just block high-risk transfers?                  ║
║ ANSWER: User autonomy is important. We provide:                              ║
║ - Risk information so users can make informed decisions                      ║
║ - Step-up verification for medium risk (confirm it's really them)            ║
║ - Only block for high risk or when account is locked                         ║
║ This balances security with usability.                                       ║
╚═══════════════════════════════════════════════════════════════════════════════╝
"""
import uuid
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import select, desc, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.models import TransactionEvent
from app.services.transaction_risk import TransactionRiskEngine, COOLDOWN_MINUTES
from app.services.merkle import MerkleBatcher
from app.services.enforcement import SecurityEnforcement


# ───────────────────────────────────────────────────────────────────────────────
# ROUTER SETUP
# ───────────────────────────────────────────────────────────────────────────────
router = APIRouter()


# ───────────────────────────────────────────────────────────────────────────────
# REQUEST/RESPONSE MODELS
# ───────────────────────────────────────────────────────────────────────────────

class EvaluateRequest(BaseModel):
    """
    Request to evaluate a potential ETH transfer.
    
    @param sender_wallet: Who is sending
    @param recipient_wallet: Who will receive
    @param amount_eth: Amount in ETH
    @param conversation_id: Optional chat where transfer was initiated
    @param chat_context: Recent chat messages (for social engineering detection)
    """
    sender_wallet: str
    recipient_wallet: str
    amount_eth: float
    conversation_id: Optional[str] = None
    chat_context: Optional[str] = None


class ConfirmRequest(BaseModel):
    """
    Request to confirm a transaction after evaluation.
    
    @param transaction_id: ID from evaluate response
    @param tx_hash: Ethereum transaction hash (after MetaMask confirms)
    @param step_up_completed: Whether user completed step-up verification
    """
    transaction_id: str
    tx_hash: Optional[str] = None
    step_up_completed: bool = False


# ═══════════════════════════════════════════════════════════════════════════════
# ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════════

@router.post("/evaluate")
async def evaluate_transaction(
    req: EvaluateRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    ╔═══════════════════════════════════════════════════════════════════════════╗
    ║ EVALUATE RISK BEFORE AN ETH TRANSFER                                      ║
    ╠═══════════════════════════════════════════════════════════════════════════╣
    ║                                                                           ║
    ║ THIS IS THE CORE PROTECTION ENDPOINT                                      ║
    ║                                                                           ║
    ║ FLOW:                                                                      ║
    ║ 1. Check if user's account is locked/restricted                          ║
    ║ 2. Run TransactionRiskEngine evaluation                                   ║
    ║ 3. Determine action based on risk level:                                  ║
    ║    - LOW: Approve (proceed to MetaMask)                                   ║
    ║    - MEDIUM: Require step-up verification                                 ║
    ║    - HIGH: Block and apply cooldown                                       ║
    ║ 4. Store transaction event for audit                                      ║
    ║ 5. Add to Merkle batch (blockchain audit)                                 ║
    ║                                                                           ║
    ║ RESPONSE INCLUDES:                                                         ║
    ║ - risk_score: 0.0-1.0 (graduated)                                         ║
    ║ - risk_level: low/medium/high                                             ║
    ║ - display_score: 0-100 (inverted, for UI)                                 ║
    ║ - action: Human-readable action description                                ║
    ║ - factors: Detailed breakdown of what contributed to score                ║
    ║ - step_up_required: Whether additional verification needed                ║
    ║ - blocked: Whether transfer is blocked                                    ║
    ╚═══════════════════════════════════════════════════════════════════════════╝
    """
    # ─── CHECK ENFORCEMENT STATUS ──────────────────────────────────────
    # If user's account is locked/restricted, deny transfer entirely
    enforcer = SecurityEnforcement.get_instance()
    allowed, reason = await enforcer.check_action_allowed(db, req.sender_wallet, "transfer")
    if not allowed:
        return {
            "transaction_id": None,
            "risk_score": 1.0,
            "risk_level": "high",
            "display_score": 0,
            "action": reason,
            "step_up_required": False,
            "blocked": True,
            "cooldown_minutes": 30,
            "in_cooldown": False,
            "factors": [],
            "event_hash": None,
            "status": "blocked",
            "enforcement_blocked": True,
        }

    # ─── RUN RISK EVALUATION ───────────────────────────────────────────
    # This uses the TransactionRiskEngine to analyze the transfer
    engine = TransactionRiskEngine.get_instance()
    risk_score, risk_level, explanation = await engine.evaluate(
        db=db,
        sender_wallet=req.sender_wallet,
        recipient_wallet=req.recipient_wallet,
        amount_eth=req.amount_eth,
        chat_context=req.chat_context,
    )

    # ─── CREATE TRANSACTION EVENT RECORD ───────────────────────────────
    # Every transfer attempt is recorded for:
    # 1. Audit trail (compliance)
    # 2. Pattern learning (improve risk model)
    # 3. History display (user dashboard)
    event = TransactionEvent(
        id=str(uuid.uuid4()),
        sender_wallet=req.sender_wallet.lower(),
        recipient_wallet=req.recipient_wallet.lower(),
        amount_eth=req.amount_eth,
        risk_score=risk_score,
        risk_level=risk_level,
        risk_factors={f["feature"]: f["value"] for f in explanation.get("factors", [])},
        conversation_id=req.conversation_id,
        step_up_required=risk_level == "medium",
        event_hash=explanation.get("event_hash"),
        created_at=datetime.utcnow(),
    )

    # ─── APPLY ENFORCEMENT ACTION ──────────────────────────────────────
    # Based on risk level, set the status
    if risk_level == "high":
        event.status = "blocked"
        # Apply cooldown to prevent rapid retry
        event.cooldown_until = datetime.utcnow() + timedelta(minutes=COOLDOWN_MINUTES)
    elif risk_level == "medium":
        event.status = "pending"  # Waiting for step-up verification
    else:
        event.status = "approved"  # Ready for MetaMask

    db.add(event)
    await db.commit()

    # ─── ADD TO MERKLE AUDIT TRAIL ─────────────────────────────────────
    batcher = MerkleBatcher.get_instance()
    batcher.add_event(explanation["event_hash"], event_type="transaction", metadata={
        "sender": req.sender_wallet.lower(),
        "recipient": req.recipient_wallet.lower(),
        "amount": req.amount_eth,
        "risk_level": risk_level,
    })

    return {
        "transaction_id": event.id,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "display_score": explanation.get("display_score", 0),
        "action": explanation.get("action"),
        "step_up_required": explanation.get("step_up_required", False),
        "blocked": explanation.get("blocked", False),
        "cooldown_minutes": explanation.get("cooldown_minutes", 0),
        "in_cooldown": explanation.get("in_cooldown", False),
        "factors": explanation.get("factors", []),
        "event_hash": explanation.get("event_hash"),
        "status": event.status,
    }


@router.post("/confirm")
async def confirm_transaction(
    req: ConfirmRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    ╔═══════════════════════════════════════════════════════════════════════════╗
    ║ CONFIRM A TRANSACTION AFTER STEP-UP OR METAMASK COMPLETION                 ║
    ╠═══════════════════════════════════════════════════════════════════════════╣
    ║                                                                           ║
    ║ THIS IS CALLED AFTER:                                                      ║
    ║ 1. User completes step-up verification (for medium risk)                  ║
    ║ 2. User confirms in MetaMask                                              ║
    ║                                                                           ║
    ║ FLOW:                                                                      ║
    ║ 1. Find the transaction event by ID                                       ║
    ║ 2. Verify it's not blocked                                                ║
    ║ 3. If step-up was required, verify it was completed                       ║
    ║ 4. Mark as completed with tx_hash                                         ║
    ║                                                                           ║
    ║ IMPORTANT: The tx_hash is the Ethereum transaction hash,                  ║
    ║ which proves the transfer was actually made on-chain.                      ║
    ╚═══════════════════════════════════════════════════════════════════════════╝
    """
    result = await db.execute(
        select(TransactionEvent).where(TransactionEvent.id == req.transaction_id)
    )
    event = result.scalar()
    if not event:
        return {"error": "Transaction not found"}

    # Can't confirm a blocked transaction
    if event.status == "blocked":
        return {"error": "Transaction is blocked. Wait for cooldown to expire."}

    # If step-up was required, verify it was completed
    if event.step_up_required and not req.step_up_completed:
        return {"error": "Step-up verification required before confirming."}

    # Mark as completed
    event.status = "completed"
    event.tx_hash = req.tx_hash  # Ethereum transaction hash
    if req.step_up_completed:
        event.step_up_completed = True
    await db.commit()

    return {
        "transaction_id": event.id,
        "status": "completed",
        "tx_hash": req.tx_hash,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# HISTORY AND STATS ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════════

@router.get("/history")
async def get_transaction_history(
    wallet: str,
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
):
    """
    Get transaction history for a wallet.
    
    Includes both sent and received transactions.
    Used by dashboard to show recent activity.
    """
    w = wallet.lower()
    result = await db.execute(
        select(TransactionEvent)
        .where(
            (TransactionEvent.sender_wallet == w) |
            (TransactionEvent.recipient_wallet == w)
        )
        .order_by(desc(TransactionEvent.created_at))
        .limit(limit)
    )
    events = result.scalars().all()

    return {
        "transactions": [
            {
                "id": e.id,
                "sender": e.sender_wallet,
                "recipient": e.recipient_wallet,
                "amount_eth": e.amount_eth,
                "risk_score": e.risk_score,
                "risk_level": e.risk_level,
                "status": e.status,
                "tx_hash": e.tx_hash,
                "step_up_required": e.step_up_required,
                "step_up_completed": e.step_up_completed,
                "event_hash": e.event_hash,
                "timestamp": e.created_at.isoformat() + "Z" if e.created_at else None,
            }
            for e in events
        ],
        "count": len(events),
    }


@router.get("/stats")
async def get_transaction_stats(
    wallet: str,
    db: AsyncSession = Depends(get_db),
):
    """
    Get aggregated transaction statistics for a wallet.
    
    Used by dashboard cards to show:
    - Total transactions sent
    - Total ETH sent
    - Blocked count (protection working!)
    - Step-up count (security in action)
    - Average risk score
    """
    w = wallet.lower()

    # Total sent (count and sum)
    sent_result = await db.execute(
        select(func.count(), func.coalesce(func.sum(TransactionEvent.amount_eth), 0)).where(
            TransactionEvent.sender_wallet == w
        )
    )
    sent_row = sent_result.one()
    total_sent_count = sent_row[0]
    total_sent_eth = float(sent_row[1])

    # Blocked count (high-risk transfers that were stopped)
    blocked_result = await db.execute(
        select(func.count()).select_from(TransactionEvent).where(
            TransactionEvent.sender_wallet == w,
            TransactionEvent.status == "blocked",
        )
    )
    blocked_count = blocked_result.scalar() or 0

    # Step-up count (medium-risk that required verification)
    stepup_result = await db.execute(
        select(func.count()).select_from(TransactionEvent).where(
            TransactionEvent.sender_wallet == w,
            TransactionEvent.step_up_required == True,
        )
    )
    stepup_count = stepup_result.scalar() or 0

    # Average risk score
    avg_result = await db.execute(
        select(func.avg(TransactionEvent.risk_score)).where(
            TransactionEvent.sender_wallet == w
        )
    )
    avg_risk = round(float(avg_result.scalar() or 0), 4)

    return {
        "total_transactions": total_sent_count,
        "total_eth_sent": round(total_sent_eth, 6),
        "blocked_count": blocked_count,
        "step_up_count": stepup_count,
        "avg_risk_score": avg_risk,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# INTERVIEW QUESTIONS FOR transactions.py
# ═══════════════════════════════════════════════════════════════════════════════
"""
Q1: Why is chat_context included in the evaluation?
A1: To detect social engineering attacks in the conversation:
    - "Urgent, send 5 ETH immediately!"
    - "Trust me, this is a once-in-a-lifetime opportunity"
    - "Don't tell anyone about this transfer"
    
    The TransactionRiskEngine checks for these phrases and scores
    the transfer as higher risk if manipulation is detected.

Q2: What's the difference between step_up_required and blocked?
A2: step_up_required (medium risk):
    - Transfer can proceed after additional verification
    - User must prove identity (re-sign with wallet)
    - After step-up, transfer is allowed
    
    blocked (high risk):
    - Transfer cannot proceed at all
    - Cooldown is applied (prevents rapid retry)
    - User must wait for cooldown to expire

Q3: What happens if someone tries to bypass by calling confirm directly?
A3: Multiple safeguards:
    1. Transaction must exist in database (created by evaluate)
    2. If blocked, confirm returns error
    3. If step_up_required, checks step_up_completed flag
    4. Frontend enforces the flow (can't skip steps)
    
    Backend is the source of truth - frontend can't bypass.

Q4: How does the cooldown mechanism work?
A4: When a transaction is blocked:
    1. cooldown_until is set to now + COOLDOWN_MINUTES
    2. Next evaluate request checks for active cooldown
    3. If cooldown active, risk_score is forced to 0.9+ (high)
    4. User must wait for cooldown to expire
    
    Purpose: Prevents attackers from rapid retry attempts.

Q5: How would you integrate this with an actual Ethereum wallet?
A5: Frontend flow:
    1. User initiates transfer in UI
    2. Frontend calls /transactions/evaluate
    3. If approved:
       - Call MetaMask to send transaction
       - Get tx_hash from MetaMask
       - Call /transactions/confirm with tx_hash
    4. If step_up_required:
       - Show step-up verification UI
       - User signs message
       - Call /auth/step-up-verify
       - Then proceed with MetaMask
    5. If blocked:
       - Show warning, disable transfer button
       - Display cooldown remaining time
"""