"""
SentinelX Transaction Router
AI-protected ETH transfer evaluation, logging, and history.
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

router = APIRouter()


class EvaluateRequest(BaseModel):
    sender_wallet: str
    recipient_wallet: str
    amount_eth: float
    conversation_id: Optional[str] = None
    chat_context: Optional[str] = None


class ConfirmRequest(BaseModel):
    transaction_id: str
    tx_hash: Optional[str] = None
    step_up_completed: bool = False


# ─── Evaluate Transaction Risk ────────────────────────────────────────

@router.post("/evaluate")
async def evaluate_transaction(
    req: EvaluateRequest,
    db: AsyncSession = Depends(get_db),
):
    """Evaluate risk before an ETH transfer. Returns risk score and enforcement action."""
    # Check security state — deny if locked/restricted
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

    engine = TransactionRiskEngine.get_instance()
    risk_score, risk_level, explanation = await engine.evaluate(
        db=db,
        sender_wallet=req.sender_wallet,
        recipient_wallet=req.recipient_wallet,
        amount_eth=req.amount_eth,
        chat_context=req.chat_context,
    )

    # Create transaction event record
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

    # Apply enforcement
    if risk_level == "high":
        event.status = "blocked"
        event.cooldown_until = datetime.utcnow() + timedelta(minutes=COOLDOWN_MINUTES)
    elif risk_level == "medium":
        event.status = "pending"
    else:
        event.status = "approved"

    db.add(event)
    await db.commit()

    # Add to Merkle audit trail
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


# ─── Confirm / Complete Transaction ───────────────────────────────────

@router.post("/confirm")
async def confirm_transaction(
    req: ConfirmRequest,
    db: AsyncSession = Depends(get_db),
):
    """Confirm a transaction after step-up or MetaMask completion."""
    result = await db.execute(
        select(TransactionEvent).where(TransactionEvent.id == req.transaction_id)
    )
    event = result.scalar()
    if not event:
        return {"error": "Transaction not found"}

    if event.status == "blocked":
        return {"error": "Transaction is blocked. Wait for cooldown to expire."}

    if event.step_up_required and not req.step_up_completed:
        return {"error": "Step-up verification required before confirming."}

    event.status = "completed"
    event.tx_hash = req.tx_hash
    if req.step_up_completed:
        event.step_up_completed = True
    await db.commit()

    return {
        "transaction_id": event.id,
        "status": "completed",
        "tx_hash": req.tx_hash,
    }


# ─── Transaction History ──────────────────────────────────────────────

@router.get("/history")
async def get_transaction_history(
    wallet: str,
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
):
    """Get transaction history for a wallet (sent + received)."""
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


# ─── Transaction Stats ───────────────────────────────────────────────

@router.get("/stats")
async def get_transaction_stats(
    wallet: str,
    db: AsyncSession = Depends(get_db),
):
    """Get aggregated transaction statistics for a wallet."""
    w = wallet.lower()

    # Total sent
    sent_result = await db.execute(
        select(func.count(), func.coalesce(func.sum(TransactionEvent.amount_eth), 0)).where(
            TransactionEvent.sender_wallet == w
        )
    )
    sent_row = sent_result.one()
    total_sent_count = sent_row[0]
    total_sent_eth = float(sent_row[1])

    # Blocked
    blocked_result = await db.execute(
        select(func.count()).select_from(TransactionEvent).where(
            TransactionEvent.sender_wallet == w,
            TransactionEvent.status == "blocked",
        )
    )
    blocked_count = blocked_result.scalar() or 0

    # Step-ups
    stepup_result = await db.execute(
        select(func.count()).select_from(TransactionEvent).where(
            TransactionEvent.sender_wallet == w,
            TransactionEvent.step_up_required == True,
        )
    )
    stepup_count = stepup_result.scalar() or 0

    # Avg risk
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
