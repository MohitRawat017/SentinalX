import uuid
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.models import TransactionEvent
from app.services.blockchain import (
    LEGACY_TRANSACTION_NETWORK,
    get_explorer_tx_url,
    get_transaction_network,
    normalize_algorand_address,
    storage_wallet,
    verify_algorand_payment,
)
from app.services.enforcement import SecurityEnforcement
from app.services.merkle import MerkleBatcher
from app.services.transaction_risk import COOLDOWN_MINUTES, TransactionRiskEngine


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


def event_network(event: TransactionEvent) -> str:
    return event.network or LEGACY_TRANSACTION_NETWORK


def event_explorer_url(event: TransactionEvent) -> Optional[str]:
    if not event.tx_hash:
        return None
    if event_network(event).startswith("algorand_"):
        return get_explorer_tx_url(event.tx_hash)
    return None


def serialize_event(event: TransactionEvent) -> dict:
    return {
        "id": event.id,
        "sender": event.sender_wallet,
        "recipient": event.recipient_wallet,
        "amount_eth": event.amount_eth,
        "risk_score": event.risk_score,
        "risk_level": event.risk_level,
        "status": event.status,
        "tx_hash": event.tx_hash,
        "step_up_required": event.step_up_required,
        "step_up_completed": event.step_up_completed,
        "event_hash": event.event_hash,
        "timestamp": event.created_at.isoformat() + "Z" if event.created_at else None,
        "network": event_network(event),
        "explorer_url": event_explorer_url(event),
    }


@router.post("/evaluate")
async def evaluate_transaction(
    req: EvaluateRequest,
    db: AsyncSession = Depends(get_db),
):
    try:
        sender_wallet = normalize_algorand_address(req.sender_wallet)
        recipient_wallet = normalize_algorand_address(req.recipient_wallet)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    sender_storage = storage_wallet(sender_wallet)
    recipient_storage = storage_wallet(recipient_wallet)

    enforcer = SecurityEnforcement.get_instance()
    allowed, reason = await enforcer.check_action_allowed(db, sender_storage, "transfer")
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
        sender_wallet=sender_storage,
        recipient_wallet=recipient_storage,
        amount_eth=req.amount_eth,
        chat_context=req.chat_context,
    )

    event = TransactionEvent(
        id=str(uuid.uuid4()),
        sender_wallet=sender_storage,
        recipient_wallet=recipient_storage,
        amount_eth=req.amount_eth,
        risk_score=risk_score,
        risk_level=risk_level,
        risk_factors={f["feature"]: f["value"] for f in explanation.get("factors", [])},
        conversation_id=req.conversation_id,
        step_up_required=risk_level == "medium",
        event_hash=explanation.get("event_hash"),
        created_at=datetime.utcnow(),
        network=get_transaction_network(),
    )

    if risk_level == "high":
        event.status = "blocked"
        event.cooldown_until = datetime.utcnow() + timedelta(minutes=COOLDOWN_MINUTES)
    elif risk_level == "medium":
        event.status = "pending"
    else:
        event.status = "approved"

    db.add(event)
    await db.commit()

    batcher = MerkleBatcher.get_instance()
    batcher.add_event(
        explanation["event_hash"],
        event_type="transaction",
        metadata={
            "sender": sender_storage,
            "recipient": recipient_storage,
            "amount": req.amount_eth,
            "risk_level": risk_level,
            "network": event.network,
        },
    )

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
        "network": event.network,
    }


@router.post("/confirm")
async def confirm_transaction(
    req: ConfirmRequest,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(TransactionEvent).where(TransactionEvent.id == req.transaction_id)
    )
    event = result.scalar_one_or_none()
    if not event:
        raise HTTPException(status_code=404, detail="Transaction not found")

    if event.status == "blocked":
        raise HTTPException(status_code=400, detail="Transaction is blocked. Wait for cooldown to expire.")

    if event.step_up_required and not req.step_up_completed:
        raise HTTPException(status_code=400, detail="Step-up verification required before confirming.")

    if event.status == "completed":
        if req.tx_hash and event.tx_hash == req.tx_hash:
            return {
                "transaction_id": event.id,
                "status": "completed",
                "tx_hash": event.tx_hash,
                "network": event_network(event),
                "explorer_url": event_explorer_url(event),
            }
        raise HTTPException(status_code=400, detail="Transaction already completed with a different tx hash.")

    verification = verify_algorand_payment(
        tx_id=req.tx_hash or "",
        sender_wallet=event.sender_wallet,
        recipient_wallet=event.recipient_wallet,
        amount_algo=event.amount_eth,
    )

    if event.network and event.network != verification["network"]:
        raise HTTPException(status_code=400, detail="Transaction network does not match the evaluated transfer.")

    event.status = "completed"
    event.tx_hash = verification["tx_id"]
    event.step_up_completed = bool(req.step_up_completed)
    event.network = verification["network"]
    await db.commit()

    return {
        "transaction_id": event.id,
        "status": "completed",
        "tx_hash": event.tx_hash,
        "network": event.network,
        "explorer_url": verification["explorer_url"],
    }


@router.get("/history")
async def get_transaction_history(
    wallet: str,
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
):
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
        "transactions": [serialize_event(event) for event in events],
        "count": len(events),
    }


@router.get("/stats")
async def get_transaction_stats(
    wallet: str,
    db: AsyncSession = Depends(get_db),
):
    w = wallet.lower()
    active_network = get_transaction_network()

    sent_result = await db.execute(
        select(func.count(), func.coalesce(func.sum(TransactionEvent.amount_eth), 0)).where(
            TransactionEvent.sender_wallet == w,
            TransactionEvent.network == active_network,
        )
    )
    sent_row = sent_result.one()
    total_sent_count = sent_row[0]
    total_sent_eth = float(sent_row[1])

    blocked_result = await db.execute(
        select(func.count()).select_from(TransactionEvent).where(
            TransactionEvent.sender_wallet == w,
            TransactionEvent.network == active_network,
            TransactionEvent.status == "blocked",
        )
    )
    blocked_count = blocked_result.scalar() or 0

    stepup_result = await db.execute(
        select(func.count()).select_from(TransactionEvent).where(
            TransactionEvent.sender_wallet == w,
            TransactionEvent.network == active_network,
            TransactionEvent.step_up_required.is_(True),
        )
    )
    stepup_count = stepup_result.scalar() or 0

    avg_result = await db.execute(
        select(func.avg(TransactionEvent.risk_score)).where(
            TransactionEvent.sender_wallet == w,
            TransactionEvent.network == active_network,
        )
    )
    avg_risk = round(float(avg_result.scalar() or 0), 4)

    return {
        "total_transactions": total_sent_count,
        "total_eth_sent": round(total_sent_eth, 6),
        "blocked_count": blocked_count,
        "step_up_count": stepup_count,
        "avg_risk_score": avg_risk,
        "network": active_network,
    }
