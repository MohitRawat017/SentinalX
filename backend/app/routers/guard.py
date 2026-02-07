"""
SentinelX GuardLayer Router
LLM + Regex data leak prevention endpoints
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

router = APIRouter()
guard = GuardLayer()


class ScanRequest(BaseModel):
    text: str
    wallet_address: Optional[str] = None
    use_llm: bool = True
    source: str = "web"  # web, sdk, api


class ScanResponse(BaseModel):
    is_risky: bool
    severity: str
    categories: list
    regex_findings: list
    llm_result: Optional[dict] = None
    content_hash: str
    event_hash: str
    scan_type: str
    message: str


class OverrideRequest(BaseModel):
    event_hash: str
    wallet_address: str
    confirmed: bool = True


# ─── Endpoints ──────────────────────────────────────────────────────

@router.post("/scan", response_model=ScanResponse)
async def scan_content(req: ScanRequest, db: AsyncSession = Depends(get_db)):
    """
    Scan text content for sensitive data leaks.
    Layer 1: Regex pattern matching (fast)
    Layer 2: LLM analysis (deep, optional)
    """
    result = await guard.scan(req.text, use_llm=req.use_llm)

    # Store guard event
    guard_event = GuardEvent(
        id=str(uuid.uuid4()),
        wallet_address=(req.wallet_address or "anonymous").lower(),
        content_hash=result["content_hash"],
        scan_type=result["scan_type"],
        risk_detected=result["is_risky"],
        risk_categories=result["categories"],
        llm_response=str(result.get("llm_result")),
        user_override=False,
        event_hash=result["event_hash"],
        timestamp=datetime.utcnow(),
    )
    db.add(guard_event)
    await db.commit()

    # Add to Merkle batch
    batcher = MerkleBatcher.get_instance()
    batcher.add_event(result["event_hash"], event_type="guard", metadata={
        "wallet": req.wallet_address or "anonymous",
        "is_risky": result["is_risky"],
        "severity": result["severity"],
    })

    message = ""
    if result["is_risky"]:
        message = f"⚠️ Sensitive data detected ({result['severity']}): {', '.join(result['categories'])}. Are you sure you want to send this?"
    else:
        message = "✅ Content looks clean. No sensitive data detected."

    return ScanResponse(
        is_risky=result["is_risky"],
        severity=result["severity"],
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
    """User explicitly overrides a guard warning and sends anyway"""
    result = await db.execute(
        select(GuardEvent).where(GuardEvent.event_hash == req.event_hash)
    )
    event = result.scalar_one_or_none()

    if event:
        event.user_override = req.confirmed
        await db.commit()

    # Log override to Merkle batch
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
    """Get guard event history"""
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
    """Get aggregate guard statistics"""
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
