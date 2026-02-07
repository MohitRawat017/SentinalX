"""
SentinelX Risk Engine Router
AI-based login anomaly detection endpoints
"""
import uuid
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.models import LoginEvent
from app.services.risk_engine import RiskEngine

router = APIRouter()


class RiskScoreRequest(BaseModel):
    wallet_address: str
    ip_address: str = "0.0.0.0"
    user_agent: str = ""
    current_hour: Optional[int] = None


class RiskScoreResponse(BaseModel):
    risk_score: float
    risk_level: str
    features: dict
    explanation: dict


class TimelinePoint(BaseModel):
    timestamp: str
    risk_score: float
    risk_level: str
    ip_address: Optional[str] = None
    geo_country: Optional[str] = None


# ─── Endpoints ──────────────────────────────────────────────────────

@router.post("/score", response_model=RiskScoreResponse)
async def compute_risk_score(req: RiskScoreRequest):
    """Compute risk score for a login attempt (standalone, without auth flow)"""
    engine = RiskEngine.get_instance()
    features = engine.compute_features(
        ip_address=req.ip_address,
        user_agent=req.user_agent,
        wallet_address=req.wallet_address,
        current_hour=req.current_hour,
    )
    risk_score, risk_level, explanation = engine.score(features)

    return RiskScoreResponse(
        risk_score=risk_score,
        risk_level=risk_level,
        features=features,
        explanation=explanation,
    )


@router.get("/timeline")
async def get_risk_timeline(
    wallet_address: Optional[str] = None,
    limit: int = Query(50, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
):
    """Get risk score timeline for dashboard visualization"""
    query = select(LoginEvent).order_by(desc(LoginEvent.timestamp)).limit(limit)
    if wallet_address:
        query = query.where(LoginEvent.wallet_address == wallet_address.lower())

    result = await db.execute(query)
    events = result.scalars().all()

    timeline = []
    for event in reversed(events):
        timeline.append({
            "timestamp": event.timestamp.isoformat() + "Z" if event.timestamp else None,
            "risk_score": event.risk_score,
            "risk_level": event.risk_level,
            "ip_address": event.ip_hash[:12] + "..." if event.ip_hash else None,
            "geo_country": event.geo_country,
            "geo_city": event.geo_city,
            "wallet_address": event.wallet_address,
            "event_hash": event.event_hash,
        })

    return {"timeline": timeline, "count": len(timeline)}


@router.get("/map")
async def get_login_map(
    wallet_address: Optional[str] = None,
    limit: int = Query(100, ge=1, le=1000),
    db: AsyncSession = Depends(get_db),
):
    """Get login origin coordinates for map visualization"""
    query = select(LoginEvent).order_by(desc(LoginEvent.timestamp)).limit(limit)
    if wallet_address:
        query = query.where(LoginEvent.wallet_address == wallet_address.lower())

    result = await db.execute(query)
    events = result.scalars().all()

    points = []
    for event in events:
        if event.geo_lat and event.geo_lng:
            points.append({
                "lat": event.geo_lat,
                "lng": event.geo_lng,
                "risk_score": event.risk_score,
                "risk_level": event.risk_level,
                "country": event.geo_country,
                "city": event.geo_city,
                "timestamp": event.timestamp.isoformat() + "Z" if event.timestamp else None,
            })

    return {"points": points, "count": len(points)}


@router.get("/stats")
async def get_risk_stats(
    wallet_address: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    """Get aggregate risk statistics"""
    query = select(LoginEvent)
    if wallet_address:
        query = query.where(LoginEvent.wallet_address == wallet_address.lower())

    result = await db.execute(query)
    events = result.scalars().all()

    if not events:
        return {
            "total_logins": 0,
            "avg_risk_score": 0,
            "high_risk_count": 0,
            "medium_risk_count": 0,
            "low_risk_count": 0,
            "step_up_triggered": 0,
            "unique_countries": [],
        }

    scores = [e.risk_score for e in events]
    countries = list(set(e.geo_country for e in events if e.geo_country))

    return {
        "total_logins": len(events),
        "avg_risk_score": round(sum(scores) / len(scores), 4),
        "high_risk_count": sum(1 for e in events if e.risk_level == "high"),
        "medium_risk_count": sum(1 for e in events if e.risk_level == "medium"),
        "low_risk_count": sum(1 for e in events if e.risk_level == "low"),
        "step_up_triggered": sum(1 for e in events if e.step_up_required),
        "unique_countries": countries,
        "latest_score": scores[-1] if scores else 0,
    }
