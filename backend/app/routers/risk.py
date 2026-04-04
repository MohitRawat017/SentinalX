"""
╔═══════════════════════════════════════════════════════════════════════════════╗
║                     SentinelX Risk Engine Router                              ║
║                     AI-Based Login Anomaly Detection API                      ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║ PURPOSE: Expose RiskEngine functionality via REST API endpoints               ║
║                                                                               ║
║ ═════════════════════════════════════════════════════════════════════════════║
║ ENDPOINTS PROVIDED:                                                           ║
║ ═════════════════════════════════════════════════════════════════════════════║
║                                                                               ║
║ POST /risk/score     - Compute risk score for a login attempt                ║
║ GET  /risk/timeline  - Get risk score history for dashboard                 ║
║ GET  /risk/map       - Get login coordinates for map visualization          ║
║ GET  /risk/stats     - Get aggregate risk statistics                         ║
║                                                                               ║
║ ═════════════════════════════════════════════════════════════════════════════║
║ HOW THIS FITS IN THE ARCHITECTURE:                                           ║
║ ═════════════════════════════════════════════════════════════════════════════║
║                                                                               ║
║ This router is a THIN LAYER that:                                             ║
║ 1. Receives HTTP requests                                                    ║
║ 2. Validates input via Pydantic models                                       ║
║ 3. Calls RiskEngine service for actual computation                           ║
║ 4. Returns formatted response                                                 ║
║                                                                               ║
║ The BUSINESS LOGIC is in services/risk_engine.py                              ║
║ This file just handles HTTP concerns (routing, validation, response format)  ║
║                                                                               ║
║ INTERVIEW QUESTION: Why separate routers from services?                      ║
║ ANSWER: Separation of Concerns:                                              ║
║ - Router: HTTP layer (parsing, validation, serialization)                    ║
║ - Service: Business logic (algorithms, rules, computation)                   ║
║ Benefits:                                                                     ║
║ - Service can be tested without HTTP                                         ║
║ - Service can be called from other places (not just this router)            ║
║ - Router can be changed without affecting logic                              ║
╚═══════════════════════════════════════════════════════════════════════════════╝
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


# ───────────────────────────────────────────────────────────────────────────────
# ROUTER SETUP
# ───────────────────────────────────────────────────────────────────────────────
router = APIRouter()


# ───────────────────────────────────────────────────────────────────────────────
# REQUEST/RESPONSE MODELS
# ───────────────────────────────────────────────────────────────────────────────
"""
Pydantic models for request validation and response serialization.
These define the API contract between frontend and backend.
"""

class RiskScoreRequest(BaseModel):
    """
    Request to compute a risk score.
    
    Used for:
    - Standalone risk assessment (not part of login flow)
    - Testing and debugging risk engine
    - Manual risk evaluation
    """
    wallet_address: str
    ip_address: str = "0.0.0.0"
    user_agent: str = ""
    geo_country: Optional[str] = None
    current_hour: Optional[int] = None  # For testing time-based rules


class RiskScoreResponse(BaseModel):
    """
    Risk score response.
    
    Contains the computed score plus detailed explanation
    for dashboard display and debugging.
    """
    risk_score: float      # 0.0 to 1.0
    risk_level: str        # "low", "medium", or "high"
    features: dict         # Individual factor values
    explanation: dict      # Full breakdown with contributions


class TimelinePoint(BaseModel):
    """Single point on the risk timeline for visualization."""
    timestamp: str
    risk_score: float
    risk_level: str
    ip_address: Optional[str] = None
    geo_country: Optional[str] = None


# ═══════════════════════════════════════════════════════════════════════════════
# ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════════

@router.post("/score", response_model=RiskScoreResponse)
async def compute_risk_score(req: RiskScoreRequest, db: AsyncSession = Depends(get_db)):
    """
    ╔═══════════════════════════════════════════════════════════════════════════╗
    ║ COMPUTE RISK SCORE FOR A LOGIN ATTEMPT                                    ║
    ╠═══════════════════════════════════════════════════════════════════════════╣
    ║                                                                           ║
    ║ STANDALONE ENDPOINT - Not part of the main auth flow                      ║
    ║ Used for testing, debugging, and manual risk assessment                   ║
    ║                                                                           ║
    ║ MAIN AUTH FLOW: Use POST /auth/verify instead (combines auth + risk)      ║
    ║                                                                           ║
    ║ RESPONSE INCLUDES:                                                         ║
    ║ - risk_score: Weighted normalized score (0.0-1.0)                         ║
    ║ - risk_level: Categorical ("low", "medium", "high")                       ║
    ║ - features: Individual factor values for each risk factor                 ║
    ║ - explanation: Full breakdown with weights and contributions              ║
    ╚═══════════════════════════════════════════════════════════════════════════╝
    """
    # Get singleton instance of RiskEngine
    engine = RiskEngine.get_instance()
    
    # Compute risk score using the service
    risk_score, risk_level, explanation = await engine.score(
        db=db,
        wallet_address=req.wallet_address,
        ip_address=req.ip_address,
        user_agent=req.user_agent,
        geo_country=req.geo_country,
        current_hour=req.current_hour,
    )

    # Transform explanation into simpler format for response
    return RiskScoreResponse(
        risk_score=risk_score,
        risk_level=risk_level,
        features={f["feature"]: f["value"] for f in explanation.get("factors", [])},
        explanation=explanation,
    )


@router.get("/timeline")
async def get_risk_timeline(
    wallet_address: Optional[str] = None,
    limit: int = Query(50, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
):
    """
    ╔═══════════════════════════════════════════════════════════════════════════╗
    ║ GET RISK SCORE TIMELINE FOR DASHBOARD VISUALIZATION                       ║
    ╠═══════════════════════════════════════════════════════════════════════════╣
    ║                                                                           ║
    ║ PURPOSE: Provide data for the risk timeline chart in the dashboard        ║
    ║                                                                           ║
    ║ RETURNS:                                                                   ║
    ║ - Ordered list of login events with risk scores                           ║
    ║ - IP addresses (hashed, truncated for privacy)                            ║
    ║ - Geographic data (country, city)                                         ║
    ║ - Event hashes for audit verification                                     ║
    ║                                                                           ║
    ║ FRONTEND USAGE:                                                            ║
    ║ - Line chart showing risk score over time                                 ║
    ║ - Color coding by risk level (green/yellow/red)                           ║
    ║ - Tooltips with details on hover                                          ║
    ╚═══════════════════════════════════════════════════════════════════════════╝
    """
    # Build query with optional wallet filter
    query = select(LoginEvent).order_by(desc(LoginEvent.timestamp)).limit(limit)
    if wallet_address:
        query = query.where(LoginEvent.wallet_address == wallet_address.lower())

    result = await db.execute(query)
    events = result.scalars().all()

    # Transform events into timeline format
    # Reversed to show oldest → newest (chronological order for charts)
    timeline = []
    for event in reversed(events):
        timeline.append({
            "timestamp": event.timestamp.isoformat() + "Z" if event.timestamp else None,
            "risk_score": event.risk_score,
            "risk_level": event.risk_level,
            # Truncate IP hash for privacy (don't expose full hash)
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
    """
    ╔═══════════════════════════════════════════════════════════════════════════╗
    ║ GET LOGIN ORIGIN COORDINATES FOR MAP VISUALIZATION                        ║
    ╠═══════════════════════════════════════════════════════════════════════════╣
    ║                                                                           ║
    ║ PURPOSE: Provide data for the world map showing login locations           ║
    ║                                                                           ║
    ║ FILTERS:                                                                   ║
    ║ - wallet_address: Filter to specific user                                 ║
    ║ - limit: Max number of points (default 100)                               ║
    ║                                                                           ║
    ║ RETURNS:                                                                   ║
    ║ - lat/lng coordinates for map markers                                     ║
    ║ - Risk score for marker color                                             ║
    ║ - Location info for tooltips                                              ║
    ║                                                                           ║
    ║ NOTE: Only includes events with valid coordinates                         ║
    ║ (geolocation may not be available for all logins)                         ║
    ╚═══════════════════════════════════════════════════════════════════════════╝
    """
    query = select(LoginEvent).order_by(desc(LoginEvent.timestamp)).limit(limit)
    if wallet_address:
        query = query.where(LoginEvent.wallet_address == wallet_address.lower())

    result = await db.execute(query)
    events = result.scalars().all()

    # Only include events with valid coordinates
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
    """
    ╔═══════════════════════════════════════════════════════════════════════════╗
    ║ GET AGGREGATE RISK STATISTICS                                              ║
    ╠═══════════════════════════════════════════════════════════════════════════╣
    ║                                                                           ║
    ║ PURPOSE: Provide summary statistics for dashboard cards                    ║
    ║                                                                           ║
    ║ RETURNS:                                                                   ║
    ║ - total_logins: Count of all login events                                 ║
    ║ - avg_risk_score: Mean risk score across all logins                       ║
    ║ - high/medium/low_risk_count: Breakdown by risk level                     ║
    ║ - step_up_triggered: How many required additional verification            ║
    ║ - unique_countries: List of countries logins came from                    ║
    ║ - latest_score: Most recent risk score                                    ║
    ║                                                                           ║
    ║ DASHBOARD USAGE:                                                           ║
    ║ - StatsCards component displays these numbers                             ║
    ║ - Used for security overview at a glance                                  ║
    ╚═══════════════════════════════════════════════════════════════════════════╝
    """
    query = select(LoginEvent)
    if wallet_address:
        query = query.where(LoginEvent.wallet_address == wallet_address.lower())

    result = await db.execute(query)
    events = result.scalars().all()

    # Handle empty case
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

    # Compute statistics
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


# ═══════════════════════════════════════════════════════════════════════════════
# INTERVIEW QUESTIONS FOR risk.py
# ═══════════════════════════════════════════════════════════════════════════════
"""
Q1: Why use Query parameters for optional filters instead of path parameters?
A1: Query parameters are better for:
    - Optional filtering (wallet_address is optional)
    - Multiple filters can be combined
    - Default values (limit=50)
    - Validation (ge=1, le=500 for limit)
    
    Path parameters are for required resource identification.

Q2: Why truncate the IP hash in timeline response?
A2: Defense in depth:
    - Even though it's already hashed, showing less is better
    - Prevents potential correlation attacks
    - Users can still identify same IPs by comparing prefixes
    - Full hash only needed for verification, not display

Q3: How would you add pagination to the timeline endpoint?
A3: Use offset-based or cursor-based pagination:
    
    Offset-based:
    @router.get("/timeline")
    async def get_timeline(
        offset: int = Query(0, ge=0),
        limit: int = Query(50, ge=1, le=500),
        ...
    ):
        query = query.offset(offset).limit(limit)
    
    Cursor-based (better for real-time data):
    @router.get("/timeline")
    async def get_timeline(
        cursor: Optional[str] = None,  # Last event's timestamp
        limit: int = Query(50),
        ...
    ):
        if cursor:
            query = query.where(LoginEvent.timestamp < cursor)
        query = query.limit(limit)

Q4: Why is the timeline reversed before returning?
A4: Database query returns newest first (DESC).
    Charts typically show oldest → newest (left to right).
    We reverse to get chronological order for visualization.

Q5: What's the difference between /risk/score and /auth/verify?
A5: /risk/score:
    - Standalone risk assessment
    - Does NOT create login event
    - Does NOT issue JWT
    - Used for testing/debugging
    
    /auth/verify:
    - Full authentication flow
    - Creates login event in DB
    - Runs risk scoring
    - Issues JWT token
    - Used for actual login
"""