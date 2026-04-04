"""
╔═══════════════════════════════════════════════════════════════════════════════╗
║                     SentinelX Dashboard Router                               ║
║                     Aggregated Dashboard Data API                             ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║ PURPOSE: Provide aggregated data for the frontend dashboard                   ║
║                                                                               ║
║ ═════════════════════════════════════════════════════════════════════════════║
║ WHAT THIS ROUTER PROVIDES:                                                    ║
║ ═════════════════════════════════════════════════════════════════════════════║
║                                                                               ║
║ 1. OVERVIEW DATA                                                              ║
║    - Statistics cards (total logins, avg risk, threats detected)             ║
║    - Trust score with level indicator                                        ║
║    - Risk timeline for charts                                                ║
║    - Map points for geographic visualization                                 ║
║    - Recent events lists                                                     ║
║                                                                               ║
║ 2. SECURITY REPORT                                                            ║
║    - AI-generated markdown report                                            ║
║    - Threat level assessment                                                 ║
║    - Summary statistics                                                      ║
║                                                                               ║
║ 3. TRUST SCORE                                                                ║
║    - Computed from all event types                                           ║
║    - Includes recency decay                                                  ║
║    - Returns both score and level                                            ║
║                                                                               ║
║ ═════════════════════════════════════════════════════════════════════════════║
║ ENDPOINTS PROVIDED:                                                           ║
║ ═════════════════════════════════════════════════════════════════════════════║
║                                                                               ║
║ GET /dashboard/overview        - Complete dashboard data                     ║
║ GET /dashboard/security-report - AI security report                          ║
║ GET /dashboard/trust-score     - Trust score for specific wallet             ║
║                                                                               ║
║ INTERVIEW QUESTION: Why separate dashboard from other routers?               ║
║ ANSWER: Separation of concerns:                                              ║
║ - Other routers handle ACTIONS (login, scan, transfer)                       ║
║ - Dashboard router handles AGGREGATION (stats, reports)                      ║
║ - Frontend needs single endpoint for dashboard load                          ║
║ - Keeps other routers focused on their domain                                ║
╚═══════════════════════════════════════════════════════════════════════════════╝
"""
import hashlib
import json
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends
from sqlalchemy import select, desc, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.models import LoginEvent, GuardEvent, TransactionEvent
from app.services.merkle import MerkleBatcher
from app.services.enforcement import SecurityEnforcement
from app.services.blockchain import get_transaction_network
from app.config import settings


# ───────────────────────────────────────────────────────────────────────────────
# ROUTER SETUP
# ───────────────────────────────────────────────────────────────────────────────
router = APIRouter()


# ═══════════════════════════════════════════════════════════════════════════════
# ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════════

@router.get("/overview")
async def get_overview(
    wallet_address: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    """
    ╔═══════════════════════════════════════════════════════════════════════════╗
    ║ GET COMPLETE DASHBOARD OVERVIEW DATA                                       ║
    ╠═══════════════════════════════════════════════════════════════════════════╣
    ║                                                                           ║
    ║ THIS IS THE MAIN DASHBOARD ENDPOINT                                       ║
    ║                                                                           ║
    ║ RETURNS:                                                                   ║
    ║ - stats: Aggregate statistics for cards                                   ║
    ║ - trust_score: Current trust level                                        ║
    ║ - enforcement: Security enforcement state                                 ║
    ║ - risk_timeline: For line chart                                           ║
    ║ - map_points: For world map                                               ║
    ║ - recent_logins: Recent login list                                        ║
    ║ - recent_guard_events: Recent DLP events                                  ║
    ║ - audit_batches: Merkle batch list                                        ║
    ║                                                                           ║
    ║ FILTERING:                                                                 ║
    ║ - No wallet_address: System-wide statistics                               ║
    ║ - With wallet_address: User-specific data                                 ║
    ╚═══════════════════════════════════════════════════════════════════════════╝
    """
    # ─── FETCH LOGIN EVENTS ─────────────────────────────────────────────
    login_query = select(LoginEvent).order_by(desc(LoginEvent.timestamp)).limit(100)
    if wallet_address:
        login_query = login_query.where(LoginEvent.wallet_address == wallet_address.lower())
    login_result = await db.execute(login_query)
    login_events = login_result.scalars().all()

    # ─── FETCH GUARD EVENTS ─────────────────────────────────────────────
    guard_query = select(GuardEvent).order_by(desc(GuardEvent.timestamp)).limit(100)
    if wallet_address:
        guard_query = guard_query.where(GuardEvent.wallet_address == wallet_address.lower())
    guard_result = await db.execute(guard_query)
    guard_events = guard_result.scalars().all()

    # ─── FETCH TRANSACTION EVENTS ───────────────────────────────────────
    active_transaction_network = get_transaction_network()
    tx_query = (
        select(TransactionEvent)
        .where(TransactionEvent.network == active_transaction_network)
        .order_by(desc(TransactionEvent.created_at))
        .limit(100)
    )
    if wallet_address:
        w = wallet_address.lower()
        tx_query = tx_query.where(
            (TransactionEvent.sender_wallet == w) | (TransactionEvent.recipient_wallet == w)
        )
    tx_result = await db.execute(tx_query)
    tx_events = tx_result.scalars().all()

    # ─── MERKLE BATCH STATS ─────────────────────────────────────────────
    batcher = MerkleBatcher.get_instance()
    merkle_stats = batcher.get_stats()

    # ─── COMPUTE AGGREGATES ─────────────────────────────────────────────
    # Use COUNT query for accurate total (not limited by fetch limit)
    count_query = select(func.count()).select_from(LoginEvent)
    if wallet_address:
        count_query = count_query.where(LoginEvent.wallet_address == wallet_address.lower())
    count_result = await db.execute(count_query)
    total_logins = count_result.scalar() or 0

    tx_stats_query = select(
        func.count(),
        func.count().filter(TransactionEvent.status == "blocked"),
        func.coalesce(func.sum(TransactionEvent.amount_eth).filter(TransactionEvent.status == "completed"), 0),
    ).where(TransactionEvent.network == active_transaction_network)
    if wallet_address:
        tx_stats_query = tx_stats_query.where(
            (TransactionEvent.sender_wallet == wallet_address.lower()) |
            (TransactionEvent.recipient_wallet == wallet_address.lower())
        )
    tx_stats_row = (await db.execute(tx_stats_query)).one()
    total_transactions = tx_stats_row[0] or 0
    blocked_transactions = tx_stats_row[1] or 0
    total_transferred = round(float(tx_stats_row[2] or 0), 6)
    
    risk_scores = [e.risk_score for e in login_events]
    avg_risk = round(sum(risk_scores) / len(risk_scores), 4) if risk_scores else 0

    # ─── TRUST SCORE COMPUTATION ────────────────────────────────────────
    trust_score = _compute_trust_score(login_events, guard_events, tx_events)

    # ─── ENFORCEMENT STATE ──────────────────────────────────────────────
    enforcement = None
    if wallet_address:
        enforcer = SecurityEnforcement.get_instance()
        enforcement = await enforcer.evaluate_and_enforce(db, wallet_address)
        # Use the enforcement trust score (includes step-up bonus) for display
        enf_score = enforcement["trust_score"]
        if enf_score >= 80:
            enf_level = "trusted"
        elif enf_score >= 50:
            enf_level = "monitoring"
        else:
            enf_level = "high_risk"
        trust_score = {"score": enf_score, "level": enf_level}

    return {
        "stats": {
            # Login statistics
            "total_logins": total_logins,
            "avg_risk_score": avg_risk,
            "high_risk_logins": sum(1 for e in login_events if e.risk_level == "high"),
            "medium_risk_logins": sum(1 for e in login_events if e.risk_level == "medium"),
            "low_risk_logins": sum(1 for e in login_events if e.risk_level == "low"),
            # Guard (DLP) statistics
            "total_guard_scans": len(guard_events),
            "threats_detected": sum(1 for e in guard_events if e.risk_detected),
            "threats_overridden": sum(1 for e in guard_events if e.user_override),
            # Audit trail statistics
            "total_batches": merkle_stats["total_batches"],
            "events_on_chain": merkle_stats["total_events_batched"],
            "pending_events": merkle_stats["pending_events"],
            # Transaction statistics
            "total_transactions": total_transactions,
            "blocked_transactions": blocked_transactions,
            "total_eth_transferred": total_transferred,
        },
        "trust_score": trust_score,
        "enforcement": enforcement,
        # Timeline for risk chart (oldest → newest)
        "risk_timeline": [
            {
                "timestamp": e.timestamp.isoformat() + "Z" if e.timestamp else None,
                "risk_score": e.risk_score,
                "risk_level": e.risk_level,
                "country": e.geo_country,
                "city": e.geo_city,
            }
            for e in reversed(login_events)
        ],
        # Points for world map
        "map_points": [
            {
                "lat": e.geo_lat,
                "lng": e.geo_lng,
                "risk_score": e.risk_score,
                "risk_level": e.risk_level,
                "country": e.geo_country,
                "city": e.geo_city,
                "timestamp": e.timestamp.isoformat() + "Z" if e.timestamp else None,
            }
            for e in login_events
            if e.geo_lat and e.geo_lng  # Only include if we have coordinates
        ],
        # Recent logins for list view
        "recent_logins": [
            {
                "wallet": e.wallet_address,
                "risk_score": e.risk_score,
                "risk_level": e.risk_level,
                "country": e.geo_country,
                "city": e.geo_city,
                "timestamp": e.timestamp.isoformat() + "Z" if e.timestamp else None,
                "event_hash": e.event_hash,
            }
            for e in login_events[:10]
        ],
        # Recent guard events for DLP list
        "recent_guard_events": [
            {
                "content_hash": e.content_hash[:16] + "...",  # Truncated for privacy
                "risk_detected": e.risk_detected,
                "categories": e.risk_categories,
                "user_override": e.user_override,
                "timestamp": e.timestamp.isoformat() + "Z" if e.timestamp else None,
                "event_hash": e.event_hash,
            }
            for e in guard_events[:10]
        ],
        "audit_batches": merkle_stats["batches"],
    }


@router.get("/security-report")
async def generate_security_report(
    wallet_address: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    """
    ╔═══════════════════════════════════════════════════════════════════════════╗
    ║ GENERATE AN AI-POWERED SECURITY SUMMARY REPORT                             ║
    ╠═══════════════════════════════════════════════════════════════════════════╣
    ║                                                                           ║
    ║ RETURNS A MARKDOWN-FORMATTED REPORT INCLUDING:                            ║
    ║ - Login activity summary                                                   ║
    ║ - High-risk alert details                                                  ║
    ║ - Data protection statistics                                               ║
    ║ - On-chain audit status                                                    ║
    ║ - Overall threat level assessment                                          ║
    ║                                                                           ║
    ║ NOTE: This is a deterministic report (no LLM used).                        ║
    ║ For an actual AI-powered report, you would call an LLM with the data.      ║
    ╚═══════════════════════════════════════════════════════════════════════════╝
    """
    # ─── GATHER DATA ────────────────────────────────────────────────────
    login_query = select(LoginEvent).order_by(desc(LoginEvent.timestamp)).limit(50)
    if wallet_address:
        login_query = login_query.where(LoginEvent.wallet_address == wallet_address.lower())
    login_result = await db.execute(login_query)
    logins = login_result.scalars().all()

    guard_query = select(GuardEvent).order_by(desc(GuardEvent.timestamp)).limit(50)
    if wallet_address:
        guard_query = guard_query.where(GuardEvent.wallet_address == wallet_address.lower())
    guard_result = await db.execute(guard_query)
    guards = guard_result.scalars().all()

    batcher = MerkleBatcher.get_instance()

    # ─── COMPUTE STATISTICS ─────────────────────────────────────────────
    # Use COUNT query for accurate total
    count_query = select(func.count()).select_from(LoginEvent)
    if wallet_address:
        count_query = count_query.where(LoginEvent.wallet_address == wallet_address.lower())
    count_result = await db.execute(count_query)
    total_logins = count_result.scalar() or 0
    
    high_risk = [e for e in logins if e.risk_level == "high"]
    unique_countries = list(set(e.geo_country for e in logins if e.geo_country))
    threats = [e for e in guards if e.risk_detected]
    overrides = [e for e in guards if e.user_override]

    # ─── BUILD REPORT ───────────────────────────────────────────────────
    report_lines = [
        f"## 🛡️ SentinelX Security Report",
        f"**Generated:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
        "",
        f"### Login Activity",
        f"- **{total_logins}** login events analyzed",
        f"- **{len(high_risk)}** high-risk logins flagged",
        f"- **{len(unique_countries)}** unique countries: {', '.join(unique_countries[:5]) if unique_countries else 'None'}",
    ]

    # Add high-risk alerts if any
    if high_risk:
        report_lines.append(f"\n### ⚠️ High-Risk Alerts")
        for event in high_risk[:3]:
            report_lines.append(
                f"- Login from **{event.geo_city or 'Unknown'}, {event.geo_country or 'Unknown'}** "
                f"scored **{event.risk_score:.2f}** (hash: `{event.event_hash[:12]}...`)"
            )

    report_lines.extend([
        f"\n### Data Protection",
        f"- **{len(guards)}** content scans performed",
        f"- **{len(threats)}** threats detected by GuardLayer",
        f"- **{len(overrides)}** user overrides recorded",
    ])

    report_lines.extend([
        f"\n### On-Chain Audit",
        f"- **{batcher.get_stats()['total_batches']}** Merkle batches created",
        f"- **{batcher.get_stats()['total_events_batched']}** events recorded on-chain",
        f"- **{batcher.get_stats()['pending_events']}** events pending",
    ])

    # Determine overall threat level
    severity = "🟢 LOW"
    if len(high_risk) > 2:
        severity = "🔴 HIGH"
    elif len(high_risk) > 0 or len(threats) > 2:
        severity = "🟡 MEDIUM"

    report_lines.extend([
        f"\n### Overall Threat Level: {severity}",
        "",
        f"*All events are cryptographically hashed and Merkle-batched for Algorand anchoring and verification.*",
    ])

    return {
        "report": "\n".join(report_lines),
        "threat_level": severity,
        "stats": {
            "total_logins": total_logins,
            "high_risk": len(high_risk),
            "threats_detected": len(threats),
            "overrides": len(overrides),
        },
    }


# ═══════════════════════════════════════════════════════════════════════════════
# TRUST SCORE COMPUTATION
# ═══════════════════════════════════════════════════════════════════════════════

def _compute_trust_score(login_events, guard_events, tx_events) -> dict:
    """
    ╔═══════════════════════════════════════════════════════════════════════════╗
    ║ COMPUTE A UNIFIED TRUST SCORE (0-100) FROM ALL RISK ENGINES                ║
    ╠═══════════════════════════════════════════════════════════════════════════╣
    ║                                                                           ║
    ║ METHODOLOGY:                                                                ║
    ║ Base Score: 100 (perfect trust)                                           ║
    ║                                                                           ║
    ║ PENALTIES:                                                                  ║
    ║ - Login penalties (max -40 points)                                        ║
    ║   - High risk login: -10 × severity × recency                             ║
    ║   - Medium risk login: -4 × severity × recency                            ║
    ║                                                                           ║
    ║ - Guard penalties (max -30 points)                                        ║
    ║   - Risk detected: -5 × recency                                           ║
    ║   - User override: -2 × recency                                           ║
    ║                                                                           ║
    ║ - Transaction penalties (max -30 points)                                  ║
    ║   - Blocked: -12 × severity × recency                                     ║
    ║   - Cooldown active: -6 × severity × recency                              ║
    ║                                                                           ║
    ║ RECENCY DECAY:                                                              ║
    ║ - More recent events have higher impact                                   ║
    ║ - Decay factor: max(0.5, 1.0 - i * 0.015)                                 ║
    ║   - i=0 (most recent): factor = 1.0                                       ║
    ║   - i=33: factor = 0.5                                                    ║
    ║                                                                           ║
    ║ LEVELS:                                                                     ║
    ║ - 80-100: "trusted"                                                       ║
    ║ - 50-79: "monitoring"                                                     ║
    ║ - 0-49: "high_risk"                                                       ║
    ║                                                                           ║
    ║ INTERVIEW QUESTION: Why recency decay?                                    ║
    ║ ANSWER:                                                                   ║
    ║ - Old behavior shouldn't permanently penalize                            ║
    ║ - Users can improve their score over time                                 ║
    ║ - Recent events are more relevant for current risk                        ║
    ╚═══════════════════════════════════════════════════════════════════════════╝
    """
    score = 100.0

    # Login penalties (max 40)
    if login_events:
        login_penalty = 0.0
        for i, e in enumerate(login_events):
            # Recency decay: older events have less impact
            recency = max(0.5, 1.0 - i * 0.015)
            severity = e.risk_score if e.risk_score else 0.5
            if e.risk_level == "high":
                login_penalty += 10 * severity * recency
            elif e.risk_level == "medium":
                login_penalty += 4 * severity * recency
        score -= min(40, login_penalty)

    # Guard penalties (max 30)
    if guard_events:
        guard_penalty = 0.0
        for i, e in enumerate(guard_events):
            recency = max(0.5, 1.0 - i * 0.015)
            if e.risk_detected:
                guard_penalty += 5 * recency
            if e.user_override:
                guard_penalty += 2 * recency
        score -= min(30, guard_penalty)

    # Transaction penalties (max 30)
    if tx_events:
        tx_penalty = 0.0
        for i, e in enumerate(tx_events):
            recency = max(0.5, 1.0 - i * 0.015)
            severity = e.risk_score if e.risk_score else 0.5
            if e.status == "blocked":
                tx_penalty += 12 * severity * recency
            elif e.cooldown_until is not None:
                tx_penalty += 6 * severity * recency
        score -= min(30, tx_penalty)

    # Ensure score is in valid range
    score = max(0, round(score))

    # Determine level
    if score >= 80:
        level = "trusted"
    elif score >= 50:
        level = "monitoring"
    else:
        level = "high_risk"

    return {
        "score": score,
        "level": level,
    }


@router.get("/trust-score")
async def get_trust_score(
    wallet_address: str,
    db: AsyncSession = Depends(get_db),
):
    """
    Get the dynamic Trust Score for a specific wallet.
    
    This endpoint computes the trust score in real-time based on
    the user's recent activity. It's useful for:
    - Displaying trust status in UI
    - Determining if additional verification is needed
    - Tracking security posture over time
    """
    w = wallet_address.lower()

    # Fetch all relevant events
    login_result = await db.execute(
        select(LoginEvent).where(LoginEvent.wallet_address == w)
        .order_by(desc(LoginEvent.timestamp)).limit(100)
    )
    login_events = login_result.scalars().all()

    guard_result = await db.execute(
        select(GuardEvent).where(GuardEvent.wallet_address == w)
        .order_by(desc(GuardEvent.timestamp)).limit(100)
    )
    guard_events = guard_result.scalars().all()

    tx_result = await db.execute(
        select(TransactionEvent).where(
            (TransactionEvent.sender_wallet == w) | (TransactionEvent.recipient_wallet == w)
        ).order_by(desc(TransactionEvent.created_at)).limit(100)
    )
    tx_events = tx_result.scalars().all()

    return _compute_trust_score(login_events, guard_events, tx_events)


# ═══════════════════════════════════════════════════════════════════════════════
# INTERVIEW QUESTIONS FOR dashboard.py
# ═══════════════════════════════════════════════════════════════════════════════
"""
Q1: Why is the overview endpoint so complex?
A1: The dashboard needs all data at once for initial load:
    - Statistics for cards
    - Timeline for charts
    - Map points for visualization
    - Recent events for lists
    
    One endpoint prevents N+1 API calls from frontend.
    For optimization, could split into separate endpoints with caching.

Q2: Why is the trust score computed differently here vs enforcement.py?
A2: They serve different purposes:
    
    enforcement.py:
    - Used for security decisions (block, allow, step-up)
    - Includes step-up bonus for recovery
    - More strict
    
    dashboard.py:
    - Used for display purposes
    - Simpler computation
    - For quick status indication
    
    In production, should use the same algorithm for consistency.

Q3: Why limit queries to 100 events?
A3: Balance between:
    - Performance: More events = slower query
    - Accuracy: 100 recent events is representative
    - Display: Dashboard can't show thousands of items anyway
    
    For full accuracy, use COUNT queries for totals.

Q4: How would you add real-time dashboard updates?
A4: Options:
    1. WebSocket: Push updates when events occur
       - Server pushes: "new login event"
       - Frontend updates dashboard
    
    2. Polling: Frontend requests every N seconds
       - Simple but inefficient
    
    3. Server-Sent Events (SSE): One-way push
       - Simpler than WebSocket for just updates
    
    4. Reactive: Use Firebase/Supabase realtime
       - Database pushes changes automatically

Q5: How would you implement dashboard caching?
A5: Strategies:
    1. Redis cache with TTL
       - Cache overview for 30 seconds
       - Invalidate on new events
    
    2. Per-user cache
       - Different cache for each wallet
       - Only invalidate that user's cache
    
    3. Partial caching
       - Cache expensive queries (aggregates)
       - Don't cache recent events (always fresh)
    
    4. Background refresh
       - Pre-compute dashboard data in background
       - Serve from cache, update async
"""
