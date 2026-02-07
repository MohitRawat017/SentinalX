"""
SentinelX Dashboard Router
Aggregated dashboard data endpoints
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
from app.config import settings

router = APIRouter()


@router.get("/overview")
async def get_overview(
    wallet_address: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    """Get complete dashboard overview data"""
    # Login events
    login_query = select(LoginEvent).order_by(desc(LoginEvent.timestamp)).limit(100)
    if wallet_address:
        login_query = login_query.where(LoginEvent.wallet_address == wallet_address.lower())
    login_result = await db.execute(login_query)
    login_events = login_result.scalars().all()

    # Guard events
    guard_query = select(GuardEvent).order_by(desc(GuardEvent.timestamp)).limit(100)
    if wallet_address:
        guard_query = guard_query.where(GuardEvent.wallet_address == wallet_address.lower())
    guard_result = await db.execute(guard_query)
    guard_events = guard_result.scalars().all()

    # Transaction events
    tx_query = select(TransactionEvent).order_by(desc(TransactionEvent.created_at)).limit(100)
    if wallet_address:
        w = wallet_address.lower()
        tx_query = tx_query.where(
            (TransactionEvent.sender_wallet == w) | (TransactionEvent.recipient_wallet == w)
        )
    tx_result = await db.execute(tx_query)
    tx_events = tx_result.scalars().all()

    # Merkle stats
    batcher = MerkleBatcher.get_instance()
    merkle_stats = batcher.get_stats()

    # Compute aggregates - use COUNT query for accurate total (not limited by fetch limit)
    count_query = select(func.count()).select_from(LoginEvent)
    if wallet_address:
        count_query = count_query.where(LoginEvent.wallet_address == wallet_address.lower())
    count_result = await db.execute(count_query)
    total_logins = count_result.scalar() or 0
    risk_scores = [e.risk_score for e in login_events]
    avg_risk = round(sum(risk_scores) / len(risk_scores), 4) if risk_scores else 0

    # Trust score computation
    trust_score = _compute_trust_score(login_events, guard_events, tx_events)

    return {
        "stats": {
            "total_logins": total_logins,
            "avg_risk_score": avg_risk,
            "high_risk_logins": sum(1 for e in login_events if e.risk_level == "high"),
            "medium_risk_logins": sum(1 for e in login_events if e.risk_level == "medium"),
            "low_risk_logins": sum(1 for e in login_events if e.risk_level == "low"),
            "total_guard_scans": len(guard_events),
            "threats_detected": sum(1 for e in guard_events if e.risk_detected),
            "threats_overridden": sum(1 for e in guard_events if e.user_override),
            "total_batches": merkle_stats["total_batches"],
            "events_on_chain": merkle_stats["total_events_batched"],
            "pending_events": merkle_stats["pending_events"],
            "total_transactions": len(tx_events),
            "blocked_transactions": sum(1 for e in tx_events if e.status == "blocked"),
            "total_eth_transferred": round(sum(e.amount_eth for e in tx_events if e.status == "completed"), 6),
        },
        "trust_score": trust_score,
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
            if e.geo_lat and e.geo_lng
        ],
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
        "recent_guard_events": [
            {
                "content_hash": e.content_hash[:16] + "...",
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
    """Generate an AI-powered security summary report"""
    # Gather data
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

    # Build report (deterministic, no LLM needed)
    # Use COUNT query for accurate total (not limited by fetch limit)
    count_query = select(func.count()).select_from(LoginEvent)
    if wallet_address:
        count_query = count_query.where(LoginEvent.wallet_address == wallet_address.lower())
    count_result = await db.execute(count_query)
    total_logins = count_result.scalar() or 0
    high_risk = [e for e in logins if e.risk_level == "high"]
    unique_countries = list(set(e.geo_country for e in logins if e.geo_country))
    threats = [e for e in guards if e.risk_detected]
    overrides = [e for e in guards if e.user_override]

    report_lines = [
        f"## 🛡️ SentinelX Security Report",
        f"**Generated:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
        "",
        f"### Login Activity",
        f"- **{total_logins}** login events analyzed",
        f"- **{len(high_risk)}** high-risk logins flagged",
        f"- **{len(unique_countries)}** unique countries: {', '.join(unique_countries[:5]) if unique_countries else 'None'}",
    ]

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

    severity = "🟢 LOW"
    if len(high_risk) > 2:
        severity = "🔴 HIGH"
    elif len(high_risk) > 0 or len(threats) > 2:
        severity = "🟡 MEDIUM"

    report_lines.extend([
        f"\n### Overall Threat Level: {severity}",
        "",
        f"*All events are cryptographically hashed and Merkle-batched for on-chain verification on Ethereum Sepolia.*",
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


# ─── Trust Score Computation ──────────────────────────────────────────

def _compute_trust_score(login_events, guard_events, tx_events) -> dict:
    """
    Compute a unified Trust Score (0-100) from all risk engines.
    Higher = more trusted. Continuously updated.
    """
    # Start at 100, deduct for risky behavior
    score = 100.0

    # Login penalties (weight: 40%)
    if login_events:
        high_logins = sum(1 for e in login_events if e.risk_level == "high")
        medium_logins = sum(1 for e in login_events if e.risk_level == "medium")
        login_penalty = min(40, high_logins * 8 + medium_logins * 3)
        score -= login_penalty

    # Guard penalties (weight: 30%)
    if guard_events:
        threats = sum(1 for e in guard_events if e.risk_detected)
        overrides = sum(1 for e in guard_events if e.user_override)
        guard_penalty = min(30, threats * 5 + overrides * 2)
        score -= guard_penalty

    # Transaction penalties (weight: 30%)
    if tx_events:
        blocked = sum(1 for e in tx_events if e.status == "blocked")
        cooldowns = sum(1 for e in tx_events if e.cooldown_until is not None)
        tx_penalty = min(30, blocked * 10 + cooldowns * 5)
        score -= tx_penalty

    score = max(0, round(score))

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
    """Get the dynamic Trust Score for a wallet."""
    w = wallet_address.lower()

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
