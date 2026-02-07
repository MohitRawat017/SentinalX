"""
SentinelX Simulation Router
Live attack simulation for demo mode
"""
import hashlib
import json
import random
import uuid
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.models import LoginEvent, GuardEvent
from app.services.risk_engine import RiskEngine
from app.services.guard_layer import GuardLayer
from app.services.merkle import MerkleBatcher

router = APIRouter()

# ─── Simulation Scenarios ───────────────────────────────────────────

SUSPICIOUS_IPS = [
    {"ip": "185.220.101.42", "country": "Russia", "city": "Moscow", "lat": 55.7558, "lng": 37.6173},
    {"ip": "103.75.190.11", "country": "Nigeria", "city": "Lagos", "lat": 6.5244, "lng": 3.3792},
    {"ip": "45.33.32.156", "country": "China", "city": "Beijing", "lat": 39.9042, "lng": 116.4074},
    {"ip": "198.51.100.23", "country": "Iran", "city": "Tehran", "lat": 35.6892, "lng": 51.3890},
    {"ip": "91.108.56.12", "country": "Brazil", "city": "Sao Paulo", "lat": -23.5505, "lng": -46.6333},
]

NORMAL_IPS = [
    {"ip": "73.162.48.93", "country": "United States", "city": "San Francisco", "lat": 37.7749, "lng": -122.4194},
    {"ip": "82.132.225.11", "country": "United Kingdom", "city": "London", "lat": 51.5074, "lng": -0.1278},
    {"ip": "192.168.1.100", "country": "United States", "city": "New York", "lat": 40.7128, "lng": -74.0060},
]

SENSITIVE_TEXTS = [
    "My credit card number is 4532015112830366 and the CVV is 123",
    "Password: SuperSecret123! for admin@company.com",
    "SSN: 123-45-6789, DOB: 01/15/1990",
    "API key: sk_live_FAKE_KEY_FOR_DEMO_ONLY, don't share this",
    "CONFIDENTIAL: Q3 revenue was $4.2M, do not share externally",
    "My private key is 0x[REDACTED_64_HEX_CHARS_FOR_DEMO]",
    "Send $5000 to account 1234567890, routing 021000021",
    "Patient diagnosis: Type 2 diabetes, prescribed metformin 500mg",
]

CLEAN_TEXTS = [
    "Hey, the meeting is at 3pm tomorrow. See you there!",
    "Can you review the PR? I added some tests.",
    "The weather looks great this weekend for hiking.",
]

WALLETS = [
    "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD28",
    "0x1234567890abcdef1234567890abcdef12345678",
    "0xdead000000000000000000000000000000000000",
    "0xAb5801a7D398351b8bE11C439e05C5B3259aeC9B",
    "0xBE0eB53F46cd790Cd13851d5EFf43D12404d33E8",
]


class SimulationRequest(BaseModel):
    scenario: str  # suspicious_login, normal_login, data_leak, clean_text, burst_attack, full_demo
    wallet_address: Optional[str] = None
    count: int = 1


# ─── Endpoints ──────────────────────────────────────────────────────

@router.post("/run")
async def run_simulation(req: SimulationRequest, db: AsyncSession = Depends(get_db)):
    """Run an attack simulation scenario"""
    wallet = req.wallet_address or random.choice(WALLETS)
    results = []

    if req.scenario == "suspicious_login":
        results = await _simulate_suspicious_login(wallet, req.count, db)
    elif req.scenario == "normal_login":
        results = await _simulate_normal_login(wallet, req.count, db)
    elif req.scenario == "data_leak":
        results = await _simulate_data_leak(wallet, req.count, db)
    elif req.scenario == "clean_text":
        results = await _simulate_clean_text(wallet, req.count, db)
    elif req.scenario == "burst_attack":
        results = await _simulate_burst_attack(wallet, db)
    elif req.scenario == "full_demo":
        results = await _simulate_full_demo(wallet, db)
    else:
        return {"error": f"Unknown scenario: {req.scenario}"}

    return {
        "scenario": req.scenario,
        "results": results,
        "count": len(results) if isinstance(results, list) else 1,
        "wallet": wallet,
    }


@router.get("/scenarios")
async def list_scenarios():
    """List available simulation scenarios"""
    return {
        "scenarios": [
            {"id": "suspicious_login", "name": "Suspicious Login", "description": "Login from a suspicious IP with unusual device fingerprint"},
            {"id": "normal_login", "name": "Normal Login", "description": "Standard login from a known IP"},
            {"id": "data_leak", "name": "Data Leak Attempt", "description": "User tries to send sensitive data (credit card, SSN, etc.)"},
            {"id": "clean_text", "name": "Clean Text", "description": "Normal text that passes GuardLayer checks"},
            {"id": "burst_attack", "name": "Burst Attack", "description": "Rapid-fire login attempts simulating a brute force attack"},
            {"id": "full_demo", "name": "Full Demo", "description": "Complete scenario: normal login -> suspicious login -> data leak -> burst attack"},
        ]
    }


# ─── Simulation Implementations ─────────────────────────────────────

async def _simulate_suspicious_login(wallet: str, count: int, db: AsyncSession):
    results = []
    risk_engine = RiskEngine.get_instance()
    batcher = MerkleBatcher.get_instance()

    for i in range(min(count, 10)):
        ip_info = random.choice(SUSPICIOUS_IPS)

        risk_score, risk_level, explanation = await risk_engine.score(
            db=db,
            wallet_address=wallet,
            ip_address=ip_info["ip"],
            user_agent="Mozilla/5.0 (Linux; Android 4.4) AppleWebKit/537.36 UnknownBot/1.0",
            geo_country=ip_info["country"],
            current_hour=random.choice([1, 2, 3, 4, 23]),
        )
        # Amplify risk for demo: ensure high score
        risk_score = max(risk_score, 0.7)
        risk_level = "high"

        event_data = json.dumps({
            "wallet": wallet.lower(), "ip": ip_info["ip"],
            "risk_score": risk_score, "sim": True,
            "timestamp": datetime.utcnow().isoformat(),
        }, sort_keys=True)
        event_hash = hashlib.sha256(event_data.encode()).hexdigest()

        features = {f["feature"]: f["value"] for f in explanation.get("factors", [])}

        login_event = LoginEvent(
            id=str(uuid.uuid4()),
            wallet_address=wallet.lower(),
            ip_address=ip_info["ip"],
            ip_hash=hashlib.sha256(ip_info["ip"].encode()).hexdigest(),
            user_agent="UnknownBot/1.0",
            geo_lat=ip_info["lat"],
            geo_lng=ip_info["lng"],
            geo_country=ip_info["country"],
            geo_city=ip_info["city"],
            risk_score=risk_score,
            risk_level=risk_level,
            risk_features=features,
            step_up_required=True,
            event_hash=event_hash,
            timestamp=datetime.utcnow() - timedelta(minutes=random.randint(0, 60)),
        )
        db.add(login_event)
        batcher.add_event(event_hash, "login_sim", {"country": ip_info["country"]})

        results.append({
            "type": "suspicious_login",
            "risk_score": risk_score,
            "risk_level": risk_level,
            "ip": ip_info["ip"],
            "country": ip_info["country"],
            "city": ip_info["city"],
            "event_hash": event_hash,
            "features": features,
            "explanation": explanation,
        })

    await db.commit()
    return results


async def _simulate_normal_login(wallet: str, count: int, db: AsyncSession):
    results = []
    risk_engine = RiskEngine.get_instance()
    batcher = MerkleBatcher.get_instance()

    for i in range(min(count, 10)):
        ip_info = random.choice(NORMAL_IPS)

        risk_score, risk_level, explanation = await risk_engine.score(
            db=db,
            wallet_address=wallet,
            ip_address=ip_info["ip"],
            user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/120.0",
            geo_country=ip_info["country"],
            current_hour=random.choice([9, 10, 11, 14, 15, 16]),
        )

        event_data = json.dumps({
            "wallet": wallet.lower(), "ip": ip_info["ip"],
            "risk_score": risk_score, "sim": True,
            "timestamp": datetime.utcnow().isoformat(),
        }, sort_keys=True)
        event_hash = hashlib.sha256(event_data.encode()).hexdigest()

        login_event = LoginEvent(
            id=str(uuid.uuid4()),
            wallet_address=wallet.lower(),
            ip_address=ip_info["ip"],
            ip_hash=hashlib.sha256(ip_info["ip"].encode()).hexdigest(),
            user_agent="Chrome/120.0",
            geo_lat=ip_info["lat"],
            geo_lng=ip_info["lng"],
            geo_country=ip_info["country"],
            geo_city=ip_info["city"],
            risk_score=risk_score,
            risk_level=risk_level,
            risk_features={f["feature"]: f["value"] for f in explanation.get("factors", [])},
            event_hash=event_hash,
            timestamp=datetime.utcnow() - timedelta(minutes=random.randint(0, 120)),
        )
        db.add(login_event)
        batcher.add_event(event_hash, "login_sim")

        results.append({
            "type": "normal_login",
            "risk_score": risk_score,
            "risk_level": risk_level,
            "ip": ip_info["ip"],
            "country": ip_info["country"],
            "event_hash": event_hash,
        })

    await db.commit()
    return results


async def _simulate_data_leak(wallet: str, count: int, db: AsyncSession):
    results = []
    guard = GuardLayer()
    batcher = MerkleBatcher.get_instance()

    for i in range(min(count, len(SENSITIVE_TEXTS))):
        text = SENSITIVE_TEXTS[i % len(SENSITIVE_TEXTS)]
        scan_result = await guard.scan(text, use_llm=False)  # Regex only for speed

        guard_event = GuardEvent(
            id=str(uuid.uuid4()),
            wallet_address=wallet.lower(),
            content_hash=scan_result["content_hash"],
            scan_type="regex",
            risk_detected=scan_result["is_risky"],
            risk_categories=scan_result["categories"],
            user_override=random.choice([True, False]),
            event_hash=scan_result["event_hash"],
            timestamp=datetime.utcnow() - timedelta(minutes=random.randint(0, 60)),
        )
        db.add(guard_event)
        batcher.add_event(scan_result["event_hash"], "guard_sim")

        results.append({
            "type": "data_leak",
            "text_preview": text[:50] + "...",
            "is_risky": scan_result["is_risky"],
            "severity": scan_result["severity"],
            "categories": scan_result["categories"],
            "event_hash": scan_result["event_hash"],
        })

    await db.commit()
    return results


async def _simulate_clean_text(wallet: str, count: int, db: AsyncSession):
    results = []
    guard = GuardLayer()

    for i in range(min(count, len(CLEAN_TEXTS))):
        text = CLEAN_TEXTS[i % len(CLEAN_TEXTS)]
        scan_result = await guard.scan(text, use_llm=False)

        results.append({
            "type": "clean_text",
            "text_preview": text[:50],
            "is_risky": scan_result["is_risky"],
            "severity": scan_result["severity"],
        })

    return results


async def _simulate_burst_attack(wallet: str, db: AsyncSession):
    """Simulate rapid-fire login burst (brute force attempt)"""
    results = []
    risk_engine = RiskEngine.get_instance()
    batcher = MerkleBatcher.get_instance()

    for i in range(8):
        ip_info = random.choice(SUSPICIOUS_IPS)

        risk_score, risk_level, explanation = await risk_engine.score(
            db=db,
            wallet_address=wallet,
            ip_address=ip_info["ip"],
            user_agent=f"Bot-Scanner/{random.randint(1,99)}",
            geo_country=ip_info["country"],
            current_hour=3,
        )
        # Amplify for demo
        risk_score = max(risk_score, 0.75)
        risk_level = "high"

        event_data = json.dumps({
            "wallet": wallet.lower(), "burst": i,
            "timestamp": datetime.utcnow().isoformat(),
        }, sort_keys=True)
        event_hash = hashlib.sha256(event_data.encode()).hexdigest()

        login_event = LoginEvent(
            id=str(uuid.uuid4()),
            wallet_address=wallet.lower(),
            ip_address=ip_info["ip"],
            ip_hash=hashlib.sha256(ip_info["ip"].encode()).hexdigest(),
            user_agent=f"Bot-Scanner/{random.randint(1,99)}",
            geo_lat=ip_info["lat"],
            geo_lng=ip_info["lng"],
            geo_country=ip_info["country"],
            geo_city=ip_info["city"],
            risk_score=risk_score,
            risk_level=risk_level,
            risk_features={f["feature"]: f["value"] for f in explanation.get("factors", [])},
            step_up_required=True,
            event_hash=event_hash,
            timestamp=datetime.utcnow() - timedelta(seconds=i * 3),
        )
        db.add(login_event)
        batcher.add_event(event_hash, "burst_sim")

        results.append({
            "type": "burst_attack",
            "attempt": i + 1,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "country": ip_info["country"],
        })

    await db.commit()
    return results


async def _simulate_full_demo(wallet: str, db: AsyncSession):
    """Run full demo sequence"""
    results = []

    # Phase 1: Normal logins
    normal = await _simulate_normal_login(wallet, 3, db)
    results.extend([{**r, "phase": "1_normal"} for r in normal])

    # Phase 2: Suspicious login
    suspicious = await _simulate_suspicious_login(wallet, 2, db)
    results.extend([{**r, "phase": "2_suspicious"} for r in suspicious])

    # Phase 3: Data leak attempts
    leaks = await _simulate_data_leak(wallet, 3, db)
    results.extend([{**r, "phase": "3_data_leak"} for r in leaks])

    # Phase 4: Burst attack
    burst = await _simulate_burst_attack(wallet, db)
    results.extend([{**r, "phase": "4_burst"} for r in burst])

    # Force create a Merkle batch
    batcher = MerkleBatcher.get_instance()
    batch = batcher.create_batch()

    batch_info = None
    if batch:
        batch_info = {
            "merkle_root": batch["merkle_root"],
            "event_count": batch["event_count"],
        }

    return {
        "phases": results,
        "total_events": len(results),
        "merkle_batch": batch_info,
        "summary": f"Demo complete: {len(normal)} normal logins, {len(suspicious)} suspicious logins, {len(leaks)} data leak attempts, {len(burst)} burst attacks.",
    }
