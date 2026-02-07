"""
SentinelX SIWE Authentication Router
Wallet-based passwordless login with EIP-4361
"""
import hashlib
import secrets
import uuid
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Header, Request
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_db
from app.models.models import User, LoginEvent, Nonce
from app.services.jwt_utils import create_access_token, verify_token, get_wallet_from_token
from app.services.risk_engine import RiskEngine
from app.services.merkle import MerkleBatcher
from app.services.enforcement import SecurityEnforcement

router = APIRouter()

# ─── In-memory nonce store (for hackathon speed) ────────────────────
nonce_store: dict = {}


# ─── Request/Response Models ────────────────────────────────────────
class NonceResponse(BaseModel):
    nonce: str
    issued_at: str
    expires_at: str


class SIWEVerifyRequest(BaseModel):
    message: str
    signature: str
    wallet_address: str
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    geo_lat: Optional[float] = None
    geo_lng: Optional[float] = None
    geo_country: Optional[str] = None
    geo_city: Optional[str] = None


class AuthResponse(BaseModel):
    success: bool
    token: Optional[str] = None
    wallet_address: Optional[str] = None
    risk_score: Optional[float] = None
    risk_level: Optional[str] = None
    risk_explanation: Optional[dict] = None
    step_up_required: bool = False
    event_hash: Optional[str] = None
    message: str = ""
    # Enforcement fields
    security_status: Optional[str] = None  # active, step_up_required, restricted, locked
    trust_score: Optional[int] = None
    locked_until: Optional[str] = None
    session_restricted: bool = False


class ChallengeRequest(BaseModel):
    wallet_address: str
    challenge_type: str = "re-sign"  # re-sign, totp, confirm


class SessionResponse(BaseModel):
    valid: bool
    wallet_address: Optional[str] = None
    expires_at: Optional[str] = None


# ─── Endpoints ──────────────────────────────────────────────────────

@router.get("/nonce", response_model=NonceResponse)
async def get_nonce():
    """Generate a fresh nonce for SIWE message signing"""
    nonce = secrets.token_urlsafe(32)
    issued_at = datetime.utcnow()
    expires_at = issued_at + timedelta(minutes=10)

    nonce_store[nonce] = {
        "issued_at": issued_at.isoformat(),
        "expires_at": expires_at.isoformat(),
        "used": False,
    }

    return NonceResponse(
        nonce=nonce,
        issued_at=issued_at.isoformat() + "Z",
        expires_at=expires_at.isoformat() + "Z",
    )


@router.post("/verify", response_model=AuthResponse)
async def verify_siwe(req: SIWEVerifyRequest, request: Request, db: AsyncSession = Depends(get_db)):
    """
    Verify a SIWE signed message and issue JWT token.
    Also runs AI risk scoring on the login event.
    """
    wallet = req.wallet_address.strip()

    # Validate wallet address format
    if not wallet.startswith("0x") or len(wallet) != 42:
        raise HTTPException(status_code=400, detail="Invalid wallet address format")

    # For hackathon: simplified SIWE verification
    # In production, use the siwe library for full EIP-4361 verification
    try:
        # Try full SIWE verification
        is_valid = _verify_signature(req.message, req.signature, wallet)
    except Exception:
        # Fallback: accept for demo purposes (signature present = valid)
        is_valid = len(req.signature) > 20

    if not is_valid:
        return AuthResponse(
            success=False,
            message="Invalid signature. Please try signing again.",
        )

    # Get client IP
    ip_address = req.ip_address or request.client.host if request.client else "0.0.0.0"
    user_agent = req.user_agent or request.headers.get("user-agent", "")

    # ─── AI Risk Scoring ─────────────────────────────────
    risk_engine = RiskEngine.get_instance()
    risk_score, risk_level, risk_explanation = await risk_engine.score(
        db=db,
        wallet_address=wallet,
        ip_address=ip_address,
        user_agent=user_agent,
        geo_country=req.geo_country,
    )

    step_up_required = risk_score >= settings.RISK_MEDIUM

    # ─── Create/Update User ──────────────────────────────
    result = await db.execute(select(User).where(User.wallet_address == wallet.lower()))
    user = result.scalar_one_or_none()

    if not user:
        user = User(
            id=str(uuid.uuid4()),
            wallet_address=wallet.lower(),
            created_at=datetime.utcnow(),
            last_login=datetime.utcnow(),
        )
        db.add(user)
    else:
        user.last_login = datetime.utcnow()

    # ─── Store Login Event ───────────────────────────────
    import json
    event_data = json.dumps({
        "wallet": wallet.lower(),
        "ip_hash": hashlib.sha256(ip_address.encode()).hexdigest(),
        "risk_score": risk_score,
        "timestamp": datetime.utcnow().isoformat(),
    }, sort_keys=True)
    event_hash = hashlib.sha256(event_data.encode()).hexdigest()

    login_event = LoginEvent(
        id=str(uuid.uuid4()),
        wallet_address=wallet.lower(),
        ip_address=ip_address,
        ip_hash=hashlib.sha256(ip_address.encode()).hexdigest(),
        user_agent=user_agent,
        geo_lat=req.geo_lat,
        geo_lng=req.geo_lng,
        geo_country=req.geo_country,
        geo_city=req.geo_city,
        risk_score=risk_score,
        risk_level=risk_level,
        risk_features=risk_explanation.get("factors"),
        step_up_required=step_up_required,
        event_hash=event_hash,
        timestamp=datetime.utcnow(),
    )
    db.add(login_event)
    await db.commit()

    # ─── Add to Merkle Batch ─────────────────────────────
    batcher = MerkleBatcher.get_instance()
    batcher.add_event(event_hash, event_type="login", metadata={
        "wallet": wallet.lower(),
        "risk_level": risk_level,
    })

    # ─── Security Enforcement ─────────────────────────────
    enforcer = SecurityEnforcement.get_instance()
    enforcement = await enforcer.evaluate_and_enforce(db, wallet)
    security_status = enforcement["security_status"]
    is_locked = security_status == "locked"
    is_restricted = security_status in ("restricted", "locked")

    # If locked, deny login entirely
    if is_locked:
        return AuthResponse(
            success=False,
            wallet_address=wallet.lower(),
            risk_score=risk_score,
            risk_level=risk_level,
            security_status=security_status,
            trust_score=enforcement["trust_score"],
            locked_until=enforcement["locked_until"],
            message=f"Account temporarily locked. {enforcement['cooldown_reason'] or 'Suspicious activity detected.'}",
        )

    # Merge enforcement step-up with login risk step-up
    enforce_step_up = security_status == "step_up_required" or step_up_required

    # ─── Issue JWT ───────────────────────────────────────
    token = create_access_token(data={
        "sub": wallet.lower(),
        "risk_level": risk_level,
        "risk_score": risk_score,
        "security_status": security_status,
    })

    msg_parts = [f"Welcome! Risk level: {risk_level}"]
    if enforce_step_up:
        msg_parts.append("Step-up verification required.")
    if is_restricted:
        msg_parts.append("Some actions are restricted due to elevated risk.")

    return AuthResponse(
        success=True,
        token=token,
        wallet_address=wallet.lower(),
        risk_score=risk_score,
        risk_level=risk_level,
        risk_explanation=risk_explanation,
        step_up_required=enforce_step_up,
        event_hash=event_hash,
        security_status=security_status,
        trust_score=enforcement["trust_score"],
        locked_until=enforcement["locked_until"],
        session_restricted=is_restricted,
        message=" — ".join(msg_parts),
    )


@router.post("/challenge")
async def step_up_challenge(req: ChallengeRequest):
    """Issue a step-up authentication challenge for high-risk logins"""
    nonce = secrets.token_urlsafe(32)
    return {
        "challenge_type": req.challenge_type,
        "nonce": nonce,
        "message": f"SentinelX Step-Up Challenge\n\nSign this message to confirm your identity.\n\nNonce: {nonce}\nTimestamp: {datetime.utcnow().isoformat()}Z",
        "expires_in": 120,
    }


@router.get("/session", response_model=SessionResponse)
async def get_session(authorization: Optional[str] = Header(None)):
    """Check if the current JWT session is valid"""
    if not authorization:
        return SessionResponse(valid=False)

    token = authorization.replace("Bearer ", "")
    payload = verify_token(token)

    if not payload:
        return SessionResponse(valid=False)

    return SessionResponse(
        valid=True,
        wallet_address=payload.get("sub"),
        expires_at=datetime.utcfromtimestamp(payload.get("exp", 0)).isoformat() + "Z",
    )


@router.post("/logout")
async def logout():
    """Logout — client should discard the JWT"""
    return {"success": True, "message": "Session ended. Please discard your token."}


@router.get("/security-state")
async def get_security_state(
    wallet_address: str,
    db: AsyncSession = Depends(get_db),
):
    """Get the current security enforcement state for a wallet."""
    enforcer = SecurityEnforcement.get_instance()
    return await enforcer.get_security_state(db, wallet_address)


@router.post("/security-state/refresh")
async def refresh_security_state(
    wallet_address: str,
    db: AsyncSession = Depends(get_db),
):
    """Recompute and return the security enforcement state."""
    enforcer = SecurityEnforcement.get_instance()
    return await enforcer.evaluate_and_enforce(db, wallet_address)


# ─── Helpers ─────────────────────────────────────────────────────────

def _verify_signature(message: str, signature: str, expected_address: str) -> bool:
    """Verify an Ethereum signature against a message and expected address"""
    try:
        from eth_account.messages import encode_defunct
        from eth_account import Account

        msg = encode_defunct(text=message)
        recovered = Account.recover_message(msg, signature=signature)
        return recovered.lower() == expected_address.lower()
    except Exception:
        # For demo: if we can't verify cryptographically, check signature format
        return len(signature) > 20 and signature.startswith("0x")
