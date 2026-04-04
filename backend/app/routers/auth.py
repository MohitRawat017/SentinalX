from __future__ import annotations

import hashlib
import json
import secrets
import uuid
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_db
from app.models.models import LoginEvent, Nonce, User
from app.services.blockchain import (
    build_step_up_message,
    normalize_algorand_address,
    verify_signature,
)
from app.services.enforcement import SecurityEnforcement
from app.services.jwt_utils import create_access_token, verify_token
from app.services.merkle import MerkleBatcher
from app.services.risk_engine import RiskEngine


router = APIRouter()


DEMO_WALLET = "SAHBJDRHHRR72JHTWSXZR5VHQQUVC7S757TJZI656FWSDO3TZZWV3IGJV4"
DEMO_LOGIN_SIGNATURE = "0x" + "a" * 130
DEMO_STEP_UP_SIGNATURE = "0x" + "b" * 130

step_up_store: dict[str, dict] = {}


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
    security_status: Optional[str] = None
    trust_score: Optional[int] = None
    locked_until: Optional[str] = None
    session_restricted: bool = False


class ChallengeRequest(BaseModel):
    wallet_address: str
    challenge_type: str = "re-sign"


class StepUpVerifyRequest(BaseModel):
    wallet_address: str
    signature: str
    nonce: str


class SessionResponse(BaseModel):
    valid: bool
    wallet_address: Optional[str] = None
    expires_at: Optional[str] = None


def _extract_nonce(message: str) -> Optional[str]:
    for line in message.splitlines():
        if line.startswith("Nonce:"):
            return line.split(":", 1)[1].strip()
    return None


def _is_demo_login(req: SIWEVerifyRequest) -> bool:
    return (
        req.wallet_address.strip().upper() == DEMO_WALLET
        and req.message.startswith("SentinelX Demo Login")
        and req.signature == DEMO_LOGIN_SIGNATURE
    )


@router.get("/nonce", response_model=NonceResponse)
async def get_nonce(db: AsyncSession = Depends(get_db)):
    now = datetime.utcnow()
    expires_at = now + timedelta(minutes=10)
    nonce = secrets.token_urlsafe(24)

    db.add(
        Nonce(
            id=str(uuid.uuid4()),
            nonce=nonce,
            created_at=now,
            expires_at=expires_at,
        )
    )
    await db.commit()

    return NonceResponse(
        nonce=nonce,
        issued_at=now.isoformat() + "Z",
        expires_at=expires_at.isoformat() + "Z",
    )


@router.post("/verify", response_model=AuthResponse)
async def verify_siwe(
    req: SIWEVerifyRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    is_demo = _is_demo_login(req)

    if is_demo:
        normalized_wallet = DEMO_WALLET
        wallet_storage = DEMO_WALLET.lower()
    else:
        try:
            normalized_wallet = normalize_algorand_address(req.wallet_address)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid Algorand wallet address")

        nonce_value = _extract_nonce(req.message)
        if not nonce_value:
            return AuthResponse(success=False, message="Nonce missing from signed message.")

        result = await db.execute(select(Nonce).where(Nonce.nonce == nonce_value))
        nonce_row = result.scalar_one_or_none()
        if nonce_row is None or nonce_row.used:
            return AuthResponse(success=False, message="Nonce is invalid or already used.")
        if nonce_row.expires_at < datetime.utcnow():
            return AuthResponse(success=False, message="Nonce expired. Please request a new sign-in message.")
        if f"Address: {normalized_wallet}" not in req.message:
            return AuthResponse(success=False, message="Signed message does not match the provided wallet.")
        if not verify_signature(normalized_wallet, req.message, req.signature):
            return AuthResponse(success=False, message="Invalid signature. Please try signing again.")

        nonce_row.used = True
        nonce_row.wallet_address = normalized_wallet.lower()
        wallet_storage = normalized_wallet.lower()

    ip_address = req.ip_address or (request.client.host if request.client else "0.0.0.0")
    user_agent = req.user_agent or request.headers.get("user-agent", "")

    risk_engine = RiskEngine.get_instance()
    risk_score, risk_level, risk_explanation = await risk_engine.score(
        db=db,
        wallet_address=wallet_storage,
        ip_address=ip_address,
        user_agent=user_agent,
        geo_country=req.geo_country,
    )

    step_up_required = risk_score >= settings.RISK_MEDIUM

    result = await db.execute(select(User).where(User.wallet_address == wallet_storage))
    user = result.scalar_one_or_none()
    if not user:
        user = User(
            id=str(uuid.uuid4()),
            wallet_address=wallet_storage,
            created_at=datetime.utcnow(),
            last_login=datetime.utcnow(),
        )
        db.add(user)
    else:
        user.last_login = datetime.utcnow()

    event_data = json.dumps(
        {
            "wallet": wallet_storage,
            "ip_hash": hashlib.sha256(ip_address.encode()).hexdigest(),
            "risk_score": risk_score,
            "timestamp": datetime.utcnow().isoformat(),
        },
        sort_keys=True,
    )
    event_hash = hashlib.sha256(event_data.encode()).hexdigest()

    login_event = LoginEvent(
        id=str(uuid.uuid4()),
        wallet_address=wallet_storage,
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

    batcher = MerkleBatcher.get_instance()
    batcher.add_event(
        event_hash,
        event_type="login",
        metadata={
            "wallet": wallet_storage,
            "risk_level": risk_level,
        },
    )

    enforcer = SecurityEnforcement.get_instance()
    enforcement = await enforcer.evaluate_and_enforce(db, wallet_storage)
    security_status = enforcement["security_status"]
    is_locked = security_status == "locked"
    is_restricted = security_status in ("restricted", "locked")

    if is_locked:
        return AuthResponse(
            success=False,
            wallet_address=wallet_storage,
            risk_score=risk_score,
            risk_level=risk_level,
            security_status=security_status,
            trust_score=enforcement["trust_score"],
            locked_until=enforcement["locked_until"],
            message=f"Account temporarily locked. {enforcement['cooldown_reason'] or 'Suspicious activity detected.'}",
        )

    enforce_step_up = security_status == "step_up_required" or step_up_required
    token = create_access_token(
        data={
            "sub": wallet_storage,
            "risk_level": risk_level,
            "risk_score": risk_score,
            "security_status": security_status,
        }
    )

    message_parts = [f"Welcome! Risk level: {risk_level}"]
    if enforce_step_up:
        message_parts.append("Step-up verification required.")
    if is_restricted:
        message_parts.append("Some actions are restricted due to elevated risk.")

    return AuthResponse(
        success=True,
        token=token,
        wallet_address=wallet_storage,
        risk_score=risk_score,
        risk_level=risk_level,
        risk_explanation=risk_explanation,
        step_up_required=enforce_step_up,
        event_hash=event_hash,
        security_status=security_status,
        trust_score=enforcement["trust_score"],
        locked_until=enforcement["locked_until"],
        session_restricted=is_restricted,
        message=" - ".join(message_parts),
    )


@router.post("/challenge")
async def step_up_challenge(req: ChallengeRequest):
    is_demo = req.wallet_address.strip().upper() == DEMO_WALLET
    try:
        signer_wallet = DEMO_WALLET if is_demo else normalize_algorand_address(req.wallet_address)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid Algorand wallet address")

    nonce = secrets.token_urlsafe(24)
    issued_at = datetime.utcnow().isoformat() + "Z"
    expires_at = datetime.utcnow() + timedelta(minutes=2)
    message = (
        f"SentinelX Demo Step-Up\nWallet: {DEMO_WALLET}\nNonce: {nonce}\nIssued At: {issued_at}"
        if is_demo
        else build_step_up_message(signer_wallet, nonce, issued_at)
    )

    step_up_store[nonce] = {
        "wallet": signer_wallet.lower(),
        "signer": signer_wallet,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "is_demo": is_demo,
    }

    return {
        "challenge_type": req.challenge_type,
        "nonce": nonce,
        "message": message,
        "expires_in": 120,
    }


@router.post("/step-up-verify")
async def step_up_verify(req: StepUpVerifyRequest, db: AsyncSession = Depends(get_db)):
    challenge = step_up_store.get(req.nonce)
    if not challenge:
        raise HTTPException(status_code=400, detail="Invalid or expired challenge nonce")

    if datetime.utcnow() > challenge["expires_at"]:
        step_up_store.pop(req.nonce, None)
        raise HTTPException(status_code=400, detail="Challenge expired. Please request a new one.")

    if challenge["is_demo"]:
        expected_wallet = DEMO_WALLET
        expected_message = (
            f"SentinelX Demo Step-Up\nWallet: {DEMO_WALLET}\nNonce: {req.nonce}\nIssued At: {challenge['issued_at']}"
        )
        if req.wallet_address.strip().upper() != expected_wallet or req.signature != DEMO_STEP_UP_SIGNATURE:
            raise HTTPException(status_code=401, detail="Invalid signature")
    else:
        try:
            normalized_wallet = normalize_algorand_address(req.wallet_address)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid Algorand wallet address")

        if normalized_wallet.lower() != challenge["wallet"]:
            raise HTTPException(status_code=400, detail="Wallet mismatch")

        expected_message = build_step_up_message(
            challenge["signer"],
            req.nonce,
            challenge["issued_at"],
        )
        if not verify_signature(normalized_wallet, expected_message, req.signature):
            raise HTTPException(status_code=401, detail="Invalid signature")

    step_up_store.pop(req.nonce, None)

    enforcer = SecurityEnforcement.get_instance()
    result = await enforcer.complete_step_up(db, challenge["wallet"], boost=20)
    return {
        "success": True,
        "message": "Step-up verification successful. Trust score boosted.",
        "enforcement": result,
    }


@router.get("/session", response_model=SessionResponse)
async def get_session(authorization: Optional[str] = Header(None)):
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
    return {"success": True, "message": "Session ended. Please discard your token."}


@router.get("/security-state")
async def get_security_state(
    wallet_address: str,
    db: AsyncSession = Depends(get_db),
):
    enforcer = SecurityEnforcement.get_instance()
    return await enforcer.get_security_state(db, wallet_address)


@router.post("/security-state/refresh")
async def refresh_security_state(
    wallet_address: str,
    db: AsyncSession = Depends(get_db),
):
    enforcer = SecurityEnforcement.get_instance()
    return await enforcer.evaluate_and_enforce(db, wallet_address)
