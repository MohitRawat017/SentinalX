"""
SentinelX Chat Router
Real-time messaging with GuardLayer DLP integration
"""
import hashlib
import json
import uuid
from datetime import datetime
from typing import Dict, List, Optional

from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect, Query
from pydantic import BaseModel
from sqlalchemy import select, desc, or_, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.models import ChatMessage
from app.services.guard_layer import GuardLayer
from app.services.merkle import MerkleBatcher

router = APIRouter()
guard = GuardLayer()


# ─── WebSocket Connection Manager ────────────────────────────────────

class ConnectionManager:
    """Manages active WebSocket connections by wallet address."""

    def __init__(self):
        self.active: Dict[str, WebSocket] = {}

    async def connect(self, wallet: str, websocket: WebSocket):
        await websocket.accept()
        self.active[wallet.lower()] = websocket

    def disconnect(self, wallet: str):
        self.active.pop(wallet.lower(), None)

    async def send_to(self, wallet: str, data: dict):
        ws = self.active.get(wallet.lower())
        if ws:
            try:
                await ws.send_json(data)
            except Exception:
                self.disconnect(wallet)


manager = ConnectionManager()


# ─── Request/Response Models ─────────────────────────────────────────

class SendRequest(BaseModel):
    sender_wallet: str
    receiver_wallet: str
    text: str
    use_llm: bool = True
    force_send: bool = False  # True = send anyway despite warning


class RedactRequest(BaseModel):
    sender_wallet: str
    receiver_wallet: str
    text: str


class SendResponse(BaseModel):
    status: str  # "delivered", "warning", "redacted_and_delivered"
    message_id: Optional[str] = None
    warning: Optional[str] = None
    scan_result: Optional[dict] = None
    event_hash: Optional[str] = None


# ─── Endpoints ───────────────────────────────────────────────────────

@router.post("/send", response_model=SendResponse)
async def send_message(req: SendRequest, db: AsyncSession = Depends(get_db)):
    """
    Send a message with GuardLayer DLP scanning.
    If sensitive data detected and force_send=False, returns a warning.
    If force_send=True, sends anyway (logged as user_override).
    """
    scan_result = await guard.scan(req.text, use_llm=req.use_llm)

    content_hash = hashlib.sha256(req.text.encode()).hexdigest()

    # If risky and not forced, return warning
    if scan_result["is_risky"] and not req.force_send:
        return SendResponse(
            status="warning",
            warning=f"Sensitive data detected ({scan_result['severity']}): {', '.join(scan_result['categories'])}. Use force_send=true to send anyway, or use /chat/redact to redact.",
            scan_result={
                "is_risky": scan_result["is_risky"],
                "severity": scan_result["severity"],
                "categories": scan_result["categories"],
                "regex_findings": scan_result["regex_findings"],
            },
            event_hash=scan_result["event_hash"],
        )

    # Store message
    msg = ChatMessage(
        id=str(uuid.uuid4()),
        sender_wallet=req.sender_wallet.lower(),
        receiver_wallet=req.receiver_wallet.lower(),
        content=req.text,
        content_hash=content_hash,
        is_scanned=True,
        risk_detected=scan_result["is_risky"],
        risk_categories=scan_result["categories"] if scan_result["is_risky"] else None,
        redacted=False,
        user_override=req.force_send and scan_result["is_risky"],
        event_hash=scan_result["event_hash"],
        timestamp=datetime.utcnow(),
    )
    db.add(msg)
    await db.commit()

    # Add to Merkle audit trail
    batcher = MerkleBatcher.get_instance()
    batcher.add_event(scan_result["event_hash"], event_type="chat", metadata={
        "sender": req.sender_wallet.lower(),
        "receiver": req.receiver_wallet.lower(),
        "risk_detected": scan_result["is_risky"],
    })

    # Push via WebSocket to receiver
    await manager.send_to(req.receiver_wallet, {
        "type": "new_message",
        "message_id": msg.id,
        "sender": req.sender_wallet.lower(),
        "content": req.text,
        "risk_detected": scan_result["is_risky"],
        "timestamp": msg.timestamp.isoformat() + "Z",
    })

    return SendResponse(
        status="delivered",
        message_id=msg.id,
        event_hash=scan_result["event_hash"],
    )


@router.post("/redact", response_model=SendResponse)
async def redact_and_send(req: RedactRequest, db: AsyncSession = Depends(get_db)):
    """
    Redact sensitive data from message text, then send the redacted version.
    """
    # Redact
    redaction = await guard.redact(req.text)
    redacted_text = redaction["redacted_text"]

    # Scan the redacted text (should be clean)
    scan_result = await guard.scan(redacted_text, use_llm=False)

    content_hash = hashlib.sha256(req.text.encode()).hexdigest()
    event_data = json.dumps({
        "content_hash": content_hash,
        "redacted": True,
        "timestamp": datetime.utcnow().isoformat(),
    }, sort_keys=True)
    event_hash = hashlib.sha256(event_data.encode()).hexdigest()

    # Store message with redacted content
    msg = ChatMessage(
        id=str(uuid.uuid4()),
        sender_wallet=req.sender_wallet.lower(),
        receiver_wallet=req.receiver_wallet.lower(),
        content=redacted_text,
        content_hash=content_hash,
        is_scanned=True,
        risk_detected=True,  # Original was risky
        risk_categories=scan_result.get("categories"),
        redacted=True,
        redacted_content=redacted_text,
        user_override=False,
        event_hash=event_hash,
        timestamp=datetime.utcnow(),
    )
    db.add(msg)
    await db.commit()

    # Audit trail
    batcher = MerkleBatcher.get_instance()
    batcher.add_event(event_hash, event_type="chat_redact", metadata={
        "sender": req.sender_wallet.lower(),
        "method": redaction["method"],
    })

    # Push via WebSocket
    await manager.send_to(req.receiver_wallet, {
        "type": "new_message",
        "message_id": msg.id,
        "sender": req.sender_wallet.lower(),
        "content": redacted_text,
        "redacted": True,
        "timestamp": msg.timestamp.isoformat() + "Z",
    })

    return SendResponse(
        status="redacted_and_delivered",
        message_id=msg.id,
        event_hash=event_hash,
    )


@router.get("/messages")
async def get_messages(
    wallet: str,
    peer: str,
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
):
    """Get message history between two wallets."""
    w1 = wallet.lower()
    w2 = peer.lower()

    result = await db.execute(
        select(ChatMessage)
        .where(
            or_(
                and_(ChatMessage.sender_wallet == w1, ChatMessage.receiver_wallet == w2),
                and_(ChatMessage.sender_wallet == w2, ChatMessage.receiver_wallet == w1),
            )
        )
        .order_by(desc(ChatMessage.timestamp))
        .limit(limit)
    )
    messages = result.scalars().all()

    return {
        "messages": [
            {
                "id": m.id,
                "sender": m.sender_wallet,
                "receiver": m.receiver_wallet,
                "content": m.content,
                "redacted": m.redacted,
                "risk_detected": m.risk_detected,
                "user_override": m.user_override,
                "timestamp": m.timestamp.isoformat() + "Z" if m.timestamp else None,
            }
            for m in reversed(messages)
        ],
        "count": len(messages),
    }


@router.get("/contacts")
async def get_contacts(
    wallet: str,
    db: AsyncSession = Depends(get_db),
):
    """Get list of wallets this user has chatted with."""
    w = wallet.lower()

    result = await db.execute(
        select(ChatMessage)
        .where(or_(ChatMessage.sender_wallet == w, ChatMessage.receiver_wallet == w))
        .order_by(desc(ChatMessage.timestamp))
    )
    messages = result.scalars().all()

    contacts = {}
    for m in messages:
        peer = m.receiver_wallet if m.sender_wallet == w else m.sender_wallet
        if peer not in contacts:
            contacts[peer] = {
                "wallet": peer,
                "last_message": m.timestamp.isoformat() + "Z" if m.timestamp else None,
                "message_count": 0,
            }
        contacts[peer]["message_count"] += 1

    return {
        "contacts": list(contacts.values()),
        "count": len(contacts),
    }


# ─── WebSocket ───────────────────────────────────────────────────────

@router.websocket("/ws/{wallet_address}")
async def websocket_endpoint(websocket: WebSocket, wallet_address: str):
    """
    WebSocket connection for real-time message delivery.
    Connect with: ws://host/chat/ws/0xYourWallet
    """
    await manager.connect(wallet_address, websocket)
    try:
        while True:
            # Keep connection alive; messages are pushed via send_to()
            data = await websocket.receive_text()
            # Echo back as heartbeat acknowledgment
            await websocket.send_json({"type": "pong", "timestamp": datetime.utcnow().isoformat() + "Z"})
    except WebSocketDisconnect:
        manager.disconnect(wallet_address)
