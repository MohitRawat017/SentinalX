"""
SentinelX Chat Router
WebSocket-centric messaging with GuardLayer DLP integration.
REST endpoints are read-only (conversations list, message history).
All message sending happens through the WebSocket.
"""
import hashlib
import json
import uuid
from datetime import datetime
from typing import Dict, Optional

from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect, Query
from sqlalchemy import select, desc, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db, AsyncSessionLocal
from app.models.models import Conversation, ConversationParticipant, Message
from app.services.guard_layer import GuardLayer
from app.services.merkle import MerkleBatcher
from app.services.jwt_utils import verify_token

router = APIRouter()
guard = GuardLayer()

SEVERITY_SCORES = {"low": 0.0, "medium": 0.3, "high": 0.6, "critical": 1.0}


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

    async def send_to(self, wallet: str, data: dict) -> bool:
        ws = self.active.get(wallet.lower())
        if ws:
            try:
                await ws.send_json(data)
                return True
            except Exception:
                self.disconnect(wallet)
        return False


manager = ConnectionManager()


# ─── Helper Functions ─────────────────────────────────────────────────

async def find_conversation(db: AsyncSession, wallet_a: str, wallet_b: str) -> Optional[str]:
    """Find existing conversation between two wallets."""
    a_convs = select(ConversationParticipant.conversation_id).where(
        ConversationParticipant.wallet_address == wallet_a.lower()
    ).scalar_subquery()

    result = await db.execute(
        select(ConversationParticipant.conversation_id).where(
            ConversationParticipant.wallet_address == wallet_b.lower(),
            ConversationParticipant.conversation_id.in_(a_convs),
        ).limit(1)
    )
    return result.scalar()


async def create_conversation_db(db: AsyncSession, wallet_a: str, wallet_b: str) -> str:
    """Create a new conversation between two wallets."""
    conv = Conversation(id=str(uuid.uuid4()))
    db.add(conv)
    db.add(ConversationParticipant(
        conversation_id=conv.id, wallet_address=wallet_a.lower(),
    ))
    db.add(ConversationParticipant(
        conversation_id=conv.id, wallet_address=wallet_b.lower(),
    ))
    await db.commit()
    return conv.id


async def get_conversation_peer(db: AsyncSession, conversation_id: str, my_wallet: str) -> Optional[str]:
    """Get the other participant's wallet in a conversation."""
    result = await db.execute(
        select(ConversationParticipant.wallet_address).where(
            ConversationParticipant.conversation_id == conversation_id,
            ConversationParticipant.wallet_address != my_wallet.lower(),
        )
    )
    return result.scalar()


# ─── WebSocket Message Handlers ──────────────────────────────────────

async def handle_create_conversation(ws: WebSocket, wallet: str, data: dict):
    """Handle create_conversation message type."""
    peer_wallet = data.get("peer_wallet", "").strip().lower()
    if not peer_wallet:
        await ws.send_json({"type": "error", "message": "peer_wallet required"})
        return

    async with AsyncSessionLocal() as db:
        existing = await find_conversation(db, wallet, peer_wallet)
        if existing:
            await ws.send_json({
                "type": "conversation_created",
                "conversation_id": existing,
                "peer": peer_wallet,
                "existing": True,
            })
            return

        conv_id = await create_conversation_db(db, wallet, peer_wallet)

    await ws.send_json({
        "type": "conversation_created",
        "conversation_id": conv_id,
        "peer": peer_wallet,
        "existing": False,
    })

    # Notify peer if online
    await manager.send_to(peer_wallet, {
        "type": "conversation_created",
        "conversation_id": conv_id,
        "peer": wallet,
        "existing": False,
    })


async def handle_send_message(ws: WebSocket, wallet: str, data: dict, force: bool = False, redact: bool = False):
    """Handle send_message, force_send, and redact_send message types."""
    conversation_id = data.get("conversation_id")
    content = data.get("content", "").strip()

    if not conversation_id or not content:
        await ws.send_json({"type": "error", "message": "conversation_id and content required"})
        return

    async with AsyncSessionLocal() as db:
        # Verify sender is a participant
        result = await db.execute(
            select(ConversationParticipant).where(
                ConversationParticipant.conversation_id == conversation_id,
                ConversationParticipant.wallet_address == wallet,
            )
        )
        if not result.scalar():
            await ws.send_json({"type": "error", "message": "Not a participant in this conversation"})
            return

        # Get peer wallet
        peer = await get_conversation_peer(db, conversation_id, wallet)

        # Handle redaction
        original_content = content
        if redact:
            redaction = await guard.redact(content)
            content = redaction["redacted_text"]

        # Run GuardLayer scan
        scan_result = await guard.scan(content, use_llm=not force)

        # If risky and not forced/redacted, return DLP warning
        if scan_result["is_risky"] and not force and not redact:
            await ws.send_json({
                "type": "dlp_warning",
                "conversation_id": conversation_id,
                "warning": f"Sensitive data detected ({scan_result['severity']}): {', '.join(scan_result['categories'])}",
                "scan_result": {
                    "is_risky": scan_result["is_risky"],
                    "severity": scan_result["severity"],
                    "categories": scan_result["categories"],
                    "regex_findings": scan_result["regex_findings"],
                },
            })
            return

        # Save message to DB
        content_hash = hashlib.sha256(original_content.encode()).hexdigest()
        risk_score = SEVERITY_SCORES.get(scan_result.get("severity", "low"), 0.0)

        msg = Message(
            id=str(uuid.uuid4()),
            conversation_id=conversation_id,
            sender_wallet=wallet,
            content=content,
            content_hash=content_hash,
            is_delivered=False,
            is_read=False,
            risk_score=risk_score,
            was_blocked=scan_result["is_risky"],
            event_hash=scan_result["event_hash"],
            risk_categories=scan_result["categories"] if scan_result["is_risky"] else None,
            redacted=redact,
            user_override=force and scan_result["is_risky"],
            created_at=datetime.utcnow(),
        )
        db.add(msg)
        await db.commit()

    # Add to Merkle audit trail
    batcher = MerkleBatcher.get_instance()
    batcher.add_event(scan_result["event_hash"], event_type="chat", metadata={
        "sender": wallet,
        "conversation_id": conversation_id,
        "risk_detected": scan_result["is_risky"],
    })

    # Build message payload
    msg_payload = {
        "message_id": msg.id,
        "conversation_id": conversation_id,
        "sender": wallet,
        "content": content,
        "redacted": redact,
        "risk_detected": scan_result["is_risky"],
        "user_override": force and scan_result["is_risky"],
        "timestamp": msg.created_at.isoformat() + "Z",
        "is_delivered": False,
        "is_read": False,
    }

    # Push to receiver
    if peer:
        await manager.send_to(peer, {**msg_payload, "type": "new_message"})

    # Confirm to sender
    await ws.send_json({**msg_payload, "type": "message_sent"})


async def handle_delivered(ws: WebSocket, wallet: str, data: dict):
    """Handle delivery ACK from receiver."""
    message_id = data.get("message_id")
    if not message_id:
        return

    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(Message).where(Message.id == message_id)
        )
        msg = result.scalar()
        if msg and not msg.is_delivered:
            msg.is_delivered = True
            await db.commit()

            # Notify sender that message was delivered
            await manager.send_to(msg.sender_wallet, {
                "type": "delivery_update",
                "message_id": message_id,
                "is_delivered": True,
            })


async def handle_read(ws: WebSocket, wallet: str, data: dict):
    """Handle read receipts."""
    message_ids = data.get("message_ids", [])
    if not message_ids:
        return

    async with AsyncSessionLocal() as db:
        senders = set()
        for mid in message_ids:
            result = await db.execute(
                select(Message).where(Message.id == mid)
            )
            msg = result.scalar()
            if msg and not msg.is_read and msg.sender_wallet != wallet:
                msg.is_read = True
                senders.add(msg.sender_wallet)
        await db.commit()

        # Notify senders
        for sender in senders:
            await manager.send_to(sender, {
                "type": "read_update",
                "message_ids": message_ids,
                "reader": wallet,
            })


# ─── REST Endpoints (Read-Only) ──────────────────────────────────────

@router.get("/conversations")
async def get_conversations(
    wallet: str,
    db: AsyncSession = Depends(get_db),
):
    """Get all conversations for a wallet with latest message preview."""
    w = wallet.lower()

    result = await db.execute(
        select(ConversationParticipant.conversation_id).where(
            ConversationParticipant.wallet_address == w
        )
    )
    conv_ids = [row[0] for row in result.all()]

    conversations = []
    for conv_id in conv_ids:
        # Get peer
        peer_result = await db.execute(
            select(ConversationParticipant.wallet_address).where(
                ConversationParticipant.conversation_id == conv_id,
                ConversationParticipant.wallet_address != w,
            )
        )
        peer = peer_result.scalar()

        # Latest message
        msg_result = await db.execute(
            select(Message)
            .where(Message.conversation_id == conv_id)
            .order_by(desc(Message.created_at))
            .limit(1)
        )
        latest = msg_result.scalar()

        # Message count
        count_result = await db.execute(
            select(func.count()).select_from(Message).where(
                Message.conversation_id == conv_id
            )
        )
        msg_count = count_result.scalar() or 0

        # Unread count
        unread_result = await db.execute(
            select(func.count()).select_from(Message).where(
                Message.conversation_id == conv_id,
                Message.sender_wallet != w,
                Message.is_read == False,
            )
        )
        unread_count = unread_result.scalar() or 0

        conversations.append({
            "conversation_id": conv_id,
            "peer": peer,
            "last_message": latest.content[:50] if latest else None,
            "last_message_time": latest.created_at.isoformat() + "Z" if latest else None,
            "message_count": msg_count,
            "unread_count": unread_count,
        })

    # Sort by latest message time (most recent first)
    conversations.sort(key=lambda x: x["last_message_time"] or "", reverse=True)

    return {"conversations": conversations}


@router.get("/conversations/{conversation_id}/messages")
async def get_messages(
    conversation_id: str,
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
):
    """Get messages in a conversation."""
    result = await db.execute(
        select(Message)
        .where(Message.conversation_id == conversation_id)
        .order_by(desc(Message.created_at))
        .limit(limit)
    )
    messages = result.scalars().all()

    return {
        "messages": [
            {
                "id": m.id,
                "conversation_id": m.conversation_id,
                "sender": m.sender_wallet,
                "content": m.content,
                "redacted": m.redacted,
                "risk_detected": bool(m.risk_categories),
                "user_override": m.user_override,
                "is_delivered": m.is_delivered,
                "is_read": m.is_read,
                "timestamp": m.created_at.isoformat() + "Z" if m.created_at else None,
            }
            for m in reversed(messages)
        ],
        "count": len(messages),
    }


# ─── WebSocket Endpoint ──────────────────────────────────────────────

@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """
    WebSocket connection for real-time messaging.
    Connect with: ws://host/chat/ws?token=JWT
    """
    # Authenticate via JWT
    token = websocket.query_params.get("token")
    if not token:
        await websocket.close(code=4001, reason="Missing token")
        return

    payload = verify_token(token)
    if not payload:
        await websocket.close(code=4001, reason="Invalid token")
        return

    wallet = payload.get("sub", "").lower()
    if not wallet:
        await websocket.close(code=4001, reason="Invalid token payload")
        return

    await manager.connect(wallet, websocket)

    try:
        while True:
            raw = await websocket.receive_text()

            try:
                data = json.loads(raw)
            except json.JSONDecodeError:
                # Treat non-JSON as ping
                await websocket.send_json({
                    "type": "pong",
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                })
                continue

            msg_type = data.get("type", "ping")

            if msg_type == "create_conversation":
                await handle_create_conversation(websocket, wallet, data)
            elif msg_type == "send_message":
                await handle_send_message(websocket, wallet, data)
            elif msg_type == "force_send":
                await handle_send_message(websocket, wallet, data, force=True)
            elif msg_type == "redact_send":
                await handle_send_message(websocket, wallet, data, redact=True)
            elif msg_type == "delivered":
                await handle_delivered(websocket, wallet, data)
            elif msg_type == "read":
                await handle_read(websocket, wallet, data)
            else:
                await websocket.send_json({
                    "type": "pong",
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                })
    except WebSocketDisconnect:
        manager.disconnect(wallet)
    except Exception:
        manager.disconnect(wallet)
