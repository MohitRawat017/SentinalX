"""
╔═══════════════════════════════════════════════════════════════════════════════╗
║                     SentinelX Chat Router                                    ║
║                     WebSocket Messaging with DLP Integration                  ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║ PURPOSE: Real-time messaging with automatic data leak prevention             ║
║                                                                               ║
║ ═════════════════════════════════════════════════════════════════════════════║
║ ARCHITECTURE: WebSocket + REST Hybrid                                        ║
║ ═════════════════════════════════════════════════════════════════════════════║
║                                                                               ║
║ WEBSOCKET (ws://host/chat/ws):                                                ║
║ - Real-time bidirectional communication                                      ║
║ - Message types: create_conversation, send_message, force_send, redact_send  ║
║ - Delivery receipts, read receipts                                            ║
║ - Authenticated via JWT in query params                                       ║
║                                                                               ║
║ REST ENDPOINTS (Read-Only):                                                   ║
║ - GET /chat/conversations - List user's conversations                        ║
║ - GET /chat/conversations/{id}/messages - Get message history                ║
║                                                                               ║
║ ═════════════════════════════════════════════════════════════════════════════║
║ DLP INTEGRATION:                                                              ║
║ ═════════════════════════════════════════════════════════════════════════════║
║                                                                               ║
║ Every message is scanned by GuardLayer before delivery:                      ║
║                                                                               ║
║ 1. User sends message via WebSocket                                          ║
║ 2. GuardLayer scans for sensitive data                                       ║
║ 3. If risky → Return warning, user can:                                      ║
║    - Cancel                                                                   ║
║    - force_send (override, logged)                                            ║
║    - redact_send (auto-redact sensitive parts)                               ║
║ 4. If clean → Deliver to recipient                                           ║
║                                                                               ║
║ ═════════════════════════════════════════════════════════════════════════════║
║ EPHEMERAL MESSAGING:                                                          ║
║ ═════════════════════════════════════════════════════════════════════════════║
║                                                                               ║
║ Messages have a 24-hour TTL (Time To Live):                                  ║
║ - expires_at is set when message is created                                  ║
║ - Expired messages are not returned by REST API                              ║
║ - Background task cleans up expired messages from database                   ║
║                                                                               ║
║ WHY EPHEMERAL?                                                                ║
║ - Privacy: Sensitive conversations don't persist forever                     ║
║ - Security: Less data to expose in a breach                                   ║
║ - Storage: Automatic cleanup reduces database size                            ║
║                                                                               ║
║ INTERVIEW QUESTION: Why WebSocket instead of REST for sending messages?      ║
║ ANSWER: Real-time requirements:                                              ║
║ - REST requires polling (inefficient)                                         ║
║ - WebSocket enables instant delivery                                          ║
║ - Lower latency for chat experience                                          ║
║ - Server can push updates (delivery, read receipts)                          ║
╚═══════════════════════════════════════════════════════════════════════════════╝
"""
import hashlib
import json
import uuid
from datetime import datetime, timedelta
from typing import Dict, Optional

from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect, Query
from sqlalchemy import select, desc, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db, AsyncSessionLocal
from app.models.models import Conversation, ConversationParticipant, Message
from app.services.guard_layer import GuardLayer
from app.services.merkle import MerkleBatcher
from app.services.jwt_utils import verify_token


# ───────────────────────────────────────────────────────────────────────────────
# ROUTER SETUP
# ───────────────────────────────────────────────────────────────────────────────
router = APIRouter()

# Initialize GuardLayer for message scanning
guard = GuardLayer()

# Map severity levels to numerical scores for risk tracking
SEVERITY_SCORES = {"low": 0.0, "medium": 0.3, "high": 0.6, "critical": 1.0}


# ═══════════════════════════════════════════════════════════════════════════════
# WEBSOCKET CONNECTION MANAGER
# ═══════════════════════════════════════════════════════════════════════════════

class ConnectionManager:
    """
    ╔═══════════════════════════════════════════════════════════════════════════╗
    ║ MANAGE ACTIVE WEBSOCKET CONNECTIONS                                        ║
    ╠═══════════════════════════════════════════════════════════════════════════╣
    ║                                                                           ║
    ║ RESPONSIBILITIES:                                                          ║
    ║ - Track which users are currently connected                               ║
    ║ - Route messages to specific users                                        ║
    ║ - Handle connection/disconnection                                          ║
    ║                                                                           ║
    ║ DATA STRUCTURE:                                                            ║
    ║ self.active = {                                                            ║
    ║     "0xabc123...": <WebSocket>,                                           ║
    ║     "0xdef456...": <WebSocket>,                                           ║
    ║ }                                                                          ║
    ║                                                                           ║
    ║ PRODUCTION CONSIDERATIONS:                                                 ║
    ║ - This is in-memory (lost on server restart)                              ║
    ║ - For multiple servers, use Redis Pub/Sub                                 ║
    ║ - Consider connection limits per user                                     ║
    ╚═══════════════════════════════════════════════════════════════════════════╝
    """

    def __init__(self):
        # Dictionary mapping wallet address to WebSocket connection
        self.active: Dict[str, WebSocket] = {}

    async def connect(self, wallet: str, websocket: WebSocket):
        """Accept and register a new WebSocket connection."""
        await websocket.accept()
        self.active[wallet.lower()] = websocket

    def disconnect(self, wallet: str):
        """Remove a disconnected user."""
        self.active.pop(wallet.lower(), None)

    async def send_to(self, wallet: str, data: dict) -> bool:
        """
        Send a message to a specific user.
        
        @returns: True if sent successfully, False if user not connected
        """
        ws = self.active.get(wallet.lower())
        if ws:
            try:
                await ws.send_json(data)
                return True
            except Exception:
                # Connection probably broken, clean up
                self.disconnect(wallet)
        return False


# Singleton instance of the connection manager
manager = ConnectionManager()


# ═══════════════════════════════════════════════════════════════════════════════
# HELPER FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

async def find_conversation(db: AsyncSession, wallet_a: str, wallet_b: str) -> Optional[str]:
    """
    Find existing conversation between two wallets.
    
    Used to avoid creating duplicate conversations.
    Returns conversation_id if exists, None otherwise.
    """
    # Get all conversations wallet_a is in
    a_convs = select(ConversationParticipant.conversation_id).where(
        ConversationParticipant.wallet_address == wallet_a.lower()
    ).scalar_subquery()

    # Find if wallet_b is in any of those conversations
    result = await db.execute(
        select(ConversationParticipant.conversation_id).where(
            ConversationParticipant.wallet_address == wallet_b.lower(),
            ConversationParticipant.conversation_id.in_(a_convs),
        ).limit(1)
    )
    return result.scalar()


async def create_conversation_db(db: AsyncSession, wallet_a: str, wallet_b: str) -> str:
    """
    Create a new conversation between two wallets.
    
    Creates:
    1. Conversation record
    2. Two ConversationParticipant records (one for each wallet)
    
    @returns: The new conversation_id
    """
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
    """
    Get the other participant's wallet in a conversation.
    
    Used to route messages to the recipient.
    """
    result = await db.execute(
        select(ConversationParticipant.wallet_address).where(
            ConversationParticipant.conversation_id == conversation_id,
            ConversationParticipant.wallet_address != my_wallet.lower(),
        )
    )
    return result.scalar()


# ═══════════════════════════════════════════════════════════════════════════════
# WEBSOCKET MESSAGE HANDLERS
# ═══════════════════════════════════════════════════════════════════════════════

async def handle_create_conversation(ws: WebSocket, wallet: str, data: dict):
    """
    ╔═══════════════════════════════════════════════════════════════════════════╗
    ║ HANDLE CREATE_CONVERSATION MESSAGE TYPE                                    ║
    ╠═══════════════════════════════════════════════════════════════════════════╣
    ║                                                                           ║
    ║ REQUEST FORMAT:                                                            ║
    ║ { "type": "create_conversation", "peer_wallet": "0x..." }                 ║
    ║                                                                           ║
    ║ RESPONSE:                                                                  ║
    ║ { "type": "conversation_created", "conversation_id": "...", "peer": "..." }║
    ║                                                                           ║
    ║ LOGIC:                                                                     ║
    ║ 1. Check if conversation already exists between these users               ║
    ║ 2. If exists → Return existing conversation                               ║
    ║ 3. If not → Create new conversation                                       ║
    ║ 4. Notify peer if they're online                                          ║
    ╚═══════════════════════════════════════════════════════════════════════════╝
    """
    peer_wallet = data.get("peer_wallet", "").strip().lower()
    if not peer_wallet:
        await ws.send_json({"type": "error", "message": "peer_wallet required"})
        return

    async with AsyncSessionLocal() as db:
        # Check for existing conversation
        existing = await find_conversation(db, wallet, peer_wallet)
        if existing:
            await ws.send_json({
                "type": "conversation_created",
                "conversation_id": existing,
                "peer": peer_wallet,
                "existing": True,
            })
            return

        # Create new conversation
        conv_id = await create_conversation_db(db, wallet, peer_wallet)

    # Confirm to sender
    await ws.send_json({
        "type": "conversation_created",
        "conversation_id": conv_id,
        "peer": peer_wallet,
        "existing": False,
    })

    # Notify peer if they're online (so they can update their UI)
    await manager.send_to(peer_wallet, {
        "type": "conversation_created",
        "conversation_id": conv_id,
        "peer": wallet,
        "existing": False,
    })


async def handle_send_message(ws: WebSocket, wallet: str, data: dict, force: bool = False, redact: bool = False):
    """
    ╔═══════════════════════════════════════════════════════════════════════════╗
    ║ HANDLE MESSAGE SENDING WITH DLP INTEGRATION                                ║
    ╠═══════════════════════════════════════════════════════════════════════════╣
    ║                                                                           ║
    ║ MESSAGE TYPES:                                                             ║
    ║ - send_message: Normal send, block if risky                               ║
    ║ - force_send: Override warning, send anyway                               ║
    ║ - redact_send: Auto-redact sensitive parts, then send                     ║
    ║                                                                           ║
    ║ FLOW:                                                                      ║
    ║ 1. Validate sender is participant                                         ║
    ║ 2. If redact: Run redaction on content                                    ║
    ║ 3. Run GuardLayer scan                                                    ║
    ║ 4. If risky and not forced/redacted → Return DLP warning                  ║
    ║ 5. Save message to DB with risk metadata                                  ║
    ║ 6. Add to Merkle audit batch                                              ║
    ║ 7. Deliver to recipient if online                                         ║
    ╚═══════════════════════════════════════════════════════════════════════════╝
    """
    conversation_id = data.get("conversation_id")
    content = data.get("content", "").strip()

    if not conversation_id or not content:
        await ws.send_json({"type": "error", "message": "conversation_id and content required"})
        return

    async with AsyncSessionLocal() as db:
        # Verify sender is a participant in this conversation
        result = await db.execute(
            select(ConversationParticipant).where(
                ConversationParticipant.conversation_id == conversation_id,
                ConversationParticipant.wallet_address == wallet,
            )
        )
        if not result.scalar():
            await ws.send_json({"type": "error", "message": "Not a participant in this conversation"})
            return

        # Get peer wallet (the recipient)
        peer = await get_conversation_peer(db, conversation_id, wallet)

        # Handle redaction mode
        original_content = content
        if redact:
            redaction = await guard.redact(content)
            content = redaction["redacted_text"]

        # Run GuardLayer scan on (possibly redacted) content
        scan_result = await guard.scan(content, use_llm=not force)

        # If risky and not forced/redacted, return warning and don't send
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

        # Save message to database
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
            user_override=force and scan_result["is_risky"],  # User overrode warning
            created_at=datetime.utcnow(),
        )
        db.add(msg)
        await db.commit()

    # Add to Merkle batch for blockchain audit trail
    batcher = MerkleBatcher.get_instance()
    batcher.add_event(scan_result["event_hash"], event_type="chat", metadata={
        "sender": wallet,
        "conversation_id": conversation_id,
        "risk_detected": scan_result["is_risky"],
    })

    # Build message payload for delivery
    msg_payload = {
        "message_id": msg.id,
        "conversation_id": conversation_id,
        "sender": wallet,
        "content": content,
        "redacted": redact,
        "risk_detected": scan_result["is_risky"],
        "user_override": force and scan_result["is_risky"],
        "timestamp": msg.created_at.isoformat() + "Z",
        "expires_at": msg.expires_at.isoformat() + "Z" if msg.expires_at else None,
        "is_delivered": False,
        "is_read": False,
    }

    # Push to recipient if online
    if peer:
        await manager.send_to(peer, {**msg_payload, "type": "new_message"})

    # Confirm to sender
    await ws.send_json({**msg_payload, "type": "message_sent"})


async def handle_delivered(ws: WebSocket, wallet: str, data: dict):
    """
    Handle delivery ACK from recipient.
    
    When recipient receives a message, they send a 'delivered' ACK.
    This updates the message status and notifies the sender.
    """
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

            # Notify original sender that message was delivered
            await manager.send_to(msg.sender_wallet, {
                "type": "delivery_update",
                "message_id": message_id,
                "is_delivered": True,
            })


async def handle_read(ws: WebSocket, wallet: str, data: dict):
    """
    Handle read receipts.
    
    When recipient opens a conversation, they send 'read' with message_ids.
    This marks messages as read and notifies the senders.
    """
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
            # Only mark as read if:
            # 1. Message exists
            # 2. Not already read
            # 3. This user is not the sender (can't read own messages)
            if msg and not msg.is_read and msg.sender_wallet != wallet:
                msg.is_read = True
                senders.add(msg.sender_wallet)
        await db.commit()

        # Notify all senders that their messages were read
        for sender in senders:
            await manager.send_to(sender, {
                "type": "read_update",
                "message_ids": message_ids,
                "reader": wallet,
            })


# ═══════════════════════════════════════════════════════════════════════════════
# REST ENDPOINTS (Read-Only)
# ═══════════════════════════════════════════════════════════════════════════════

@router.get("/conversations")
async def get_conversations(
    wallet: str,
    db: AsyncSession = Depends(get_db),
):
    """
    Get all conversations for a wallet.
    
    Returns list of conversations with:
    - Peer wallet address
    - Last message preview
    - Unread count
    - Total message count
    
    Used by frontend to display conversation list.
    """
    w = wallet.lower()

    # Get all conversation IDs for this wallet
    result = await db.execute(
        select(ConversationParticipant.conversation_id).where(
            ConversationParticipant.wallet_address == w
        )
    )
    conv_ids = [row[0] for row in result.all()]

    conversations = []
    now = datetime.utcnow()
    
    for conv_id in conv_ids:
        # Get peer wallet
        peer_result = await db.execute(
            select(ConversationParticipant.wallet_address).where(
                ConversationParticipant.conversation_id == conv_id,
                ConversationParticipant.wallet_address != w,
            )
        )
        peer = peer_result.scalar()

        # Get latest non-expired message
        msg_result = await db.execute(
            select(Message)
            .where(Message.conversation_id == conv_id, Message.expires_at > now)
            .order_by(desc(Message.created_at))
            .limit(1)
        )
        latest = msg_result.scalar()

        # Count non-expired messages
        count_result = await db.execute(
            select(func.count()).select_from(Message).where(
                Message.conversation_id == conv_id,
                Message.expires_at > now,
            )
        )
        msg_count = count_result.scalar() or 0

        # Count unread messages (not from self, not read, not expired)
        unread_result = await db.execute(
            select(func.count()).select_from(Message).where(
                Message.conversation_id == conv_id,
                Message.sender_wallet != w,
                Message.is_read == False,
                Message.expires_at > now,
            )
        )
        unread_count = unread_result.scalar() or 0

        conversations.append({
            "conversation_id": conv_id,
            "peer": peer,
            "last_message": latest.content[:50] if latest else None,  # Preview first 50 chars
            "last_message_time": latest.created_at.isoformat() + "Z" if latest else None,
            "message_count": msg_count,
            "unread_count": unread_count,
        })

    # Sort by most recent message first
    conversations.sort(key=lambda x: x["last_message_time"] or "", reverse=True)

    return {"conversations": conversations}


@router.get("/conversations/{conversation_id}/messages")
async def get_messages(
    conversation_id: str,
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
):
    """
    Get message history for a conversation.
    
    Only returns non-expired messages (24-hour TTL).
    Messages are returned in chronological order (oldest first).
    """
    now = datetime.utcnow()
    result = await db.execute(
        select(Message)
        .where(
            Message.conversation_id == conversation_id,
            Message.expires_at > now,  # Only non-expired
        )
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
                "expires_at": m.expires_at.isoformat() + "Z" if m.expires_at else None,
            }
            # reversed() to show oldest first (chat order)
            for m in reversed(messages)
        ],
        "count": len(messages),
    }


# ═══════════════════════════════════════════════════════════════════════════════
# WEBSOCKET ENDPOINT
# ═══════════════════════════════════════════════════════════════════════════════

@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """
    ╔═══════════════════════════════════════════════════════════════════════════╗
    ║ MAIN WEBSOCKET ENDPOINT FOR REAL-TIME MESSAGING                            ║
    ╠═══════════════════════════════════════════════════════════════════════════╣
    ║                                                                           ║
    ║ CONNECTION:                                                                ║
    ║ ws://host/chat/ws?token=JWT                                                ║
    ║                                                                           ║
    ║ AUTHENTICATION:                                                             ║
    ║ JWT token is passed as query parameter (WebSocket doesn't support headers)║
    ║ Token is verified and wallet address extracted                            ║
    ║                                                                           ║
    ║ MESSAGE TYPES:                                                             ║
    ║ Incoming:                                                                  ║
    ║ - create_conversation: Start new chat                                     ║
    ║ - send_message: Send message (blocked if risky)                           ║
    ║ - force_send: Override DLP warning                                        ║
    ║ - redact_send: Auto-redact and send                                       ║
    ║ - delivered: ACK message delivery                                          ║
    ║ - read: Mark messages as read                                              ║
    ║                                                                           ║
    ║ Outgoing:                                                                  ║
    ║ - conversation_created: New conversation notification                     ║
    ║ - message_sent: Confirmation of sent message                              ║
    ║ - new_message: Incoming message from peer                                 ║
    ║ - dlp_warning: Sensitive data detected warning                            ║
    ║ - delivery_update: Message was delivered                                  ║
    ║ - read_update: Messages were read                                          ║
    ╚═══════════════════════════════════════════════════════════════════════════╝
    """
    # Authenticate via JWT from query parameter
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

    # Register connection
    await manager.connect(wallet, websocket)

    try:
        # Main message loop
        while True:
            raw = await websocket.receive_text()

            # Parse JSON message
            try:
                data = json.loads(raw)
            except json.JSONDecodeError:
                # Non-JSON is treated as ping
                await websocket.send_json({
                    "type": "pong",
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                })
                continue

            # Route by message type
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
                # Unknown type = pong
                await websocket.send_json({
                    "type": "pong",
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                })
    except WebSocketDisconnect:
        manager.disconnect(wallet)
    except Exception:
        # Unexpected error - clean up connection
        manager.disconnect(wallet)


# ═══════════════════════════════════════════════════════════════════════════════
# INTERVIEW QUESTIONS FOR chat.py
# ═══════════════════════════════════════════════════════════════════════════════
"""
Q1: Why pass JWT in query parameter instead of header?
A1: WebSocket connections don't support custom headers.
    The browser WebSocket API doesn't allow adding Authorization header.
    Options for WebSocket auth:
    1. Query parameter: ws://host/ws?token=JWT (what we use)
    2. First message: Send auth message after connecting
    3. Cookie: Use httpOnly cookie (works for same-site)
    
    Query param is simplest but appears in logs - use short-lived tokens.

Q2: How would you scale this for multiple servers?
A2: Problem: ConnectionManager is in-memory, not shared.
    Solution: Redis Pub/Sub
    1. Each server maintains its own ConnectionManager
    2. When server A needs to send to user on server B:
       - Publish message to Redis channel "user:0xabc"
       - Server B subscribes and forwards to connected WebSocket
    3. All servers subscribe to all user channels
    4. Redis acts as message broker

Q3: What's the difference between force_send and redact_send?
A3: force_send:
    - User acknowledges the risk
    - Sends original content unchanged
    - Logged as user_override for audit
    
    redact_send:
    - Automatically masks sensitive data with ****
    - Reduces risk without user decision
    - Example: "My card is 4111-****-****-1111"

Q4: Why 24-hour message expiration?
A4: Benefits:
    - Privacy: Sensitive conversations don't persist
    - Security: Limited data exposure in breach
    - Storage: Automatic cleanup
    
    Implementation:
    - Model has expires_at field (default: created_at + 24 hours)
    - Queries filter out expired messages
    - Background task periodically deletes expired records

Q5: How do delivery and read receipts work?
A5: Flow:
    1. Sender sends message
    2. Server stores message (is_delivered=False, is_read=False)
    3. Server pushes to recipient's WebSocket
    4. Recipient's client sends "delivered" ACK
    5. Server updates is_delivered=True
    6. Server notifies sender: "delivery_update"
    7. Recipient opens conversation, client sends "read"
    8. Server updates is_read=True
    9. Server notifies sender: "read_update"
"""