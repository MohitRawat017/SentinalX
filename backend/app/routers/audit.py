"""
SentinelX Audit Trail Router
Merkle batching and on-chain proof verification endpoints
"""
from typing import List, Optional

from fastapi import APIRouter
from pydantic import BaseModel

from app.services.merkle import MerkleBatcher

router = APIRouter()


class VerifyRequest(BaseModel):
    event_hash: str
    proof: List[str]
    merkle_root: str


class BatchRequest(BaseModel):
    force: bool = False


# ─── Endpoints ──────────────────────────────────────────────────────

@router.get("/stats")
async def get_audit_stats():
    """Get Merkle batching statistics"""
    batcher = MerkleBatcher.get_instance()
    return batcher.get_stats()


@router.get("/batches")
async def get_batches():
    """Get all Merkle batches"""
    batcher = MerkleBatcher.get_instance()
    stats = batcher.get_stats()
    return {
        "batches": stats["batches"],
        "total": stats["total_batches"],
        "pending_events": stats["pending_events"],
    }


@router.post("/batch")
async def create_batch(req: BatchRequest):
    """Force create a Merkle batch from pending events"""
    batcher = MerkleBatcher.get_instance()

    if not batcher.pending_events:
        return {"success": False, "message": "No pending events to batch"}

    batch = batcher.create_batch()
    if batch:
        return {
            "success": True,
            "batch": {
                "id": batch["id"],
                "merkle_root": batch["merkle_root"],
                "event_count": batch["event_count"],
                "status": batch["status"],
                "created_at": batch["created_at"],
            },
            "message": f"Batch created with {batch['event_count']} events. Merkle root: {batch['merkle_root'][:20]}...",
        }
    return {"success": False, "message": "Failed to create batch"}


@router.get("/proof/{merkle_root}/{event_hash}")
async def get_proof(merkle_root: str, event_hash: str):
    """Get Merkle proof for a specific event"""
    batcher = MerkleBatcher.get_instance()
    proof = batcher.get_proof(merkle_root, event_hash)

    if not proof:
        return {
            "success": False,
            "message": "Event not found in the specified batch",
        }

    return {
        "success": True,
        "proof": proof,
        "etherscan_url": f"https://sepolia.etherscan.io/tx/{proof.get('tx_hash', 'pending')}",
    }


@router.post("/verify")
async def verify_inclusion(req: VerifyRequest):
    """Verify that an event hash is included in a Merkle batch"""
    batcher = MerkleBatcher.get_instance()
    is_valid = batcher.verify_inclusion(
        event_hash=req.event_hash,
        proof=req.proof,
        merkle_root=req.merkle_root,
    )

    return {
        "is_valid": is_valid,
        "event_hash": req.event_hash,
        "merkle_root": req.merkle_root,
        "message": "✅ Event verified — inclusion proof is valid." if is_valid
        else "❌ Verification failed — event not in batch.",
    }


@router.get("/pending")
async def get_pending_events():
    """Get events waiting to be batched"""
    batcher = MerkleBatcher.get_instance()
    return {
        "pending": batcher.pending_events[-20:],
        "count": len(batcher.pending_events),
    }
