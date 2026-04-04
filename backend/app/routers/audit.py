from __future__ import annotations

from typing import List

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


@router.get("/stats")
async def get_audit_stats():
    return MerkleBatcher.get_instance().get_stats()


@router.get("/batches")
async def get_batches():
    stats = MerkleBatcher.get_instance().get_stats()
    return {
        "batches": stats["batches"],
        "total": stats["total_batches"],
        "pending_events": stats["pending_events"],
    }


@router.post("/batch")
async def create_batch(req: BatchRequest):
    batcher = MerkleBatcher.get_instance()
    batch = await batcher.create_batch(force=req.force)
    if not batch:
        return {"success": False, "message": "No pending events to batch"}

    return {
        "success": True,
        "batch": batch,
        "message": (
            f"Batch anchored with {batch['event_count']} events."
            if batch.get("tx_hash")
            else f"Batch created with {batch['event_count']} events and queued for Algorand anchoring."
        ),
    }


@router.get("/proof/{merkle_root}/{event_hash}")
async def get_proof(merkle_root: str, event_hash: str):
    proof = MerkleBatcher.get_instance().get_proof(merkle_root, event_hash)
    if not proof:
        return {"success": False, "message": "Event not found in the specified batch"}

    return {
        "success": True,
        **proof,
    }


@router.post("/verify")
async def verify_inclusion(req: VerifyRequest):
    is_valid = MerkleBatcher.get_instance().verify_inclusion(
        event_hash=req.event_hash,
        proof=req.proof,
        merkle_root=req.merkle_root,
    )
    return {
        "is_valid": is_valid,
        "event_hash": req.event_hash,
        "merkle_root": req.merkle_root,
        "message": "Event verified against the Algorand-anchored Merkle root." if is_valid else "Verification failed.",
    }


@router.get("/pending")
async def get_pending_events():
    batcher = MerkleBatcher.get_instance()
    return {
        "pending": batcher.pending_events[-20:],
        "count": len(batcher.pending_events),
    }
