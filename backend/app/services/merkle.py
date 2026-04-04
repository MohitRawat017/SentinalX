from __future__ import annotations

import asyncio
import hashlib
from datetime import datetime
from typing import Any, Optional

from sqlalchemy import desc, select

from app.config import settings
from app.database import AsyncSessionLocal
from app.models.models import AuditBatch, GuardEvent, LoginEvent, TransactionEvent
from app.services.blockchain import get_explorer_tx_url, store_merkle_batch


def _normalize_hash(value: str) -> str:
    cleaned = (value or "").strip().lower().removeprefix("0x")
    if len(cleaned) == 64 and all(ch in "0123456789abcdef" for ch in cleaned):
        return cleaned
    return hashlib.sha256(cleaned.encode("utf-8")).hexdigest()


def _hash_pair(left: str, right: str) -> str:
    ordered = sorted((_normalize_hash(left), _normalize_hash(right)))
    return hashlib.sha256("".join(ordered).encode("utf-8")).hexdigest()


def _build_levels(leaves: list[str]) -> list[list[str]]:
    if not leaves:
        return []

    levels = [[_normalize_hash(leaf) for leaf in leaves]]
    while len(levels[-1]) > 1:
        current = levels[-1]
        next_level: list[str] = []
        for index in range(0, len(current), 2):
            left = current[index]
            right = current[index + 1] if index + 1 < len(current) else current[index]
            next_level.append(_hash_pair(left, right))
        levels.append(next_level)
    return levels


def get_merkle_root(leaves: list[str]) -> Optional[str]:
    levels = _build_levels(leaves)
    if not levels:
        return None
    return levels[-1][0]


def get_merkle_proof(leaves: list[str], index: int) -> list[str]:
    levels = _build_levels(leaves)
    if not levels or index < 0 or index >= len(levels[0]):
        return []

    proof: list[str] = []
    cursor = index
    for level in levels[:-1]:
        sibling_index = cursor + 1 if cursor % 2 == 0 else cursor - 1
        if sibling_index >= len(level):
            sibling_index = cursor
        proof.append(level[sibling_index])
        cursor //= 2
    return proof


def verify_proof(event_hash: str, proof: list[str], merkle_root: str) -> bool:
    current = _normalize_hash(event_hash)
    for sibling in proof:
        current = _hash_pair(current, sibling)
    return current == _normalize_hash(merkle_root)


class MerkleBatcher:
    _instance: Optional["MerkleBatcher"] = None

    def __init__(self) -> None:
        self.pending_events: list[dict[str, Any]] = []
        self.batches: list[dict[str, Any]] = []
        self._lock = asyncio.Lock()
        self._initialized = False

    @classmethod
    def get_instance(cls) -> "MerkleBatcher":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    async def initialize(self) -> None:
        if self._initialized:
            return

        async with AsyncSessionLocal() as db:
            result = await db.execute(
                select(AuditBatch).order_by(desc(AuditBatch.timestamp))
            )
            rows = list(result.scalars().all())
            self.batches = [self._serialize_batch(row) for row in rows]

            pending_rows = [row for row in rows if row.status != "confirmed" and row.event_hashes]

        for row in reversed(pending_rows):
            await self._submit_existing_batch(row.merkle_root)

        self._initialized = True

    def add_event(self, event_hash: str, event_type: str = "event", metadata: Optional[dict[str, Any]] = None) -> None:
        item = {
            "event_hash": _normalize_hash(event_hash),
            "event_type": event_type,
            "metadata": metadata or {},
            "timestamp": datetime.utcnow().isoformat() + "Z",
        }
        self.pending_events.append(item)

        if len(self.pending_events) >= settings.MERKLE_BATCH_SIZE:
            try:
                loop = asyncio.get_running_loop()
                loop.create_task(self.create_batch(force=True))
            except RuntimeError:
                pass

    async def create_batch(self, force: bool = False) -> Optional[dict[str, Any]]:
        async with self._lock:
            if not self.pending_events:
                return None
            if not force and len(self.pending_events) < settings.MERKLE_BATCH_SIZE:
                return None

            events = list(self.pending_events)
            self.pending_events.clear()

        event_hashes = [event["event_hash"] for event in events]
        merkle_root = get_merkle_root(event_hashes)
        if not merkle_root:
            return None

        async with AsyncSessionLocal() as db:
            batch = AuditBatch(
                merkle_root=merkle_root,
                event_count=len(event_hashes),
                event_hashes=event_hashes,
                status="pending",
            )
            db.add(batch)
            await db.commit()
            await db.refresh(batch)

        batch_dict = self._serialize_batch(batch)
        self.batches.insert(0, batch_dict)
        await self._sync_event_batch_references(event_hashes, merkle_root, None)
        await self._submit_existing_batch(merkle_root)
        return self.get_batch(merkle_root)

    async def run_background(self) -> None:
        while True:
            try:
                await asyncio.sleep(settings.MERKLE_BATCH_INTERVAL_SECONDS)
                if self.pending_events:
                    await self.create_batch(force=True)
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # pragma: no cover - background safety
                print(f"MerkleBatcher error: {exc}")
                await asyncio.sleep(5)

    def get_batch(self, merkle_root: str) -> Optional[dict[str, Any]]:
        normalized = _normalize_hash(merkle_root)
        return next((batch for batch in self.batches if batch["merkle_root"] == normalized), None)

    def get_proof(self, merkle_root: str, event_hash: str) -> Optional[dict[str, Any]]:
        batch = self.get_batch(merkle_root)
        if not batch:
            return None

        normalized_event_hash = _normalize_hash(event_hash)
        try:
            index = [_normalize_hash(item) for item in batch["event_hashes"]].index(normalized_event_hash)
        except ValueError:
            return None

        proof = get_merkle_proof(batch["event_hashes"], index)
        explorer_url = get_explorer_tx_url(batch.get("tx_hash"))
        return {
            "batch_id": batch["id"],
            "event_hash": normalized_event_hash,
            "merkle_root": batch["merkle_root"],
            "proof": proof,
            "tx_hash": batch.get("tx_hash"),
            "explorer_url": explorer_url,
            "etherscan_url": explorer_url,
        }

    def verify_inclusion(self, event_hash: str, proof: list[str], merkle_root: str) -> bool:
        return verify_proof(event_hash, proof, merkle_root)

    def get_stats(self) -> dict[str, Any]:
        return {
            "total_batches": len(self.batches),
            "pending_events": len(self.pending_events),
            "total_events_batched": sum(batch["event_count"] for batch in self.batches),
            "batches": self.batches,
        }

    async def _submit_existing_batch(self, merkle_root: str) -> None:
        batch = self.get_batch(merkle_root)
        if not batch or batch.get("status") == "confirmed":
            return

        submission = await store_merkle_batch(merkle_root)
        if submission is None:
            return

        tx_id = submission["tx_id"]
        confirmed_round = submission.get("confirmed_round")

        async with AsyncSessionLocal() as db:
            result = await db.execute(
                select(AuditBatch).where(AuditBatch.merkle_root == merkle_root)
            )
            batch_row = result.scalar_one_or_none()
            if batch_row is None:
                return

            batch_row.tx_hash = tx_id
            batch_row.block_number = confirmed_round
            batch_row.status = "confirmed"
            await db.commit()

        await self._sync_event_batch_references(batch["event_hashes"], merkle_root, tx_id)
        cached = self.get_batch(merkle_root)
        if cached:
            cached["tx_hash"] = tx_id
            cached["block_number"] = confirmed_round
            cached["status"] = "confirmed"
            cached["explorer_url"] = get_explorer_tx_url(tx_id)

    async def _sync_event_batch_references(self, event_hashes: list[str], merkle_root: str, tx_hash: Optional[str]) -> None:
        if not event_hashes:
            return

        async with AsyncSessionLocal() as db:
            normalized_hashes = [_normalize_hash(value) for value in event_hashes]
            for model in (LoginEvent, GuardEvent, TransactionEvent):
                result = await db.execute(
                    select(model).where(model.event_hash.in_(normalized_hashes))
                )
                for row in result.scalars().all():
                    row.merkle_root = merkle_root
                    if tx_hash:
                        row.tx_hash = tx_hash
            await db.commit()

    @staticmethod
    def _serialize_batch(batch: AuditBatch) -> dict[str, Any]:
        tx_hash = batch.tx_hash
        return {
            "id": batch.id,
            "merkle_root": _normalize_hash(batch.merkle_root),
            "event_count": batch.event_count or 0,
            "event_hashes": batch.event_hashes or [],
            "tx_hash": tx_hash,
            "block_number": batch.block_number,
            "status": batch.status or "pending",
            "created_at": (batch.timestamp or datetime.utcnow()).isoformat() + "Z",
            "explorer_url": get_explorer_tx_url(tx_hash),
        }
