"""
SentinelX Merkle Batching Service
Collects event hashes, builds Merkle trees, posts roots on-chain
"""
import asyncio
import hashlib
import json
import math
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from app.config import settings


def keccak256(data: bytes) -> str:
    """Compute keccak256 hash (fallback to sha3_256 if pysha3 not available)"""
    try:
        import sha3
        h = sha3.keccak_256()
        h.update(data)
        return "0x" + h.hexdigest()
    except ImportError:
        h = hashlib.sha256(data)
        return "0x" + h.hexdigest()


class MerkleTree:
    """Standard Merkle tree with keccak256 hashing"""

    def __init__(self, leaves: List[str]):
        self.leaves = [self._to_bytes32(leaf) for leaf in leaves]
        self.layers: List[List[str]] = []
        self.root: str = ""
        self._build()

    def _to_bytes32(self, hex_str: str) -> str:
        """Normalize a hex string to bytes32"""
        if hex_str.startswith("0x"):
            hex_str = hex_str[2:]
        return hex_str.ljust(64, "0")[:64]

    def _hash_pair(self, a: str, b: str) -> str:
        """Hash two nodes together (sorted for consistency)"""
        pair = sorted([a, b])
        combined = bytes.fromhex(pair[0]) + bytes.fromhex(pair[1])
        return keccak256(combined)[2:]  # strip 0x

    def _build(self):
        """Build the Merkle tree from leaves up"""
        if not self.leaves:
            self.root = "0x" + "0" * 64
            return

        current_layer = self.leaves[:]
        self.layers = [current_layer[:]]

        while len(current_layer) > 1:
            next_layer = []
            for i in range(0, len(current_layer), 2):
                if i + 1 < len(current_layer):
                    next_layer.append(self._hash_pair(current_layer[i], current_layer[i + 1]))
                else:
                    next_layer.append(current_layer[i])
            current_layer = next_layer
            self.layers.append(current_layer[:])

        self.root = "0x" + current_layer[0]

    def get_proof(self, leaf_index: int) -> List[str]:
        """Get Merkle proof for a specific leaf"""
        if leaf_index >= len(self.leaves):
            return []

        proof = []
        index = leaf_index

        for layer in self.layers[:-1]:
            if index % 2 == 0:
                # Right sibling
                if index + 1 < len(layer):
                    proof.append("0x" + layer[index + 1])
            else:
                # Left sibling
                proof.append("0x" + layer[index - 1])
            index = index // 2

        return proof

    def verify_proof(self, leaf: str, proof: List[str], root: str) -> bool:
        """Verify a Merkle proof"""
        current = self._to_bytes32(leaf)

        for sibling in proof:
            sibling_clean = self._to_bytes32(sibling)
            current = self._hash_pair(current, sibling_clean)

        return ("0x" + current) == root


class MerkleBatcher:
    """Collects events and batches them into Merkle trees"""

    _instance = None

    def __init__(self):
        self.pending_events: List[Dict] = []
        self.batches: List[Dict] = []
        self.trees: Dict[str, MerkleTree] = {}

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def add_event(self, event_hash: str, event_type: str = "login", metadata: Optional[Dict] = None):
        """Add an event hash to the pending batch"""
        self.pending_events.append({
            "event_hash": event_hash,
            "event_type": event_type,
            "metadata": metadata or {},
            "timestamp": datetime.utcnow().isoformat(),
        })

        # Auto-batch if threshold reached
        if len(self.pending_events) >= settings.MERKLE_BATCH_SIZE:
            return self.create_batch()
        return None

    def create_batch(self) -> Optional[Dict]:
        """Create a Merkle batch from pending events"""
        if not self.pending_events:
            return None

        event_hashes = [e["event_hash"] for e in self.pending_events]
        tree = MerkleTree(event_hashes)

        batch = {
            "id": f"batch_{len(self.batches) + 1}",
            "merkle_root": tree.root,
            "event_count": len(event_hashes),
            "event_hashes": event_hashes,
            "events": self.pending_events[:],
            "created_at": datetime.utcnow().isoformat(),
            "tx_hash": None,
            "status": "pending",
        }

        self.trees[tree.root] = tree
        self.batches.append(batch)
        self.pending_events = []

        return batch

    def get_proof(self, merkle_root: str, event_hash: str) -> Optional[Dict]:
        """Get Merkle proof for a specific event in a batch"""
        tree = self.trees.get(merkle_root)
        if not tree:
            return None

        # Find the leaf index
        normalized_hash = tree._to_bytes32(event_hash)
        try:
            leaf_index = tree.leaves.index(normalized_hash)
        except ValueError:
            return None

        proof = tree.get_proof(leaf_index)
        is_valid = tree.verify_proof(event_hash, proof, merkle_root)

        return {
            "event_hash": event_hash,
            "merkle_root": merkle_root,
            "proof": proof,
            "leaf_index": leaf_index,
            "is_valid": is_valid,
        }

    def verify_inclusion(self, event_hash: str, proof: List[str], merkle_root: str) -> bool:
        """Verify that an event is included in a batch"""
        tree = MerkleTree([])  # Dummy tree for utility methods
        return tree.verify_proof(event_hash, proof, merkle_root)

    def get_stats(self) -> Dict:
        """Get batching statistics"""
        return {
            "pending_events": len(self.pending_events),
            "total_batches": len(self.batches),
            "total_events_batched": sum(b["event_count"] for b in self.batches),
            "batches": [
                {
                    "id": b["id"],
                    "merkle_root": b["merkle_root"],
                    "event_count": b["event_count"],
                    "status": b["status"],
                    "tx_hash": b["tx_hash"],
                    "created_at": b["created_at"],
                }
                for b in self.batches[-10:]  # Last 10 batches
            ],
        }

    async def run_background(self):
        """Background task: periodically create batches"""
        while True:
            await asyncio.sleep(settings.MERKLE_BATCH_INTERVAL_SECONDS)
            if self.pending_events:
                batch = self.create_batch()
                if batch:
                    print(f"🌲 Merkle batch created: {batch['merkle_root'][:16]}... ({batch['event_count']} events)")
