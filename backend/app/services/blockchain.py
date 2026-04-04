from __future__ import annotations

import base64
from functools import lru_cache
from typing import Optional

from algosdk import account, encoding, mnemonic, transaction
from algosdk.v2client import algod
from nacl.signing import VerifyKey

from app.config import settings


MESSAGE_PREFIX = b"MX"


def normalize_algorand_address(address: str) -> str:
    normalized = (address or "").strip().upper()
    if not normalized or not encoding.is_valid_address(normalized):
        raise ValueError("Invalid Algorand wallet address")
    return normalized


def storage_wallet(address: str) -> str:
    return normalize_algorand_address(address).lower()


def build_sign_in_message(wallet_address: str, nonce: str, issued_at: str, origin: Optional[str] = None) -> str:
    origin_line = f"Origin: {origin}\n" if origin else ""
    return (
        "Sign in to SentinelX\n"
        f"Address: {normalize_algorand_address(wallet_address)}\n"
        f"{origin_line}"
        f"Nonce: {nonce}\n"
        f"Issued At: {issued_at}"
    )


def build_step_up_message(wallet_address: str, nonce: str, issued_at: str) -> str:
    return (
        "SentinelX Step-Up Verification\n"
        "Sign this message to restore full access.\n"
        f"Address: {normalize_algorand_address(wallet_address)}\n"
        f"Nonce: {nonce}\n"
        f"Issued At: {issued_at}"
    )


def _decode_signature(signature_b64: str) -> bytes:
    try:
        return base64.b64decode(signature_b64, validate=True)
    except Exception as exc:  # pragma: no cover - defensive
        raise ValueError("Invalid signature encoding") from exc


def verify_signature(wallet_address: str, message: str, signature_b64: str) -> bool:
    try:
        signer = normalize_algorand_address(wallet_address)
        signature = _decode_signature(signature_b64)
        public_key = encoding.decode_address(signer)
        VerifyKey(public_key).verify(MESSAGE_PREFIX + message.encode("utf-8"), signature)
        return True
    except Exception:
        return False


@lru_cache(maxsize=1)
def get_algod_client() -> algod.AlgodClient:
    return algod.AlgodClient(settings.ALGO_ALGOD_TOKEN, settings.ALGO_ALGOD_URL)


def is_algorand_submission_configured() -> bool:
    return bool(settings.ALGO_APP_ID and settings.ALGO_MNEMONIC)


async def store_merkle_batch(merkle_root_hex: str) -> Optional[dict]:
    if not is_algorand_submission_configured():
        return None

    algod_client = get_algod_client()
    sender_private_key = mnemonic.to_private_key(settings.ALGO_MNEMONIC)
    sender_address = account.address_from_private_key(sender_private_key)
    params = algod_client.suggested_params()
    merkle_root_bytes = bytes.fromhex(merkle_root_hex.removeprefix("0x"))

    txn = transaction.ApplicationCallTxn(
        sender=sender_address,
        sp=params,
        index=settings.ALGO_APP_ID,
        on_complete=transaction.OnComplete.NoOpOC,
        app_args=[b"store_batch", merkle_root_bytes],
    )
    signed_txn = txn.sign(sender_private_key)
    tx_id = algod_client.send_transaction(signed_txn)
    confirmation = transaction.wait_for_confirmation(algod_client, tx_id, 4)

    return {
        "tx_id": tx_id,
        "confirmed_round": confirmation.get("confirmed-round"),
    }


def get_explorer_tx_url(tx_id: Optional[str]) -> Optional[str]:
    if not tx_id:
        return None
    base = settings.ALGO_EXPLORER_TX_BASE.rstrip("/")
    return f"{base}/{tx_id}/"
