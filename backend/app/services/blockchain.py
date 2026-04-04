from __future__ import annotations

import base64
from functools import lru_cache
from decimal import Decimal, InvalidOperation
from typing import Optional

from algosdk import account, encoding, mnemonic, transaction
from algosdk.v2client import algod
from nacl.signing import VerifyKey

from app.config import settings


MESSAGE_PREFIX = b"MX"
LEGACY_TRANSACTION_NETWORK = "ethereum_sepolia"


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


def get_transaction_network() -> str:
    network = (settings.ALGO_NETWORK or "testnet").strip().lower() or "testnet"
    return f"algorand_{network}"


def algo_to_microalgos(amount_algo: float | str | Decimal) -> int:
    try:
        amount = Decimal(str(amount_algo))
    except (InvalidOperation, ValueError, TypeError) as exc:
        raise ValueError("Invalid ALGO amount") from exc

    if amount <= 0:
        raise ValueError("Amount must be greater than zero")

    microalgos = amount * Decimal("1000000")
    if microalgos != microalgos.quantize(Decimal("1")):
        raise ValueError("ALGO amounts support up to 6 decimal places")

    return int(microalgos)


def verify_algorand_payment(
    tx_id: str,
    sender_wallet: str,
    recipient_wallet: str,
    amount_algo: float | str | Decimal,
) -> dict:
    normalized_tx_id = (tx_id or "").strip()
    if not normalized_tx_id:
        raise ValueError("Algorand transaction ID is required")

    algod_client = get_algod_client()
    try:
        tx_info = algod_client.pending_transaction_information(normalized_tx_id)
    except Exception as exc:  # pragma: no cover - network/provider failure
        raise ValueError("Unable to fetch Algorand transaction details") from exc

    pool_error = (tx_info.get("pool-error") or "").strip()
    if pool_error:
        raise ValueError(f"Algorand transaction rejected: {pool_error}")

    confirmed_round = int(tx_info.get("confirmed-round") or 0)
    if confirmed_round <= 0:
        raise ValueError("Algorand transaction is not confirmed yet")

    txn_payload = (tx_info.get("txn") or {}).get("txn") or {}
    if txn_payload.get("type") != "pay":
        raise ValueError("Algorand transaction is not a payment")

    actual_sender = normalize_algorand_address(txn_payload.get("snd", ""))
    actual_receiver = normalize_algorand_address(txn_payload.get("rcv", ""))
    actual_amount = int(txn_payload.get("amt") or 0)

    expected_sender = normalize_algorand_address(sender_wallet)
    expected_receiver = normalize_algorand_address(recipient_wallet)
    expected_amount = algo_to_microalgos(amount_algo)

    if actual_sender != expected_sender:
        raise ValueError("Algorand transaction sender does not match the evaluated wallet")
    if actual_receiver != expected_receiver:
        raise ValueError("Algorand transaction receiver does not match the evaluated recipient")
    if actual_amount != expected_amount:
        raise ValueError("Algorand transaction amount does not match the evaluated amount")

    return {
        "tx_id": normalized_tx_id,
        "sender_wallet": actual_sender.lower(),
        "recipient_wallet": actual_receiver.lower(),
        "amount_microalgos": actual_amount,
        "confirmed_round": confirmed_round,
        "network": get_transaction_network(),
        "explorer_url": get_explorer_tx_url(normalized_tx_id),
    }
