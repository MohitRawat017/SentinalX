import argparse
import base64
import os
from pathlib import Path

from algosdk import account, mnemonic, transaction
from algosdk.v2client import algod
from pyteal import Mode, compileTeal

from audit_contract import approval_program, clear_program


REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_ENV_FILE = REPO_ROOT / "backend" / ".env"

DEFAULT_ENDPOINTS = {
    "testnet": {
        "url": "https://testnet-api.algonode.cloud",
        "token": "",
    },
    "localnet": {
        "url": "http://localhost:4001",
        "token": "a" * 64,
    },
}


def read_env_file(env_path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not env_path.exists():
        return values

    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()

    return values


def get_setting(
    env_data: dict[str, str],
    primary_key: str,
    legacy_key: str | None = None,
    default: str = "",
) -> str:
    value = os.getenv(primary_key)
    if value not in (None, ""):
        return value

    if primary_key in env_data and env_data[primary_key] != "":
        return env_data[primary_key]

    if legacy_key:
        legacy_value = os.getenv(legacy_key)
        if legacy_value not in (None, ""):
            return legacy_value
        if legacy_key in env_data and env_data[legacy_key] != "":
            return env_data[legacy_key]

    return default


def write_env_value(env_path: Path, key: str, value: str) -> None:
    lines = env_path.read_text(encoding="utf-8").splitlines() if env_path.exists() else []
    updated = False
    for index, line in enumerate(lines):
        if line.startswith(f"{key}="):
            lines[index] = f"{key}={value}"
            updated = True
            break

    if not updated:
        lines.append(f"{key}={value}")

    env_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def decode_global_state(app_info: dict) -> dict[str, str | int]:
    decoded: dict[str, str | int] = {}
    for item in app_info.get("params", {}).get("global-state", []):
        key = base64.b64decode(item["key"]).decode("utf-8")
        value = item["value"]
        if value.get("type") == 1:
            decoded[key] = value.get("uint", 0)
        else:
            raw_bytes = value.get("bytes", "")
            decoded[key] = base64.b64decode(raw_bytes).hex() if raw_bytes else ""
    return decoded


def resolve_environment(cli_environment: str | None, env_data: dict[str, str]) -> str:
    return (
        cli_environment
        or os.getenv("ALGOKIT_ENVIRONMENT")
        or get_setting(env_data, "ALGO_NETWORK", "ALGORAND_NETWORK", "testnet")
        or "testnet"
    ).lower()


def resolve_algod_client(environment: str, env_data: dict[str, str]) -> algod.AlgodClient:
    defaults = DEFAULT_ENDPOINTS.get(environment, DEFAULT_ENDPOINTS["testnet"])
    algod_url = get_setting(env_data, "ALGO_ALGOD_URL", "ALGORAND_NODE_URL", defaults["url"])
    algod_token = get_setting(env_data, "ALGO_ALGOD_TOKEN", "ALGORAND_NODE_TOKEN", defaults["token"])
    return algod.AlgodClient(algod_token, algod_url)


def compile_program(client: algod.AlgodClient, source: str) -> bytes:
    compiled = client.compile(source)
    return base64.b64decode(compiled["result"])


def main():
    parser = argparse.ArgumentParser(description="Deploy SentinelX audit anchor app.")
    parser.add_argument(
        "--environment",
        choices=sorted(DEFAULT_ENDPOINTS.keys()),
        help="Target AlgoKit environment name.",
    )
    parser.add_argument(
        "--env-file",
        default=str(DEFAULT_ENV_FILE),
        help="Path to the backend .env file to read/write.",
    )
    parser.add_argument(
        "--no-write-env",
        action="store_true",
        help="Skip writing the deployed app ID back to the backend .env file.",
    )
    args = parser.parse_args()

    env_path = Path(args.env_file).resolve()
    env_data = read_env_file(env_path)
    environment = resolve_environment(args.environment, env_data)
    deployer_mnemonic = get_setting(env_data, "ALGO_MNEMONIC", "ALGO_DEPLOYER_MNEMONIC")
    if not deployer_mnemonic:
        raise RuntimeError("Missing ALGO_MNEMONIC or ALGO_DEPLOYER_MNEMONIC in the backend env file.")

    try:
        sender_private_key = mnemonic.to_private_key(deployer_mnemonic)
    except Exception as exc:
        raise RuntimeError(
            "Configured Algorand mnemonic is invalid. Update ALGO_MNEMONIC with a real 25-word testnet account mnemonic before deploying."
        ) from exc

    client = resolve_algod_client(environment, env_data)
    sender_address = account.address_from_private_key(sender_private_key)

    approval_source = compileTeal(approval_program(), mode=Mode.Application, version=6)
    clear_source = compileTeal(clear_program(), mode=Mode.Application, version=6)
    approval_binary = compile_program(client, approval_source)
    clear_binary = compile_program(client, clear_source)

    params = client.suggested_params()
    global_schema = transaction.StateSchema(num_uints=1, num_byte_slices=1)
    local_schema = transaction.StateSchema(num_uints=0, num_byte_slices=0)

    create_txn = transaction.ApplicationCreateTxn(
        sender=sender_address,
        sp=params,
        on_complete=transaction.OnComplete.NoOpOC,
        approval_program=approval_binary,
        clear_program=clear_binary,
        global_schema=global_schema,
        local_schema=local_schema,
    )
    signed_txn = create_txn.sign(sender_private_key)
    tx_id = client.send_transaction(signed_txn)
    confirmation = transaction.wait_for_confirmation(client, tx_id, 4)
    app_id = confirmation["application-index"]
    app_info = client.application_info(app_id)
    state = decode_global_state(app_info)

    if not args.no_write_env:
        write_env_value(env_path, "ALGO_APP_ID", str(app_id))
        write_env_value(env_path, "AUDIT_APP_ID", str(app_id))

    print(f"Deployed SentinelX audit anchor to {environment}.")
    print(f"Application ID: {app_id}")
    print(f"Transaction ID: {tx_id}")
    print(f"Global state: batch_count={state.get('batch_count', 0)}, last_root={state.get('last_root', '')}")
    if args.no_write_env:
        print("Update your environment with:")
        print(f"ALGO_APP_ID={app_id}")
    else:
        print(f"Updated {env_path} with ALGO_APP_ID and AUDIT_APP_ID.")


if __name__ == "__main__":
    main()
