"""SentinelX Backend Configuration"""
import os
from pydantic_settings import BaseSettings
from dotenv import load_dotenv

load_dotenv()


class Settings(BaseSettings):
    # App
    APP_NAME: str = "SentinelX"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = True

    # Auth / JWT
    SECRET_KEY: str = os.getenv("SECRET_KEY", "sentinelx-dev-secret-key-change-me")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    # OpenAI
    OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")

    # Ethereum
    SEPOLIA_RPC_URL: str = os.getenv("SEPOLIA_RPC_URL", "https://eth-sepolia.g.alchemy.com/v2/demo")
    DEPLOYER_PRIVATE_KEY: str = os.getenv("DEPLOYER_PRIVATE_KEY", "")
    AUDIT_CONTRACT_ADDRESS: str = os.getenv("AUDIT_CONTRACT_ADDRESS", "0x0000000000000000000000000000000000000000")

    # Database
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite+aiosqlite:///./sentinelx.db")

    # CORS
    FRONTEND_URL: str = os.getenv("FRONTEND_URL", "http://localhost:5173")

    # Risk thresholds
    RISK_LOW: float = 0.3
    RISK_MEDIUM: float = 0.7

    # Merkle batching
    MERKLE_BATCH_SIZE: int = 50
    MERKLE_BATCH_INTERVAL_SECONDS: int = 300  # 5 minutes

    class Config:
        env_file = ".env"
        extra = "allow"


settings = Settings()
