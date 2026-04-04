"""
╔═══════════════════════════════════════════════════════════════════════════════╗
║                     SentinelX Backend Configuration                           ║
║                     Environment Variables & Settings                          ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║ PURPOSE: Centralized configuration management using Pydantic Settings         ║
║                                                                               ║
║ WHY PYDANTIC SETTINGS?                                                        ║
║ - Type validation: Ensures correct types for all config values               ║
║ - Environment variable loading: Reads from .env file automatically           ║
║ - Default values: Provides fallbacks for development                         ║
║ - Immutable: Settings can't be accidentally changed at runtime               ║
║                                                                               ║
║ CONFIGURATION PATTERN:                                                        ║
║ - Development: Uses default values                                           ║
║ - Production: Overrides via environment variables                            ║
║ - Secrets: Never hardcoded, always from env vars                             ║
║                                                                               ║
║ INTERVIEW QUESTION: Why not just use os.getenv() everywhere?                 ║
║ ANSWER: Pydantic Settings provides:                                          ║
║ 1. Type conversion (string "60" → int 60)                                    ║
║ 2. Validation (fail fast on invalid config)                                  ║
║ 3. Centralized defaults                                                      ║
║ 4. IDE autocomplete support                                                  ║
║ 5. Easy testing (can mock settings object)                                   ║
╚═══════════════════════════════════════════════════════════════════════════════╝
"""
import os
from pydantic_settings import BaseSettings
from dotenv import load_dotenv

# Load environment variables from .env file
# This is called before Settings class is instantiated
load_dotenv()


class Settings(BaseSettings):
    """
    ╔═══════════════════════════════════════════════════════════════════════════╗
    ║ APPLICATION SETTINGS                                                      ║
    ╠═══════════════════════════════════════════════════════════════════════════╣
    ║ All settings are loaded from environment variables with fallback defaults.║
    ║ Pydantic automatically validates types and converts values.               ║
    ╚═══════════════════════════════════════════════════════════════════════════╝
    """
    
    # ═══════════════════════════════════════════════════════════════════════════
    # APPLICATION METADATA
    # ═══════════════════════════════════════════════════════════════════════════
    APP_NAME: str = "SentinelX"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = True  # Enables SQL query logging in development
    
    # ═══════════════════════════════════════════════════════════════════════════
    # AUTHENTICATION / JWT SETTINGS
    # ═══════════════════════════════════════════════════════════════════════════
    """
    JWT (JSON Web Token) Configuration:
    - SECRET_KEY: Used to sign tokens. MUST be unique and unpredictable in production.
    - ALGORITHM: HS256 is symmetric encryption (same key signs and verifies).
    - ACCESS_TOKEN_EXPIRE_MINUTES: Token validity period (60 minutes default).
    
    SECURITY NOTES:
    - SECRET_KEY should be a cryptographically random string (32+ chars)
    - In production, rotate keys periodically
    - Use RS256 (asymmetric) for distributed systems
    
    INTERVIEW QUESTION: Why HS256 vs RS256?
    ANSWER: 
    - HS256 (HMAC): Single secret key, faster, simpler. Good for monoliths.
    - RS256 (RSA): Public/private key pair. Slower but allows token verification
      without sharing the signing key. Better for microservices.
    """
    SECRET_KEY: str = os.getenv("SECRET_KEY", "sentinelx-dev-secret-key-change-me")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    
    # ═══════════════════════════════════════════════════════════════════════════
    # OPENROUTER API (LLM INTEGRATION)
    # ═══════════════════════════════════════════════════════════════════════════
    """
    OpenRouter provides access to multiple LLM providers through a single API.
    Used by GuardLayer for:
    - Content analysis (detecting sensitive data)
    - Text redaction (replacing sensitive data with placeholders)
    
    WHY OPENROUTER?
    - Single API key for multiple LLM providers
    - Cheaper than direct OpenAI API
    - Access to open-source models (Llama, Mistral, etc.)
    
    FALLBACK: If no API key, system uses regex-only mode (no LLM enhancement)
    """
    OPENROUTER_API_KEY: str = os.getenv("OPENROUTER_API_KEY", "")
    
    # ═══════════════════════════════════════════════════════════════════════════
    # ETHEREUM / BLOCKCHAIN SETTINGS
    # ═══════════════════════════════════════════════════════════════════════════
    """
    Ethereum Sepolia Testnet Configuration:
    - SEPOLIA_RPC_URL: Blockchain node endpoint for reading/writing
    - DEPLOYER_PRIVATE_KEY: Private key for signing transactions (DANGER!)
    - AUDIT_CONTRACT_ADDRESS: Deployed smart contract for Merkle root storage
    
    SECURITY CRITICAL:
    - NEVER commit private keys to git
    - Use environment variables or secrets manager
    - In production, use HSM (Hardware Security Module) or vault
    
    INTERVIEW QUESTION: Why use Sepolia testnet instead of mainnet?
    ANSWER: 
    - Free ETH for testing (no real money at risk)
    - Faster block times for development
    - Same API as mainnet for easy migration
    - Test contracts can be redeployed without cost
    """
    SEPOLIA_RPC_URL: str = os.getenv("SEPOLIA_RPC_URL", "https://eth-sepolia.g.alchemy.com/v2/demo")
    DEPLOYER_PRIVATE_KEY: str = os.getenv("DEPLOYER_PRIVATE_KEY", "")
    AUDIT_CONTRACT_ADDRESS: str = os.getenv("AUDIT_CONTRACT_ADDRESS", "0x0000000000000000000000000000000000000000")

    # Algorand auth + audit settings
    ALGO_ALGOD_URL: str = os.getenv(
        "ALGO_ALGOD_URL",
        os.getenv("ALGORAND_NODE_URL", "https://testnet-api.algonode.cloud"),
    )
    ALGO_ALGOD_TOKEN: str = os.getenv(
        "ALGO_ALGOD_TOKEN",
        os.getenv("ALGORAND_NODE_TOKEN", ""),
    )
    ALGO_APP_ID: int = int(os.getenv("ALGO_APP_ID", os.getenv("AUDIT_APP_ID", "0")))
    ALGO_MNEMONIC: str = os.getenv(
        "ALGO_MNEMONIC",
        os.getenv("ALGO_DEPLOYER_MNEMONIC", ""),
    )
    ALGO_NETWORK: str = os.getenv(
        "ALGO_NETWORK",
        os.getenv("ALGORAND_NETWORK", "testnet"),
    )
    ALGO_EXPLORER_TX_BASE: str = os.getenv(
        "ALGO_EXPLORER_TX_BASE",
        "https://testnet.explorer.perawallet.app/tx/",
    )
    
    # ═══════════════════════════════════════════════════════════════════════════
    # DATABASE SETTINGS
    # ═══════════════════════════════════════════════════════════════════════════
    """
    PostgreSQL with AsyncPG Driver:
    - DATABASE_URL format: postgresql+asyncpg://user:password@host:port/database
    
    WHY POSTGRESQL?
    - ACID compliance for financial transactions
    - JSONB support for flexible risk_factors storage
    - Excellent async support via asyncpg
    - Better concurrency than SQLite
    
    WHY ASYNC?
    - Non-blocking database operations
    - Handle thousands of concurrent connections
    - Matches FastAPI's async architecture
    """
    DATABASE_URL: str = os.getenv("DATABASE_URL", "postgresql+asyncpg://localhost:5432/sentinelx")
    DATABASE_SSL_MODE: str = os.getenv("DATABASE_SSL_MODE", "")
    RESET_DB_ON_STARTUP: bool = os.getenv("RESET_DB_ON_STARTUP", "false").lower() == "true"
    
    # ═══════════════════════════════════════════════════════════════════════════
    # CORS SETTINGS
    # ═══════════════════════════════════════════════════════════════════════════
    """
    CORS (Cross-Origin Resource Sharing):
    - FRONTEND_URL: Comma-separated list of allowed origins
    
    EXAMPLE: "http://localhost:5173,https://myapp.vercel.app"
    """
    FRONTEND_URL: str = os.getenv("FRONTEND_URL", "http://localhost:5173")
    
    # ═══════════════════════════════════════════════════════════════════════════
    # RISK ENGINE THRESHOLDS
    # ═══════════════════════════════════════════════════════════════════════════
    """
    Risk Score Thresholds (0.0 to 1.0):
    - RISK_LOW: Below this = low risk, no friction
    - RISK_MEDIUM: Above this = medium risk, step-up required
    - Above RISK_MEDIUM = high risk, potentially blocked
    
    These values control when additional verification is required.
    Lower values = stricter security (more false positives)
    Higher values = more permissive (more false negatives)
    
    INTERVIEW QUESTION: How would you tune these thresholds?
    ANSWER: 
    1. Collect historical data on login attempts
    2. Analyze false positive/negative rates at different thresholds
    3. Use ROC curves to find optimal balance
    4. Consider user experience vs security tradeoff
    """
    RISK_LOW: float = 0.3
    RISK_MEDIUM: float = 0.7
    
    # ═══════════════════════════════════════════════════════════════════════════
    # MERKLE BATCHING SETTINGS
    # ═══════════════════════════════════════════════════════════════════════════
    """
    Merkle Tree Batching Configuration:
    - MERKLE_BATCH_SIZE: Number of events per batch before auto-commit
    - MERKLE_BATCH_INTERVAL_SECONDS: Time between forced batches
    
    WHY BATCHING?
    - Reduces on-chain transaction costs (one tx for many events)
    - Each Merkle root represents 50 events
    - Events are hashed, never storing raw data on-chain
    
    BALANCE:
    - Smaller batch = more frequent on-chain updates (higher cost)
    - Larger batch = less frequent updates (higher latency)
    """
    MERKLE_BATCH_SIZE: int = 50
    MERKLE_BATCH_INTERVAL_SECONDS: int = 300  # 5 minutes

    class Config:
        """Pydantic Settings configuration"""
        env_file = ".env"  # Read from .env file
        extra = "allow"    # Allow extra fields not defined here


# ───────────────────────────────────────────────────────────────────────────────
# GLOBAL SETTINGS INSTANCE
# ───────────────────────────────────────────────────────────────────────────────
"""
Single instance of Settings used throughout the application.
Import this instead of creating new Settings instances:

    from app.config import settings
    print(settings.APP_NAME)  # "SentinelX"

INTERVIEW QUESTION: Why use a singleton pattern for settings?
ANSWER: 
- Ensures consistent configuration across the application
- Avoids re-reading environment variables multiple times
- Memory efficient (one instance shared everywhere)
"""
settings = Settings()


# ═══════════════════════════════════════════════════════════════════════════════
# INTERVIEW QUESTIONS FOR config.py
# ═══════════════════════════════════════════════════════════════════════════════
"""
Q1: How do you handle secrets in production?
A1: Never use .env files in production. Instead:
    - Use a secrets manager (AWS Secrets Manager, HashiCorp Vault)
    - Inject secrets as environment variables at runtime
    - Use Kubernetes secrets for containerized deployments
    - Rotate secrets regularly

Q2: What's the difference between .env and environment variables?
A2: .env is a file for local development. In production:
    - Environment variables are set by the platform (Render, AWS, etc.)
    - .env files should be in .gitignore (never committed)
    - load_dotenv() reads .env into environment variables

Q3: How would you validate configuration on startup?
A3: Add a validator to Settings class:
    @validator('SECRET_KEY')
    def validate_secret_key(cls, v):
        if v == 'sentinelx-dev-secret-key-change-me':
            import warnings
            warnings.warn('Using default SECRET_KEY! Change in production.')
        return v

Q4: What happens if a required environment variable is missing?
A4: With default values, the app starts. To make a field required:
    SECRET_KEY: str  # No default = required
    
    Pydantic will raise ValidationError if missing, crashing the app
    with a clear error message.
"""
