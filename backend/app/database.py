"""
╔═══════════════════════════════════════════════════════════════════════════════╗
║                     SentinelX Database Session Management                     ║
║                     Async PostgreSQL with SQLAlchemy                          ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║ PURPOSE: Configure async database connection and session management           ║
║                                                                               ║
║ KEY CONCEPTS:                                                                 ║
║ - Async Engine: Non-blocking database operations using asyncpg               ║
║ - Session Factory: Creates database sessions for each request                ║
║ - Connection Pooling: Reuses connections for efficiency                      ║
║ - Dependency Injection: FastAPI pattern for database access                  ║
║                                                                               ║
║ ARCHITECTURE:                                                                 ║
║ Request → FastAPI → get_db() → AsyncSession → Query → Response              ║
║                                                                               ║
║ INTERVIEW QUESTION: Why async database operations?                           ║
║ ANSWER: In async web frameworks like FastAPI, blocking database calls       ║
║ would block the entire event loop. Async drivers (asyncpg) allow the        ║
║ server to handle other requests while waiting for database responses.        ║
║ This enables handling thousands of concurrent connections with one worker.   ║
╚═══════════════════════════════════════════════════════════════════════════════╝
"""
from sqlalchemy import inspect, text
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.engine import make_url
from sqlalchemy.orm import sessionmaker
from app.config import settings
from app.models.models import Base
from app.services.blockchain import LEGACY_TRANSACTION_NETWORK


# ───────────────────────────────────────────────────────────────────────────────
# DATABASE URL CONVERSION
# ───────────────────────────────────────────────────────────────────────────────
def get_database_url() -> str:
    """
    Convert DATABASE_URL to asyncpg-compatible format.
    
    ╔═══════════════════════════════════════════════════════════════════════════╗
    ║ WHY CONVERSION IS NEEDED:                                                 ║
    ║                                                                           ║
    ║ Cloud providers (Render, Heroku) provide URLs like:                       ║
    ║   postgres://user:pass@host:port/db                                       ║
    ║                                                                           ║
    ║ But SQLAlchemy asyncpg requires:                                          ║
    ║   postgresql+asyncpg://user:pass@host:port/db                             ║
    ║                                                                           ║
    ║ This function normalizes the URL format for async operations.             ║
    ╚═══════════════════════════════════════════════════════════════════════════╝
    
    Args:
        None (reads from settings.DATABASE_URL)
    
    Returns:
        str: Asyncpg-compatible database URL
    """
    url = settings.DATABASE_URL
    
    # Convert postgres:// to postgresql+asyncpg://
    if url.startswith("postgres://"):
        url = url.replace("postgres://", "postgresql+asyncpg://", 1)
    elif url.startswith("postgresql://"):
        url = url.replace("postgresql://", "postgresql+asyncpg://", 1)
    
    return url


def get_database_connect_args() -> dict:
    """
    Add driver-specific connect args for hosted Postgres providers.

    AsyncPG expects SSL to be configured via connect kwargs, not libpq's
    sslmode query param once SQLAlchemy has parsed the URL.
    """
    url = make_url(get_database_url())
    query_keys = {key.lower() for key in url.query}
    if "ssl" in query_keys or "sslmode" in query_keys:
        return {}

    ssl_mode = settings.DATABASE_SSL_MODE.strip().lower()
    host = (url.host or "").lower()
    is_remote_host = bool(host) and host not in {"localhost", "127.0.0.1"}

    # Most hosted Postgres services require TLS, while local development usually
    # does not. Allow explicit env override when needed.
    if not ssl_mode and is_remote_host:
        ssl_mode = "require"

    if not ssl_mode:
        return {}

    if ssl_mode == "disable":
        return {"ssl": False}

    return {"ssl": ssl_mode}


def get_database_error_hint(exc: Exception) -> str:
    """Return a short, actionable hint for common local database failures."""
    hints = []
    error_text = str(exc).lower()
    raw_url = settings.DATABASE_URL.lower()

    if "render.com" in raw_url:
        hints.append(
            "If you are running locally against Render Postgres, use the external database URL instead of the internal/private URL."
        )
    if "ssl" in error_text or "tls" in error_text:
        hints.append(
            "Hosted Postgres connections often require TLS. Set DATABASE_SSL_MODE=require if your provider enforces SSL."
        )

    return " ".join(hints)


# ───────────────────────────────────────────────────────────────────────────────
# ASYNC ENGINE CONFIGURATION
# ───────────────────────────────────────────────────────────────────────────────
"""
╔═══════════════════════════════════════════════════════════════════════════════╗
║ SQLAlchemy Async Engine                                                       ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║ The engine is the starting point for any SQLAlchemy application.              ║
║ It maintains a pool of connections to the database.                           ║
║                                                                               ║
║ CONNECTION POOL SETTINGS:                                                     ║
║ - pool_size=5: Number of connections to keep open                            ║
║ - max_overflow=10: Additional connections allowed during spikes              ║
║ - Total max connections = pool_size + max_overflow = 15                      ║
║                                                                               ║
║ WHY POOLING?                                                                  ║
║ - Creating connections is expensive (TCP handshake, auth)                    ║
║ - Reusing connections is much faster                                         ║
║ - Pool manages connection lifecycle automatically                            ║
║                                                                               ║
║ INTERVIEW QUESTION: What happens if pool is exhausted?                       ║
║ ANSWER: New requests wait for a connection to become available.              ║
║ If timeout is exceeded, an exception is raised. In production, monitor       ║
║ pool usage and adjust pool_size based on traffic patterns.                   ║
╚═══════════════════════════════════════════════════════════════════════════════╝
"""
engine = create_async_engine(
    get_database_url(),
    echo=settings.DEBUG,  # Log SQL queries when DEBUG=True (development only!)
    pool_size=5,          # Number of permanent connections in the pool
    max_overflow=10,      # Additional connections allowed during traffic spikes
    connect_args=get_database_connect_args(),
)


# ───────────────────────────────────────────────────────────────────────────────
# SESSION FACTORY CONFIGURATION
# ───────────────────────────────────────────────────────────────────────────────
"""
╔═══════════════════════════════════════════════════════════════════════════════╗
║ Session Factory (sessionmaker)                                                ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║ A factory that produces AsyncSession instances.                               ║
║                                                                               ║
║ WHY sessionmaker?                                                             ║
║ - Ensures consistent session configuration                                   ║
║ - Manages session lifecycle                                                   ║
║ - Thread-safe (each thread gets its own session)                             ║
║                                                                               ║
║ CONFIGURATION:                                                                ║
║ - class_=AsyncSession: Use async session class                               ║
║ - expire_on_commit=False: Objects remain accessible after commit             ║
║                                                                               ║
║ INTERVIEW QUESTION: Why expire_on_commit=False?                              ║
║ ANSWER: By default, SQLAlchemy "expires" objects after commit, meaning       ║
║ accessing their attributes triggers a new database query. Setting this to    ║
║ False keeps objects usable after commit, which is what we want in web apps   ║
║ where we return the object data in the response.                             ║
╚═══════════════════════════════════════════════════════════════════════════════╝
"""
AsyncSessionLocal = sessionmaker(
    engine,                    # The async engine created above
    class_=AsyncSession,       # Use async session class
    expire_on_commit=False,    # Keep objects accessible after commit
)


# ───────────────────────────────────────────────────────────────────────────────
# DATABASE INITIALIZATION
# ───────────────────────────────────────────────────────────────────────────────
async def init_db():
    """
    Create all database tables.
    
    ╔═══════════════════════════════════════════════════════════════════════════╗
    ║ DATABASE INITIALIZATION                                                   ║
    ╠═══════════════════════════════════════════════════════════════════════════╣
    ║ This function is called on application startup (see main.py lifespan).   ║
    ║                                                                           ║
    ║ WHAT IT DOES:                                                              ║
    ║ 1. drop_all: Removes all existing tables (⚠️ DATA LOSS IN PRODUCTION!)   ║
    ║ 2. create_all: Creates tables from models.py definitions                  ║
    ║                                                                           ║
    ║ PRODUCTION NOTE:                                                           ║
    ║ In production, NEVER use drop_all/create_all! Instead:                    ║
    ║ - Use Alembic migrations for schema changes                               ║
    ║ - Migrations are versioned and reversible                                 ║
    ║ - No data loss during deployments                                         ║
    ║                                                                           ║
    ║ INTERVIEW QUESTION: Why run_sync?                                         ║
    ║ ANSWER: SQLAlchemy's metadata operations (create_all, drop_all) are      ║
    ║ synchronous. run_sync allows running sync functions in async context.     ║
    ║ The connection is async, but the DDL operations inside run_sync block.    ║
    ╚═══════════════════════════════════════════════════════════════════════════╝
    """
    try:
        async with engine.begin() as conn:
            if settings.RESET_DB_ON_STARTUP:
                # Explicit opt-in only. Unconditional drop_all was wiping data on
                # every restart, which is dangerous even for demos.
                await conn.run_sync(Base.metadata.drop_all)

            # Create any missing tables from models.py definitions.
            await conn.run_sync(Base.metadata.create_all)
            await bootstrap_transaction_event_network(conn)
    except Exception as exc:
        hint = get_database_error_hint(exc)
        if hint:
            raise RuntimeError(f"Database initialization failed. {hint}") from exc
        raise


async def bootstrap_transaction_event_network(conn) -> None:
    def get_columns(sync_conn):
        inspector = inspect(sync_conn)
        return {column["name"] for column in inspector.get_columns("transaction_events")}

    columns = await conn.run_sync(get_columns)
    if "network" not in columns:
        await conn.execute(text("ALTER TABLE transaction_events ADD COLUMN network VARCHAR"))

    await conn.execute(
        text(
            """
            UPDATE transaction_events
            SET network = :legacy_network
            WHERE network IS NULL
            """
        ),
        {"legacy_network": LEGACY_TRANSACTION_NETWORK},
    )


# ───────────────────────────────────────────────────────────────────────────────
# DATABASE SESSION DEPENDENCY
# ───────────────────────────────────────────────────────────────────────────────
async def get_db():
    """
    Dependency injection: yields an async database session.
    
    ╔═══════════════════════════════════════════════════════════════════════════╗
    ║ FASTAPI DEPENDENCY INJECTION PATTERN                                      ║
    ╠═══════════════════════════════════════════════════════════════════════════╣
    ║ This function is used as a FastAPI dependency in route handlers:          ║
    ║                                                                           ║
    ║ @router.get("/users")                                                      ║
    ║ async def get_users(db: AsyncSession = Depends(get_db)):                  ║
    ║     # db is automatically injected by FastAPI                             ║
    ║     ...                                                                    ║
    ║                                                                           ║
    ║ LIFECYCLE:                                                                 ║
    ║ 1. Before request: New session created from factory                       ║
    ║ 2. During request: Session used for queries                               ║
    ║ 3. After request: Session closed (returned to pool)                       ║
    ║                                                                           ║
    ║ WHY try/finally?                                                           ║
    ║ Ensures session is always closed, even if an exception occurs.            ║
    ║ If we don't close sessions, connections leak from the pool.               ║
    ║                                                                           ║
    ║ INTERVIEW QUESTION: What's the difference between commit and close?       ║
    ║ ANSWER:                                                                    ║
    ║ - commit(): Saves pending changes to database                             ║
    ║ - close(): Returns connection to pool (doesn't commit/rollback)           ║
    ║ Route handlers should commit explicitly when needed.                       ║
    ╚═══════════════════════════════════════════════════════════════════════════╝
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session  # Provide session to route handler
        finally:
            await session.close()  # Always close, even on exception


# ═══════════════════════════════════════════════════════════════════════════════
# INTERVIEW QUESTIONS FOR database.py
# ═══════════════════════════════════════════════════════════════════════════════
"""
Q1: What's the difference between SQLAlchemy Core and ORM?
A1: SQLAlchemy has two layers:
    - Core: Low-level SQL expression language. You write SQL-like code.
      Example: conn.execute(users.select())
    - ORM (Object Relational Mapping): High-level, maps Python classes to tables.
      Example: session.query(User).all()
    We use ORM (models.py) for cleaner, more Pythonic code.

Q2: How do you handle database migrations in production?
A2: Use Alembic, SQLAlchemy's migration tool:
    1. alembic revision --autogenerate -m "add user table"
    2. alembic upgrade head
    This creates versioned migration scripts that can be reviewed and rolled back.

Q3: What is N+1 problem and how do you prevent it?
A3: N+1 occurs when you fetch N records and make N additional queries for related
    data. Prevent with:
    - joinedload(): Fetch related data in one query (JOIN)
    - selectinload(): Fetch related data with IN clause
    Example: session.query(User).options(joinedload(User.posts)).all()

Q4: How would you handle database connection failures?
A4: Several strategies:
    - Connection pool has built-in retry
    - Use health checks to detect failures
    - Implement circuit breaker pattern
    - Fall back to read replica if available
    - Return graceful error to user with retry suggestion
"""
