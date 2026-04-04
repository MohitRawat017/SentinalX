"""
╔═══════════════════════════════════════════════════════════════════════════════╗
║                     SentinelX — Web3 Adaptive Security Platform               ║
║                           Main FastAPI Application                            ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║ ARCHITECTURE OVERVIEW:                                                        ║
║ This is the entry point for the SentinelX backend. It:                        ║
║ 1. Initializes the FastAPI application with lifecycle management              ║
║ 2. Configures CORS for frontend communication                                 ║
║ 3. Registers all API routers (auth, risk, guard, audit, etc.)                 ║
║ 4. Starts background tasks (Merkle batching, message cleanup)                 ║
║                                                                               ║
║ KEY CONCEPTS:                                                                 ║
║ - Lifespan Context: Modern FastAPI pattern for startup/shutdown logic         ║
║ - CORS Middleware: Allows frontend (React) to communicate with backend        ║
║ - Background Tasks: Async tasks that run alongside the API                    ║
║                                                                               ║
║ INTERVIEW QUESTION: Why use lifespan context manager instead of on_event?     ║
║ ANSWER: The @app.on_event("startup") decorator is deprecated in FastAPI 0.93+ ║
║ Lifespan context managers are the modern approach. They provide:              ║
║ - Better control over startup/shutdown sequence                              ║
║ - Proper async resource cleanup                                              ║
║ - Support for yielding control after startup                                 ║
╚═══════════════════════════════════════════════════════════════════════════════╝
"""
import asyncio
from datetime import datetime
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.config import settings
from app.database import init_db, AsyncSessionLocal
from app.routers import auth, risk, guard, audit, simulation, dashboard, chat, transactions
from app.services.merkle import MerkleBatcher
from sqlalchemy import delete
from app.models.models import Message


# ───────────────────────────────────────────────────────────────────────────────
# BACKGROUND TASK: Message Cleanup
# ───────────────────────────────────────────────────────────────────────────────
async def cleanup_expired_messages():
    """
    Background task: delete expired messages every 60 seconds.
    
    ╔═══════════════════════════════════════════════════════════════════════════╗
    ║ PURPOSE: Maintain chat privacy by auto-deleting messages after 24 hours   ║
    ║                                                                           ║
    ║ WHY: SentinelX implements ephemeral messaging for security:               ║
    ║ - Reduces data exposure in case of breach                                 ║
    ║ - Implements "data minimization" principle (GDPR compliance)              ║
    ║ - Messages older than 24 hours are automatically removed                  ║
    ║                                                                           ║
    ║ IMPLEMENTATION:                                                           ║
    ║ 1. Sleep for 60 seconds between cleanup cycles                            ║
    ║ 2. Delete all Message rows where expires_at <= current time               ║
    ║ 3. Commit the deletion to database                                        ║
    ║                                                                           ║
    ║ INTERVIEW QUESTION: Why run cleanup as background task vs scheduled job?  ║
    ║ ANSWER: Background task is simpler for a hackathon/demo. In production,   ║
    ║ you'd use a scheduled job (Celery, cron) or database-level TTL (MongoDB,  ║
    ║ Redis). This approach works for single-instance deployments.              ║
    ╚═══════════════════════════════════════════════════════════════════════════╝
    """
    while True:
        try:
            await asyncio.sleep(60)
            async with AsyncSessionLocal() as db:
                result = await db.execute(
                    delete(Message).where(Message.expires_at <= datetime.utcnow())
                )
                if result.rowcount > 0:
                    await db.commit()
                    print(f"Cleaned up {result.rowcount} expired messages")
                else:
                    await db.rollback()
        except asyncio.CancelledError:
            break
        except Exception as e:
            print(f"Message cleanup error: {e}")


# ───────────────────────────────────────────────────────────────────────────────
# LIFESPAN CONTEXT MANAGER
# ───────────────────────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application startup / shutdown lifecycle.
    
    ╔═══════════════════════════════════════════════════════════════════════════╗
    ║ LIFESPAN PATTERN - Modern FastAPI startup/shutdown management             ║
    ╠═══════════════════════════════════════════════════════════════════════════╣
    ║ This async context manager handles:                                        ║
    ║                                                                           ║
    ║ STARTUP (before yield):                                                   ║
    ║ 1. init_db() - Creates database tables (drops and recreates for dev)      ║
    ║ 2. MerkleBatcher.get_instance() - Initializes singleton for audit trails  ║
    ║ 3. asyncio.create_task() - Starts background tasks concurrently           ║
    ║                                                                           ║
    ║ SHUTDOWN (after yield):                                                   ║
    ║ 1. Cancel all background tasks gracefully                                 ║
    ║ 2. Await cancellation to ensure clean shutdown                            ║
    ║                                                                           ║
    ║ INTERVIEW QUESTION: What happens if we don't cancel tasks on shutdown?    ║
    ║ ANSWER: Tasks would be abruptly terminated, potentially leaving:          ║
    ║ - Database transactions incomplete                                        ║
    ║ - Merkle batches uncommitted                                              ║
    ║ - Resources not properly released                                         ║
    ║ Proper cancellation ensures clean state for next startup.                 ║
    ╚═══════════════════════════════════════════════════════════════════════════╝
    """
    # ═══════════════════════════════════════════════════════════════════════════
    # STARTUP PHASE
    # ═══════════════════════════════════════════════════════════════════════════
    
    # Initialize database - creates all tables defined in models.py
    # Note: In production, you'd use Alembic migrations instead of drop_all/create_all
    await init_db()
    
    # Get singleton instance of MerkleBatcher
    # Singleton pattern ensures only one batcher exists across the application
    batcher = MerkleBatcher.get_instance()
    await batcher.initialize()
    
    # Start Merkle batcher as background task
    # This periodically creates Merkle trees from event hashes for on-chain verification
    merkle_task = asyncio.create_task(batcher.run_background())
    
    # Start message cleanup as background task
    # This removes expired chat messages (24h TTL for privacy)
    cleanup_task = asyncio.create_task(cleanup_expired_messages())
    
    print("SentinelX Backend is running")
    
    # Yield control to the application - everything after this runs on shutdown
    yield
    
    # ═══════════════════════════════════════════════════════════════════════════
    # SHUTDOWN PHASE
    # ═══════════════════════════════════════════════════════════════════════════
    
    # Cancel background tasks gracefully
    merkle_task.cancel()
    cleanup_task.cancel()
    
    # Wait for tasks to finish cancellation
    # asyncio.CancelledError is expected when cancelling tasks
    try:
        await merkle_task
    except asyncio.CancelledError:
        pass
    try:
        await cleanup_task
    except asyncio.CancelledError:
        pass


# ───────────────────────────────────────────────────────────────────────────────
# FASTAPI APPLICATION INSTANCE
# ───────────────────────────────────────────────────────────────────────────────

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Web3 adaptive security platform with AI-powered anomaly detection, LLM data guardrails, and Algorand-anchored audit trails.",
    lifespan=lifespan,  # Attach the lifespan context manager defined above
)

# ───────────────────────────────────────────────────────────────────────────────
# CORS (Cross-Origin Resource Sharing) CONFIGURATION
# ───────────────────────────────────────────────────────────────────────────────
"""
╔═══════════════════════════════════════════════════════════════════════════════╗
║ CORS allows the frontend (running on a different port/domain) to make        ║
║ API requests to this backend.                                                 ║
║                                                                               ║
║ WHY CORS IS NEEDED:                                                          ║
║ - Frontend runs on localhost:5173 (Vite dev server)                          ║
║ - Backend runs on localhost:8000 (FastAPI/Uvicorn)                           ║
║ - Browsers block cross-origin requests by default (same-origin policy)       ║
║                                                                               ║
║ SECURITY CONSIDERATIONS:                                                      ║
║ - allow_origins: Only specified domains can make requests                    ║
║ - allow_credentials: Allows cookies/auth headers to be sent                  ║
║ - allow_methods=["*"]: All HTTP methods allowed (GET, POST, etc.)            ║
║ - allow_headers=["*"]: All headers allowed                                   ║
║                                                                               ║
║ INTERVIEW QUESTION: Why not use allow_origins=["*"] with credentials?        ║
║ ANSWER: This is a security risk! Browsers reject this combination            ║
║ because it would allow any website to make authenticated requests.           ║
║ Always specify exact origins when using credentials=True.                    ║
╚═══════════════════════════════════════════════════════════════════════════════╝
"""

# Parse comma-separated frontend URLs from environment variable
# Example: FRONTEND_URL="http://localhost:5173,https://myapp.vercel.app"
_origins = [o.strip().rstrip("/") for o in settings.FRONTEND_URL.split(",") if o.strip()]

# Always allow local development origins
_origins.extend(["http://localhost:5173", "http://localhost:3000"])

# Remove duplicates using set, then convert back to list
_origins = list(set(_origins))

app.add_middleware(
    CORSMiddleware,
    allow_origins=_origins,       # Only these origins can make requests
    allow_credentials=True,       # Allow cookies/Authorization header
    allow_methods=["*"],          # Allow all HTTP methods (GET, POST, PUT, DELETE, etc.)
    allow_headers=["*"],          # Allow all headers (Content-Type, Authorization, etc.)
)

# ───────────────────────────────────────────────────────────────────────────────
# API ROUTERS (ENDPOINT GROUPS)
# ───────────────────────────────────────────────────────────────────────────────
"""
╔═══════════════════════════════════════════════════════════════════════════════╗
║ ROUTER ORGANIZATION                                                           ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║ Each router handles a specific domain:                                        ║
║                                                                               ║
║ /auth        → SIWE wallet authentication, JWT tokens, step-up verification  ║
║ /risk        → AI risk scoring, login anomaly detection, risk timeline       ║
║ /guard       → GuardLayer DLP, content scanning, data leak prevention        ║
║ /audit       → Merkle batching, on-chain proof verification                  ║
║ /simulation  → Attack simulation for demo/testing purposes                   ║
║ /dashboard   → Analytics overview, trust score, security reports             ║
║ /chat        → WebSocket real-time messaging with DLP integration            ║
║ /transactions→ ETH transfer risk evaluation and logging                      ║
║                                                                               ║
║ INTERVIEW QUESTION: Why use routers instead of putting all endpoints here?   ║
║ ANSWER: Separation of concerns! Each domain has its own file:                ║
║ - Easier to maintain and test                                                ║
║ - Team members can work on different routers independently                   ║
║ - Clear API structure from the URL prefix                                    ║
╚═══════════════════════════════════════════════════════════════════════════════╝
"""

app.include_router(auth.router, prefix="/auth", tags=["Authentication"])
app.include_router(risk.router, prefix="/risk", tags=["Risk Engine"])
app.include_router(guard.router, prefix="/guard", tags=["GuardLayer"])
app.include_router(audit.router, prefix="/audit", tags=["Audit Trail"])
app.include_router(simulation.router, prefix="/simulation", tags=["Simulation"])
app.include_router(dashboard.router, prefix="/dashboard", tags=["Dashboard"])
app.include_router(chat.router, prefix="/chat", tags=["Chat"])
app.include_router(transactions.router, prefix="/transactions", tags=["Transactions"])


# ───────────────────────────────────────────────────────────────────────────────
# ROOT ENDPOINT - API Information
# ───────────────────────────────────────────────────────────────────────────────
@app.get("/")
async def root():
    """
    Root endpoint - returns API metadata and available modules.
    
    Used by:
    - Frontend to verify backend is running
    - Load balancers/monitoring for health checks
    - API documentation (auto-generated by FastAPI at /docs)
    """
    return {
        "name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "status": "running",
        "modules": [
            "Algorand Wallet Auth",
            "AI Risk Engine",
            "GuardLayer DLP",
            "Transaction Risk Engine",
            "Algorand Audit Trail",
            "Live Dashboard",
            "Attack Simulation",
            "Real-time Chat",
        ],
    }


# ───────────────────────────────────────────────────────────────────────────────
# HEALTH CHECK ENDPOINT
# ───────────────────────────────────────────────────────────────────────────────
@app.get("/health")
async def health():
    """
    Health check endpoint for load balancers and monitoring.
    
    INTERVIEW QUESTION: What's the difference between /health and /ready?
    ANSWER: In Kubernetes/containerized deployments:
    - /health (liveness): "Is the app running?" If fails, container restarts
    - /ready (readiness): "Is the app ready to serve traffic?" If fails, 
      container is removed from load balancer but not restarted
    
    This simple endpoint checks if the API responds. For production, you'd
    also check database connectivity, external services, etc.
    """
    return {"status": "healthy"}


# ═══════════════════════════════════════════════════════════════════════════════
# INTERVIEW QUESTIONS FOR main.py
# ═══════════════════════════════════════════════════════════════════════════════
"""
Q1: How does FastAPI handle async/await compared to Flask?
A1: FastAPI is built on Starlette (async framework) and uses Python's asyncio.
    Flask is synchronous by default. FastAPI can handle thousands of concurrent
    connections with a single worker because it uses non-blocking I/O.

Q2: What is the difference between background tasks and Celery?
A2: Background tasks (asyncio.create_task) run in the same process as the API.
    Celery runs in separate worker processes. Background tasks are simpler but
    don't survive process restarts. Celery is better for production workloads.

Q3: Why do we need CORS middleware?
A3: Browsers enforce Same-Origin Policy for security. When frontend (port 5173)
    calls backend (port 8000), browser blocks it. CORS middleware tells the
    browser "this backend accepts requests from these origins."

Q4: How would you scale this application horizontally?
A4: Several considerations:
    - Use a proper task queue (Celery) instead of asyncio background tasks
    - Replace in-memory singletons with Redis for shared state
    - Use database connection pooling (already configured)
    - Deploy behind a load balancer with multiple API instances
"""
