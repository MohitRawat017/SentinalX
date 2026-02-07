"""
SentinelX — Web3 Adaptive Security Platform
Main FastAPI Application
"""
import asyncio
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.config import settings
from app.database import init_db
from app.routers import auth, risk, guard, audit, simulation, dashboard
from app.services.merkle import MerkleBatcher


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup / shutdown lifecycle"""
    # Startup
    await init_db()
    # Start Merkle batcher background task
    batcher = MerkleBatcher.get_instance()
    task = asyncio.create_task(batcher.run_background())
    print("🛡️  SentinelX Backend is running")
    yield
    # Shutdown
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Web3 Adaptive Security Platform — AI-powered anomaly detection, LLM data guardrails, and on-chain audit trails.",
    lifespan=lifespan,
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.FRONTEND_URL, "http://localhost:5173", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Routers
app.include_router(auth.router, prefix="/auth", tags=["Authentication"])
app.include_router(risk.router, prefix="/risk", tags=["Risk Engine"])
app.include_router(guard.router, prefix="/guard", tags=["GuardLayer"])
app.include_router(audit.router, prefix="/audit", tags=["Audit Trail"])
app.include_router(simulation.router, prefix="/simulation", tags=["Simulation"])
app.include_router(dashboard.router, prefix="/dashboard", tags=["Dashboard"])


@app.get("/")
async def root():
    return {
        "name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "status": "running",
        "modules": [
            "SIWE Wallet Auth",
            "AI Risk Engine",
            "GuardLayer DLP",
            "Merkle Audit Trail",
            "Live Dashboard",
            "Attack Simulation",
        ],
    }


@app.get("/health")
async def health():
    return {"status": "healthy"}
