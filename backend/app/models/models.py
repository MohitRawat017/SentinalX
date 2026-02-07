"""SQLAlchemy database models for SentinelX"""
import uuid
from datetime import datetime
from sqlalchemy import (
    Column, String, Float, Boolean, DateTime, Text, Integer, JSON, create_engine
)
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker as async_sessionmaker

Base = declarative_base()


def generate_uuid():
    return str(uuid.uuid4())


class User(Base):
    __tablename__ = "users"

    id = Column(String, primary_key=True, default=generate_uuid)
    wallet_address = Column(String, unique=True, nullable=False, index=True)
    ens_name = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime, default=datetime.utcnow)


class LoginEvent(Base):
    __tablename__ = "login_events"

    id = Column(String, primary_key=True, default=generate_uuid)
    wallet_address = Column(String, nullable=False, index=True)
    ip_address = Column(String, nullable=True)
    ip_hash = Column(String, nullable=True)
    user_agent = Column(String, nullable=True)
    geo_lat = Column(Float, nullable=True)
    geo_lng = Column(Float, nullable=True)
    geo_country = Column(String, nullable=True)
    geo_city = Column(String, nullable=True)
    risk_score = Column(Float, default=0.0)
    risk_level = Column(String, default="low")
    risk_features = Column(JSON, nullable=True)
    step_up_required = Column(Boolean, default=False)
    step_up_completed = Column(Boolean, default=False)
    event_hash = Column(String, nullable=True)
    merkle_root = Column(String, nullable=True)
    tx_hash = Column(String, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)


class GuardEvent(Base):
    __tablename__ = "guard_events"

    id = Column(String, primary_key=True, default=generate_uuid)
    wallet_address = Column(String, nullable=False, index=True)
    content_hash = Column(String, nullable=False)
    scan_type = Column(String, default="regex")  # regex, llm, both
    risk_detected = Column(Boolean, default=False)
    risk_categories = Column(JSON, nullable=True)
    llm_response = Column(Text, nullable=True)
    user_override = Column(Boolean, default=False)
    event_hash = Column(String, nullable=True)
    merkle_root = Column(String, nullable=True)
    tx_hash = Column(String, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)


class AuditBatch(Base):
    __tablename__ = "audit_batches"

    id = Column(String, primary_key=True, default=generate_uuid)
    merkle_root = Column(String, nullable=False, unique=True)
    event_count = Column(Integer, default=0)
    event_hashes = Column(JSON, nullable=True)
    tx_hash = Column(String, nullable=True)
    block_number = Column(Integer, nullable=True)
    gas_used = Column(Integer, nullable=True)
    status = Column(String, default="pending")  # pending, submitted, confirmed
    timestamp = Column(DateTime, default=datetime.utcnow)


class Nonce(Base):
    __tablename__ = "nonces"

    id = Column(String, primary_key=True, default=generate_uuid)
    nonce = Column(String, unique=True, nullable=False)
    wallet_address = Column(String, nullable=True)
    used = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)
