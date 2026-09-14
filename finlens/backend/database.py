"""
FinLens Database Layer
═══════════════════════
Async SQLAlchemy setup with connection pooling, session management,
automatic table creation, and migration support.

Supports SQLite (development) and PostgreSQL (production).
"""

import os
import uuid
import asyncio
import logging
from datetime import datetime, timedelta
from contextlib import asynccontextmanager
from typing import AsyncGenerator, Optional

from sqlalchemy import (
    Column, String, Integer, Float, Boolean, DateTime, Text, JSON,
    ForeignKey, Index, UniqueConstraint, CheckConstraint, event,
    create_engine, text, inspect
)
from sqlalchemy.ext.asyncio import (
    AsyncSession, AsyncEngine, create_async_engine,
    async_sessionmaker, AsyncAttrs
)
from sqlalchemy.orm import (
    DeclarativeBase, Mapped, mapped_column, relationship,
    selectinload, joinedload
)
from sqlalchemy.pool import StaticPool, NullPool
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger("finlens.db")

# ═══════════════════════════════════════════════════════════════════════
# Database Configuration
# ═══════════════════════════════════════════════════════════════════════

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite+aiosqlite:///./finlens.db")
DATABASE_ECHO = os.getenv("DATABASE_ECHO", "false").lower() == "true"

# Pool settings for production
POOL_SIZE = int(os.getenv("DB_POOL_SIZE", "10"))
MAX_OVERFLOW = int(os.getenv("DB_MAX_OVERFLOW", "20"))
POOL_TIMEOUT = int(os.getenv("DB_POOL_TIMEOUT", "30"))
POOL_RECYCLE = int(os.getenv("DB_POOL_RECYCLE", "1800"))


# ═══════════════════════════════════════════════════════════════════════
# Base Model
# ═══════════════════════════════════════════════════════════════════════

class Base(DeclarativeBase, AsyncAttrs):
    """Base class for all database models."""

    def to_dict(self) -> dict:
        """Convert model instance to dictionary."""
        result = {}
        for column in self.__table__.columns:
            value = getattr(self, column.name)
            if isinstance(value, datetime):
                value = value.isoformat()
            elif isinstance(value, uuid.UUID):
                value = str(value)
            result[column.name] = value
        return result

    def update(self, **kwargs):
        """Update model attributes from keyword arguments."""
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)

    def __repr__(self):
        pk = getattr(self, 'id', '???')
        return f"<{self.__class__.__name__}(id={pk})>"


# ═══════════════════════════════════════════════════════════════════════
# User Model
# ═══════════════════════════════════════════════════════════════════════

class User(Base):
    """User account with authentication and profile data."""
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    username: Mapped[str] = mapped_column(String(50), unique=True, index=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    full_name: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    phone: Mapped[Optional[str]] = mapped_column(String(15), nullable=True)

    # Profile
    avatar_url: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    bio: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    language: Mapped[str] = mapped_column(String(10), default="en")
    timezone: Mapped[str] = mapped_column(String(50), default="Asia/Kolkata")

    # Financial profile
    annual_income: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    risk_tolerance: Mapped[str] = mapped_column(String(20), default="moderate")
    investment_experience: Mapped[str] = mapped_column(String(20), default="beginner")

    # Gamification
    points: Mapped[int] = mapped_column(Integer, default=0)
    level: Mapped[int] = mapped_column(Integer, default=1)
    badges: Mapped[Optional[dict]] = mapped_column(JSON, default=list)
    streak_days: Mapped[int] = mapped_column(Integer, default=0)
    last_active: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    # Status
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    is_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_login: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    # Relationships
    scan_history: Mapped[list["ScanHistory"]] = relationship("ScanHistory", back_populates="user", cascade="all, delete-orphan")
    scam_reports: Mapped[list["ScamReport"]] = relationship("ScamReport", back_populates="reporter", cascade="all, delete-orphan")
    portfolio: Mapped[Optional["Portfolio"]] = relationship("Portfolio", back_populates="user", uselist=False, cascade="all, delete-orphan")
    alerts: Mapped[list["Alert"]] = relationship("Alert", back_populates="user", cascade="all, delete-orphan")
    expenses: Mapped[list["Expense"]] = relationship("Expense", back_populates="user", cascade="all, delete-orphan")
    sessions: Mapped[list["UserSession"]] = relationship("UserSession", back_populates="user", cascade="all, delete-orphan")

    __table_args__ = (
        Index("idx_user_points", "points"),
        Index("idx_user_level", "level"),
    )


# ═══════════════════════════════════════════════════════════════════════
# User Session Model (for auth)
# ═══════════════════════════════════════════════════════════════════════

class UserSession(Base):
    """Active user session for JWT token management."""
    __tablename__ = "user_sessions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    token_jti: Mapped[str] = mapped_column(String(36), unique=True, nullable=False, index=True)
    refresh_token: Mapped[str] = mapped_column(String(500), nullable=False)
    device_info: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    ip_address: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    is_revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    last_used: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    user: Mapped["User"] = relationship("User", back_populates="sessions")


# ═══════════════════════════════════════════════════════════════════════
# Scan History Model
# ═══════════════════════════════════════════════════════════════════════

class ScanHistory(Base):
    """Records every AI interaction for analytics and PRISM tracing."""
    __tablename__ = "scan_history"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    session_id: Mapped[str] = mapped_column(String(50), index=True, nullable=False)

    # Scan details
    scan_type: Mapped[str] = mapped_column(String(30), nullable=False)  # scam, health, literacy, portfolio, expense, simulator
    input_text: Mapped[str] = mapped_column(Text, nullable=False)
    output_data: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    raw_response: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # AI metadata
    model_used: Mapped[str] = mapped_column(String(50), default="gemini-2.5-flash")
    agent_id: Mapped[str] = mapped_column(String(50), nullable=False)
    latency_ms: Mapped[int] = mapped_column(Integer, default=0)
    tokens_used: Mapped[int] = mapped_column(Integer, default=0)
    confidence: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    # Risk scoring (for scam scans)
    risk_level: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    risk_score: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    scam_type: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)

    # Health scoring (for health scans)
    health_score: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    health_grade: Mapped[Optional[str]] = mapped_column(String(2), nullable=True)

    # PRISM integration
    prism_trace_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    prism_sent: Mapped[bool] = mapped_column(Boolean, default=False)

    # Guardrails
    guardrail_passed: Mapped[bool] = mapped_column(Boolean, default=True)
    guardrail_violations: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    # Feedback
    user_rating: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)  # 1-5
    user_feedback: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Metadata
    device_type: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    ip_address: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    country: Mapped[Optional[str]] = mapped_column(String(3), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)

    user: Mapped[Optional["User"]] = relationship("User", back_populates="scan_history")

    __table_args__ = (
        Index("idx_scan_type_created", "scan_type", "created_at"),
        Index("idx_scan_risk", "risk_level", "risk_score"),
        Index("idx_scan_user_type", "user_id", "scan_type"),
    )


# ═══════════════════════════════════════════════════════════════════════
# Scam Report Model (crowdsourced)
# ═══════════════════════════════════════════════════════════════════════

class ScamReport(Base):
    """Crowdsourced scam reports from the community."""
    __tablename__ = "scam_reports"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    reporter_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)

    # Scam details
    scam_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    scam_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # Original scam message
    scam_url: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    scam_phone: Mapped[Optional[str]] = mapped_column(String(15), nullable=True)
    scam_upi_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)

    # Verification
    severity: Mapped[str] = mapped_column(String(20), default="medium")  # low, medium, high, critical
    verified: Mapped[bool] = mapped_column(Boolean, default=False)
    verification_count: Mapped[int] = mapped_column(Integer, default=0)
    dismiss_count: Mapped[int] = mapped_column(Integer, default=0)

    # Location
    city: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    state: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)

    # Financial impact
    amount_lost: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    attempted: Mapped[bool] = mapped_column(Boolean, default=False)  # Attempted but not succeeded

    # Engagement
    views: Mapped[int] = mapped_column(Integer, default=0)
    upvotes: Mapped[int] = mapped_column(Integer, default=0)
    comments: Mapped[Optional[dict]] = mapped_column(JSON, default=list)

    # Status
    status: Mapped[str] = mapped_column(String(20), default="active")  # active, resolved, dismissed, escalated
    admin_notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    reporter: Mapped[Optional["User"]] = relationship("User", back_populates="scam_reports")

    __table_args__ = (
        Index("idx_scam_severity", "severity"),
        Index("idx_scam_status", "status"),
        Index("idx_scam_type_severity", "scam_type", "severity"),
    )


# ═══════════════════════════════════════════════════════════════════════
# Portfolio Model
# ═══════════════════════════════════════════════════════════════════════

class Portfolio(Base):
    """User investment portfolio with holdings and transactions."""
    __tablename__ = "portfolios"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id", ondelete="CASCADE"), unique=True, nullable=False)

    # Portfolio summary
    total_invested: Mapped[float] = mapped_column(Float, default=0.0)
    current_value: Mapped[float] = mapped_column(Float, default=0.0)
    total_returns: Mapped[float] = mapped_column(Float, default=0.0)
    returns_percentage: Mapped[float] = mapped_column(Float, default=0.0)

    # Allocation targets (JSON)
    target_allocation: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    actual_allocation: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    # Risk profile
    risk_score: Mapped[int] = mapped_column(Integer, default=50)  # 0-100
    sharpe_ratio: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    max_drawdown: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    # Settings
    rebalance_frequency: Mapped[str] = mapped_column(String(20), default="quarterly")
    auto_invest: Mapped[bool] = mapped_column(Boolean, default=False)
    monthly_investment: Mapped[float] = mapped_column(Float, default=0.0)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    user: Mapped["User"] = relationship("User", back_populates="portfolio")
    holdings: Mapped[list["PortfolioHolding"]] = relationship("PortfolioHolding", back_populates="portfolio", cascade="all, delete-orphan")
    transactions: Mapped[list["PortfolioTransaction"]] = relationship("PortfolioTransaction", back_populates="portfolio", cascade="all, delete-orphan")


class PortfolioHolding(Base):
    """Individual investment holding in a portfolio."""
    __tablename__ = "portfolio_holdings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    portfolio_id: Mapped[str] = mapped_column(String(36), ForeignKey("portfolios.id", ondelete="CASCADE"), nullable=False)

    # Asset details
    asset_type: Mapped[str] = mapped_column(String(30), nullable=False)  # equity, mutual_fund, fd, gold, bond, crypto
    asset_name: Mapped[str] = mapped_column(String(100), nullable=False)
    asset_symbol: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    asset_category: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)  # large_cap, mid_cap, etc.

    # Investment details
    units: Mapped[float] = mapped_column(Float, default=0.0)
    avg_buy_price: Mapped[float] = mapped_column(Float, default=0.0)
    total_invested: Mapped[float] = mapped_column(Float, default=0.0)
    current_price: Mapped[float] = mapped_column(Float, default=0.0)
    current_value: Mapped[float] = mapped_column(Float, default=0.0)

    # Returns
    absolute_returns: Mapped[float] = mapped_column(Float, default=0.0)
    returns_percentage: Mapped[float] = mapped_column(Float, default=0.0)
    xirr: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    # Metadata
    first_invested: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_updated: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    portfolio: Mapped["Portfolio"] = relationship("Portfolio", back_populates="holdings")

    __table_args__ = (
        Index("idx_holding_portfolio", "portfolio_id"),
        Index("idx_holding_type", "asset_type"),
    )


class PortfolioTransaction(Base):
    """Transaction history for portfolio."""
    __tablename__ = "portfolio_transactions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    portfolio_id: Mapped[str] = mapped_column(String(36), ForeignKey("portfolios.id", ondelete="CASCADE"), nullable=False)

    transaction_type: Mapped[str] = mapped_column(String(10), nullable=False)  # buy, sell, dividend, sip
    asset_name: Mapped[str] = mapped_column(String(100), nullable=False)
    asset_symbol: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)

    units: Mapped[float] = mapped_column(Float, nullable=False)
    price_per_unit: Mapped[float] = mapped_column(Float, nullable=False)
    total_amount: Mapped[float] = mapped_column(nullable=False)
    charges: Mapped[float] = mapped_column(Float, default=0.0)
    tax: Mapped[float] = mapped_column(Float, default=0.0)

    # SIP specific
    sip_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    is_sip: Mapped[bool] = mapped_column(Boolean, default=False)

    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    portfolio: Mapped["Portfolio"] = relationship("Portfolio", back_populates="transactions")


# ═══════════════════════════════════════════════════════════════════════
# Expense Model
# ═══════════════════════════════════════════════════════════════════════

class Expense(Base):
    """User expense tracking entries."""
    __tablename__ = "expenses"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)

    # Expense details
    amount: Mapped[float] = mapped_column(Float, nullable=False)
    description: Mapped[str] = mapped_column(String(200), nullable=False)
    category: Mapped[str] = mapped_column(String(30), nullable=False, index=True)
    subcategory: Mapped[Optional[str]] = mapped_column(String(30), nullable=True)

    # Payment
    payment_method: Mapped[str] = mapped_column(String(20), default="upi")  # upi, cash, card, netbanking
    merchant: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)

    # Location
    city: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)

    # Split expenses
    is_split: Mapped[bool] = mapped_column(Boolean, default=False)
    split_group_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    split_members: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    my_share: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    # AI categorization
    ai_categorized: Mapped[bool] = mapped_column(Boolean, default=False)
    confidence: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    # Tags
    tags: Mapped[Optional[dict]] = mapped_column(JSON, default=list)
    is_recurring: Mapped[bool] = mapped_column(Boolean, default=False)
    recurring_frequency: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)

    # Income vs Expense
    is_income: Mapped[bool] = mapped_column(Boolean, default=False)

    date: Mapped[datetime] = mapped_column(DateTime, nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    user: Mapped["User"] = relationship("User", back_populates="expenses")

    __table_args__ = (
        Index("idx_expense_user_date", "user_id", "date"),
        Index("idx_expense_category_date", "category", "date"),
        Index("idx_expense_amount", "amount"),
    )


# ═══════════════════════════════════════════════════════════════════════
# Alert Model
# ═══════════════════════════════════════════════════════════════════════

class Alert(Base):
    """User alerts for scam warnings, portfolio changes, budget limits."""
    __tablename__ = "alerts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)

    alert_type: Mapped[str] = mapped_column(String(30), nullable=False)  # scam_warning, portfolio_change, budget_limit, system
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(10), default="info")  # info, warning, critical

    # Context
    related_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)  # ID of related entity
    data: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    # Status
    is_read: Mapped[bool] = mapped_column(Boolean, default=False)
    is_dismissed: Mapped[bool] = mapped_column(Boolean, default=False)
    action_url: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    read_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    user: Mapped["User"] = relationship("User", back_populates="alerts")


# ═══════════════════════════════════════════════════════════════════════
# Scam Pattern Model (for learning)
# ═══════════════════════════════════════════════════════════════════════

class ScamPattern(Base):
    """Learned scam patterns from community reports and AI analysis."""
    __tablename__ = "scam_patterns"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    pattern_name: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    scam_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    description: Mapped[str] = mapped_column(Text, nullable=False)

    # Pattern features
    keywords: Mapped[Optional[dict]] = mapped_column(JSON, default=list)
    regex_patterns: Mapped[Optional[dict]] = mapped_column(JSON, default=list)
    sender_patterns: Mapped[Optional[dict]] = mapped_column(JSON, default=list)
    behavioral_signals: Mapped[Optional[dict]] = mapped_column(JSON, default=list)

    # Stats
    occurrence_count: Mapped[int] = mapped_column(Integer, default=1)
    false_positive_rate: Mapped[float] = mapped_column(Float, default=0.0)
    confidence: Mapped[float] = mapped_column(Float, default=0.5)

    # Severity
    avg_amount_lost: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    geographic_spread: Mapped[Optional[dict]] = mapped_column(JSON, default=list)

    first_seen: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


# ═══════════════════════════════════════════════════════════════════════
# Bill Split Group Model
# ═══════════════════════════════════════════════════════════════════════

class BillSplitGroup(Base):
    """Group for splitting expenses among friends."""
    __tablename__ = "bill_split_groups"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    created_by: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), nullable=False)
    members: Mapped[dict] = mapped_column(JSON, nullable=False)  # List of user_ids
    total_expenses: Mapped[float] = mapped_column(Float, default=0.0)
    settlements: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)  # Who owes whom

    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


# ═══════════════════════════════════════════════════════════════════════
# Scam Intelligence Feed Model
# ═══════════════════════════════════════════════════════════════════════

class ScamIntelligenceFeed(Base):
    """Real-time scam intelligence feed data."""
    __tablename__ = "scam_intelligence_feed"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scam_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    source: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    source_url: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)

    severity: Mapped[str] = mapped_column(String(10), nullable=False)
    affected_regions: Mapped[Optional[dict]] = mapped_column(JSON, default=list)
    estimated_victims: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    estimated_loss: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    published_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


# ═══════════════════════════════════════════════════════════════════════
# Database Engine & Session Management
# ═══════════════════════════════════════════════════════════════════════

class DatabaseManager:
    """Manages database engine, sessions, and lifecycle."""

    def __init__(self):
        self.engine: Optional[AsyncEngine] = None
        self.session_factory: Optional[async_sessionmaker] = None
        self._initialized = False

    async def initialize(self):
        """Initialize the database engine and create tables."""
        if self._initialized:
            return

        # Choose pool strategy based on database type
        if "sqlite" in DATABASE_URL:
            connect_args = {"check_same_thread": False}
            self.engine = create_async_engine(
                DATABASE_URL,
                echo=DATABASE_ECHO,
                connect_args=connect_args,
                poolclass=StaticPool,
            )
        else:
            self.engine = create_async_engine(
                DATABASE_URL,
                echo=DATABASE_ECHO,
                pool_size=POOL_SIZE,
                max_overflow=MAX_OVERFLOW,
                pool_timeout=POOL_TIMEOUT,
                pool_recycle=POOL_RECYCLE,
            )

        self.session_factory = async_sessionmaker(
            bind=self.engine,
            class_=AsyncSession,
            expire_on_commit=False,
        )

        # Create all tables
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        self._initialized = True
        logger.info("Database initialized successfully")

    async def close(self):
        """Close the database engine."""
        if self.engine:
            await self.engine.dispose()
            self._initialized = False
            logger.info("Database connections closed")

    @asynccontextmanager
    async def get_session(self) -> AsyncGenerator[AsyncSession, None]:
        """Get an async database session."""
        if not self._initialized:
            await self.initialize()

        async with self.session_factory() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise
            finally:
                await session.close()

    async def get_or_create(self, model, defaults=None, **kwargs):
        """Get an existing record or create a new one."""
        async with self.get_session() as session:
            instance = await session.execute(
                model.__table__.select().where(
                    *[getattr(model, k) == v for k, v in kwargs.items()]
                )
            )
            result = instance.scalar_one_or_none()

            if result:
                return result

            result = model(**kwargs, **(defaults or {}))
            session.add(result)
            await session.flush()
            return result

    async def health_check(self) -> dict:
        """Check database health and return stats."""
        try:
            async with self.get_session() as session:
                # Count records in key tables
                users = await session.execute(text("SELECT COUNT(*) FROM users"))
                scans = await session.execute(text("SELECT COUNT(*) FROM scan_history"))
                reports = await session.execute(text("SELECT COUNT(*) FROM scam_reports"))

                return {
                    "status": "healthy",
                    "engine": str(self.engine.url).split("@")[-1] if "@" in str(self.engine.url) else "sqlite",
                    "tables": len(Base.metadata.tables),
                    "stats": {
                        "users": users.scalar(),
                        "scans": scans.scalar(),
                        "scam_reports": reports.scalar(),
                    }
                }
        except Exception as e:
            return {
                "status": "unhealthy",
                "error": str(e)
            }


# Singleton database manager
db_manager = DatabaseManager()


# ═══════════════════════════════════════════════════════════════════════
# Dependency for FastAPI
# ═══════════════════════════════════════════════════════════════════════

async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency that yields a database session."""
    async with db_manager.get_session() as session:
        yield session
