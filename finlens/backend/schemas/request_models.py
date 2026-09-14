"""
═══════════════════════════════════════════════════════════════════════════════
FinLens Request Schemas
═══════════════════════════════════════════════════════════════════════════════

Pydantic models for incoming API request validation.
Every endpoint has a corresponding request model with field validation,
custom validators, and documentation-ready descriptions.

Models cover:
- Authentication (register, login, refresh, logout)
- Scam analysis (single message, batch, URL scan, phone check)
- Financial health (profile, expenses, income)
- Literacy chat (questions, topics, quiz)
- Portfolio (holdings, goals, rebalance)
- Expenses (CRUD, bulk import, categories)
- Bill splitting (groups, settlements)
- Alerts (create, acknowledge, preferences)
- Scam reports (community reporting)
- User profile (update, preferences, gamification)
- PRISM traces (custom events)
"""

import re
import uuid
from typing import Optional, List, Dict, Any, Union
from datetime import datetime, date
from enum import Enum

from pydantic import (
    BaseModel, Field, EmailStr, field_validator,
    model_validator, ConfigDict, HttpUrl
)


# ═══════════════════════════════════════════════════════════════════════════════
# Enums
# ═══════════════════════════════════════════════════════════════════════════════

class ScanType(str, Enum):
    SCAM = "scam"
    HEALTH = "health"
    LITERACY = "literacy"
    PORTFOLIO = "portfolio"
    EXPENSE = "expense"
    SIMULATOR = "simulator"
    BILL_SPLIT = "bill_split"

class RiskTolerance(str, Enum):
    CONSERVATIVE = "conservative"
    MODERATE = "moderate"
    AGGRESSIVE = "aggressive"
    VERY_AGGRESSIVE = "very_aggressive"

class InvestmentExperience(str, Enum):
    BEGINNER = "beginner"
    INTERMEDIATE = "intermediate"
    ADVANCED = "advanced"
    EXPERT = "expert"

class PaymentMethod(str, Enum):
    UPI = "upi"
    CASH = "cash"
    CARD = "card"
    NETBANKING = "netbanking"
    WALLET = "wallet"

class ExpenseCategory(str, Enum):
    HOUSING = "housing"
    FOOD = "food"
    TRANSPORT = "transport"
    UTILITIES = "utilities"
    ENTERTAINMENT = "entertainment"
    SHOPPING = "shopping"
    HEALTH = "health"
    EDUCATION = "education"
    FINANCIAL = "financial"
    PERSONAL = "personal"
    OTHER = "other"

class AlertSeverity(str, Enum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"

class AlertType(str, Enum):
    SCAM_WARNING = "scam_warning"
    PORTFOLIO_CHANGE = "portfolio_change"
    BUDGET_LIMIT = "budget_limit"
    SYSTEM = "system"
    LEARNING_REMINDER = "learning_reminder"

class Language(str, Enum):
    ENGLISH = "en"
    HINDI = "hi"
    TAMIL = "ta"
    TELUGU = "te"
    KANNADA = "kn"
    MALAYALAM = "ml"
    BENGALI = "bn"
    MARATHI = "mr"
    GUJARATI = "gu"

class ThemePreference(str, Enum):
    DARK = "dark"
    LIGHT = "light"
    SYSTEM = "system"
    CYBER_SECURITY = "cyber_security"

class AssetType(str, Enum):
    EQUITY = "equity"
    MUTUAL_FUND = "mutual_fund"
    INDEX_FUND = "index_fund"
    ELSS = "elss"
    FD = "fd"
    PPF = "ppf"
    NPS = "nps"
    BONDS = "bonds"
    GOLD = "gold"
    SGB = "sgb"
    GOLD_ETF = "gold_etf"
    REIT = "reit"
    CRYPTO = "crypto"
    CASH = "cash"
    OTHER = "other"

class TransactionType(str, Enum):
    BUY = "buy"
    SELL = "sell"
    DIVIDEND = "dividend"
    SIP = "sip"

class GoalType(str, Enum):
    EMERGENCY_FUND = "emergency_fund"
    RETIREMENT = "retirement"
    HOUSE = "house"
    CAR = "car"
    EDUCATION = "education"
    WEDDING = "wedding"
    VACATION = "vacation"
    CUSTOM = "custom"


# ═══════════════════════════════════════════════════════════════════════════════
# Authentication Schemas
# ═══════════════════════════════════════════════════════════════════════════════

class RegisterRequest(BaseModel):
    """User registration request."""
    email: EmailStr = Field(..., description="Valid email address")
    username: str = Field(
        ..., min_length=3, max_length=30,
        pattern=r"^[a-zA-Z0-9_-]+$",
        description="Username (3-30 chars, alphanumeric + _-)"
    )
    password: str = Field(
        ..., min_length=8, max_length=128,
        description="Password (min 8 chars, must include uppercase, lowercase, digit)"
    )
    full_name: Optional[str] = Field(None, max_length=100)
    phone: Optional[str] = Field(None, description="Indian phone number")

    @field_validator("password")
    @classmethod
    def validate_password_strength(cls, v):
        if not re.search(r"[A-Z]", v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not re.search(r"[a-z]", v):
            raise ValueError("Password must contain at least one lowercase letter")
        if not re.search(r"\d", v):
            raise ValueError("Password must contain at least one digit")
        return v

    @field_validator("phone")
    @classmethod
    def validate_phone(cls, v):
        if v is not None:
            cleaned = re.sub(r"[\s\-+]", "", v)
            if cleaned.startswith("91") and len(cleaned) == 12:
                cleaned = cleaned[2:]
            if not re.match(r"^[6-9]\d{9}$", cleaned):
                raise ValueError("Invalid Indian phone number")
        return v


class LoginRequest(BaseModel):
    """User login request."""
    email: EmailStr
    password: str = Field(..., min_length=1)
    device_info: Optional[str] = Field(None, max_length=200)
    remember_me: bool = Field(False)


class TokenRefreshRequest(BaseModel):
    """Token refresh request."""
    refresh_token: str = Field(..., min_length=10)


class LogoutRequest(BaseModel):
    """Logout request."""
    all_devices: bool = Field(False, description="Log out from all devices")


# ═══════════════════════════════════════════════════════════════════════════════
# Scam Analysis Schemas
# ═══════════════════════════════════════════════════════════════════════════════

class ScamAnalysisRequest(BaseModel):
    """Analyze a suspicious message for scam indicators."""
    message: str = Field(
        ..., min_length=1, max_length=10000,
        description="The suspicious message to analyze (WhatsApp, SMS, email, etc.)"
    )
    source: Optional[str] = Field(
        None, max_length=50,
        description="Source platform (whatsapp, sms, email, telegram, social_media)"
    )
    sender: Optional[str] = Field(
        None, max_length=200,
        description="Sender identifier (phone number, email, username)"
    )
    language: Language = Field(Language.ENGLISH, description="Response language")
    session_id: Optional[str] = Field(None, description="Conversation session ID")
    include_educational: bool = Field(
        True, description="Include educational tips about the scam type"
    )
    context: Optional[str] = Field(
        None, max_length=2000,
        description="Additional context about the message (e.g., 'received in group')"
    )


class BatchScamRequest(BaseModel):
    """Analyze multiple messages at once."""
    messages: List[ScamAnalysisRequest] = Field(
        ..., min_length=1, max_length=20,
        description="List of messages to analyze (max 20 at once)"
    )
    session_id: Optional[str] = None


class PhoneCheckRequest(BaseModel):
    """Check if a phone number is associated with known scams."""
    phone_number: str = Field(..., description="Phone number to check")
    context: Optional[str] = Field(None, description="Context of the interaction")


class UrlScanRequest(BaseModel):
    """Scan a URL for phishing/malicious indicators."""
    url: str = Field(..., max_length=2000, description="URL to scan")
    context: Optional[str] = Field(None, description="Where the URL was received")


class ScamReportSubmitRequest(BaseModel):
    """Submit a community scam report."""
    scam_type: str = Field(..., max_length=50)
    title: str = Field(..., min_length=10, max_length=200)
    description: str = Field(..., min_length=20, max_length=5000)
    scam_message: Optional[str] = Field(None, max_length=5000)
    scam_url: Optional[str] = Field(None, max_length=500)
    scam_phone: Optional[str] = Field(None, max_length=15)
    scam_upi_id: Optional[str] = Field(None, max_length=100)
    severity: str = Field("medium", pattern=r"^(low|medium|high|critical)$")
    city: Optional[str] = Field(None, max_length=50)
    state: Optional[str] = Field(None, max_length=50)
    amount_lost: Optional[float] = Field(None, ge=0)
    attempted: bool = Field(False, description="Scam was attempted but failed")

    @field_validator("description")
    @classmethod
    def validate_description_not_empty(cls, v):
        if len(v.strip()) < 20:
            raise ValueError("Description must be at least 20 characters")
        return v


# ═══════════════════════════════════════════════════════════════════════════════
# Financial Health Schemas
# ═══════════════════════════════════════════════════════════════════════════════

class ExpenseEntryRequest(BaseModel):
    """Single expense entry."""
    amount: float = Field(..., gt=0, description="Expense amount in INR")
    description: str = Field(..., min_length=1, max_length=200)
    category: ExpenseCategory
    subcategory: Optional[str] = Field(None, max_length=30)
    payment_method: PaymentMethod = Field(PaymentMethod.UPI)
    merchant: Optional[str] = Field(None, max_length=100)
    date: Optional[datetime] = Field(None, description="Transaction date")
    tags: List[str] = Field(default_factory=list, max_length=10)
    is_income: bool = Field(False)
    is_recurring: bool = Field(False)
    recurring_frequency: Optional[str] = Field(
        None, pattern=r"^(daily|weekly|monthly|quarterly|yearly)$"
    )
    latitude: Optional[float] = Field(None, ge=-90, le=90)
    longitude: Optional[float] = Field(None, ge=-180, le=180)
    notes: Optional[str] = Field(None, max_length=500)


class BulkExpenseImportRequest(BaseModel):
    """Bulk import expenses (CSV-like format)."""
    expenses: List[ExpenseEntryRequest] = Field(
        ..., min_length=1, max_length=500,
        description="List of expenses to import"
    )
    skip_duplicates: bool = Field(True)


class FinancialHealthRequest(BaseModel):
    """Comprehensive financial health check request."""
    monthly_income: float = Field(..., gt=0, description="Monthly income in INR")
    monthly_expenses: Optional[float] = Field(None, ge=0)
    age: Optional[int] = Field(None, ge=18, le=100)
    dependents: int = Field(0, ge=0, le=20)
    risk_tolerance: RiskTolerance = Field(RiskTolerance.MODERATE)
    investment_experience: InvestmentExperience = Field(InvestmentExperience.BEGINNER)
    existing_investments: Optional[str] = Field(
        None, max_length=5000,
        description="Description of existing investments"
    )
    financial_goals: List[str] = Field(default_factory=list, max_length=5)
    monthly_expenses_breakdown: Optional[Dict[str, float]] = Field(
        None, description="Category-wise monthly expenses"
    )
    has_emergency_fund: bool = Field(False)
    has_health_insurance: bool = Field(False)
    has_life_insurance: bool = Field(False)
    outstanding_loans: Optional[float] = Field(None, ge=0)
    language: Language = Field(Language.ENGLISH)
    session_id: Optional[str] = None


class QuickHealthRequest(BaseModel):
    """Quick 3-question financial health check."""
    income: float = Field(..., gt=0)
    expenses: float = Field(..., ge=0)
    savings: float = Field(..., ge=0)


# ═══════════════════════════════════════════════════════════════════════════════
# Financial Literacy Schemas
# ═══════════════════════════════════════════════════════════════════════════════

class LiteracyQuestionRequest(BaseModel):
    """Ask a financial literacy question."""
    question: str = Field(
        ..., min_length=3, max_length=2000,
        description="Your financial question"
    )
    topic: Optional[str] = Field(
        None, max_length=50,
        description="Topic hint (investing, taxes, insurance, budgeting, etc.)"
    )
    experience_level: InvestmentExperience = Field(InvestmentExperience.BEGINNER)
    language: Language = Field(Language.ENGLISH)
    session_id: Optional[str] = None
    include_examples: bool = Field(True, description="Include practical examples")
    include_india_context: bool = Field(True, description="Include India-specific info")


class QuizRequest(BaseModel):
    """Request a financial literacy quiz."""
    topic: str = Field(..., description="Quiz topic")
    difficulty: str = Field("beginner", pattern=r"^(beginner|intermediate|advanced)$")
    num_questions: int = Field(5, ge=3, le=20)


class QuizAnswerRequest(BaseModel):
    """Submit quiz answers."""
    quiz_id: str
    answers: List[Dict[str, str]] = Field(..., description="Question ID -> answer mapping")


# ═══════════════════════════════════════════════════════════════════════════════
# Portfolio Schemas
# ═══════════════════════════════════════════════════════════════════════════════

class PortfolioHoldingRequest(BaseModel):
    """Add/update a portfolio holding."""
    asset_type: AssetType
    asset_name: str = Field(..., min_length=1, max_length=100)
    asset_symbol: Optional[str] = Field(None, max_length=20)
    asset_category: Optional[str] = Field(None, max_length=50)
    units: float = Field(..., gt=0)
    avg_buy_price: float = Field(..., gt=0)
    current_price: Optional[float] = Field(None, ge=0)
    purchase_date: Optional[datetime] = None
    notes: Optional[str] = Field(None, max_length=500)


class PortfolioAnalysisRequest(BaseModel):
    """Request portfolio analysis."""
    holdings: List[PortfolioHoldingRequest] = Field(..., min_length=1, max_length=100)
    age: Optional[int] = Field(None, ge=18, le=100)
    risk_tolerance: RiskTolerance = Field(RiskTolerance.MODERATE)
    monthly_income: Optional[float] = Field(None, ge=0)
    monthly_expenses: Optional[float] = Field(None, ge=0)
    monthly_sip: Optional[float] = Field(None, ge=0)
    goals: Optional[List[Dict[str, Any]]] = Field(None, description="Financial goals")
    session_id: Optional[str] = None


class SIPSetupRequest(BaseModel):
    """Set up a new SIP."""
    fund_name: str = Field(..., min_length=3, max_length=100)
    fund_type: AssetType = Field(AssetType.MUTUAL_FUND)
    monthly_amount: float = Field(..., gt=0, description="Monthly SIP amount in INR")
    start_date: date = Field(..., description="SIP start date")
    duration_years: int = Field(..., ge=1, le=30)
    auto_increase: bool = Field(False, description="Auto-increase SIP by 10% yearly")


class InvestmentGoalRequest(BaseModel):
    """Set an investment goal."""
    name: str = Field(..., min_length=3, max_length=100)
    goal_type: GoalType
    target_amount: float = Field(..., gt=0)
    target_date: date = Field(..., description="When you need this money")
    current_savings: float = Field(0, ge=0)
    monthly_contribution: Optional[float] = Field(None, ge=0)


class RebalanceRequest(BaseModel):
    """Request portfolio rebalancing."""
    holdings: List[PortfolioHoldingRequest] = Field(..., min_length=1)
    risk_tolerance: RiskTolerance = Field(RiskTolerance.MODERATE)
    tax_bracket: Optional[int] = Field(None, ge=0, le=30, description="Income tax slab %")


# ═══════════════════════════════════════════════════════════════════════════════
# Bill Splitting Schemas
# ═══════════════════════════════════════════════════════════════════════════════

class BillSplitGroupRequest(BaseModel):
    """Create a bill split group."""
    name: str = Field(..., min_length=2, max_length=100)
    member_names: List[str] = Field(..., min_length=2, max_length=20)


class BillSplitEntryRequest(BaseModel):
    """Add an expense to a bill split group."""
    group_id: str
    description: str = Field(..., min_length=1, max_length=200)
    total_amount: float = Field(..., gt=0)
    paid_by: str = Field(..., description="Who paid")
    split_among: List[str] = Field(..., min_length=1)
    split_type: str = Field("equal", pattern=r"^(equal|exact|percentage|shares)$")
    split_values: Optional[List[float]] = Field(None)


class SettlementRequest(BaseModel):
    """Record a settlement between members."""
    group_id: str
    from_member: str
    to_member: str
    amount: float = Field(..., gt=0)
    payment_method: PaymentMethod = Field(PaymentMethod.UPI)


# ═══════════════════════════════════════════════════════════════════════════════
# Alert Schemas
# ═══════════════════════════════════════════════════════════════════════════════

class AlertCreateRequest(BaseModel):
    """Create a custom alert."""
    alert_type: AlertType
    title: str = Field(..., min_length=5, max_length=200)
    message: str = Field(..., min_length=5, max_length=1000)
    severity: AlertSeverity = Field(AlertSeverity.INFO)
    data: Optional[Dict[str, Any]] = None
    action_url: Optional[str] = Field(None, max_length=500)


class AlertPreferencesRequest(BaseModel):
    """Update alert preferences."""
    scam_warnings: bool = Field(True)
    portfolio_alerts: bool = Field(True)
    budget_reminders: bool = Field(True)
    learning_reminders: bool = Field(True)
    weekly_report: bool = Field(True)
    push_enabled: bool = Field(True)
    email_enabled: bool = Field(False)
    quiet_hours_start: Optional[int] = Field(None, ge=0, le=23)
    quiet_hours_end: Optional[int] = Field(None, ge=0, le=23)


# ═══════════════════════════════════════════════════════════════════════════════
# User Profile Schemas
# ═══════════════════════════════════════════════════════════════════════════════

class ProfileUpdateRequest(BaseModel):
    """Update user profile."""
    full_name: Optional[str] = Field(None, min_length=1, max_length=100)
    phone: Optional[str] = None
    bio: Optional[str] = Field(None, max_length=500)
    avatar_url: Optional[str] = Field(None, max_length=500)
    language: Optional[Language] = None
    timezone: Optional[str] = Field(None, max_length=50)
    theme: Optional[ThemePreference] = None


class FinancialProfileRequest(BaseModel):
    """Update financial profile for personalization."""
    annual_income: Optional[float] = Field(None, gt=0)
    monthly_income: Optional[float] = Field(None, gt=0)
    monthly_expenses: Optional[float] = Field(None, ge=0)
    risk_tolerance: Optional[RiskTolerance] = None
    investment_experience: Optional[InvestmentExperience] = None
    financial_goals: Optional[List[str]] = None
    has_emergency_fund: Optional[bool] = None
    has_health_insurance: Optional[bool] = None
    has_life_insurance: Optional[bool] = None


class PasswordChangeRequest(BaseModel):
    """Change password."""
    current_password: str = Field(..., min_length=1)
    new_password: str = Field(..., min_length=8, max_length=128)

    @field_validator("new_password")
    @classmethod
    def validate_new_password(cls, v):
        if not re.search(r"[A-Z]", v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not re.search(r"[a-z]", v):
            raise ValueError("Password must contain at least one lowercase letter")
        if not re.search(r"\d", v):
            raise ValueError("Password must contain at least one digit")
        return v


# ═══════════════════════════════════════════════════════════════════════════════
# Analytics & Reporting Schemas
# ═══════════════════════════════════════════════════════════════════════════════

class AnalyticsQueryRequest(BaseModel):
    """Query analytics data."""
    metric: str = Field(
        ..., description="Metric to query (scans, risk_distribution, scam_types, etc.)"
    )
    start_date: Optional[date] = None
    end_date: Optional[date] = None
    group_by: Optional[str] = Field(None, description="Group by (day, week, month)")
    filters: Optional[Dict[str, Any]] = None


class FeedbackRequest(BaseModel):
    """Submit feedback on a scan result."""
    scan_id: str
    rating: int = Field(..., ge=1, le=5)
    feedback: Optional[str] = Field(None, max_length=1000)
    was_helpful: Optional[bool] = None
    feedback_tags: List[str] = Field(default_factory=list, max_length=5)


# ═══════════════════════════════════════════════════════════════════════════════
# Gamification Schemas
# ═══════════════════════════════════════════════════════════════════════════════

class LeaderboardQuery(BaseModel):
    """Query the leaderboard."""
    period: str = Field("weekly", pattern=r"^(daily|weekly|monthly|all_time)$")
    limit: int = Field(10, ge=1, le=100)


class BadgeClaimRequest(BaseModel):
    """Claim a badge achievement."""
    badge_id: str


# ═══════════════════════════════════════════════════════════════════════════════
# Pagination (reusable)
# ═══════════════════════════════════════════════════════════════════════════════

class PaginationParams(BaseModel):
    """Reusable pagination parameters."""
    page: int = Field(1, ge=1, description="Page number")
    per_page: int = Field(20, ge=1, le=100, description="Items per page")
    sort_by: Optional[str] = Field(None, description="Sort field")
    sort_order: str = Field("desc", pattern=r"^(asc|desc)$")


class DateRangeParams(BaseModel):
    """Reusable date range parameters."""
    start_date: Optional[date] = None
    end_date: Optional[date] = None

    @model_validator(mode="after")
    def validate_date_range(self):
        if self.start_date and self.end_date:
            if self.start_date > self.end_date:
                raise ValueError("start_date must be before end_date")
        return self
