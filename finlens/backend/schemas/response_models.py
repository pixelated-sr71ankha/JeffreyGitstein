"""
═══════════════════════════════════════════════════════════════════════════════
FinLens Response Schemas
═══════════════════════════════════════════════════════════════════════════════

Standardized API response models ensuring consistent JSON structure
across all endpoints. Every response wraps data in a standard envelope
with success status, data payload, metadata, and optional errors.
"""

from typing import Optional, List, Dict, Any, Generic, TypeVar
from datetime import datetime

from pydantic import BaseModel, Field


T = TypeVar("T")


# ═══════════════════════════════════════════════════════════════════════════════
# Standard Response Envelope
# ═══════════════════════════════════════════════════════════════════════════════

class ResponseMetadata(BaseModel):
    """Metadata included in every API response."""
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    request_id: Optional[str] = None
    latency_ms: Optional[int] = None
    version: str = "1.0.0"


class ErrorDetail(BaseModel):
    """Detailed error information."""
    code: str
    message: str
    field: Optional[str] = None
    suggestion: Optional[str] = None


class APIResponse(BaseModel):
    """Standard API response envelope."""
    success: bool
    data: Optional[Any] = None
    error: Optional[ErrorDetail] = None
    metadata: ResponseMetadata = Field(default_factory=ResponseMetadata)
    prism_trace_status: Optional[str] = None


class PaginatedResponse(BaseModel):
    """Paginated list response."""
    success: bool
    data: List[Any] = Field(default_factory=list)
    total: int = 0
    page: int = 1
    per_page: int = 20
    total_pages: int = 0
    has_next: bool = False
    has_prev: bool = False
    metadata: ResponseMetadata = Field(default_factory=ResponseMetadata)


# ═══════════════════════════════════════════════════════════════════════════════
# Authentication Responses
# ═══════════════════════════════════════════════════════════════════════════════

class TokenPair(BaseModel):
    """JWT token pair for authentication."""
    access_token: str
    refresh_token: str
    token_type: str = "Bearer"
    expires_in: int = Field(description="Access token TTL in seconds")


class AuthResponse(BaseModel):
    """Authentication response (login/register)."""
    user: "UserProfile"
    tokens: TokenPair
    message: str = "Success"


class UserProfile(BaseModel):
    """User profile data."""
    id: str
    email: str
    username: str
    full_name: Optional[str] = None
    phone: Optional[str] = None
    avatar_url: Optional[str] = None
    bio: Optional[str] = None
    language: str = "en"
    timezone: str = "Asia/Kolkata"
    points: int = 0
    level: int = 1
    badges: List[Dict[str, Any]] = Field(default_factory=list)
    streak_days: int = 0
    is_verified: bool = False
    created_at: Optional[str] = None


# ═══════════════════════════════════════════════════════════════════════════════
# Scam Analysis Responses
# ═══════════════════════════════════════════════════════════════════════════════

class RedFlag(BaseModel):
    """A single red flag detected in the message."""
    indicator: str
    severity: str  # critical, high, medium, low
    explanation: str
    scam_pattern: Optional[str] = None


class ScamAnalysisResponse(BaseModel):
    """Complete scam analysis result."""
    risk_level: str = Field(description="SAFE, SUSPICIOUS, DANGEROUS, or CONFIRMED_SCAM")
    risk_score: int = Field(ge=0, le=100, description="Risk score 0-100")
    scam_type: Optional[str] = Field(None, description="Classified scam type")
    confidence: int = Field(ge=0, le=100, description="Analysis confidence %")
    verdict: str = Field(description="Human-readable verdict")
    explanation: str = Field(description="Detailed explanation of the analysis")
    red_flags: List[RedFlag] = Field(default_factory=list)
    safe_indicators: List[str] = Field(default_factory=list)
    action: str = Field(description="Recommended action")
    educational_note: Optional[str] = Field(None)
    similar_scam_reports: Optional[int] = Field(None)
    strategies_used: List[str] = Field(default_factory=list)
    strategy_scores: Dict[str, int] = Field(default_factory=dict)
    processing_time_ms: Optional[int] = None
    scan_id: Optional[str] = None


class PhoneCheckResponse(BaseModel):
    """Phone number scam check result."""
    phone_number: str
    is_suspicious: bool
    risk_level: str
    reports_count: int = 0
    scam_types: List[str] = Field(default_factory=list)
    last_reported: Optional[str] = None
    regions: List[str] = Field(default_factory=list)


class UrlScanResponse(BaseModel):
    """URL scan result."""
    url: str
    is_suspicious: bool
    risk_level: str
    threats: List[str] = Field(default_factory=list)
    domain_age_days: Optional[int] = None
    ssl_valid: Optional[bool] = None
    redirects: int = 0
    similar_domains: List[str] = Field(default_factory=list)


class BatchScamResponse(BaseModel):
    """Batch scam analysis result."""
    results: List[ScamAnalysisResponse]
    total_analyzed: int
    scam_count: int
    suspicious_count: int
    safe_count: int
    processing_time_ms: int


# ═══════════════════════════════════════════════════════════════════════════════
# Financial Health Responses
# ═══════════════════════════════════════════════════════════════════════════════

class CategoryBreakdown(BaseModel):
    """Breakdown of a single expense category."""
    name: str
    icon: str
    total: float
    percentage: float
    count: int
    average: float
    budget_limit: Optional[float] = None
    status: Optional[str] = None  # on_track, over_budget, well_under


class HealthRecommendation(BaseModel):
    """A single financial health recommendation."""
    category: str
    priority: str  # critical, high, medium, low
    title: str
    detail: str
    potential_savings: Optional[float] = None
    impact: Optional[str] = None


class FinancialHealthResponse(BaseModel):
    """Comprehensive financial health assessment."""
    health_score: int = Field(ge=0, le=100)
    health_grade: str
    monthly_income: float
    total_expenses: float
    net_savings: float
    savings_rate: float
    category_breakdown: Dict[str, CategoryBreakdown] = Field(default_factory=dict)
    daily_average: float
    monthly_average: float
    top_expenses: List[Dict[str, Any]] = Field(default_factory=list)
    anomalies: List[Dict[str, Any]] = Field(default_factory=list)
    budget: Optional[Dict[str, Any]] = None
    budget_status: Optional[Dict[str, Any]] = None
    trends: Optional[Dict[str, Any]] = None
    savings_opportunities: List[Dict[str, Any]] = Field(default_factory=list)
    recommendations: List[HealthRecommendation] = Field(default_factory=list)
    insights: List[Dict[str, Any]] = Field(default_factory=list)
    ai_analysis: Optional[str] = None
    scan_id: Optional[str] = None


# ═══════════════════════════════════════════════════════════════════════════════
# Financial Literacy Responses
# ═══════════════════════════════════════════════════════════════════════════════

class LiteracyResponse(BaseModel):
    """Financial literacy Q&A response."""
    response: str
    topic: Optional[str] = None
    subtopics: List[str] = Field(default_factory=list)
    confidence: Optional[float] = None
    sources: List[str] = Field(default_factory=list)
    related_questions: List[str] = Field(default_factory=list)
    key_takeaways: List[str] = Field(default_factory=list)
    india_specific: List[str] = Field(default_factory=list)
    disclaimer: Optional[str] = None
    scan_id: Optional[str] = None


class QuizQuestion(BaseModel):
    """A single quiz question."""
    id: str
    question: str
    options: List[str]
    explanation: str
    difficulty: str
    topic: str


class QuizResponse(BaseModel):
    """Quiz generation response."""
    quiz_id: str
    topic: str
    difficulty: str
    questions: List[QuizQuestion]
    total_questions: int


class QuizResultResponse(BaseModel):
    """Quiz result after submission."""
    quiz_id: str
    score: int
    total: int
    percentage: float
    grade: str
    correct_answers: List[Dict[str, Any]]
    explanations: List[Dict[str, Any]]
    points_earned: int
    badge_earned: Optional[str] = None


# ═══════════════════════════════════════════════════════════════════════════════
# Portfolio Responses
# ═══════════════════════════════════════════════════════════════════════════════

class PortfolioHoldingResponse(BaseModel):
    """Single holding in portfolio."""
    id: str
    asset_type: str
    asset_name: str
    asset_symbol: Optional[str]
    units: float
    avg_buy_price: float
    current_price: float
    current_value: float
    absolute_returns: float
    returns_percentage: float
    xirr: Optional[float]
    first_invested: Optional[str]


class AllocationSlice(BaseModel):
    """Asset allocation breakdown."""
    asset_class: str
    current_pct: float
    target_pct: float
    current_value: float
    target_value: float
    drift: float


class RebalancingAction(BaseModel):
    """A single rebalancing action."""
    asset_class: str
    action: str  # buy or sell
    amount: float
    current_pct: float
    target_pct: float
    reason: str


class PortfolioAnalysisResponse(BaseModel):
    """Complete portfolio analysis result."""
    health_score: int = Field(ge=0, le=100)
    health_grade: str
    risk_rating: str
    total_invested: float
    current_value: float
    total_returns: float
    returns_percentage: float
    holdings: List[PortfolioHoldingResponse] = Field(default_factory=list)
    allocation: List[AllocationSlice] = Field(default_factory=list)
    risk_metrics: Dict[str, Any] = Field(default_factory=dict)
    suggestions: List[Dict[str, Any]] = Field(default_factory=list)
    rebalancing_actions: List[RebalancingAction] = Field(default_factory=list)
    tax_optimization: List[Dict[str, Any]] = Field(default_factory=list)
    goal_progress: Optional[Dict[str, Any]] = None
    sip_recommendation: Optional[Dict[str, Any]] = None
    ai_analysis: Optional[str] = None
    scan_id: Optional[str] = None


# ═══════════════════════════════════════════════════════════════════════════════
# Expense Tracker Responses
# ═══════════════════════════════════════════════════════════════════════════════

class ExpenseSummary(BaseModel):
    """Expense tracking summary."""
    total_expenses: float
    total_income: float
    net_savings: float
    expense_count: int
    income_count: int
    avg_daily_expense: float
    avg_transaction: float
    largest_expense: Optional[Dict[str, Any]] = None
    most_frequent_category: Optional[str] = None


class ExpenseAnalyticsResponse(BaseModel):
    """Expense analytics result."""
    summary: ExpenseSummary
    category_breakdown: Dict[str, CategoryBreakdown]
    daily_trend: List[Dict[str, Any]] = Field(default_factory=list)
    weekly_trend: List[Dict[str, Any]] = Field(default_factory=list)
    monthly_comparison: List[Dict[str, Any]] = Field(default_factory=list)
    anomalies: List[Dict[str, Any]] = Field(default_factory=list)
    savings_opportunities: List[Dict[str, Any]] = Field(default_factory=list)
    payment_method_split: Dict[str, float] = Field(default_factory=dict)
    merchant_breakdown: List[Dict[str, Any]] = Field(default_factory=list)
    insights: List[str] = Field(default_factory=list)


# ═══════════════════════════════════════════════════════════════════════════════
# Bill Split Responses
# ═══════════════════════════════════════════════════════════════════════════════

class BillSplitMember(BaseModel):
    """Member in a bill split group."""
    name: str
    total_paid: float
    total_owed: float
    net_balance: float  # positive = owed money, negative = owes money


class Settlement(BaseModel):
    """Settlement between two members."""
    from_member: str
    to_member: str
    amount: float
    suggested_method: str = "UPI"


class BillSplitGroupResponse(BaseModel):
    """Bill split group summary."""
    group_id: str
    name: str
    members: List[BillSplitMember]
    total_expenses: float
    settlements: List[Settlement]
    is_settled: bool


# ═══════════════════════════════════════════════════════════════════════════════
# Alert Responses
# ═══════════════════════════════════════════════════════════════════════════════

class AlertResponse(BaseModel):
    """Alert notification."""
    id: str
    alert_type: str
    title: str
    message: str
    severity: str
    is_read: bool
    action_url: Optional[str]
    created_at: str


class AlertSummary(BaseModel):
    """Alert summary counts."""
    total: int
    unread: int
    critical: int
    warning: int
    info: int


# ═══════════════════════════════════════════════════════════════════════════════
# Gamification Responses
# ═══════════════════════════════════════════════════════════════════════════════

class LeaderboardEntry(BaseModel):
    """Single leaderboard entry."""
    rank: int
    username: str
    full_name: Optional[str]
    avatar_url: Optional[str]
    points: int
    level: int
    badges_count: int
    streak_days: int


class Badge(BaseModel):
    """Achievement badge."""
    id: str
    name: str
    description: str
    icon: str
    category: str
    points: int
    earned_at: Optional[str] = None
    is_earned: bool = False


class GamificationProfile(BaseModel):
    """User's gamification status."""
    points: int
    level: int
    points_to_next_level: int
    level_progress_pct: float
    streak_days: int
    longest_streak: int
    badges_earned: List[Badge]
    badges_available: List[Badge]
    rank: Optional[int] = None
    total_scans: int = 0
    scams_caught: int = 0
    quizzes_passed: int = 0


class PointsEarned(BaseModel):
    """Points earned from an action."""
    points_earned: int
    total_points: int
    level: int
    level_up: bool = False
    new_level: Optional[int] = None
    reason: str


# ═══════════════════════════════════════════════════════════════════════════════
# Analytics & Dashboard Responses
# ═══════════════════════════════════════════════════════════════════════════════

class DashboardStats(BaseModel):
    """User dashboard statistics."""
    total_scans: int
    scams_detected: int
    money_protected: Optional[float]
    scan_streak: int
    points: int
    level: int
    alerts_count: int
    recent_activity: List[Dict[str, Any]] = Field(default_factory=list)
    weekly_scan_count: int = 0
    weekly_scam_count: int = 0
    top_scam_type: Optional[str] = None


class SystemHealthResponse(BaseModel):
    """System health status."""
    status: str
    database: Dict[str, Any]
    prism: Dict[str, Any]
    uptime_seconds: float
    total_users: int
    total_scans: int
    version: str


# ═══════════════════════════════════════════════════════════════════════════════
# Scam Report Responses
# ═══════════════════════════════════════════════════════════════════════════════

class ScamReportResponse(BaseModel):
    """Community scam report."""
    id: str
    scam_type: str
    title: str
    description: str
    severity: str
    verified: bool
    verification_count: int
    views: int
    upvotes: int
    city: Optional[str]
    state: Optional[str]
    amount_lost: Optional[float]
    created_at: str


class ScamIntelligenceFeedResponse(BaseModel):
    """Scam intelligence feed item."""
    id: str
    scam_type: str
    title: str
    summary: str
    severity: str
    source: Optional[str]
    affected_regions: List[str]
    estimated_victims: Optional[int]
    estimated_loss: Optional[float]
    published_at: str


class ScamStatsResponse(BaseModel):
    """Scam detection statistics."""
    total_reports: int
    verified_reports: int
    total_scans: int
    detection_rate: float
    top_scam_types: List[Dict[str, Any]]
    monthly_trend: List[Dict[str, Any]]
    geographic_heatmap: Dict[str, int]
    avg_risk_score: float
    high_risk_detected: int
