"""
═══════════════════════════════════════════════════════════════════════════════
FinLens Expense Analyzer Agent
═══════════════════════════════════════════════════════════════════════════════

AI-powered expense tracking and analysis engine featuring:
- Automatic transaction categorization using NLP
- Spending pattern detection and trend analysis
- Budget creation and monitoring (50/30/20 and custom)
- Anomaly detection (unusual spending)
- Savings opportunity identification
- Bill splitting calculations
- Monthly/yearly reports with actionable insights
- Indian-specific expense categories and benchmarks
"""

import re
import json
import math
import logging
from typing import Optional
from datetime import datetime, timedelta
from collections import defaultdict
from dataclasses import dataclass, field

logger = logging.getLogger("finlens.expense_analyzer")


# ═══════════════════════════════════════════════════════════════════════
# Indian Expense Categories (India-specific)
# ═══════════════════════════════════════════════════════════════════════

EXPENSE_CATEGORIES = {
    "housing": {
        "name": "Housing & Rent",
        "icon": "🏠",
        "subcategories": ["rent", "maintenance", "society_maintenance", "property_tax", "home_loan_emi"],
        "budget_percentage": {"recommended": 30, "max": 35},
        "keywords": ["rent", "society", "maintenance", "emi", "property", "house", "flat", "apartment"],
        "merchants": ["nobroker", "housing.com", "99acres", "society"]
    },
    "food": {
        "name": "Food & Groceries",
        "icon": "🍛",
        "subcategories": ["groceries", "dining_out", "food_delivery", "tea_coffee", "tiffin"],
        "budget_percentage": {"recommended": 15, "max": 20},
        "keywords": ["grocery", "vegetable", "fruit", "swiggy", "zomato", "restaurant", "food", "meal", "lunch", "dinner", "breakfast", "chai", "coffee"],
        "merchants": ["swiggy", "zomato", "bigbasket", "blinkit", "zepto", "dmart", "reliance fresh", "more超市", "jjmart"]
    },
    "transport": {
        "name": "Transportation",
        "icon": "🚗",
        "subcategories": ["fuel", "metro", "bus", "auto", "cab", "parking", "vehicle_emi", "insurance"],
        "budget_percentage": {"recommended": 10, "max": 15},
        "keywords": ["uber", "ola", "metro", "petrol", "diesel", "parking", "bus", "auto", "train", "flight", "irctc", "rapido"],
        "merchants": ["uber", "ola", "rapido", "irctc", "metro"]
    },
    "utilities": {
        "name": "Bills & Utilities",
        "icon": "📱",
        "subcategories": ["electricity", "water", "gas", "internet", "mobile", "dth", "broadband"],
        "budget_percentage": {"recommended": 5, "max": 8},
        "keywords": ["electricity", "bill", "recharge", "broadband", "wifi", "gas", "water", "jio", "airtel", "bsnl", "vi"],
        "merchants": ["jio", "airtel", "bsnl", "vi", "act", "bsnl", "bescom", "mSEDCL"]
    },
    "entertainment": {
        "name": "Entertainment & Lifestyle",
        "icon": "🎬",
        "subcategories": ["movies", "streaming", "subscriptions", "hobbies", "events"],
        "budget_percentage": {"recommended": 5, "max": 10},
        "keywords": ["netflix", "hotstar", "prime", "movie", "concert", "game", "play", "book", "gym", "club"],
        "merchants": ["netflix", "amazon prime", "hotstar", "bookmyshow", "pvr", "inox"]
    },
    "shopping": {
        "name": "Shopping & Personal",
        "icon": "🛍️",
        "subcategories": ["clothing", "electronics", "personal_care", "accessories", "home_decor"],
        "budget_percentage": {"recommended": 5, "max": 10},
        "keywords": ["amazon", "flipkart", "myntra", "nykaa", "clothes", "shoes", "phone", "laptop", "gadget"],
        "merchants": ["amazon", "flipkart", "myntra", "ajio", "nykaa", "croma", "reliance digital"]
    },
    "health": {
        "name": "Health & Medical",
        "icon": "🏥",
        "subcategories": ["doctor", "medicine", "hospital", "insurance", "gym", "wellness"],
        "budget_percentage": {"recommended": 5, "max": 10},
        "keywords": ["doctor", "medicine", "pharmacy", "hospital", "health", "medical", "lab", "test", "gym", "yoga", "practo"],
        "merchants": ["practo", "1mg", "pharmeasy", "medplus", "apollo", "pharmeasy"]
    },
    "education": {
        "name": "Education & Learning",
        "icon": "📚",
        "subcategories": ["tuition", "courses", "books", "exams", "certifications"],
        "budget_percentage": {"recommended": 5, "max": 10},
        "keywords": ["course", "class", "tuition", "book", "udemy", "coursera", "unacademy", "exam", "fee"],
        "merchants": ["udemy", "coursera", "unacademy", "byjus"]
    },
    "financial": {
        "name": "Financial Services",
        "icon": "💳",
        "subcategories": ["sip", "insurance_premium", "loan_emi", "bank_charges", "investment"],
        "budget_percentage": {"recommended": 20, "max": 30},
        "keywords": ["sip", "mutual fund", "insurance", "premium", "emi", "loan", "investment", "ppf", "nps"],
        "merchants": ["zerodha", "groww", "kuvera", "paytm money"]
    },
    "personal": {
        "name": "Personal & Social",
        "icon": "👥",
        "subcategories": ["gifts", "donations", "social", "travel", "vacation"],
        "budget_percentage": {"recommended": 5, "max": 10},
        "keywords": ["gift", "donation", "temple", "church", "charity", "travel", "hotel", "vacation", "trip"],
        "merchants": ["irctc", "makemytrip", "booking.com", "goibibo"]
    }
}

# AI categorization keywords for fuzzy matching
CATEGORY_KEYWORD_MAP = {}
for cat_id, cat in EXPENSE_CATEGORIES.items():
    for keyword in cat.get("keywords", []):
        CATEGORY_KEYWORD_MAP[keyword.lower()] = cat_id


# ═══════════════════════════════════════════════════════════════════════
# Data Classes
# ═══════════════════════════════════════════════════════════════════════

@dataclass
class ExpenseEntry:
    """Single expense entry."""
    id: str
    amount: float
    description: str
    category: str
    subcategory: Optional[str] = None
    payment_method: str = "upi"
    merchant: Optional[str] = None
    date: Optional[datetime] = None
    tags: list = field(default_factory=list)
    is_income: bool = False
    is_recurring: bool = False
    confidence: float = 1.0


@dataclass
class SpendingAnalysis:
    """Complete spending analysis result."""
    total_spent: float
    total_income: float
    net_savings: float
    savings_rate: float
    category_breakdown: dict
    daily_average: float
    monthly_average: float
    top_expenses: list
    spending_trend: str  # increasing, stable, decreasing
    anomalies: list
    budget_status: dict
    insights: list
    recommendations: list
    health_score: int
    health_grade: str


# ═══════════════════════════════════════════════════════════════════════
# AI Categorization Engine
# ═══════════════════════════════════════════════════════════════════════

class CategorizationEngine:
    """
    Rule-based + keyword-based expense categorization.
    Uses fuzzy matching and merchant database for accuracy.
    """

    def categorize(self, description: str, amount: float = 0) -> tuple[str, float]:
        """
        Categorize an expense description.

        Returns:
            (category_id, confidence)
        """
        desc_lower = description.lower().strip()

        # ─── Exact keyword match ──────────────────────────────────
        for keyword, cat_id in CATEGORY_KEYWORD_MAP.items():
            if keyword in desc_lower:
                return cat_id, 0.9

        # ─── Merchant match ───────────────────────────────────────
        for cat_id, cat in EXPENSE_CATEGORIES.items():
            for merchant in cat.get("merchants", []):
                if merchant.lower() in desc_lower:
                    return cat_id, 0.95

        # ─── Pattern-based matching ───────────────────────────────
        patterns = {
            "food": [r'\b(food|eat|meal|lunch|dinner|breakfast|snack|chai|tea|coffee)\b'],
            "transport": [r'\b(uber|ola|rapido|auto|taxi|cab|metro|bus|train)\b'],
            "utilities": [r'\b(recharge|bill|electricity|water|gas|internet|wifi|broadband)\b'],
            "entertainment": [r'\b(movie|netflix|hotstar|prime|show|game|play)\b'],
            "shopping": [r'\b(buy|purchase|shop|amazon|flipkart|myntra)\b'],
            "health": [r'\b(doctor|medicine|pharmacy|hospital|medical|health|gym)\b'],
            "financial": [r'\b(sip|invest|insurance|premium|emi|loan|mutual)\b'],
        }

        for cat_id, cat_patterns in patterns.items():
            for pat in cat_patterns:
                if re.search(pat, desc_lower):
                    return cat_id, 0.75

        # ─── Amount-based heuristics ──────────────────────────────
        if amount > 0:
            if amount > 50000:
                return "financial", 0.4  # Large amounts often financial
            elif amount > 20000:
                return "shopping", 0.3
            elif amount < 100:
                return "food", 0.3  # Small amounts often food/tea

        return "personal", 0.2  # Default fallback


# ═══════════════════════════════════════════════════════════════════════
# Anomaly Detection
# ═══════════════════════════════════════════════════════════════════════

class AnomalyDetector:
    """Detects unusual spending patterns and anomalies."""

    def detect(self, expenses: list[ExpenseEntry], monthly_income: float = 0) -> list[dict]:
        """Detect anomalies in expense data."""
        anomalies = []

        if not expenses:
            return anomalies

        # ─── Single large transaction ─────────────────────────────
        if monthly_income > 0:
            threshold = monthly_income * 0.3  # 30% of monthly income
            for exp in expenses:
                if exp.amount > threshold and not exp.is_income:
                    anomalies.append({
                        "type": "large_transaction",
                        "severity": "warning",
                        "title": f"Large expense: ₹{exp.amount:,.0f}",
                        "detail": f"'{exp.description}' is {exp.amount/monthly_income*100:.0f}% of your monthly income. Consider if this was planned.",
                        "amount": exp.amount,
                        "date": exp.date.isoformat() if exp.date else None
                    })

        # ─── Category spike detection ─────────────────────────────
        category_totals = defaultdict(float)
        category_count = defaultdict(int)
        for exp in expenses:
            if not exp.is_income:
                category_totals[exp.category] += exp.amount
                category_count[exp.category] += 1

        for cat_id, cat_info in EXPENSE_CATEGORIES.items():
            total = category_totals.get(cat_id, 0)
            budget_max = cat_info.get("budget_percentage", {}).get("max", 100)
            if monthly_income > 0:
                budget_amount = monthly_income * budget_max / 100
                if total > budget_amount:
                    anomalies.append({
                        "type": "category_overrun",
                        "severity": "warning",
                        "title": f"{cat_info['name']} over budget",
                        "detail": f"You spent ₹{total:,.0f} on {cat_info['name']}, exceeding the recommended max of ₹{budget_amount:,.0f} ({budget_max}% of income).",
                        "amount": total,
                        "budget": budget_amount
                    })

        # ─── Frequency anomalies ──────────────────────────────────
        if len(expenses) > 5:
            avg_amount = sum(e.amount for e in expenses if not e.is_income) / max(1, sum(1 for e in expenses if not e.is_income))
            for exp in expenses:
                if not exp.is_income and exp.amount > avg_amount * 4:
                    anomalies.append({
                        "type": "unusual_amount",
                        "severity": "info",
                        "title": f"Unusually high: ₹{exp.amount:,.0f}",
                        "detail": f"'{exp.description}' is {exp.amount/avg_amount:.1f}x your average transaction (₹{avg_amount:,.0f}).",
                        "amount": exp.amount
                    })

        return anomalies


# ═══════════════════════════════════════════════════════════════════════
# Budget Engine
# ═══════════════════════════════════════════════════════════════════════

class BudgetEngine:
    """Creates and monitors budgets based on income and spending patterns."""

    def create_budget(self, monthly_income: float, risk_tolerance: str = "moderate") -> dict:
        """Create a personalized budget plan."""
        profiles = {
            "conservative": {
                "needs": 55, "wants": 15, "savings": 30,
                "categories": {
                    "housing": 30, "food": 12, "transport": 8, "utilities": 5,
                    "entertainment": 3, "shopping": 3, "health": 4, "education": 3,
                    "financial": 25, "personal": 5
                }
            },
            "moderate": {
                "needs": 50, "wants": 30, "savings": 20,
                "categories": {
                    "housing": 28, "food": 15, "transport": 10, "utilities": 5,
                    "entertainment": 5, "shopping": 5, "health": 5, "education": 5,
                    "financial": 15, "personal": 5
                }
            },
            "aggressive": {
                "needs": 40, "wants": 20, "savings": 40,
                "categories": {
                    "housing": 25, "food": 10, "transport": 8, "utilities": 4,
                    "entertainment": 3, "shopping": 3, "health": 4, "education": 3,
                    "financial": 35, "personal": 5
                }
            }
        }

        profile = profiles.get(risk_tolerance, profiles["moderate"])
        budget = {
            "monthly_income": monthly_income,
            "risk_profile": risk_tolerance,
            "allocation": {
                "needs": {"percentage": profile["needs"], "amount": monthly_income * profile["needs"] / 100},
                "wants": {"percentage": profile["wants"], "amount": monthly_income * profile["wants"] / 100},
                "savings": {"percentage": profile["savings"], "amount": monthly_income * profile["savings"] / 100},
            },
            "category_budgets": {}
        }

        for cat_id, pct in profile["categories"].items():
            cat_info = EXPENSE_CATEGORIES.get(cat_id, {})
            budget["category_budgets"][cat_id] = {
                "name": cat_info.get("name", cat_id),
                "icon": cat_info.get("icon", "📋"),
                "percentage": pct,
                "monthly_limit": round(monthly_income * pct / 100),
                "daily_limit": round(monthly_income * pct / 100 / 30),
            }

        return budget

    def check_budget_status(
        self, budget: dict, expenses: list[ExpenseEntry]
    ) -> dict:
        """Check current spending against budget."""
        today = datetime.utcnow()
        days_in_month = 30
        day_of_month = today.day
        month_progress = day_of_month / days_in_month

        status = {
            "month_progress": round(month_progress * 100, 1),
            "day_of_month": day_of_month,
            "categories": {},
            "overall_status": "on_track"
        }

        total_spent = 0
        total_budget = 0

        for cat_id, budget_info in budget.get("category_budgets", {}).items():
            cat_spent = sum(
                e.amount for e in expenses
                if e.category == cat_id and not e.is_income
            )
            cat_limit = budget_info["monthly_limit"]
            total_spent += cat_spent
            total_budget += cat_limit

            spent_pct = (cat_spent / cat_limit * 100) if cat_limit > 0 else 0
            expected_pct = month_progress * 100

            if spent_pct > expected_pct + 20:
                status_flag = "over_budget"
            elif spent_pct > expected_pct:
                status_flag = "slightly_over"
            elif spent_pct < expected_pct - 30:
                status_flag = "well_under"
            else:
                status_flag = "on_track"

            status["categories"][cat_id] = {
                "name": budget_info["name"],
                "icon": budget_info["icon"],
                "spent": round(cat_spent),
                "budget": cat_limit,
                "remaining": round(max(0, cat_limit - cat_spent)),
                "spent_percentage": round(spent_pct, 1),
                "expected_percentage": round(expected_pct, 1),
                "status": status_flag,
                "daily_avg": round(cat_spent / max(1, day_of_month)),
                "projected_month_end": round(cat_spent / max(0.1, month_progress)),
            }

        # Overall status
        overall_spent_pct = (total_spent / total_budget * 100) if total_budget > 0 else 0
        if overall_spent_pct > month_progress * 120:
            status["overall_status"] = "overspending"
        elif overall_spent_pct > month_progress * 105:
            status["overall_status"] = "slightly_over"
        else:
            status["overall_status"] = "on_track"

        status["total_spent"] = round(total_spent)
        status["total_budget"] = round(total_budget)
        status["remaining"] = round(max(0, total_budget - total_spent))

        return status


# ═══════════════════════════════════════════════════════════════════════
# Trend Analysis
# ═══════════════════════════════════════════════════════════════════════

class TrendAnalyzer:
    """Analyzes spending trends over time."""

    def analyze(self, expenses: list[ExpenseEntry]) -> dict:
        """Analyze spending trends from expense history."""
        if not expenses:
            return {"trend": "no_data", "insights": []}

        # Group by month
        monthly_totals = defaultdict(float)
        monthly_categories = defaultdict(lambda: defaultdict(float))

        for exp in expenses:
            if exp.is_income or not exp.date:
                continue
            month_key = exp.date.strftime("%Y-%m")
            monthly_totals[month_key] += exp.amount
            monthly_categories[month_key][exp.category] += exp.amount

        if len(monthly_totals) < 2:
            return {"trend": "insufficient_data", "insights": []}

        # Calculate trend
        sorted_months = sorted(monthly_totals.keys())
        amounts = [monthly_totals[m] for m in sorted_months]

        # Simple linear regression
        n = len(amounts)
        x_mean = (n - 1) / 2
        y_mean = sum(amounts) / n

        numerator = sum((i - x_mean) * (amounts[i] - y_mean) for i in range(n))
        denominator = sum((i - x_mean) ** 2 for i in range(n))

        if denominator > 0:
            slope = numerator / denominator
        else:
            slope = 0

        if slope > y_mean * 0.05:
            trend = "increasing"
        elif slope < -y_mean * 0.05:
            trend = "decreasing"
        else:
            trend = "stable"

        # Generate insights
        insights = []

        # Overall trend
        if trend == "increasing":
            insights.append({
                "type": "trend",
                "severity": "warning",
                "message": f"Your spending has been increasing by ~₹{abs(slope):,.0f}/month. Review discretionary expenses."
            })
        elif trend == "decreasing":
            insights.append({
                "type": "trend",
                "severity": "positive",
                "message": f"Great job! Your spending has been decreasing by ~₹{abs(slope):,.0f}/month."
            })

        # Category-wise trends
        for cat_id in set().union(*[set(monthly_categories[m].keys()) for m in sorted_months]):
            cat_amounts = [monthly_categories[m].get(cat_id, 0) for m in sorted_months]
            if len(cat_amounts) >= 2:
                recent_avg = sum(cat_amounts[-2:]) / 2
                older_avg = sum(cat_amounts[:-2]) / max(1, len(cat_amounts) - 2)
                if older_avg > 0:
                    change_pct = (recent_avg - older_avg) / older_avg * 100
                    if change_pct > 30:
                        cat_name = EXPENSE_CATEGORIES.get(cat_id, {}).get("name", cat_id)
                        insights.append({
                            "type": "category_spike",
                            "severity": "warning",
                            "message": f"{cat_name} spending increased by {change_pct:.0f}% recently (₹{older_avg:,.0f} → ₹{recent_avg:,.0f}/month)"
                        })

        return {
            "trend": trend,
            "slope_per_month": round(slope, 2),
            "average_monthly": round(y_mean, 2),
            "months_analyzed": n,
            "total_range": {
                "lowest": round(min(amounts)),
                "highest": round(max(amounts)),
                "lowest_month": sorted_months[amounts.index(min(amounts))],
                "highest_month": sorted_months[amounts.index(max(amounts))],
            },
            "insights": insights,
        }


# ═══════════════════════════════════════════════════════════════════════
# Savings Opportunity Finder
# ═══════════════════════════════════════════════════════════════════════

class SavingsFinder:
    """Identifies specific opportunities to reduce expenses."""

    def find_opportunities(
        self, expenses: list[ExpenseEntry], monthly_income: float
    ) -> list[dict]:
        """Find actionable savings opportunities."""
        opportunities = []

        if not expenses or monthly_income <= 0:
            return opportunities

        # ─── Dining out analysis ──────────────────────────────────
        dining_expenses = [
            e for e in expenses
            if e.category == "food" and e.subcategory in ("dining_out", "food_delivery")
        ]
        dining_total = sum(e.amount for e in dining_expenses)
        dining_count = len(dining_expenses)

        if dining_total > monthly_income * 0.1:
            potential_savings = dining_total * 0.4
            opportunities.append({
                "type": "reduce_dining",
                "potential_monthly_savings": round(potential_savings),
                "title": "Reduce dining out/food delivery",
                "detail": f"You spend ₹{dining_total:,.0f}/month on dining ({dining_count} transactions). Cooking at home 2 more times/week could save ~₹{potential_savings:,.0f}/month.",
                "impact": f"₹{potential_savings * 12:,.0f}/year saved"
            })

        # ─── Subscription analysis ────────────────────────────────
        subscription_categories = ["entertainment"]
        for cat_id in subscription_categories:
            cat_expenses = [e for e in expenses if e.category == cat_id and e.is_recurring]
            cat_total = sum(e.amount for e in cat_expenses)
            if cat_total > 1000:
                opportunities.append({
                    "type": "review_subscriptions",
                    "potential_monthly_savings": round(cat_total * 0.5),
                    "title": "Review recurring subscriptions",
                    "detail": f"You have ₹{cat_total:,.0f}/month in recurring entertainment expenses. Audit which ones you actually use.",
                    "impact": f"Up to ₹{cat_total * 6:,.0f}/year saved"
                })

        # ─── Food delivery premium ────────────────────────────────
        delivery_expenses = [
            e for e in expenses
            if e.merchant and e.merchant.lower() in ("swiggy", "zomato")
        ]
        if delivery_expenses:
            delivery_total = sum(e.amount for e in delivery_expenses)
            # Food delivery costs ~40% more than cooking at home
            premium = delivery_total * 0.4
            if premium > 1000:
                opportunities.append({
                    "type": "cooking_savings",
                    "potential_monthly_savings": round(premium),
                    "title": "Cook at home instead of ordering",
                    "detail": f"Food delivery costs you ₹{delivery_total:,.0f}/month. Switching to home cooking for 50% of orders saves ~₹{premium:,.0f}/month.",
                    "impact": f"₹{premium * 12:,.0f}/year saved + healthier eating"
                })

        # ─── Unoptimized spending ─────────────────────────────────
        total_expenses = sum(e.amount for e in expenses if not e.is_income)
        if total_expenses > monthly_income:
            overshoot = total_expenses - monthly_income
            opportunities.append({
                "type": "overspending",
                "potential_monthly_savings": round(overshoot),
                "title": "You're spending more than you earn!",
                "detail": f"Total expenses (₹{total_expenses:,.0f}) exceed income (₹{monthly_income:,.0f}) by ₹{overshoot:,.0f}. This is unsustainable.",
                "impact": "Prevents debt accumulation"
            })

        # Sort by potential savings (highest first)
        opportunities.sort(key=lambda o: o.get("potential_monthly_savings", 0), reverse=True)

        return opportunities


# ═══════════════════════════════════════════════════════════════════════
# Main Analysis Orchestrator
# ═══════════════════════════════════════════════════════════════════════

_categorizer = CategorizationEngine()
_anomaly_detector = AnomalyDetector()
_budget_engine = BudgetEngine()
_trend_analyzer = TrendAnalyzer()
_savings_finder = SavingsFinder()


def analyze_expenses(
    expenses: list[dict],
    monthly_income: float = 0,
    monthly_expenses_budget: float = 0,
) -> dict:
    """
    Comprehensive expense analysis.

    Args:
        expenses: List of expense dicts with amount, description, date
        monthly_income: User's monthly income
        monthly_expenses_budget: Optional custom budget

    Returns:
        Complete spending analysis
    """
    # Convert to ExpenseEntry objects
    entries = []
    for e in expenses:
        cat, conf = _categorizer.categorize(
            e.get("description", ""), e.get("amount", 0)
        )
        entries.append(ExpenseEntry(
            id=e.get("id", ""),
            amount=e.get("amount", 0),
            description=e.get("description", ""),
            category=cat,
            subcategory=e.get("subcategory"),
            payment_method=e.get("payment_method", "upi"),
            merchant=e.get("merchant"),
            date=datetime.fromisoformat(e["date"]) if e.get("date") else None,
            tags=e.get("tags", []),
            is_income=e.get("is_income", False),
            confidence=conf,
        ))

    # ─── Category breakdown ───────────────────────────────────────
    category_totals = defaultdict(float)
    category_counts = defaultdict(int)
    total_spent = 0
    total_income = 0

    for entry in entries:
        if entry.is_income:
            total_income += entry.amount
        else:
            total_spent += entry.amount
            category_totals[entry.category] += entry.amount
            category_counts[entry.category] += 1

    category_breakdown = {}
    for cat_id, total in category_totals.items():
        cat_info = EXPENSE_CATEGORIES.get(cat_id, {})
        category_breakdown[cat_id] = {
            "name": cat_info.get("name", cat_id),
            "icon": cat_info.get("icon", "📋"),
            "total": round(total, 2),
            "percentage": round(total / total_spent * 100, 1) if total_spent > 0 else 0,
            "count": category_counts[cat_id],
            "average": round(total / category_counts[cat_id]) if category_counts[cat_id] > 0 else 0,
        }

    # ─── Daily and monthly averages ───────────────────────────────
    date_range_days = 30
    if entries:
        dates = [e.date for e in entries if e.date]
        if len(dates) >= 2:
            date_range_days = max(1, (max(dates) - min(dates)).days)

    daily_average = total_spent / max(1, date_range_days)
    monthly_average = daily_average * 30

    # ─── Top expenses ─────────────────────────────────────────────
    non_income = [e for e in entries if not e.is_income]
    top_expenses = sorted(non_income, key=lambda e: e.amount, reverse=True)[:10]
    top_expenses_list = [
        {"amount": e.amount, "description": e.description, "category": e.category, "date": e.date.isoformat() if e.date else None}
        for e in top_expenses
    ]

    # ─── Run analysis engines ─────────────────────────────────────
    anomalies = _anomaly_detector.detect(entries, monthly_income)
    trend_data = _trend_analyzer.analyze(entries)
    savings = _savings_finder.find_opportunities(entries, monthly_income)

    # ─── Budget ───────────────────────────────────────────────────
    if monthly_income > 0:
        budget = _budget_engine.create_budget(monthly_income)
        budget_status = _budget_engine.check_budget_status(budget, entries)
    else:
        budget = None
        budget_status = None

    # ─── Savings rate ─────────────────────────────────────────────
    net_savings = total_income - total_spent
    savings_rate = (net_savings / total_income * 100) if total_income > 0 else 0

    # ─── Health score ─────────────────────────────────────────────
    health_score = 50
    if savings_rate > 30:
        health_score += 20
    elif savings_rate > 20:
        health_score += 15
    elif savings_rate > 10:
        health_score += 10
    elif savings_rate > 0:
        health_score += 5
    else:
        health_score -= 20

    if len(anomalies) == 0:
        health_score += 10
    elif len(anomalies) > 3:
        health_score -= 10

    if trend_data.get("trend") == "decreasing":
        health_score += 10
    elif trend_data.get("trend") == "increasing":
        health_score -= 10

    health_score = max(0, min(100, health_score))

    if health_score >= 80:
        grade = "A+"
    elif health_score >= 70:
        grade = "A"
    elif health_score >= 60:
        grade = "B+"
    elif health_score >= 50:
        grade = "B"
    elif health_score >= 35:
        grade = "C"
    else:
        grade = "D"

    # ─── Build insights ───────────────────────────────────────────
    insights = []
    insights.extend(trend_data.get("insights", []))
    if savings_rate < 10 and monthly_income > 0:
        insights.append({
            "type": "savings_rate",
            "severity": "warning",
            "message": f"Your savings rate is {savings_rate:.1f}%. Aim for at least 20% for long-term financial health."
        })

    return {
        "health_score": health_score,
        "health_grade": grade,
        "total_spent": round(total_spent, 2),
        "total_income": round(total_income, 2),
        "net_savings": round(net_savings, 2),
        "savings_rate": round(savings_rate, 1),
        "category_breakdown": category_breakdown,
        "daily_average": round(daily_average),
        "monthly_average": round(monthly_average),
        "top_expenses": top_expenses_list,
        "anomalies": anomalies,
        "budget": budget,
        "budget_status": budget_status,
        "trends": trend_data,
        "savings_opportunities": savings,
        "insights": insights,
        "expense_count": len(entries),
        "date_range_days": date_range_days,
    }
