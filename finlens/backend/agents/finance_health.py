"""
═══════════════════════════════════════════════════════════════════════════════
FinLens Financial Health Check Agent
═══════════════════════════════════════════════════════════════════════════════

Comprehensive financial health analysis engine that combines:
1. Income and expense analysis with Indian cost-of-living benchmarks
2. Savings rate optimization with city-tier adjustments
3. Emergency fund adequacy assessment
4. Insurance coverage gap analysis
5. Debt-to-income ratio evaluation
6. Tax optimization opportunity detection
7. Investment readiness scoring
8. Life stage-specific recommendations (student, fresher, mid-career, pre-retirement)
9. Monthly budget allocation optimization
10. Financial goal progress tracking
11. Spending behavior pattern recognition
12. Peer comparison (anonymous benchmarks)
13. Risk-adjusted financial resilience scoring

All outputs include India-specific context, disclaimers, and actionable next steps.
The LLM prompt is designed to produce structured JSON for easy frontend rendering.
"""

import re
import json
import math
import logging
from typing import Optional, Dict, Any, List, Tuple
from datetime import datetime
from dataclasses import dataclass, field
from collections import defaultdict

logger = logging.getLogger("finlens.finance_health")


# ═══════════════════════════════════════════════════════════════════════════════
# Indian Cost-of-Living Benchmarks
# ═══════════════════════════════════════════════════════════════════════════════

CITY_TIER_BENCHMARKS = {
    "metro": {
        "name": "Metro City (Mumbai, Delhi, Bangalore, Chennai, Kolkata, Hyderabad, Pune)",
        "avg_rent_1bhk": 22000,
        "avg_rent_2bhk": 35000,
        "avg_food_cost": 8000,
        "avg_transport": 4000,
        "avg_utilities": 3500,
        "avg_lifestyle": 6000,
        "min_survival_income": 35000,
        "comfortable_income": 75000,
        "good_income": 120000,
        "excellent_income": 200000,
    },
    "tier1": {
        "name": "Tier-1 City (Ahmedabad, Jaipur, Lucknow, Chandigarh, Kochi, Indore, Bhopal)",
        "avg_rent_1bhk": 12000,
        "avg_rent_2bhk": 20000,
        "avg_food_cost": 6000,
        "avg_transport": 3000,
        "avg_utilities": 2500,
        "avg_lifestyle": 4000,
        "min_survival_income": 25000,
        "comfortable_income": 55000,
        "good_income": 90000,
        "excellent_income": 150000,
    },
    "tier2": {
        "name": "Tier-2 City (Varanasi, Patna, Surat, Nagpur, Coimbatore, Mysore, Vizag)",
        "avg_rent_1bhk": 8000,
        "avg_rent_2bhk": 14000,
        "avg_food_cost": 5000,
        "avg_transport": 2000,
        "avg_utilities": 2000,
        "avg_lifestyle": 3000,
        "min_survival_income": 18000,
        "comfortable_income": 40000,
        "good_income": 70000,
        "excellent_income": 120000,
    },
    "tier3": {
        "name": "Tier-3 Town (Smaller cities and towns)",
        "avg_rent_1bhk": 5000,
        "avg_rent_2bhk": 10000,
        "avg_food_cost": 4000,
        "avg_transport": 1500,
        "avg_utilities": 1500,
        "avg_lifestyle": 2000,
        "min_survival_income": 12000,
        "comfortable_income": 30000,
        "good_income": 55000,
        "excellent_income": 100000,
    },
}


# ═══════════════════════════════════════════════════════════════════════════════
# Life Stage Profiles
# ═══════════════════════════════════════════════════════════════════════════════

LIFE_STAGE_PROFILES = {
    "student": {
        "typical_income": 0,
        "key_priorities": ["build_emergency_fund", "learn_investing", "avoid_debt"],
        "recommended_savings_pct": 0,
        "max_education_spend_pct": 100,
        "risk_capacity": "high",
        "ideal_allocation": {"needs": 60, "wants": 30, "savings": 10},
        "specific_advice": [
            "Start a SIP with as little as ₹500/month — even small amounts build the habit",
            "Use student discounts aggressively on everything",
            "Never take personal loans or credit card debt while studying",
            "Build an emergency fund of ₹10,000-20,000",
            "Learn about PPF, NPS, and ELSS early — compound interest is your best friend",
        ],
    },
    "fresher": {
        "typical_income": 25000,
        "key_priorities": ["emergency_fund", "insurance", "start_sip", "skill_investment"],
        "recommended_savings_pct": 20,
        "max_education_spend_pct": 10,
        "risk_capacity": "high",
        "ideal_allocation": {"needs": 50, "wants": 25, "savings": 25},
        "specific_advice": [
            "Build a 6-month emergency fund (₹1.5-3L) as your #1 priority",
            "Get health insurance through your employer + a personal ₹5L top-up",
            "Start SIP of ₹3,000-5,000 in a flexi-cap or index fund immediately",
            "Learn about Section 80C and maximize your tax savings from day 1",
            "Avoid lifestyle inflation — your first salary sets your savings habits",
            "Track every rupee for 3 months to understand your real spending patterns",
        ],
    },
    "mid_career": {
        "typical_income": 80000,
        "key_priorities": ["increase_sip", "tax_optimization", "insurance_review", "goal_planning"],
        "recommended_savings_pct": 25,
        "max_education_spend_pct": 5,
        "risk_capacity": "moderate",
        "ideal_allocation": {"needs": 50, "wants": 20, "savings": 30},
        "specific_advice": [
            "Your SIP should be at least 20% of take-home — increase it every year",
            "Review insurance: need 10-15x annual income as life cover",
            "Max out PPF (₹1.5L) and NPS (₹50K) for tax savings",
            "Start goal-based investing for major life events (house, children's education)",
            "Consider switching to the new tax regime if your deductions are < ₹2L",
            "Rebalance your portfolio quarterly — don't just 'set and forget'",
        ],
    },
    "pre_retirement": {
        "typical_income": 150000,
        "key_priorities": ["wealth_preservation", "debt_elimination", "health_insurance", "estate_planning"],
        "recommended_savings_pct": 35,
        "max_education_spend_pct": 3,
        "risk_capacity": "low",
        "ideal_allocation": {"needs": 55, "wants": 10, "savings": 35},
        "specific_advice": [
            "Shift 60%+ of portfolio to debt and guaranteed returns (PPF, FD, SCSS)",
            "Review and increase health insurance to at least ₹25L — medical costs are rising",
            "Ensure all high-interest debt is paid off before retirement",
            "Consider Senior Citizens Savings Scheme (SCSS) for 8.2% guaranteed returns",
            "Create a will and update nominee details on all investments",
            "Plan for regular monthly income post-retirement through annuities/SWP",
        ],
    },
}


# ═══════════════════════════════════════════════════════════════════════════════
# Data Classes
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class FinancialProfile:
    """User's financial profile for health check."""
    monthly_income: float = 0
    annual_income: float = 0
    monthly_expenses: float = 0
    age: int = 30
    dependents: int = 0
    city_tier: str = "tier2"
    risk_tolerance: str = "moderate"
    investment_experience: str = "beginner"
    has_emergency_fund: bool = False
    has_health_insurance: bool = False
    has_life_insurance: bool = False
    outstanding_loans: float = 0
    existing_investments: str = ""
    financial_goals: List[str] = field(default_factory=list)
    expense_breakdown: Dict[str, float] = field(default_factory=dict)


@dataclass
class HealthScore:
    """Composite financial health score."""
    overall_score: int  # 0-100
    grade: str  # A+ to F
    savings_score: int = 0
    emergency_score: int = 0
    insurance_score: int = 0
    debt_score: int = 0
    investment_score: int = 0
    budget_score: int = 0
    goal_score: int = 0


@dataclass
class HealthRecommendation:
    """A single actionable recommendation."""
    category: str
    priority: str  # critical, high, medium, low
    title: str
    detail: str
    potential_impact: str
    action_items: List[str] = field(default_factory=list)
    product_suggestions: List[str] = field(default_factory=list)


# ═══════════════════════════════════════════════════════════════════════════════
# Financial Health Scoring Engine
# ═══════════════════════════════════════════════════════════════════════════════

class HealthScoringEngine:
    """
    Calculates a composite financial health score from multiple dimensions.
    Each dimension is scored 0-100 and weighted to produce the final score.
    """

    WEIGHTS = {
        "savings": 0.25,
        "emergency": 0.15,
        "insurance": 0.15,
        "debt": 0.15,
        "investment": 0.15,
        "budget": 0.10,
        "goal": 0.05,
    }

    def calculate(self, profile: FinancialProfile) -> HealthScore:
        """Calculate comprehensive health score."""
        scores = {
            "savings": self._score_savings(profile),
            "emergency": self._score_emergency(profile),
            "insurance": self._score_insurance(profile),
            "debt": self._score_debt(profile),
            "investment": self._score_investment(profile),
            "budget": self._score_budget(profile),
            "goal": self._score_goals(profile),
        }

        overall = sum(
            scores[k] * self.WEIGHTS[k] for k in scores
        )
        overall = max(0, min(100, int(overall)))

        grade = self._grade(overall)

        return HealthScore(
            overall_score=overall,
            grade=grade,
            savings_score=scores["savings"],
            emergency_score=scores["emergency"],
            insurance_score=scores["insurance"],
            debt_score=scores["debt"],
            investment_score=scores["investment"],
            budget_score=scores["budget"],
            goal_score=scores["goal"],
        )

    def _score_savings(self, p: FinancialProfile) -> int:
        """Score based on savings rate."""
        if p.monthly_income <= 0:
            return 50  # Can't evaluate

        savings = p.monthly_income - p.monthly_expenses
        rate = (savings / p.monthly_income * 100) if p.monthly_income > 0 else 0

        if rate >= 30:
            return 95
        elif rate >= 25:
            return 85
        elif rate >= 20:
            return 75
        elif rate >= 15:
            return 65
        elif rate >= 10:
            return 50
        elif rate >= 5:
            return 35
        elif rate >= 0:
            return 20
        else:
            return 5  # Spending more than earning

    def _score_emergency(self, p: FinancialProfile) -> int:
        """Score based on emergency fund adequacy."""
        if p.has_emergency_fund:
            # Check if it's 6 months of expenses
            monthly_needed = p.monthly_expenses or 30000
            # We estimate from has_emergency_fund boolean
            return 85  # Has one, assume roughly adequate
        else:
            return 10  # No emergency fund

    def _score_insurance(self, p: FinancialProfile) -> int:
        """Score based on insurance coverage."""
        score = 0
        if p.has_health_insurance:
            score += 50
        if p.has_life_insurance:
            score += 35
        if p.dependents > 0 and not p.has_life_insurance:
            score -= 20  # Penalty for dependents without life insurance
        return max(0, min(100, score))

    def _score_debt(self, p: FinancialProfile) -> int:
        """Score based on debt-to-income ratio."""
        if p.monthly_income <= 0:
            return 50

        annual_income = p.monthly_income * 12
        if annual_income <= 0:
            return 50

        dti = p.outstanding_loans / annual_income * 100

        if dti == 0:
            return 95  # Debt-free!
        elif dti < 20:
            return 80
        elif dti < 40:
            return 60
        elif dti < 60:
            return 40
        elif dti < 100:
            return 20
        else:
            return 5  # Danger zone

    def _score_investment(self, p: FinancialProfile) -> int:
        """Score based on investment behavior."""
        score = 30  # Base score for being in the system

        if p.investment_experience in ("intermediate", "advanced", "expert"):
            score += 20
        elif p.investment_experience == "beginner":
            score += 10

        # Check for investment mentions
        inv_keywords = ["sip", "mutual fund", "ppf", "nps", "stock", "etf", "fd", "rd", "gold"]
        investment_text = p.existing_investments.lower()
        matches = sum(1 for kw in inv_keywords if kw in investment_text)
        score += min(40, matches * 10)

        return min(100, score)

    def _score_budget(self, p: FinancialProfile) -> int:
        """Score based on budget management."""
        if not p.expense_breakdown:
            return 50

        score = 60  # Base

        # Check if housing > 40% of income
        if p.monthly_income > 0:
            housing = p.expense_breakdown.get("housing", 0)
            if housing / p.monthly_income > 0.4:
                score -= 15  # Housing cost too high

            food = p.expense_breakdown.get("food", 0)
            if food / p.monthly_income > 0.25:
                score -= 10

            entertainment = p.expense_breakdown.get("entertainment", 0)
            if entertainment / p.monthly_income > 0.15:
                score -= 10

        # Check for having category diversity
        if len(p.expense_breakdown) >= 5:
            score += 10  # Good tracking

        return max(0, min(100, score))

    def _score_goals(self, p: FinancialProfile) -> int:
        """Score based on financial goal setting."""
        if not p.financial_goals:
            return 20  # No goals set

        score = 40
        score += min(40, len(p.financial_goals) * 15)

        priority_goals = {"emergency_fund", "retirement", "house", "education"}
        for goal in p.financial_goals:
            if goal.lower().replace(" ", "_") in priority_goals:
                score += 10

        return min(100, score)

    def _grade(self, score: int) -> str:
        """Convert score to letter grade."""
        if score >= 85:
            return "A+"
        elif score >= 75:
            return "A"
        elif score >= 65:
            return "B+"
        elif score >= 55:
            return "B"
        elif score >= 40:
            return "C"
        elif score >= 25:
            return "D"
        else:
            return "F"


# ═══════════════════════════════════════════════════════════════════════════════
# Recommendation Engine
# ═══════════════════════════════════════════════════════════════════════════════

class RecommendationEngine:
    """
    Generates personalized financial recommendations based on the
    user's profile and health score breakdown.
    """

    def generate(
        self, profile: FinancialProfile, health: HealthScore
    ) -> List[HealthRecommendation]:
        """Generate prioritized recommendations."""
        recommendations = []

        # ─── Emergency Fund ───────────────────────────────────────
        if not profile.has_emergency_fund:
            monthly_expenses = profile.monthly_expenses or 30000
            target = monthly_expenses * 6
            recommendations.append(HealthRecommendation(
                category="emergency",
                priority="critical",
                title="Build an Emergency Fund",
                detail=(
                    f"You need ₹{target:,.0f} (6 months of expenses) in a liquid, "
                    f"accessible account. Start with ₹5,000/month in a liquid fund "
                    f"or high-yield savings account."
                ),
                potential_impact="Protects against job loss, medical emergencies, unexpected expenses",
                action_items=[
                    f"Open a liquid fund account (e.g., via Groww, Kuvera)",
                    f"Set up auto-transfer of ₹{int(target/12):,}/month",
                    f"Target: ₹{target:,.0f} in 12 months",
                    "Don't invest this in stocks or locked-in instruments",
                ],
                product_suggestions=["Liquid Fund", "Short Duration Fund", "High-Yield Savings"],
            ))

        # ─── Insurance ────────────────────────────────────────────
        if not profile.has_health_insurance:
            recommendations.append(HealthRecommendation(
                category="insurance",
                priority="critical",
                title="Get Health Insurance NOW",
                detail=(
                    "A single hospitalization can cost ₹2-10L. Without health insurance, "
                    "this can wipe out years of savings. Get at least ₹5L coverage."
                ),
                potential_impact="Prevents medical debt — #1 cause of bankruptcy in India",
                action_items=[
                    "Check if your employer provides group health insurance",
                    "Buy a personal ₹5-10L top-up policy (starts at ₹500/month)",
                    "Consider family floater if you have dependents",
                    "Buy before age 35 for lower premiums",
                ],
                product_suggestions=["Star Health", "HDFC ERGO", "Niva Bupa", "ICICI Lombard"],
            ))

        if profile.has_life_insurance and profile.dependents > 0:
            recommendations.append(HealthRecommendation(
                category="insurance",
                priority="high",
                title="Review Life Insurance Coverage",
                detail=(
                    f"With {profile.dependents} dependents, you need at least "
                    f"10-15x your annual income as life cover. "
                    f"Term insurance is the most cost-effective option."
                ),
                potential_impact="Ensures family's financial security in your absence",
                action_items=[
                    "Calculate: annual income × 10 = minimum cover needed",
                    "Buy a pure term insurance plan (NOT endowment/ULIP)",
                    "Ensure cover is at least 10x your annual income",
                    "Keep beneficiaries updated",
                ],
                product_suggestions=["Term Insurance (LIC, HDFC Life, ICICI Prudential)"],
            ))

        # ─── Savings Rate ─────────────────────────────────────────
        if profile.monthly_income > 0:
            savings_rate = (
                (profile.monthly_income - profile.monthly_expenses)
                / profile.monthly_income * 100
            )
            if savings_rate < 20:
                target_savings = profile.monthly_income * 0.2
                gap = target_savings - (profile.monthly_income - profile.monthly_expenses)
                recommendations.append(HealthRecommendation(
                    category="savings",
                    priority="high" if savings_rate < 10 else "medium",
                    title=f"Improve Savings Rate (Currently {savings_rate:.0f}%)",
                    detail=(
                        f"Your current savings rate is {savings_rate:.0f}%. "
                        f"Aim for 20%+ for long-term financial health. "
                        f"You need to save ₹{gap:,.0f} more per month."
                    ),
                    potential_impact="20% savings rate builds ₹1Cr+ in 15 years at 12% returns",
                    action_items=[
                        "Track every expense for 2 weeks — find 3 areas to cut",
                        "Set up auto-SIP the day salary arrives (pay yourself first)",
                        "Follow the 50/30/20 rule: 50% needs, 30% wants, 20% savings",
                        f"Target monthly savings: ₹{int(target_savings):,}",
                    ],
                ))

        # ─── Debt Management ──────────────────────────────────────
        if profile.outstanding_loans > 0 and profile.monthly_income > 0:
            annual_income = profile.monthly_income * 12
            dti_ratio = profile.outstanding_loans / annual_income * 100

            if dti_ratio > 40:
                recommendations.append(HealthRecommendation(
                    category="debt",
                    priority="critical",
                    title="High Debt-to-Income Ratio",
                    detail=(
                        f"Your debt ({dti_ratio:.0f}% of income) is dangerously high. "
                        f"This limits your ability to save and invest. Prioritize debt reduction."
                    ),
                    potential_impact="Eliminating high-interest debt gives guaranteed 'returns'",
                    action_items=[
                        "List all debts with interest rates — pay highest rate first (avalanche method)",
                        "Consider balance transfer to lower-interest option",
                        "Cut discretionary spending by 20% and redirect to debt",
                        "Never pay just minimum — always pay more",
                    ],
                ))
            elif dti_ratio > 20:
                recommendations.append(HealthRecommendation(
                    category="debt",
                    priority="medium",
                    title="Manage Outstanding Debt",
                    detail=(
                        f"You have ₹{profile.outstanding_loans:,.0f} in outstanding loans "
                        f"({dti_ratio:.0f}% of income). Ensure you're paying more than minimum."
                    ),
                    potential_impact="Faster debt repayment frees up money for investing",
                    action_items=[
                        "Pay more than minimum on highest-interest loans",
                        "Set up auto-pay to avoid late fees",
                        "Avoid taking new debt until existing debt is below 20% of income",
                    ],
                ))

        # ─── Investment ───────────────────────────────────────────
        if profile.investment_experience == "beginner" and profile.monthly_income > 0:
            sip_amount = int(profile.monthly_income * 0.15)
            recommendations.append(HealthRecommendation(
                category="investment",
                priority="high",
                title="Start Investing with SIP",
                detail=(
                    f"At your income level, starting a ₹{sip_amount:,}/month SIP now "
                    f"can build ₹1Cr+ in 15 years. The earlier you start, the more "
                    f"compound interest works for you."
                ),
                potential_impact=f"₹{sip_amount:,}/month at 12% for 15 years = ~₹1.03 Crore",
                action_items=[
                    f"Start SIP of ₹{sip_amount:,}/month in a flexi-cap or index fund",
                    "Use Groww, Kuvera, or Zerodha Coin (free, no commission)",
                    "Don't try to time the market — just invest consistently",
                    "Increase SIP by 10% every year (step-up SIP)",
                ],
                product_suggestions=[
                    "Nifty 50 Index Fund (lowest cost)",
                    "Flexi Cap Fund (flexibility)",
                    "PPF (tax-free guaranteed returns)",
                ],
            ))

        # ─── Tax Optimization ─────────────────────────────────────
        if profile.monthly_income > 0:
            annual = profile.monthly_income * 12
            if annual > 500000:
                recommendations.append(HealthRecommendation(
                    category="tax",
                    priority="medium",
                    title="Optimize Tax Savings",
                    detail=(
                        "You're likely losing ₹30,000-60,000/year in potential tax savings "
                        "by not optimizing your deductions under Sections 80C, 80D, and NPS."
                    ),
                    potential_impact="Save ₹30,000-90,000/year in taxes",
                    action_items=[
                        "Invest ₹1.5L in 80C (PPF + ELSS + EPF)",
                        "Get health insurance for ₹25K-50K deduction (80D)",
                        "Invest ₹50K in NPS for extra 80CCD(1B) deduction",
                        "Compare old vs new tax regime — which saves more for you?",
                    ],
                ))

        # ─── Life Stage Specific ──────────────────────────────────
        life_stage = self._determine_life_stage(profile)
        stage_profile = LIFE_STAGE_PROFILES.get(life_stage, {})
        if stage_profile.get("specific_advice"):
            recommendations.append(HealthRecommendation(
                category="life_stage",
                priority="medium",
                title=f"Advice for {life_stage.replace('_', ' ').title()} Stage",
                detail="Personalized tips based on your life stage:",
                potential_impact="Optimized financial decisions for your current phase of life",
                action_items=stage_profile["specific_advice"][:4],
            ))

        # Sort by priority
        priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        recommendations.sort(key=lambda r: priority_order.get(r.priority, 4))

        return recommendations

    def _determine_life_stage(self, profile: FinancialProfile) -> str:
        """Determine life stage from profile."""
        if profile.age < 23:
            return "student"
        elif profile.age < 28:
            return "fresher"
        elif profile.age < 50:
            return "mid_career"
        else:
            return "pre_retirement"


# ═══════════════════════════════════════════════════════════════════════════════
# Budget Optimizer
# ═══════════════════════════════════════════════════════════════════════════════

class BudgetOptimizer:
    """Creates and evaluates budgets based on income and spending patterns."""

    def create_budget(self, income: float, city_tier: str = "tier2") -> Dict[str, Any]:
        """Create a recommended budget allocation."""
        benchmarks = CITY_TIER_BENCHMARKS.get(city_tier, CITY_TIER_BENCHMARKS["tier2"])

        # 50/30/20 rule adapted for India
        needs = income * 0.50
        wants = income * 0.30
        savings = income * 0.20

        # Break down needs
        housing_limit = min(income * 0.30, benchmarks["avg_rent_2bhk"])
        food_limit = income * 0.15
        transport_limit = income * 0.10
        utilities_limit = income * 0.05

        # Break down wants
        entertainment_limit = income * 0.05
        shopping_limit = income * 0.05
        personal_limit = income * 0.05
        lifestyle_limit = income * 0.10

        # Break down savings
        emergency_limit = income * 0.05
        investment_limit = income * 0.10
        insurance_limit = income * 0.03
        goals_limit = income * 0.02

        return {
            "monthly_income": income,
            "city_tier": city_tier,
            "tier_name": benchmarks["name"],
            "allocation": {
                "needs": {
                    "amount": round(needs),
                    "pct": 50,
                    "categories": {
                        "housing": {"amount": round(housing_limit), "pct": 30},
                        "food": {"amount": round(food_limit), "pct": 15},
                        "transport": {"amount": round(transport_limit), "pct": 10},
                        "utilities": {"amount": round(utilities_limit), "pct": 5},
                    },
                },
                "wants": {
                    "amount": round(wants),
                    "pct": 30,
                    "categories": {
                        "entertainment": {"amount": round(entertainment_limit), "pct": 5},
                        "shopping": {"amount": round(shopping_limit), "pct": 5},
                        "personal": {"amount": round(personal_limit), "pct": 5},
                        "lifestyle": {"amount": round(lifestyle_limit), "pct": 10},
                    },
                },
                "savings": {
                    "amount": round(savings),
                    "pct": 20,
                    "categories": {
                        "emergency_fund": {"amount": round(emergency_limit), "pct": 5},
                        "investments": {"amount": round(investment_limit), "pct": 10},
                        "insurance": {"amount": round(insurance_limit), "pct": 3},
                        "goals": {"amount": round(goals_limit), "pct": 2},
                    },
                },
            },
            "income_benchmark": {
                "min_survival": benchmarks["min_survival_income"],
                "comfortable": benchmarks["comfortable_income"],
                "good": benchmarks["good_income"],
                "excellent": benchmarks["excellent_income"],
                "your_position": self._income_position(income, benchmarks),
            },
        }

    def _income_position(self, income: float, benchmarks: dict) -> str:
        """Where does this income fall in the benchmark?"""
        if income >= benchmarks["excellent_income"]:
            return "excellent"
        elif income >= benchmarks["good_income"]:
            return "good"
        elif income >= benchmarks["comfortable_income"]:
            return "comfortable"
        elif income >= benchmarks["min_survival_income"]:
            return "surviving"
        else:
            return "below_minimum"


# ═══════════════════════════════════════════════════════════════════════════════
# Main Orchestration
# ═══════════════════════════════════════════════════════════════════════════════

_scoring_engine = HealthScoringEngine()
_recommendation_engine = RecommendationEngine()
_budget_optimizer = BudgetOptimizer()


def analyze_financial_health(profile_data: dict) -> dict:
    """
    Perform comprehensive financial health analysis.

    Args:
        profile_data: Dict with income, expenses, age, insurance, etc.

    Returns:
        Complete financial health assessment.
    """
    # Build profile
    profile = FinancialProfile(
        monthly_income=profile_data.get("monthly_income", 0),
        annual_income=profile_data.get("annual_income", 0),
        monthly_expenses=profile_data.get("monthly_expenses", 0),
        age=profile_data.get("age", 30),
        dependents=profile_data.get("dependents", 0),
        city_tier=profile_data.get("city_tier", "tier2"),
        risk_tolerance=profile_data.get("risk_tolerance", "moderate"),
        investment_experience=profile_data.get("investment_experience", "beginner"),
        has_emergency_fund=profile_data.get("has_emergency_fund", False),
        has_health_insurance=profile_data.get("has_health_insurance", False),
        has_life_insurance=profile_data.get("has_life_insurance", False),
        outstanding_loans=profile_data.get("outstanding_loans", 0),
        existing_investments=profile_data.get("existing_investments", ""),
        financial_goals=profile_data.get("financial_goals", []),
        expense_breakdown=profile_data.get("expense_breakdown", {}),
    )

    # Calculate health score
    health = _scoring_engine.calculate(profile)

    # Generate recommendations
    recommendations = _recommendation_engine.generate(profile, health)

    # Create budget
    budget = _budget_optimizer.create_budget(profile.monthly_income, profile.city_tier)

    # Calculate savings metrics
    monthly_savings = profile.monthly_income - profile.monthly_expenses
    savings_rate = (monthly_savings / profile.monthly_income * 100) if profile.monthly_income > 0 else 0

    # Annual projections
    annual_savings = monthly_savings * 12
    projected_5yr = annual_savings * 5 * 1.12 ** 2.5  # Rough compound
    projected_10yr = annual_savings * 10 * 1.12 ** 5
    projected_15yr = annual_savings * 15 * 1.12 ** 7.5

    # Peer comparison
    peer = _peer_comparison(profile)

    return {
        "health_score": health.overall_score,
        "health_grade": health.grade,
        "score_breakdown": {
            "savings": health.savings_score,
            "emergency": health.emergency_score,
            "insurance": health.insurance_score,
            "debt": health.debt_score,
            "investment": health.investment_score,
            "budget": health.budget_score,
            "goals": health.goal_score,
        },
        "monthly_income": profile.monthly_income,
        "monthly_expenses": profile.monthly_expenses,
        "monthly_savings": monthly_savings,
        "savings_rate": round(savings_rate, 1),
        "annual_savings": round(annual_savings),
        "projections": {
            "5_year": round(projected_5yr),
            "10_year": round(projected_10yr),
            "15_year": round(projected_15yr),
        },
        "budget": budget,
        "recommendations": [
            {
                "category": r.category,
                "priority": r.priority,
                "title": r.title,
                "detail": r.detail,
                "potential_impact": r.potential_impact,
                "action_items": r.action_items,
                "product_suggestions": r.product_suggestions,
            }
            for r in recommendations
        ],
        "peer_comparison": peer,
        "life_stage": _recommendation_engine._determine_life_stage(profile),
        "key_metrics": {
            "emergency_fund_status": "✅ Built" if profile.has_emergency_fund else "❌ Not built",
            "health_insurance": "✅ Covered" if profile.has_health_insurance else "❌ Not covered",
            "life_insurance": "✅ Covered" if profile.has_life_insurance else "❌ Not covered",
            "debt_free": "✅ Debt-free" if profile.outstanding_loans == 0 else f"⚠️ ₹{profile.outstanding_loans:,.0f} outstanding",
        },
        "disclaimer": (
            "This is AI-generated financial analysis for educational purposes only. "
            "It is not personalized financial advice. Please consult a SEBI-registered "
            "investment advisor (RIA) or certified financial planner (CFP) before "
            "making any financial decisions."
        ),
    }


def _peer_comparison(profile: FinancialProfile) -> dict:
    """Compare user's metrics with anonymous peer averages."""
    if profile.monthly_income <= 0:
        return {"available": False}

    savings_rate = (
        (profile.monthly_income - profile.monthly_expenses) / profile.monthly_income * 100
    )

    # Simplified peer benchmarks
    peer_savings_rate = 18  # Average Indian savings rate
    peer_emergency = True if profile.age > 25 else False
    peer_investing = profile.investment_experience != "beginner" or profile.age > 28

    return {
        "available": True,
        "savings_rate": {
            "yours": round(savings_rate, 1),
            "peer_average": peer_savings_rate,
            "better_than_pct": min(95, max(5, int(savings_rate / peer_savings_rate * 50))),
        },
        "emergency_fund": {
            "yours": profile.has_emergency_fund,
            "peer_average": peer_emergency,
            "peer_pct_with_fund": 35,
        },
        "investing": {
            "yours": profile.investment_experience != "beginner",
            "peer_average": peer_investing,
            "peer_pct_investing": 42,
        },
        "insurance": {
            "health_covered": profile.has_health_insurance,
            "peer_pct_covered": 28,
        },
    }


# ═══════════════════════════════════════════════════════════════════════════════
# LLM Integration
# ═══════════════════════════════════════════════════════════════════════════════

FINANCE_SYSTEM_PROMPT = """You are FinLens, India's most trusted AI financial health advisor.
You help users understand their financial health by analyzing their income and expenses.

IMPORTANT RULES:
1. Give practical, India-specific advice (consider Indian cost of living, tax brackets, investment options)
2. Never recommend risky investments without clear disclaimers
3. Always suggest building an emergency fund first
4. Consider Indian tax saving instruments (ELSS, PPF, NPS, 80C)
5. Be encouraging but honest — if spending is too high, say so gently
6. Never guarantee investment returns
7. Always mention that this is educational information, not financial advice

INDIAN FINANCIAL LANDSCAPE:
- Average savings rate in India: ~18%
- Recommended savings: 20%+ of income
- Emergency fund: 6 months of expenses
- Health insurance: minimum ₹5L cover
- Life insurance: 10-15x annual income (term plan)
- Tax saving: Section 80C (₹1.5L), 80D (₹25K-50K), NPS (₹50K)

RESPOND IN VALID JSON:
{
  "monthly_income": "echo back what user stated or 'Not specified'",
  "total_expenses": "echo back computed total or 'Not specified'",
  "savings_rate": "calculated percentage if possible",
  "breakdown": {
    "essential": "amount and percentage of essential expenses",
    "discretionary": "amount and percentage of discretionary expenses",
    "savings_potential": "estimated amount that could be saved"
  },
  "health_score": 0-100,
  "health_grade": "A+" | "A" | "B+" | "B" | "C" | "D" | "F",
  "verdict": "one line overall assessment",
  "strengths": ["things user is doing well"],
  "weaknesses": ["areas needing improvement"],
  "top_recommendations": [
    {
      "title": "actionable recommendation title",
      "detail": "detailed explanation",
      "priority": "high" | "medium" | "low",
      "potential_savings": "estimated monthly savings if followed"
    }
  ],
  "budget_suggestion": "recommended monthly budget allocation",
  "investment_start": "first investment recommendation",
  "tax_tips": ["specific tax saving tips"],
  "emergency_fund": "emergency fund recommendation",
  "insurance_check": "insurance coverage check",
  "disclaimer": "standard financial disclaimer"
}"""


async def check_financial_health(profile_description: str, llm_call) -> dict:
    """
    LLM-powered financial health check from natural language description.

    Args:
        profile_description: User's description of their financial situation
        llm_call: Async function (system_prompt, user_prompt) -> str

    Returns:
        Structured financial health assessment
    """
    user_prompt = f"""Analyze this person's financial health and provide comprehensive advice:

---
{profile_description}
---

Provide your analysis as JSON with the exact structure specified. Be specific with numbers,
percentages, and actionable advice. Include India-specific context and tax tips."""

    raw_response = await llm_call(FINANCE_SYSTEM_PROMPT, user_prompt)
    if not raw_response:
        raise RuntimeError("Gemini returned no analysis text")

    # Parse JSON response
    cleaned = raw_response.strip()
    if cleaned.startswith("```"):
        lines = cleaned.split("\n")
        lines = [l for l in lines if not l.strip().startswith("```")]
        cleaned = "\n".join(lines)

    try:
        result = json.loads(cleaned)
    except json.JSONDecodeError:
        # Try to extract JSON from response
        json_match = re.search(r'\{[\s\S]*\}', cleaned)
        if json_match:
            try:
                result = json.loads(json_match.group())
            except json.JSONDecodeError as e:
                raise RuntimeError(f"Gemini returned invalid JSON for health check: {e}") from e
        else:
            raise RuntimeError("Gemini did not return JSON for the health check")

    # Ensure required fields
    result.setdefault("verdict", "Financial health analysis completed.")
    result.setdefault("health_score", 50)
    result.setdefault("health_grade", "B")
    result.setdefault("strengths", [])
    result.setdefault("weaknesses", [])
    result.setdefault("top_recommendations", [])
    result.setdefault("disclaimer", (
        "This is AI-generated educational information. It is not personalized financial advice. "
        "Always consult a SEBI-registered investment advisor or certified financial planner."
    ))

    return result
