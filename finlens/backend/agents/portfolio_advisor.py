"""
═══════════════════════════════════════════════════════════════════════════════
FinLens Portfolio Advisor Agent
═══════════════════════════════════════════════════════════════════════════════

Comprehensive portfolio analysis and advisory engine covering:
- Current portfolio health assessment
- Asset allocation analysis (equity, debt, gold, alternatives)
- Risk profiling and portfolio risk metrics
- Rebalancing recommendations
- SIP optimization
- Tax-efficient investing suggestions
- Indian market-specific guidance (ELSS, PPF, NPS, SGB)
- Goal-based planning

All advice is India-specific and includes appropriate disclaimers.
"""

import json
import math
import logging
from typing import Optional
from dataclasses import dataclass, field
from datetime import datetime, timedelta

logger = logging.getLogger("finlens.portfolio_advisor")


# ═══════════════════════════════════════════════════════════════════════
# Indian Financial Product Database
# ═══════════════════════════════════════════════════════════════════════

INDIAN_FINANCIAL_PRODUCTS = {
    "equity_mutual_funds": {
        "large_cap": {
            "category": "Large Cap Equity",
            "expected_return": {"min": 10, "max": 16, "avg": 12},
            "risk_level": "moderate",
            "lock_in": "None (exit load: 1% if < 1 year)",
            "tax": "LTCG 12% above ₹1.25L, STCG 20%",
            "min_sip": 500,
            "examples": ["HDFC Large Cap Fund", "ICICI Pru Bluechip", "SBI Bluechip"]
        },
        "mid_cap": {
            "category": "Mid Cap Equity",
            "expected_return": {"min": 12, "max": 22, "avg": 15},
            "risk_level": "high",
            "lock_in": "None (exit load: 1% if < 1 year)",
            "tax": "LTCG 12% above ₹1.25L, STCG 20%",
            "min_sip": 500,
            "examples": ["HDFC Mid-Cap Opportunities", "Kotak Emerging Equity", "Axis Midcap"]
        },
        "small_cap": {
            "category": "Small Cap Equity",
            "expected_return": {"min": 15, "max": 30, "avg": 18},
            "risk_level": "very_high",
            "lock_in": "None (exit load: 1% if < 1 year)",
            "tax": "LTCG 12% above ₹1.25L, STCG 20%",
            "min_sip": 500,
            "examples": ["Nippon India Small Cap", "SBI Small Cap", "Quant Small Cap"]
        },
        "flexi_cap": {
            "category": "Flexi Cap Equity",
            "expected_return": {"min": 11, "max": 18, "avg": 13},
            "risk_level": "moderate_high",
            "lock_in": "None",
            "tax": "LTCG 12% above ₹1.25L, STCG 20%",
            "min_sip": 500,
            "examples": ["Parag Parikh Flexi Cap", "HDFC Flexi Cap", "PGIM India Flexi Cap"]
        },
        "index_fund": {
            "category": "Index Fund",
            "expected_return": {"min": 10, "max": 14, "avg": 12},
            "risk_level": "moderate",
            "lock_in": "None",
            "tax": "LTCG 12% above ₹1.25L, STCG 20%",
            "min_sip": 100,
            "examples": ["UTI Nifty 50 Index", "HDFC Index Fund Sensex", "Motilal Oswal Nifty Next 50"]
        },
        "elss": {
            "category": "ELSS (Tax Saver)",
            "expected_return": {"min": 10, "max": 18, "avg": 14},
            "risk_level": "moderate_high",
            "lock_in": "3 years (mandatory)",
            "tax": "Section 80C deduction up to ₹1.5L. LTCG 12% above ₹1.25L",
            "min_sip": 500,
            "examples": ["Mirae Asset ELSS", "Quant ELSS Tax Saver", "Canara Robeco ELSS"]
        }
    },
    "debt_products": {
        "ppf": {
            "category": "Public Provident Fund",
            "expected_return": {"min": 7.1, "max": 7.1, "avg": 7.1},
            "risk_level": "zero",
            "lock_in": "15 years (partial withdrawal after 7 years)",
            "tax": "EEE (exempt at all three stages)",
            "min_investment": 500,
            "max_investment": 150000,
            "notes": "Government backed, highest safety"
        },
        "fd": {
            "category": "Fixed Deposit",
            "expected_return": {"min": 6.5, "max": 7.5, "avg": 7.0},
            "risk_level": "zero",
            "lock_in": "Flexible (7 days to 10 years)",
            "tax": "Interest taxed at income slab rate. 80C for 5-year FD",
            "min_investment": 1000,
            "notes": "DICGC insured up to ₹5L per bank"
        },
        "nps": {
            "category": "National Pension System",
            "expected_return": {"min": 8, "max": 14, "avg": 10},
            "risk_level": "moderate",
            "lock_in": "Until 60 (partial withdrawal after 3 years)",
            "tax": "80CCD(1B) additional ₹50K deduction. 80CCD(1) up to 10% of salary",
            "min_investment": 1000,
            "notes": "60% tax-free at maturity if used for annuity"
        }
    },
    "alternative_investments": {
        "gold_etf": {
            "category": "Gold ETF / SGB",
            "expected_return": {"min": 8, "max": 14, "avg": 10},
            "risk_level": "low_moderate",
            "lock_in": "None (SGB: 8 years for tax-free gains)",
            "tax": "SGB: Tax-free if held 8 years. Gold ETF: LTCG 12.5% above ₹1.25L",
            "min_investment": 100,
            "notes": "SGBs offer 2.5% annual interest over gold price appreciation"
        },
        "reits": {
            "category": "REITs",
            "expected_return": {"min": 7, "max": 12, "avg": 9},
            "risk_level": "moderate",
            "lock_in": "None (listed on exchange)",
            "tax": "Dividend taxed at slab rate",
            "min_investment": 500,
            "examples": ["Embassy REIT", "Mindspace REIT", "Brookfield REIT"]
        }
    }
}

# Risk profile templates
RISK_PROFILES = {
    "conservative": {
        "equity": 20, "debt": 50, "gold": 15, "cash": 15,
        "description": "Capital preservation focus. Suitable for near-term goals (< 3 years) or low risk tolerance.",
        "recommended_funds": ["PPF", "FD", "Large Cap Index Fund", "Liquid Fund"]
    },
    "moderate": {
        "equity": 50, "debt": 30, "gold": 10, "cash": 10,
        "description": "Balanced approach. Suitable for medium-term goals (3-7 years) with moderate risk tolerance.",
        "recommended_funds": ["Flexi Cap Fund", "PPF", "NPS", "Gold ETF"]
    },
    "aggressive": {
        "equity": 75, "debt": 15, "gold": 5, "cash": 5,
        "description": "Growth focus. Suitable for long-term goals (> 7 years) with high risk tolerance.",
        "recommended_funds": ["Flexi Cap", "Mid Cap", "Small Cap", "PPF"]
    },
    "very_aggressive": {
        "equity": 90, "debt": 5, "gold": 3, "cash": 2,
        "description": "Maximum growth. Only for experienced investors with very long horizons (10+ years).",
        "recommended_funds": ["Mid Cap", "Small Cap", "Sectoral/Thematic"]
    }
}

# Age-based allocation guidelines
AGE_BASED_RULES = {
    "equity_percentage": lambda age: max(20, min(90, 120 - age)),
    "debt_percentage": lambda age: max(5, min(60, age - 10)),
    "emergency_months": lambda age: 6 if age < 30 else (9 if age < 50 else 12),
}


# ═══════════════════════════════════════════════════════════════════════
# Portfolio Analysis Engine
# ═══════════════════════════════════════════════════════════════════════

@dataclass
class PortfolioAnalysis:
    """Complete portfolio analysis result."""
    health_score: int  # 0-100
    health_grade: str
    risk_rating: str
    total_invested: float
    current_value: float
    total_returns: float
    returns_percentage: float
    current_allocation: dict
    recommended_allocation: dict
    allocation_drift: dict
    suggestions: list
    risk_metrics: dict
    tax_optimization: list
    rebalancing_actions: list
    goal_progress: Optional[dict] = None
    monthly_sip_recommendation: Optional[dict] = None


def analyze_portfolio_data(portfolio_data: dict) -> PortfolioAnalysis:
    """
    Analyze portfolio data and produce comprehensive assessment.

    Args:
        portfolio_data: dict with holdings, user profile, goals etc.

    Returns:
        PortfolioAnalysis with complete assessment
    """
    holdings = portfolio_data.get("holdings", [])
    user_profile = portfolio_data.get("user_profile", {})
    risk_tolerance = user_profile.get("risk_tolerance", "moderate")
    age = user_profile.get("age", 30)

    # ─── Calculate current values ─────────────────────────────────
    total_invested = sum(h.get("total_invested", 0) for h in holdings)
    current_value = sum(h.get("current_value", 0) for h in holdings)
    total_returns = current_value - total_invested
    returns_pct = (total_returns / total_invested * 100) if total_invested > 0 else 0

    # ─── Calculate current allocation ─────────────────────────────
    allocation = {"equity": 0, "debt": 0, "gold": 0, "alternatives": 0, "cash": 0}
    for h in holdings:
        asset_type = h.get("asset_type", "").lower()
        value = h.get("current_value", 0)
        if asset_type in ("equity", "mutual_fund", "stock"):
            allocation["equity"] += value
        elif asset_type in ("fd", "ppf", "nps", "bonds", "debt_fund"):
            allocation["debt"] += value
        elif asset_type in ("gold", "sgb", "gold_etf"):
            allocation["gold"] += value
        else:
            allocation["alternatives"] += value

    if current_value > 0:
        allocation_pct = {k: round(v / current_value * 100, 1) for k, v in allocation.items()}
    else:
        allocation_pct = {"equity": 0, "debt": 0, "gold": 0, "alternatives": 0, "cash": 0}

    # ─── Recommended allocation ───────────────────────────────────
    target = RISK_PROFILES.get(risk_tolerance, RISK_PROFILES["moderate"])
    recommended = {
        "equity": target["equity"],
        "debt": target["debt"],
        "gold": target["gold"],
        "cash": target.get("cash", 10)
    }

    # Age-based adjustment
    age_equity = AGE_BASED_RULES["equity_percentage"](age)
    if abs(age_equity - recommended["equity"]) > 15:
        recommended["equity"] = int((recommended["equity"] + age_equity) / 2)
        recommended["debt"] = 100 - recommended["equity"] - recommended["gold"] - recommended.get("cash", 10)

    # ─── Calculate drift ──────────────────────────────────────────
    drift = {}
    for k in ["equity", "debt", "gold"]:
        current = allocation_pct.get(k, 0)
        target_val = recommended.get(k, 0)
        drift[k] = round(current - target_val, 1)

    # ─── Health scoring ───────────────────────────────────────────
    health_score = 50  # Base score

    # Allocation alignment (-20 to +20)
    drift_penalty = sum(abs(v) for v in drift.values()) * 0.5
    health_score -= min(20, int(drift_penalty))

    # Returns quality (-10 to +15)
    if returns_pct > 15:
        health_score += 15
    elif returns_pct > 10:
        health_score += 10
    elif returns_pct > 5:
        health_score += 5
    elif returns_pct < 0:
        health_score -= 10

    # Diversification (-10 to +10)
    non_zero_alloc = sum(1 for v in allocation_pct.values() if v > 5)
    health_score += min(10, non_zero_alloc * 3)

    # Emergency fund check
    has_emergency = any(
        h.get("asset_type", "").lower() in ("fd", "liquid", "savings", "cash")
        for h in holdings
    )
    if has_emergency:
        health_score += 5
    else:
        health_score -= 10

    health_score = max(0, min(100, health_score))

    # Grade
    if health_score >= 85:
        grade = "A+"
    elif health_score >= 75:
        grade = "A"
    elif health_score >= 65:
        grade = "B+"
    elif health_score >= 55:
        grade = "B"
    elif health_score >= 40:
        grade = "C"
    elif health_score >= 25:
        grade = "D"
    else:
        grade = "F"

    # ─── Risk metrics ─────────────────────────────────────────────
    risk_metrics = {
        "equity_allocation": allocation_pct.get("equity", 0),
        "debt_allocation": allocation_pct.get("debt", 0),
        "concentration_risk": _calculate_concentration_risk(holdings),
        "diversification_score": min(100, non_zero_alloc * 25),
        "volatility_estimate": _estimate_portfolio_volatility(allocation_pct),
        "max_drawdown_estimate": _estimate_max_drawdown(allocation_pct),
    }

    # ─── Generate suggestions ─────────────────────────────────────
    suggestions = _generate_suggestions(
        allocation_pct, recommended, drift, holdings, user_profile, risk_metrics
    )

    # ─── Tax optimization ─────────────────────────────────────────
    tax_opt = _tax_optimization_suggestions(holdings, user_profile)

    # ─── Rebalancing actions ──────────────────────────────────────
    rebalancing = _calculate_rebalancing(allocation, recommended, current_value, holdings)

    return PortfolioAnalysis(
        health_score=health_score,
        health_grade=grade,
        risk_rating=_risk_rating_from_score(health_score),
        total_invested=total_invested,
        current_value=current_value,
        total_returns=round(total_returns, 2),
        returns_percentage=round(returns_pct, 2),
        current_allocation=allocation_pct,
        recommended_allocation=recommended,
        allocation_drift=drift,
        suggestions=suggestions,
        risk_metrics=risk_metrics,
        tax_optimization=tax_opt,
        rebalancing_actions=rebalancing,
    )


def _calculate_concentration_risk(holdings: list) -> str:
    """Assess concentration risk in the portfolio."""
    if not holdings:
        return "no_data"

    total_value = sum(h.get("current_value", 0) for h in holdings)
    if total_value == 0:
        return "no_data"

    # Check if any single holding is > 30% of portfolio
    max_holdings_pct = max(h.get("current_value", 0) / total_value * 100 for h in holdings)

    if max_holdings_pct > 50:
        return "very_high"
    elif max_holdings_pct > 30:
        return "high"
    elif max_holdings_pct > 20:
        return "moderate"
    else:
        return "low"


def _estimate_portfolio_volatility(allocation_pct: dict) -> dict:
    """Estimate portfolio volatility based on asset allocation."""
    equity_vol = 18.0  # Historical Nifty volatility
    debt_vol = 4.0
    gold_vol = 15.0

    equity_w = allocation_pct.get("equity", 0) / 100
    debt_w = allocation_pct.get("debt", 0) / 100
    gold_w = allocation_pct.get("gold", 0) / 100

    # Simplified volatility estimate (ignoring correlations)
    portfolio_vol = math.sqrt(
        (equity_w * equity_vol) ** 2 +
        (debt_w * debt_vol) ** 2 +
        (gold_w * gold_vol) ** 2 +
        2 * equity_w * debt_w * equity_vol * debt_vol * 0.2 +
        2 * equity_w * gold_w * equity_vol * gold_vol * 0.1
    )

    return {
        "annual_volatility": round(portfolio_vol, 1),
        "monthly_volatility": round(portfolio_vol / math.sqrt(12), 1),
        "category": "low" if portfolio_vol < 8 else "moderate" if portfolio_vol < 14 else "high"
    }


def _estimate_max_drawdown(allocation_pct: dict) -> dict:
    """Estimate maximum drawdown based on allocation."""
    equity_w = allocation_pct.get("equity", 0) / 100
    # Historical: Nifty max drawdown ~38% (2020), ~25% (2018)
    estimated_dd = equity_w * 30 + (1 - equity_w) * 5

    return {
        "estimated_max_drawdown": round(estimated_dd, 1),
        "worst_case_loss": f"₹{{}}".replace("{}", "X") + f" ({round(estimated_dd, 1)}%) in extreme market conditions",
        "category": "low" if estimated_dd < 10 else "moderate" if estimated_dd < 20 else "high"
    }


def _risk_rating_from_score(score: int) -> str:
    """Convert health score to risk rating."""
    if score >= 80:
        return "Well-Optimized"
    elif score >= 60:
        return "Needs Minor Adjustment"
    elif score >= 40:
        return "Needs Attention"
    else:
        return "Requires Immediate Action"


def _generate_suggestions(
    current_alloc: dict,
    recommended: dict,
    drift: dict,
    holdings: list,
    profile: dict,
    risk_metrics: dict,
) -> list:
    """Generate actionable portfolio improvement suggestions."""
    suggestions = []

    # ─── Allocation suggestions ───────────────────────────────────
    if abs(drift.get("equity", 0)) > 10:
        direction = "increase" if drift["equity"] < 0 else "reduce"
        suggestions.append({
            "type": "allocation",
            "priority": "high",
            "title": f"{'Increase' if direction == 'increase' else 'Reduce'} equity allocation",
            "detail": f"Your equity allocation is {current_alloc.get('equity', 0)}% but should be ~{recommended['equity']}%. {direction.title()} equity by {abs(drift['equity']):.0f}%.",
            "impact": "Alignment with your risk profile and time horizon"
        })

    # ─── Emergency fund ───────────────────────────────────────────
    has_emergency = any(
        h.get("asset_type", "").lower() in ("fd", "liquid", "savings")
        and h.get("current_value", 0) > 0
        for h in holdings
    )
    monthly_expenses = profile.get("monthly_expenses", 30000)
    emergency_needed = monthly_expenses * 6

    if not has_emergency:
        suggestions.append({
            "type": "safety",
            "priority": "critical",
            "title": "Build an emergency fund first",
            "detail": f"Before investing aggressively, build an emergency fund of ₹{emergency_needed:,.0f} (6 months of expenses). Keep it in a liquid fund or savings account.",
            "impact": "Financial safety net for unexpected events"
        })

    # ─── Diversification ──────────────────────────────────────────
    if risk_metrics.get("concentration_risk") in ("high", "very_high"):
        suggestions.append({
            "type": "risk",
            "priority": "high",
            "title": "Reduce concentration risk",
            "detail": "One or more holdings represent >30% of your portfolio. Diversify across different fund houses and asset categories.",
            "impact": "Reduced portfolio volatility and single-point-of-failure risk"
        })

    # ─── SIP recommendations ──────────────────────────────────────
    sip_amount = profile.get("monthly_sip", 0)
    if sip_amount == 0:
        income = profile.get("monthly_income", 0)
        if income > 0:
            recommended_sip = int(income * 0.2)
            suggestions.append({
                "type": "investment",
                "priority": "medium",
                "title": "Start a SIP immediately",
                "detail": f"Start with ₹{recommended_sip:,}/month (20% of income) in an index fund or flexi cap fund.",
                "impact": "Rupee cost averaging and compounding benefits"
            })

    # ─── Tax optimization ─────────────────────────────────────────
    tax_invested = sum(
        h.get("current_value", 0) for h in holdings
        if h.get("asset_type", "").lower() in ("elss",)
    )
    if tax_invested < 150000:
        remaining_80c = 150000 - tax_invested
        suggestions.append({
            "type": "tax",
            "priority": "medium",
            "title": f"Optimize 80C: ₹{remaining_80c:,.0f} remaining",
            "detail": f"You can invest ₹{remaining_80c:,.0f} more in ELSS/PPF/NPS to maximize your ₹1.5L Section 80C deduction.",
            "impact": f"Tax savings of up to ₹{int(remaining_80c * 0.3):,} (at 30% slab)"
        })

    # ─── NPS suggestion ───────────────────────────────────────────
    nps_invested = sum(
        h.get("current_value", 0) for h in holdings
        if h.get("asset_type", "").lower() in ("nps",)
    )
    if nps_invested == 0:
        suggestions.append({
            "type": "tax",
            "priority": "low",
            "title": "Consider NPS for extra tax savings",
            "detail": "Invest ₹50,000/year in NPS for an additional ₹50,000 deduction under Section 80CCD(1B).",
            "impact": "Up to ₹15,500 additional tax savings per year"
        })

    # ─── Gold allocation ──────────────────────────────────────────
    gold_pct = current_alloc.get("gold", 0)
    if gold_pct < 5:
        suggestions.append({
            "type": "allocation",
            "priority": "low",
            "title": "Consider adding 5-10% gold allocation",
            "detail": "Gold provides portfolio diversification and acts as a hedge during equity market downturns. Consider Sovereign Gold Bonds (SGBs) for 2.5% annual interest + gold price appreciation.",
            "impact": "Portfolio diversification and downside protection"
        })

    # ─── Sort by priority ─────────────────────────────────────────
    priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    suggestions.sort(key=lambda s: priority_order.get(s.get("priority", "low"), 4))

    return suggestions


def _tax_optimization_suggestions(holdings: list, profile: dict) -> list:
    """Generate tax optimization recommendations."""
    suggestions = []
    income = profile.get("annual_income", 0)

    if income <= 0:
        return suggestions

    # Tax regime comparison
    if income <= 700000:
        suggestions.append({
            "type": "regime",
            "recommendation": "New Tax Regime",
            "reason": f"At ₹{income:,.0f} annual income, the new regime with standard deduction of ₹75,000 is likely better. No need to maintain investment proofs."
        })
    else:
        suggestions.append({
            "type": "regime",
            "recommendation": "Compare both regimes",
            "reason": "Use the income tax calculator to compare old vs new regime based on your actual 80C, 80D, and HRA deductions."
        })

    # LTCG optimization
    equity_invested = sum(
        h.get("total_invested", 0) for h in holdings
        if h.get("asset_type", "").lower() in ("equity", "mutual_fund", "stock")
    )
    if equity_invested > 125000:
        suggestions.append({
            "type": "ltcg",
            "recommendation": "Book LTCG strategically",
            "reason": "With significant equity investments, consider booking partial profits up to ₹1.25L annually to stay within the LTCG tax-free limit."
        })

    # PPF suggestion for high earners
    if income > 1000000:
        suggestions.append({
            "type": "ppf",
            "recommendation": "Max out PPF contribution",
            "reason": "Invest ₹1.5L in PPF for risk-free, tax-free returns at 7.1%. This is EEE (exempt at contribution, interest, and maturity)."
        })

    return suggestions


def _calculate_rebalancing(
    current: dict, recommended: dict, total_value: float, holdings: list
) -> list:
    """Calculate specific rebalancing actions."""
    actions = []

    for asset_class in ["equity", "debt", "gold"]:
        current_val = current.get(asset_class, 0)
        target_pct = recommended.get(asset_class, 0) / 100
        target_val = total_value * target_pct
        diff = target_val - current_val

        if abs(diff) > total_value * 0.05:  # Only if > 5% drift
            action = "Buy" if diff > 0 else "Sell"
            actions.append({
                "asset_class": asset_class,
                "action": action,
                "amount": abs(round(diff)),
                "current_pct": round(current.get(asset_class, 0), 1),
                "target_pct": recommended.get(asset_class, 0),
            })

    return actions


# ═══════════════════════════════════════════════════════════════════════
# LLM Integration
# ═══════════════════════════════════════════════════════════════════════

PORTFOLIO_SYSTEM_PROMPT = """You are FinLens, India's most trusted AI portfolio advisor.

You help users understand and optimize their investment portfolio with India-specific advice.

IMPORTANT RULES:
1. Always mention risks alongside benefits
2. Use Indian Rupee amounts and Indian financial context
3. Reference SEBI-registered investment advisors for personalized advice
4. Never guarantee returns on any investment
5. Consider Indian tax implications (LTCG, STCG, 80C, 80D, NPS)
6. Recommend specific fund categories, NOT specific fund names (to avoid SEBI issues)

INDIAN INVESTMENT LANDSCAPE:
- Equity Mutual Funds: Large Cap (12-16%), Mid Cap (15-22%), Small Cap (18-30%)
- Debt: PPF (7.1%), FD (6.5-7.5%), NPS (8-14%)
- Gold: SGBs (gold return + 2.5% interest), Gold ETF (gold return)
- Tax: LTCG 12% above ₹1.25L, STCG 20%, 80C up to ₹1.5L

RESPOND IN VALID JSON:
{
  "health_score": 0-100,
  "health_grade": "A+" | "A" | "B+" | "B" | "C" | "D" | "F",
  "verdict": "one sentence overall assessment",
  "portfolio_summary": "brief portfolio analysis",
  "strengths": ["things user is doing well"],
  "risks": ["identified risks"],
  "suggestions": [{"title": "...", "detail": "...", "priority": "high|medium|low"}],
  "rebalancing": [{"asset_class": "...", "action": "buy|sell", "reason": "..."}],
  "tax_tips": ["specific tax optimization suggestions"],
  "monthly_plan": "recommended monthly investment plan",
  "disclaimer": "standard investment disclaimer"
}"""


async def analyze_portfolio(portfolio_description: str, llm_call) -> dict:
    """
    Analyze a portfolio described in natural language.

    Args:
        portfolio_description: Natural language description of holdings
        llm_call: Async function (system_prompt, user_prompt) -> str

    Returns:
        Structured portfolio analysis
    """
    user_prompt = f"""Analyze this investment portfolio and provide comprehensive advice:

---
{portfolio_description}
---

Provide your analysis as JSON. Be specific with numbers, percentages, and actionable advice.
Include India-specific tax optimization tips."""

    raw_response = await llm_call(PORTFOLIO_SYSTEM_PROMPT, user_prompt)

    # Parse JSON
    cleaned = raw_response.strip()
    if cleaned.startswith("```"):
        lines = cleaned.split("\n")
        lines = [l for l in lines if not l.strip().startswith("```")]
        cleaned = "\n".join(lines)

    try:
        result = json.loads(cleaned)
    except json.JSONDecodeError:
        import re
        json_match = re.search(r'\{[\s\S]*\}', cleaned)
        if json_match:
            result = json.loads(json_match.group())
        else:
            result = {
                "verdict": "Could not complete full analysis. Please provide more details about your holdings.",
                "health_score": 50,
                "health_grade": "B",
                "strengths": [],
                "risks": [],
                "suggestions": [{"title": "Provide more details", "detail": "List your individual investments with amounts.", "priority": "medium"}],
            }

    # Ensure required fields
    if "disclaimer" not in result:
        result["disclaimer"] = "This is AI-generated educational information. Consult a SEBI-registered investment advisor before making investment decisions."

    return result
