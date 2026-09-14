"""
═══════════════════════════════════════════════════════════════════════════════
FinLens Indian Finance Utilities
═══════════════════════════════════════════════════════════════════════════════

India-specific financial calculation utilities:
- Income Tax Calculator (Old & New Regime FY 2024-25)
- GST Calculator
- EMI Calculator (Home, Car, Personal)
- SIP Returns Calculator (Future Value)
- PPF Calculator
- NPS Calculator
- FD/RD Maturity Calculator
- Stamp Duty Calculator (Property)
- Capital Gains Tax (LTCG/STCG)
- EPF Calculator
- HRA Exemption Calculator
- Section 80C/80D optimization helpers
- Indian Financial Year helpers
- Currency formatting (Indian numbering system)
"""

import math
from typing import Optional, Dict, Any, List, Tuple
from datetime import datetime, date


# ═══════════════════════════════════════════════════════════════════════════════
# Indian Tax Brackets FY 2024-25
# ═══════════════════════════════════════════════════════════════════════════════

# New Tax Regime (Default from FY 2023-24, updated FY 2024-25)
NEW_REGIME_BRACKETS = [
    (0, 300000, 0),
    (300000, 700000, 5),
    (700000, 1000000, 10),
    (1000000, 1200000, 15),
    (1200000, 1500000, 20),
    (1500000, float("inf"), 30),
]
NEW_REGIME_STANDARD_DEDUCTION = 75000

# Old Tax Regime
OLD_REGIME_BRACKETS = [
    (0, 250000, 0),
    (250000, 500000, 5),
    (500000, 1000000, 20),
    (1000000, float("inf"), 30),
]
OLD_REGIME_STANDARD_DEDUCTION = 50000

# Surcharge thresholds (both regimes)
SURCHARGE_THRESHOLDS = [
    (5000000, 10),
    (10000000, 15),
    (20000000, 25),
    (500000000, 37),
]

# Cess rate
CESS_RATE = 4  # 4% Health & Education Cess


# ═══════════════════════════════════════════════════════════════════════════════
# Tax Calculator
# ═══════════════════════════════════════════════════════════════════════════════

def calculate_tax_old_regime(
    gross_income: float,
    section_80c: float = 0,
    section_80d: float = 0,
    hra_exemption: float = 0,
    other_deductions: float = 0,
    home_loan_interest: float = 0,
) -> Dict[str, Any]:
    """
    Calculate income tax under Old Tax Regime.

    Args:
        gross_income: Annual gross income
        section_80c: Section 80C investments (max 1.5L)
        section_80d: Section 80D health insurance premium
        hra_exemption: HRA exemption amount
        other_deductions: Other deductions (80E, 80G, etc.)
        home_loan_interest: Home loan interest deduction (max 2L)

    Returns:
        Dict with detailed tax breakdown
    """
    # Cap deductions
    section_80c = min(section_80c, 150000)
    section_80d = min(section_80d, 100000)
    home_loan_interest = min(home_loan_interest, 200000)

    total_deductions = (
        OLD_REGIME_STANDARD_DEDUCTION
        + section_80c
        + section_80d
        + hra_exemption
        + other_deductions
        + home_loan_interest
    )

    taxable_income = max(0, gross_income - total_deductions)

    # Calculate tax
    tax = _calculate_slab_tax(taxable_income, OLD_REGIME_BRACKETS)

    # Surcharge
    surcharge_rate = _get_surcharge_rate(taxable_income)
    surcharge = tax * surcharge_rate / 100

    # Cess
    cess = (tax + surcharge) * CESS_RATE / 100

    total_tax = tax + surcharge + cess
    effective_rate = (total_tax / gross_income * 100) if gross_income > 0 else 0

    return {
        "regime": "old",
        "gross_income": gross_income,
        "total_deductions": total_deductions,
        "taxable_income": taxable_income,
        "tax_before_surcharge": tax,
        "surcharge_rate": surcharge_rate,
        "surcharge": round(surcharge),
        "cess": round(cess),
        "total_tax": round(total_tax),
        "monthly_tax": round(total_tax / 12),
        "in_hand_monthly": round((gross_income - total_tax) / 12),
        "effective_tax_rate": round(effective_rate, 2),
        "deduction_breakdown": {
            "standard_deduction": OLD_REGIME_STANDARD_DEDUCTION,
            "section_80c": section_80c,
            "section_80d": section_80d,
            "hra_exemption": hra_exemption,
            "home_loan_interest": home_loan_interest,
            "other_deductions": other_deductions,
        },
    }


def calculate_tax_new_regime(
    gross_income: float,
    standard_deduction: float = 75000,
) -> Dict[str, Any]:
    """
    Calculate income tax under New Tax Regime (FY 2024-25).

    New regime offers lower rates but fewer deductions.
    Standard deduction of ₹75,000 is available.
    """
    taxable_income = max(0, gross_income - standard_deduction)

    # Calculate tax
    tax = _calculate_slab_tax(taxable_income, NEW_REGIME_BRACKETS)

    # Section 87A rebate (up to ₹25,000 for income up to ₹7L)
    rebate = 0
    if taxable_income <= 700000:
        rebate = min(tax, 25000)

    tax_after_rebate = max(0, tax - rebate)

    # Surcharge
    surcharge_rate = _get_surcharge_rate(taxable_income)
    surcharge = tax_after_rebate * surcharge_rate / 100

    # Cess
    cess = (tax_after_rebate + surcharge) * CESS_RATE / 100

    total_tax = tax_after_rebate + surcharge + cess
    effective_rate = (total_tax / gross_income * 100) if gross_income > 0 else 0

    return {
        "regime": "new",
        "gross_income": gross_income,
        "standard_deduction": standard_deduction,
        "taxable_income": taxable_income,
        "tax_before_rebate": tax,
        "rebate_87a": rebate,
        "tax_after_rebate": tax_after_rebate,
        "surcharge_rate": surcharge_rate,
        "surcharge": round(surcharge),
        "cess": round(cess),
        "total_tax": round(total_tax),
        "monthly_tax": round(total_tax / 12),
        "in_hand_monthly": round((gross_income - total_tax) / 12),
        "effective_tax_rate": round(effective_rate, 2),
    }


def compare_tax_regimes(
    gross_income: float,
    deductions: Dict[str, float] = None,
) -> Dict[str, Any]:
    """Compare old vs new tax regime and recommend the better one."""
    if deductions is None:
        deductions = {}

    old_result = calculate_tax_old_regime(
        gross_income=gross_income,
        section_80c=deductions.get("80c", 0),
        section_80d=deductions.get("80d", 0),
        hra_exemption=deductions.get("hra", 0),
        other_deductions=deductions.get("other", 0),
        home_loan_interest=deductions.get("home_loan", 0),
    )
    new_result = calculate_tax_new_regime(gross_income)

    savings = old_result["total_tax"] - new_result["total_tax"]
    recommended = "new" if savings > 0 else "old"

    return {
        "gross_income": gross_income,
        "old_regime": old_result,
        "new_regime": new_result,
        "savings_with_new_regime": savings,
        "recommended_regime": recommended,
        "annual_savings": abs(savings),
        "monthly_savings": round(abs(savings) / 12),
    }


def _calculate_slab_tax(income: float, brackets: list) -> float:
    """Calculate tax based on slab brackets."""
    tax = 0
    for lower, upper, rate in brackets:
        if income <= lower:
            break
        taxable_in_slab = min(income, upper) - lower
        tax += taxable_in_slab * rate / 100
    return tax


def _get_surcharge_rate(income: float) -> float:
    """Get surcharge rate based on income."""
    rate = 0
    for threshold, r in SURCHARGE_THRESHOLDS:
        if income > threshold:
            rate = r
    # Cap surcharge at 15% for income > 5Cr (as per latest rules)
    if income > 50000000:
        rate = min(rate, 15)
    return rate


# ═══════════════════════════════════════════════════════════════════════════════
# EMI Calculator
# ═══════════════════════════════════════════════════════════════════════════════

def calculate_emi(
    principal: float,
    annual_rate: float,
    tenure_months: int,
) -> Dict[str, Any]:
    """
    Calculate EMI for a loan.

    Args:
        principal: Loan amount
        annual_rate: Annual interest rate (%)
        tenure_months: Loan tenure in months

    Returns:
        Dict with EMI, total payment, total interest, and amortization schedule
    """
    if annual_rate == 0:
        emi = principal / tenure_months
        return {
            "emi": round(emi),
            "total_payment": round(principal),
            "total_interest": 0,
            "principal": principal,
            "interest_rate": 0,
            "tenure_months": tenure_months,
        }

    monthly_rate = annual_rate / (12 * 100)
    emi = principal * monthly_rate * (1 + monthly_rate) ** tenure_months / (
        ((1 + monthly_rate) ** tenure_months) - 1
    )

    total_payment = emi * tenure_months
    total_interest = total_payment - principal

    # Generate amortization schedule
    balance = principal
    schedule = []
    yearly_summary = {}

    for month in range(1, tenure_months + 1):
        interest_part = balance * monthly_rate
        principal_part = emi - interest_part
        balance -= principal_part

        year = (month - 1) // 12 + 1
        if year not in yearly_summary:
            yearly_summary[year] = {
                "year": year,
                "principal_paid": 0,
                "interest_paid": 0,
                "closing_balance": 0,
            }
        yearly_summary[year]["principal_paid"] += principal_part
        yearly_summary[year]["interest_paid"] += interest_part
        yearly_summary[year]["closing_balance"] = max(0, balance)

        if month <= 12 or month == tenure_months:  # First year + last month
            schedule.append({
                "month": month,
                "emi": round(emi),
                "principal": round(principal_part),
                "interest": round(interest_part),
                "balance": round(max(0, balance)),
            })

    return {
        "emi": round(emi),
        "total_payment": round(total_payment),
        "total_interest": round(total_interest),
        "interest_to_principal_ratio": round(total_interest / principal * 100, 1),
        "principal": principal,
        "interest_rate": annual_rate,
        "tenure_months": tenure_months,
        "yearly_summary": list(yearly_summary.values()),
        "sample_amortization": schedule,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# SIP Calculator
# ═══════════════════════════════════════════════════════════════════════════════

def calculate_sip(
    monthly_investment: float,
    annual_return: float,
    tenure_years: int,
    step_up_pct: float = 0,
) -> Dict[str, Any]:
    """
    Calculate SIP returns with optional annual step-up.

    Args:
        monthly_investment: Monthly SIP amount
        annual_return: Expected annual return (%)
        tenure_years: Investment duration in years
        step_up_pct: Annual SIP increase percentage (0 = no step-up)

    Returns:
        Dict with projected returns and growth chart
    """
    monthly_rate = annual_return / (12 * 100)
    total_months = tenure_years * 12

    total_invested = 0
    future_value = 0
    current_sip = monthly_investment
    yearly_data = []

    for month in range(1, total_months + 1):
        # Step up annually
        if step_up_pct > 0 and month > 1 and (month - 1) % 12 == 0:
            current_sip *= (1 + step_up_pct / 100)

        total_invested += current_sip
        # Future value of this month's investment
        remaining_months = total_months - month
        future_value += current_sip * (1 + monthly_rate) ** remaining_months

        # Yearly snapshots
        if month % 12 == 0:
            year = month // 12
            yearly_data.append({
                "year": year,
                "invested": round(total_invested),
                "value": round(future_value),
                "returns": round(future_value - total_invested),
                "returns_pct": round(
                    ((future_value - total_invested) / total_invested * 100)
                    if total_invested > 0 else 0, 1
                ),
            })

    wealth_gained = future_value - total_invested
    wealth_multiple = future_value / total_invested if total_invested > 0 else 0

    return {
        "monthly_investment": monthly_investment,
        "annual_return": annual_return,
        "tenure_years": tenure_years,
        "step_up_pct": step_up_pct,
        "total_invested": round(total_invested),
        "future_value": round(future_value),
        "wealth_gained": round(wealth_gained),
        "wealth_multiple": round(wealth_multiple, 2),
        "yearly_growth": yearly_data,
        "monthly_breakdown_sample": yearly_data[:3] if yearly_data else [],
    }


# ═══════════════════════════════════════════════════════════════════════════════
# PPF Calculator
# ═══════════════════════════════════════════════════════════════════════════════

def calculate_ppf(
    annual_investment: float,
    years: int = 15,
    ppf_rate: float = 7.1,
) -> Dict[str, Any]:
    """
    Calculate PPF maturity value.
    PPF has a 15-year lock-in with annual compounding.
    """
    annual_investment = min(annual_investment, 150000)  # Max ₹1.5L/year

    balance = 0
    yearly_data = []

    for year in range(1, years + 1):
        interest = (balance + annual_investment) * ppf_rate / 100
        balance = balance + annual_investment + interest

        yearly_data.append({
            "year": year,
            "invested": annual_investment * year,
            "interest": round(interest),
            "balance": round(balance),
        })

    total_invested = annual_investment * years
    total_interest = balance - total_invested

    return {
        "annual_investment": annual_investment,
        "years": years,
        "rate": ppf_rate,
        "total_invested": round(total_invested),
        "maturity_value": round(balance),
        "total_interest": round(total_interest),
        "tax_benefit_80c": min(annual_investment, 150000),
        "is_triple_exempt": True,
        "yearly_data": yearly_data,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# FD Calculator
# ═══════════════════════════════════════════════════════════════════════════════

def calculate_fd(
    principal: float,
    annual_rate: float,
    tenure_years: float,
    compounding: str = "quarterly",
) -> Dict[str, Any]:
    """Calculate Fixed Deposit maturity."""
    compounding_map = {
        "monthly": 12,
        "quarterly": 4,
        "half_yearly": 2,
        "yearly": 1,
    }
    n = compounding_map.get(compounding, 4)
    maturity = principal * (1 + annual_rate / (100 * n)) ** (n * tenure_years)
    interest_earned = maturity - principal

    return {
        "principal": principal,
        "rate": annual_rate,
        "tenure_years": tenure_years,
        "compounding": compounding,
        "maturity_value": round(maturity),
        "interest_earned": round(interest_earned),
        "effective_rate": round(((maturity / principal) ** (1 / tenure_years) - 1) * 100, 2),
    }


# ═══════════════════════════════════════════════════════════════════════════════
# Capital Gains Tax
# ═══════════════════════════════════════════════════════════════════════════════

def calculate_stcg_tax(
    gains: float,
    asset_type: str = "equity",
) -> Dict[str, Any]:
    """Calculate Short-Term Capital Gains tax."""
    if asset_type == "equity":
        rate = 20  # 20% STCG on equity (listed, sold within 1 year)
    elif asset_type == "debt":
        rate = 30  # Taxed at slab rate (simplified to 30%)
    else:
        rate = 30

    tax = gains * rate / 100
    return {
        "gains": gains,
        "asset_type": asset_type,
        "tax_rate": rate,
        "tax": round(tax),
        "net_gains": round(gains - tax),
    }


def calculate_ltcg_tax(
    gains: float,
    asset_type: str = "equity",
) -> Dict[str, Any]:
    """Calculate Long-Term Capital Gains tax."""
    if asset_type == "equity":
        exemption_limit = 125000  # ₹1.25L exemption
        rate = 12  # 12% LTCG on equity
        taxable_gains = max(0, gains - exemption_limit)
    elif asset_type == "gold":
        exemption_limit = 125000
        rate = 12.5
        taxable_gains = max(0, gains - exemption_limit)
    elif asset_type == "property":
        exemption_limit = 0
        rate = 20
        taxable_gains = gains
    else:
        exemption_limit = 0
        rate = 10
        taxable_gains = gains

    tax = taxable_gains * rate / 100
    return {
        "gains": gains,
        "asset_type": asset_type,
        "exemption_limit": exemption_limit,
        "taxable_gains": taxable_gains,
        "tax_rate": rate,
        "tax": round(tax),
        "net_gains": round(gains - tax),
    }


# ═══════════════════════════════════════════════════════════════════════════════
# HRA Exemption Calculator
# ═══════════════════════════════════════════════════════════════════════════════

def calculate_hra_exemption(
    basic_salary: float,
    hra_received: float,
    rent_paid: float,
    is_metro: bool = True,
) -> Dict[str, Any]:
    """
    Calculate HRA exemption under Section 10(13A).
    HRA exemption is minimum of:
    1. Actual HRA received
    2. 50% of basic salary (metro) or 40% (non-metro)
    3. Rent paid - 10% of basic salary
    """
    metro_pct = 50 if is_metro else 40
    basic_pct = basic_salary * metro_pct / 100
    rent_minus_basic = rent_paid - (basic_salary * 10 / 100)

    exemption = min(hra_received, basic_pct, max(0, rent_minus_basic))

    return {
        "hra_received": hra_received,
        "basic_salary": basic_salary,
        "rent_paid": rent_paid,
        "is_metro": is_metro,
        "option_1_actual_hra": hra_received,
        "option_2_salary_pct": round(basic_pct),
        "option_3_rent_minus_basic": round(max(0, rent_minus_basic)),
        "exemption_amount": round(exemption),
        "taxable_hra": round(max(0, hra_received - exemption)),
    }


# ═══════════════════════════════════════════════════════════════════════════════
# Currency Formatting (Indian Numbering System)
# ═══════════════════════════════════════════════════════════════════════════════

def format_indian_currency(amount: float) -> str:
    """
    Format number in Indian currency notation (lakhs, crores).

    Examples:
        150000 → ₹1,50,000
        1500000 → ₹15,00,000
        15000000 → ₹1,50,00,000
    """
    if amount < 0:
        return "-" + format_indian_currency(-amount)

    amount = round(amount)
    s = str(amount)

    if len(s) <= 3:
        return f"₹{s}"

    # Last 3 digits
    last3 = s[-3:]
    remaining = s[:-3]

    # Group remaining digits in pairs
    parts = []
    while remaining:
        parts.append(remaining[-2:])
        remaining = remaining[:-2]

    formatted = ",".join(reversed(parts)) + "," + last3
    return f"₹{formatted}"


def format_amount_compact(amount: float) -> str:
    """
    Format amount in compact notation (L/C).

    Examples:
        1500 → ₹1.5K
        150000 → ₹1.5L
        15000000 → ₹1.5Cr
    """
    if abs(amount) >= 10000000:
        return f"₹{amount / 10000000:.1f}Cr"
    elif abs(amount) >= 100000:
        return f"₹{amount / 100000:.1f}L"
    elif abs(amount) >= 1000:
        return f"₹{amount / 1000:.1f}K"
    else:
        return f"₹{amount:.0f}"


# ═══════════════════════════════════════════════════════════════════════════════
# Financial Year Helpers
# ═══════════════════════════════════════════════════════════════════════════════

def get_current_financial_year() -> Tuple[int, int]:
    """Get the current Indian financial year (April-March)."""
    now = datetime.now()
    if now.month >= 4:
        return (now.year, now.year + 1)
    else:
        return (now.year - 1, now.year)


def get_financial_year_string() -> str:
    """Get formatted FY string like '2024-25'."""
    start, end = get_current_financial_year()
    return f"{start}-{str(end)[-2:]}"


def is_quarter_end(d: date = None) -> bool:
    """Check if a date is a quarter-end (Mar, Jun, Sep, Dec)."""
    if d is None:
        d = date.today()
    return d.month in (3, 6, 9, 12) and d.day >= 28


# ═══════════════════════════════════════════════════════════════════════════════
# 50/30/20 Budget Rule (India-adapted)
# ═══════════════════════════════════════════════════════════════════════════════

def calculate_budget_allocation(
    monthly_income: float,
    city_tier: str = "tier2",
    dependents: int = 0,
) -> Dict[str, Any]:
    """
    Calculate recommended budget allocation based on income and lifestyle.

    Adapts the 50/30/20 rule for Indian cost of living.
    """
    # Base allocation
    needs_pct = 50
    wants_pct = 30
    savings_pct = 20

    # Adjust for city tier
    if city_tier == "tier1":
        needs_pct += 5
        savings_pct -= 5
    elif city_tier == "tier3":
        needs_pct -= 5
        savings_pct += 5

    # Adjust for dependents
    needs_pct += min(15, dependents * 3)
    savings_pct = max(10, savings_pct - min(10, dependents * 3))

    # Ensure totals add up
    wants_pct = max(5, 100 - needs_pct - savings_pct)

    categories = {
        "housing": {"pct": 25, "amount": round(monthly_income * 0.25)},
        "food": {"pct": 12, "amount": round(monthly_income * 0.12)},
        "transport": {"pct": 8, "amount": round(monthly_income * 0.08)},
        "utilities": {"pct": 5, "amount": round(monthly_income * 0.05)},
        "entertainment": {"pct": 5, "amount": round(monthly_income * 0.05)},
        "shopping": {"pct": 5, "amount": round(monthly_income * 0.05)},
        "health": {"pct": 4, "amount": round(monthly_income * 0.04)},
        "emergency_fund": {"pct": 5, "amount": round(monthly_income * 0.05)},
        "investments": {"pct": 15, "amount": round(monthly_income * 0.15)},
        "insurance": {"pct": 3, "amount": round(monthly_income * 0.03)},
    }

    return {
        "monthly_income": monthly_income,
        "city_tier": city_tier,
        "dependents": dependents,
        "allocation": {
            "needs": {"pct": needs_pct, "amount": round(monthly_income * needs_pct / 100)},
            "wants": {"pct": wants_pct, "amount": round(monthly_income * wants_pct / 100)},
            "savings": {"pct": savings_pct, "amount": round(monthly_income * savings_pct / 100)},
        },
        "categories": categories,
        "emergency_fund_target": round(monthly_income * 6),
        "recommended_sip": round(monthly_income * 0.15),
    }
