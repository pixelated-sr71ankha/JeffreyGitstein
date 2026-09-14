"""
═══════════════════════════════════════════════════════════════════════════════
FinLens Formatters
═══════════════════════════════════════════════════════════════════════════════

Data formatting utilities:
- Currency formatting (INR)
- Date/time formatting
- Percentage formatting
- Risk level formatting
- Report formatting
- Markdown/text formatting
"""

from datetime import datetime, date, timedelta
from typing import Optional, Any


# ═══════════════════════════════════════════════════════════════════════════════
# Currency
# ═══════════════════════════════════════════════════════════════════════════════

def format_inr(amount: float, show_symbol: bool = True) -> str:
    """Format amount in Indian Rupees with proper comma separation."""
    if amount < 0:
        return ("-" if show_symbol else "-") + format_inr(-amount, show_symbol)
    amount = round(amount)
    s = str(int(amount))
    if len(s) <= 3:
        result = s
    else:
        last3 = s[-3:]
        remaining = s[:-3]
        parts = []
        while remaining:
            parts.append(remaining[-2:])
            remaining = remaining[:-2]
        result = ",".join(reversed(parts)) + "," + last3
    return f"₹{result}" if show_symbol else result


def format_compact(amount: float) -> str:
    """Format amount in compact form: ₹1.5K, ₹2.3L, ₹5.1Cr."""
    if abs(amount) >= 10000000:
        return f"₹{amount / 10000000:.1f}Cr"
    elif abs(amount) >= 100000:
        return f"₹{amount / 100000:.1f}L"
    elif abs(amount) >= 1000:
        return f"₹{amount / 1000:.1f}K"
    return f"₹{amount:.0f}"


# ═══════════════════════════════════════════════════════════════════════════════
# Date/Time
# ═══════════════════════════════════════════════════════════════════════════════

def format_relative_time(dt: datetime) -> str:
    """Format datetime as relative time: '2 hours ago', 'yesterday', etc."""
    now = datetime.utcnow()
    diff = now - dt
    seconds = diff.total_seconds()

    if seconds < 60:
        return "just now"
    elif seconds < 3600:
        mins = int(seconds / 60)
        return f"{mins} minute{'s' if mins != 1 else ''} ago"
    elif seconds < 86400:
        hours = int(seconds / 3600)
        return f"{hours} hour{'s' if hours != 1 else ''} ago"
    elif seconds < 172800:
        return "yesterday"
    elif seconds < 604800:
        days = int(seconds / 86400)
        return f"{days} days ago"
    else:
        return dt.strftime("%b %d, %Y")


def format_date_indian(d: date) -> str:
    """Format date in Indian format: DD/MM/YYYY."""
    return d.strftime("%d/%m/%Y")


def format_datetime_full(dt: datetime) -> str:
    """Format datetime as 'DD Mon YYYY, HH:MM AM/PM'."""
    return dt.strftime("%d %b %Y, %I:%M %p")


def get_financial_year(dt: datetime = None) -> str:
    """Get FY string for a date: '2024-25'."""
    if dt is None:
        dt = datetime.now()
    if dt.month >= 4:
        return f"{dt.year}-{str(dt.year + 1)[-2:]}"
    return f"{dt.year - 1}-{str(dt.year)[-2:]}"


# ═══════════════════════════════════════════════════════════════════════════════
# Risk & Scoring
# ═══════════════════════════════════════════════════════════════════════════════

RISK_EMOJIS = {
    "SAFE": "✅",
    "SUSPICIOUS": "⚠️",
    "DANGEROUS": "🔶",
    "CONFIRMED_SCAM": "🚨",
}

RISK_COLORS = {
    "SAFE": "#22c55e",
    "SUSPICIOUS": "#f59e0b",
    "DANGEROUS": "#f97316",
    "CONFIRMED_SCAM": "#ef4444",
}


def format_risk_level(level: str) -> str:
    """Format risk level with emoji."""
    emoji = RISK_EMOJIS.get(level, "❓")
    return f"{emoji} {level.replace('_', ' ').title()}"


def format_risk_color(level: str) -> str:
    """Get color code for risk level."""
    return RISK_COLORS.get(level, "#6b7280")


def format_percentage(value: float, decimals: int = 1) -> str:
    """Format percentage with sign."""
    sign = "+" if value > 0 else ""
    return f"{sign}{value:.{decimals}f}%"


def format_score_bar(score: int, max_score: int = 100) -> str:
    """Create a text-based score bar."""
    filled = int(score / max_score * 20)
    bar = "█" * filled + "░" * (20 - filled)
    return f"[{bar}] {score}/{max_score}"


def format_health_grade(grade: str) -> str:
    """Format health grade with description."""
    descriptions = {
        "A+": "Excellent 🌟",
        "A": "Very Good 👍",
        "B+": "Good 😊",
        "B": "Average 😐",
        "C": "Needs Improvement ⚠️",
        "D": "Poor 🔴",
        "F": "Critical 🚨",
    }
    desc = descriptions.get(grade, "")
    return f"Grade {grade} — {desc}" if desc else f"Grade {grade}"


# ═══════════════════════════════════════════════════════════════════════════════
# Report Formatting
# ═══════════════════════════════════════════════════════════════════════════════

def format_scan_summary(scan_data: dict) -> str:
    """Format a scan result as a readable summary."""
    risk = scan_data.get("risk_level", "UNKNOWN")
    score = scan_data.get("risk_score", 0)
    emoji = RISK_EMOJIS.get(risk, "❓")

    lines = [
        f"{emoji} Risk Assessment: {risk.replace('_', ' ').title()}",
        f"📊 Risk Score: {format_score_bar(score)}",
    ]

    if scan_data.get("scam_type"):
        lines.append(f"🏷️  Type: {scan_data['scam_type'].replace('_', ' ').title()}")

    if scan_data.get("confidence"):
        lines.append(f"🎯 Confidence: {scan_data['confidence']}%")

    if scan_data.get("red_flags"):
        lines.append("\n🚩 Red Flags:")
        for flag in scan_data["red_flags"]:
            if isinstance(flag, dict):
                lines.append(f"  • {flag.get('indicator', flag.get('detail', 'Unknown'))}")
            else:
                lines.append(f"  • {flag}")

    if scan_data.get("action"):
        lines.append(f"\n💡 Action: {scan_data['action']}")

    return "\n".join(lines)


def format_portfolio_summary(portfolio: dict) -> str:
    """Format portfolio analysis as readable summary."""
    invested = portfolio.get("total_invested", 0)
    current = portfolio.get("current_value", 0)
    returns_pct = portfolio.get("returns_percentage", 0)
    grade = portfolio.get("health_grade", "?")

    lines = [
        f"📊 Portfolio Health: {format_health_grade(grade)}",
        f"💰 Invested: {format_inr(invested)}",
        f"📈 Current Value: {format_inr(current)}",
        f"📉 Returns: {format_percentage(returns_pct)}",
    ]

    if portfolio.get("allocation"):
        lines.append("\nAsset Allocation:")
        for k, v in portfolio["allocation"].items():
            lines.append(f"  • {k.title()}: {v}%")

    return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════════════════
# Table Formatting
# ═══════════════════════════════════════════════════════════════════════════════

def format_table(headers: list, rows: list, max_col_width: int = 30) -> str:
    """Format data as an ASCII table."""
    if not rows:
        return ""

    # Calculate column widths
    col_widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            if i < len(col_widths):
                col_widths[i] = min(max_col_width, max(col_widths[i], len(str(cell))))

    # Header
    header_line = " | ".join(h.ljust(col_widths[i]) for i, h in enumerate(headers))
    separator = "-+-".join("-" * w for w in col_widths)

    lines = [header_line, separator]
    for row in rows:
        line = " | ".join(
            str(row[i] if i < len(row) else "").ljust(col_widths[i])
            for i in range(len(headers))
        )
        lines.append(line)

    return "\n".join(lines)
