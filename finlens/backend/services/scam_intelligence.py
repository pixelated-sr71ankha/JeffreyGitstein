"""
═══════════════════════════════════════════════════════════════════════════════
FinLens Scam Intelligence Service
═══════════════════════════════════════════════════════════════════════════════

Advanced scam intelligence engine that goes beyond simple pattern matching:
- Community-powered scam database with crowdsourced reports
- Real-time scam trend analysis across regions
- Phone number reputation scoring
- URL/domain reputation checking
- Scam pattern evolution tracking
- Cross-referencing with known scam campaigns
- Geographic hot-spot detection
- Financial impact estimation
- Historical scan analytics
"""

import re
import json
import math
import hashlib
import logging
from typing import Optional, List, Dict, Any, Tuple
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from dataclasses import dataclass, field
from pathlib import Path

from sqlalchemy import select, func, and_, or_, desc
from sqlalchemy.ext.asyncio import AsyncSession

from database import (
    ScanHistory, ScamReport, ScamPattern, ScamIntelligenceFeed,
    db_manager
)

logger = logging.getLogger("finlens.scam_intelligence")


# ═══════════════════════════════════════════════════════════════════════════════
# Scam Knowledge Base
# ═══════════════════════════════════════════════════════════════════════════════

KNOWLEDGE_DIR = Path(__file__).parent.parent / "knowledge"

# Known scam domains (simplified — real system would use a full DB)
KNOWN_SCAM_DOMAINS = {
    "verifykyc-update.com", " bankverify.in", "upi-collect.net",
    "free-reward.win", "claimprize.today", "lottery-winner.info",
    "invest-doubles.xyz", "tradingbot-pro.tk", "crypto-profit.ml",
    "job-offer-now.ga", "work-from-home.top", "earn-daily.pw",
    "govt-refund.site", "tax-refund.in", "insurance-claim.org",
    "urgent-action.xyz", "account-verify.tk", "bank-alert.ml",
}

# Known scam phone number patterns (country + area codes commonly spoofed)
SCAM_PHONE_PREFIXES = [
    "+1415", "+1201", "+4470", "+614", "+971",
    "1415", "1201", "4470",  # without country code
]

# UPI handle patterns that are commonly used in scams
SUSPICIOUS_UPI_HANDLES = {
    "pay", "collect", "verify", "refund", "claim", "prize",
    "winner", "free", "bonus", "cash", "reward",
}


# ═══════════════════════════════════════════════════════════════════════════════
# Data Classes
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class ReputationScore:
    """Reputation score for a phone number, URL, or UPI ID."""
    entity: str
    entity_type: str  # phone, url, upi
    score: float  # 0.0 (dangerous) to 1.0 (trustworthy)
    risk_level: str
    report_count: int = 0
    verified_reports: int = 0
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    associated_scam_types: List[str] = field(default_factory=list)
    regions: List[str] = field(default_factory=list)
    total_amount_lost: float = 0.0


@dataclass
class ScamTrend:
    """A detected trend in scam activity."""
    trend_type: str  # increasing, decreasing, new_variant, seasonal
    scam_type: str
    description: str
    severity: str
    affected_regions: List[str]
    estimated_growth_pct: float
    data_points: int
    confidence: float


@dataclass
class IntelligenceReport:
    """A comprehensive intelligence report."""
    report_type: str
    title: str
    summary: str
    key_findings: List[str]
    recommendations: List[str]
    risk_level: str
    affected_population: str
    estimated_impact: str
    generated_at: datetime


# ═══════════════════════════════════════════════════════════════════════════════
# URL Reputation Engine
# ═══════════════════════════════════════════════════════════════════════════════

class URLReputationEngine:
    """Analyze URLs for phishing and malicious indicators."""

    # Suspicious TLDs
    SUSPICIOUS_TLDS = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".pw", ".click", ".link"}

    # Legitimate financial domains
    LEGITIMATE_DOMAINS = {
        "hdfcbank.com", "icicibank.com", "sbibank.com", "axisbank.com",
        "kotakbank.com", "bankofbaroda.com", "pnb.co.in", "canarabank.in",
        "paytm.com", "phonepe.com", "gpay.com", "amazonpay.in",
        "zerodha.com", "groww.in", "kuvera.in", "etmoney.com",
        "sebi.gov.in", "amfiindia.com", "irdai.gov.in",
    }

    def analyze_url(self, url: str) -> Dict[str, Any]:
        """
        Comprehensive URL analysis for scam indicators.

        Returns:
            Dict with risk_score, threats list, and metadata.
        """
        threats = []
        risk_score = 0
        url_lower = url.lower().strip()

        # ─── Basic URL validation ─────────────────────────────────
        if not url_lower.startswith(("http://", "https://")):
            threats.append("Missing protocol (http/https)")
            risk_score += 10

        # ─── Extract domain ───────────────────────────────────────
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url_lower)
            domain = parsed.hostname or ""
            path = parsed.path
            query = parsed.query
        except Exception:
            threats.append("Malformed URL")
            return {"risk_score": 80, "threats": threats, "is_suspicious": True}

        # ─── Check against known scam domains ─────────────────────
        if domain in KNOWN_SCAM_DOMAINS:
            threats.append(f"Known scam domain: {domain}")
            risk_score += 50

        # ─── Domain TLD analysis ──────────────────────────────────
        for tld in self.SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                threats.append(f"Suspicious TLD: {tld}")
                risk_score += 20
                break

        # ─── Lookalike domain detection ───────────────────────────
        for legit_domain in self.LEGITIMATE_DOMAINS:
            if self._is_lookalike(domain, legit_domain):
                threats.append(f"Possible impersonation of {legit_domain}")
                risk_score += 35
                break

        # ─── URL shortener detection ──────────────────────────────
        shorteners = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "buff.ly"}
        if domain in shorteners:
            threats.append(f"URL shortener detected: {domain}")
            risk_score += 15

        # ─── IP address instead of domain ─────────────────────────
        ip_pattern = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
        if ip_pattern.match(domain):
            threats.append("IP address used instead of domain name")
            risk_score += 25

        # ─── Excessive subdomains ─────────────────────────────────
        subdomain_count = domain.count(".")
        if subdomain_count > 3:
            threats.append(f"Excessive subdomains ({subdomain_count})")
            risk_score += 10

        # ─── Phishing keyword detection in URL ───────────────────
        phishing_keywords = [
            "verify", "kyc", "update", "confirm", "secure", "account",
            "login", "signin", "auth", "bank", "urgent", "suspend",
            "claim", "prize", "winner", "free", "bonus",
        ]
        for keyword in phishing_keywords:
            if keyword in url_lower:
                threats.append(f"Phishing keyword in URL: '{keyword}'")
                risk_score += 8

        # ─── HTTP (not HTTPS) check ──────────────────────────────
        if url_lower.startswith("http://") and not url_lower.startswith("http://localhost"):
            threats.append("Not using HTTPS encryption")
            risk_score += 10

        # ─── Query parameter analysis ─────────────────────────────
        if query:
            suspicious_params = ["token", "password", "otp", "pin", "account", "card"]
            for param in suspicious_params:
                if param in query.lower():
                    threats.append(f"Sensitive data in URL parameter: '{param}'")
                    risk_score += 15

        # ─── Path analysis ────────────────────────────────────────
        suspicious_paths = ["wp-admin", "phpmyadmin", ".env", "config", "backup"]
        for sp in suspicious_paths:
            if sp in path.lower():
                threats.append(f"Suspicious path component: '{sp}'")
                risk_score += 10

        # Clamp
        risk_score = min(100, max(0, risk_score))

        return {
            "url": url,
            "domain": domain,
            "risk_score": risk_score,
            "is_suspicious": risk_score >= 30,
            "threats": threats,
            "threat_count": len(threats),
            "ssl_required": risk_score < 30,
        }

    def _is_lookalike(self, domain: str, legitimate: str) -> bool:
        """Check if domain is a lookalike/typosquat of a legitimate domain."""
        # Remove TLD for comparison
        leg_name = legitimate.split(".")[0]
        dom_parts = domain.split(".")

        # Check for character substitution
        for part in dom_parts:
            if len(part) < 3:
                continue
            # Common substitutions
            normalized = part.replace("0", "o").replace("1", "l").replace("3", "e")
            leg_normalized = leg_name.replace("0", "o").replace("1", "l").replace("3", "e")

            if normalized == leg_normalized and part != leg_name:
                return True

            # Levenshtein-like: if edit distance is very small
            if len(part) == len(leg_name):
                diff_count = sum(1 for a, b in zip(part, leg_name) if a != b)
                if 0 < diff_count <= 2:
                    return True

            # Homograph attacks (Cyrillic, etc.)
            suspicious_chars = {"а": "a", "е": "e", "о": "o", "р": "p", "с": "c"}
            translated = "".join(suspicious_chars.get(c, c) for c in part)
            if translated == leg_name:
                return True

        return False


# ═══════════════════════════════════════════════════════════════════════════════
# Phone Reputation Engine
# ═══════════════════════════════════════════════════════════════════════════════

class PhoneReputationEngine:
    """Check phone number reputation against scam reports."""

    # Indian mobile number patterns
    INDIAN_MOBILE = re.compile(r"^(?:\+91|91|0)?[6-9]\d{9}$")

    # International scam hotspots (area codes frequently used in scams)
    HIGH_RISK_PREFIXES = {
        "+1415": "San Francisco area — common in tech support scams",
        "+1201": "New Jersey area — common in IRS/insurance scams",
        "+4470": "UK premium rate — common in prize/lottery scams",
        "+971": "UAE — common in business email compromise",
        "+612": "Australia — common in ATO/tax scams",
    }

    def analyze_phone(self, phone_number: str) -> Dict[str, Any]:
        """
        Analyze a phone number for scam indicators.

        Returns:
            Dict with risk assessment.
        """
        threats = []
        risk_score = 0
        phone = phone_number.strip().replace(" ", "").replace("-", "")

        # ─── Format check ─────────────────────────────────────────
        if not self.INDIAN_MOBILE.match(phone.lstrip("+").lstrip("0")):
            # Could be international
            for prefix, desc in self.HIGH_RISK_PREFIXES.items():
                if phone.startswith(prefix):
                    threats.append(f"High-risk international prefix: {prefix} — {desc}")
                    risk_score += 30
                    break

        # ─── Premium rate detection ───────────────────────────────
        premium_prefixes = ["1900", "1901", "1902", "1903", "900", "901"]
        for pp in premium_prefixes:
            if phone.endswith(pp) or phone.endswith(pp[1:]):
                threats.append(f"Premium rate number detected (prefix {pp})")
                risk_score += 25

        # ─── VoIP indicator ──────────────────────────────────────
        voip_prefixes = ["+4470", "+4476", "+4477", "+4478", "+4479"]
        for vp in voip_prefixes:
            if phone.startswith(vp):
                threats.append("VoIP number (can be spoofed)")
                risk_score += 15

        # ─── Sequential/repeated digits ──────────────────────────
        digits = re.sub(r"\D", "", phone)
        if len(digits) >= 6:
            # Check for repeated digits
            if len(set(digits[-4:])) == 1:
                threats.append("Repeated digits at end — possible fake number")
                risk_score += 10

            # Check for sequential digits
            sequential = all(
                int(digits[i]) == int(digits[i-1]) + 1
                for i in range(max(0, len(digits)-4), len(digits))
                if i > 0
            )
            if sequential:
                threats.append("Sequential digits — possible fake number")
                risk_score += 10

        risk_score = min(100, max(0, risk_score))

        return {
            "phone_number": phone_number,
            "risk_score": risk_score,
            "is_suspicious": risk_score >= 30,
            "threats": threats,
            "threat_count": len(threats),
            "is_indian_mobile": bool(self.INDIAN_MOBILE.match(phone.lstrip("+").lstrip("0"))),
        }

    async def get_phone_reputation(
        self,
        session: AsyncSession,
        phone_number: str,
    ) -> ReputationScore:
        """Get phone number reputation from scam reports database."""
        # Count reports mentioning this phone number
        reports = await session.execute(
            select(ScamReport).where(
                ScamReport.scam_phone == phone_number,
                ScamReport.status != "dismissed",
            )
        )
        report_list = reports.scalars().all()

        report_count = len(report_list)
        verified_count = sum(1 for r in report_list if r.verified)
        scam_types = list(set(r.scam_type for r in report_list))
        regions = list(set(filter(None, [r.city for r in report_list])))
        total_lost = sum(r.amount_lost or 0 for r in report_list)

        # Calculate score
        if report_count == 0:
            score = 0.5  # Unknown
            risk_level = "UNKNOWN"
        else:
            # More reports = lower score
            score = max(0.0, 1.0 - (report_count * 0.15) - (verified_count * 0.1))
            if score < 0.2:
                risk_level = "DANGEROUS"
            elif score < 0.4:
                risk_level = "SUSPICIOUS"
            else:
                risk_level = "UNCERTAIN"

        first_seen = min((r.created_at for r in report_list), default=None)
        last_seen = max((r.created_at for r in report_list), default=None)

        return ReputationScore(
            entity=phone_number,
            entity_type="phone",
            score=score,
            risk_level=risk_level,
            report_count=report_count,
            verified_reports=verified_count,
            first_seen=first_seen,
            last_seen=last_seen,
            associated_scam_types=scam_types,
            regions=regions,
            total_amount_lost=total_lost,
        )


# ═══════════════════════════════════════════════════════════════════════════════
# Scam Trend Analyzer
# ═══════════════════════════════════════════════════════════════════════════════

class ScamTrendAnalyzer:
    """Analyzes trends in scam activity over time."""

    async def analyze_trends(
        self,
        session: AsyncSession,
        days: int = 30,
    ) -> List[ScamTrend]:
        """
        Analyze scam trends over the specified period.

        Compares the most recent half of the period with the earlier half
        to detect increases, decreases, and new scam variants.
        """
        cutoff = datetime.utcnow() - timedelta(days=days)
        mid_point = datetime.utcnow() - timedelta(days=days // 2)

        # Get reports in first half
        first_half = await session.execute(
            select(ScamReport).where(
                ScamReport.created_at >= cutoff,
                ScamReport.created_at < mid_point,
            )
        )
        first_reports = first_half.scalars().all()

        # Get reports in second half
        second_half = await session.execute(
            select(ScamReport).where(
                ScamReport.created_at >= mid_point,
            )
        )
        second_reports = second_half.scalars().all()

        trends = []

        # Compare scam type distributions
        first_types = Counter(r.scam_type for r in first_reports)
        second_types = Counter(r.scam_type for r in second_reports)

        all_types = set(first_types.keys()) | set(second_types.keys())

        for scam_type in all_types:
            first_count = first_types.get(scam_type, 0)
            second_count = second_types.get(scam_type, 0)

            if first_count == 0 and second_count > 0:
                # New scam type appearing
                trends.append(ScamTrend(
                    trend_type="new_variant",
                    scam_type=scam_type,
                    description=f"New wave of {scam_type} scams detected",
                    severity="high",
                    affected_regions=[],
                    estimated_growth_pct=100.0,
                    data_points=second_count,
                    confidence=min(0.9, second_count * 0.1),
                ))
            elif first_count > 0:
                growth = ((second_count - first_count) / first_count) * 100
                if abs(growth) > 20:  # Significant change
                    trends.append(ScamTrend(
                        trend_type="increasing" if growth > 0 else "decreasing",
                        scam_type=scam_type,
                        description=(
                            f"{scam_type} scams {'increased' if growth > 0 else 'decreased'} "
                            f"by {abs(growth):.0f}%"
                        ),
                        severity="high" if growth > 50 else "medium",
                        affected_regions=[],
                        estimated_growth_pct=growth,
                        data_points=first_count + second_count,
                        confidence=min(0.85, (first_count + second_count) * 0.05),
                    ))

        # Sort by severity
        severity_order = {"high": 0, "medium": 1, "low": 2}
        trends.sort(key=lambda t: severity_order.get(t.severity, 3))

        return trends

    async def get_geographic_heatmap(
        self,
        session: AsyncSession,
        days: int = 90,
    ) -> Dict[str, int]:
        """Get geographic distribution of scam reports."""
        cutoff = datetime.utcnow() - timedelta(days=days)

        result = await session.execute(
            select(ScamReport.city, func.count(ScamReport.id))
            .where(
                ScamReport.created_at >= cutoff,
                ScamReport.city.isnot(None),
            )
            .group_by(ScamReport.city)
            .order_by(desc(func.count(ScamReport.id)))
        )

        return {row[0]: row[1] for row in result.all()}


# ═══════════════════════════════════════════════════════════════════════════════
# Analytics Aggregator
# ═══════════════════════════════════════════════════════════════════════════════

class ScamAnalytics:
    """Aggregate scam detection analytics."""

    async def get_detection_stats(
        self,
        session: AsyncSession,
        user_id: str = None,
    ) -> Dict[str, Any]:
        """Get comprehensive scam detection statistics."""
        # Base query filters
        filters = [ScanHistory.scan_type == "scam"]
        if user_id:
            filters.append(ScanHistory.user_id == user_id)

        # Total scans
        total = await session.execute(
            select(func.count(ScanHistory.id)).where(and_(*filters))
        )
        total_scans = total.scalar() or 0

        # Risk level distribution
        risk_dist = await session.execute(
            select(
                ScanHistory.risk_level,
                func.count(ScanHistory.id)
            )
            .where(and_(*filters, ScanHistory.risk_level.isnot(None)))
            .group_by(ScanHistory.risk_level)
        )
        risk_distribution = {row[0]: row[1] for row in risk_dist.all()}

        # Scam type distribution
        type_dist = await session.execute(
            select(
                ScanHistory.scam_type,
                func.count(ScanHistory.id)
            )
            .where(and_(*filters, ScanHistory.scam_type.isnot(None)))
            .group_by(ScanHistory.scam_type)
        )
        scam_types = {row[0]: row[1] for row in type_dist.all()}

        # Average risk score
        avg_score = await session.execute(
            select(func.avg(ScanHistory.risk_score))
            .where(and_(*filters, ScanHistory.risk_score.isnot(None)))
        )
        avg_risk_score = avg_score.scalar() or 0

        # High-risk detections
        high_risk = await session.execute(
            select(func.count(ScanHistory.id))
            .where(and_(*filters, ScanHistory.risk_score >= 70))
        )
        high_risk_count = high_risk.scalar() or 0

        # Detection rate (% classified as scam or dangerous)
        detected = await session.execute(
            select(func.count(ScanHistory.id))
            .where(
                and_(
                    *filters,
                    ScanHistory.risk_level.in_(["CONFIRMED_SCAM", "DANGEROUS"])
                )
            )
        )
        detected_count = detected.scalar() or 0
        detection_rate = (detected_count / total_scans * 100) if total_scans > 0 else 0

        # Monthly trend
        monthly = await session.execute(
            select(
                func.strftime("%Y-%m", ScanHistory.created_at).label("month"),
                func.count(ScanHistory.id),
                func.avg(ScanHistory.risk_score),
            )
            .where(and_(*filters))
            .group_by("month")
            .order_by("month")
            .limit(12)
        )
        monthly_trend = [
            {"month": row[0], "count": row[1], "avg_risk": round(row[2] or 0, 1)}
            for row in monthly.all()
        ]

        # Community reports count
        reports_count = await session.execute(
            select(func.count(ScamReport.id)).where(ScamReport.status != "dismissed")
        )
        community_reports = reports_count.scalar() or 0

        verified_reports = await session.execute(
            select(func.count(ScamReport.id)).where(ScamReport.verified == True)
        )
        verified_count = verified_reports.scalar() or 0

        return {
            "total_scans": total_scans,
            "risk_distribution": risk_distribution,
            "scam_type_distribution": scam_types,
            "avg_risk_score": round(avg_risk_score, 1),
            "high_risk_detected": high_risk_count,
            "detection_rate": round(detection_rate, 1),
            "monthly_trend": monthly_trend,
            "community_reports": community_reports,
            "verified_reports": verified_count,
        }

    async def get_user_scan_history(
        self,
        session: AsyncSession,
        user_id: str,
        scan_type: str = None,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """Get user's scan history."""
        query = select(ScanHistory).where(ScanHistory.user_id == user_id)

        if scan_type:
            query = query.where(ScanHistory.scan_type == scan_type)

        query = query.order_by(desc(ScanHistory.created_at)).limit(limit)

        result = await session.execute(query)
        scans = result.scalars().all()

        return [
            {
                "id": s.id,
                "scan_type": s.scan_type,
                "input_text": s.input_text[:200] if s.input_text else None,
                "risk_level": s.risk_level,
                "risk_score": s.risk_score,
                "scam_type": s.scam_type,
                "health_score": s.health_score,
                "created_at": s.created_at.isoformat() if s.created_at else None,
            }
            for s in scans
        ]


# ═══════════════════════════════════════════════════════════════════════════════
# Singleton instances
# ═══════════════════════════════════════════════════════════════════════════════

url_engine = URLReputationEngine()
phone_engine = PhoneReputationEngine()
trend_analyzer = ScamTrendAnalyzer()
scam_analytics = ScamAnalytics()
