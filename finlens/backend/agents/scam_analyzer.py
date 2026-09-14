"""
═══════════════════════════════════════════════════════════════════════════════
FinLens Enhanced Scam Analyzer Agent
═══════════════════════════════════════════════════════════════════════════════

Multi-strategy scam detection engine combining:
1. Rule-based pattern matching (fast, deterministic)
2. NLP feature extraction (linguistic signals)
3. LLM-powered deep analysis (contextual understanding)
4. Community intelligence (crowdsourced reports)
5. Behavioral analysis (urgency, pressure, social engineering tactics)

Each strategy produces an independent confidence score. The final verdict
is a weighted ensemble of all strategies, ensuring robust detection even
when individual strategies fail.
"""

import re
import json
import math
import hashlib
import logging
from typing import Optional
from pathlib import Path
from datetime import datetime, timedelta
from collections import Counter
from dataclasses import dataclass, field

logger = logging.getLogger("finlens.scam_analyzer")

# ═══════════════════════════════════════════════════════════════════════
# Knowledge Base Loading
# ═══════════════════════════════════════════════════════════════════════

KNOWLEDGE_PATH = Path(__file__).parent.parent / "knowledge" / "scam_patterns.json"

def _load_knowledge_base() -> dict:
    """Load and cache the scam patterns knowledge base."""
    try:
        with open(KNOWLEDGE_PATH, encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        logger.warning(f"Knowledge base not found at {KNOWLEDGE_PATH}, using built-in patterns")
        return _builtin_knowledge_base()
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse knowledge base: {e}")
        return _builtin_knowledge_base()


def _builtin_knowledge_base() -> dict:
    """Fallback built-in knowledge base if file is missing."""
    return {
        "scam_categories": {
            "upi_fraud": {
                "name": "UPI Payment Fraud",
                "severity": "critical",
                "keywords": ["upi", "pin", "qr", "collect", "vpa", "gpay", "phonepe", "paytm"],
                "patterns": ["share.*pin", "qr.*code.*scan", "upi.*collect", "verify.*account.*upi"],
                "red_flags": ["asking for upi pin", "sharing qr to receive money", "fake collect request"]
            },
            "investment_scam": {
                "name": "Fake Investment Scheme",
                "severity": "critical",
                "keywords": ["invest", "return", "profit", "guaranteed", "daily", "weekly", "double", "crypto", "trading bot"],
                "patterns": ["guaranteed.*return", "double.*money", "risk.?free", "daily.*profit", "ai.*trading.*bot"],
                "red_flags": ["guaranteed returns", "no risk", "double your money", "limited time"]
            },
            "phishing": {
                "name": "Phishing Scam",
                "severity": "high",
                "keywords": ["verify", "kyc", "account", "suspend", "block", "urgent", "click", "link"],
                "patterns": ["account.*suspend", "kyc.*update", "verify.*within.*hour", "click.*link"],
                "red_flags": ["fake urls", "urgent action", "account suspension threat"]
            },
            "otp_fraud": {
                "name": "OTP Fraud",
                "severity": "critical",
                "keywords": ["otp", "code", "verification", "share", "send"],
                "patterns": ["share.*otp", "tell.*code", "forward.*otp", "verification.*code"],
                "red_flags": ["asking for otp", "pretending to be bank"]
            }
        }
    }


KNOWLEDGE_BASE = _load_knowledge_base()


# ═══════════════════════════════════════════════════════════════════════
# Data Classes for Analysis Results
# ═══════════════════════════════════════════════════════════════════════

@dataclass
class StrategyResult:
    """Result from a single detection strategy."""
    strategy_name: str
    confidence: float  # 0.0 to 1.0
    risk_level: str    # SAFE, SUSPICIOUS, DANGEROUS, CONFIRMED_SCAM
    risk_score: int    # 0 to 100
    scam_type: Optional[str] = None
    matched_patterns: list = field(default_factory=list)
    evidence: list = field(default_factory=list)
    reasoning: str = ""


@dataclass
class AnalysisResult:
    """Final combined analysis result from all strategies."""
    risk_level: str
    risk_score: int
    scam_type: Optional[str]
    confidence: int
    verdict: str
    explanation: str
    red_flags: list
    safe_indicators: list
    action: str
    educational_note: str
    strategies_used: list
    strategy_scores: dict
    detection_metadata: dict
    linguistic_analysis: Optional[dict] = None
    similar_reports: Optional[list] = None


# ═══════════════════════════════════════════════════════════════════════
# Strategy 1: Rule-Based Pattern Matching
# ═══════════════════════════════════════════════════════════════════════

class RuleBasedDetector:
    """
    Fast, deterministic scam detection using regex patterns,
    keyword matching, and known scam signatures.
    """

    # High-confidence scam keywords (score boost: +15 each)
    CRITICAL_KEYWORDS = {
        "upi pin", "share pin", "send otp", "share otp", "tell me the code",
        "guaranteed returns", "risk free", "double your money", "100% profit",
        "digital arrest", "cbi officer", "money laundering", "transfer to safe account",
        "click this link immediately", "account will be frozen", "kyc update",
    }

    # Moderate-risk keywords (score boost: +8 each)
    MODERATE_KEYWORDS = {
        "urgent", "immediately", "within 24 hours", "last chance", "limited time",
        "congratulations", "you won", "you have been selected", "claim your prize",
        "work from home", "earn per day", "no experience needed", "registration fee",
        "join now", "act fast", "don't tell anyone", "keep this confidential",
        "process fee", "refundable", "investment opportunity", "passive income",
    }

    # Safe indicators (score reduction: -10 each)
    SAFE_KEYWORDS = {
        "your monthly statement", "account balance as on", "transaction alert",
        "salary credited", "emi debited", "interest credited", "account statement",
        "your order has been delivered", "your appointment is confirmed",
    }

    # Phone number patterns (Indian)
    INDIAN_PHONE_PATTERN = re.compile(
        r'(?:(?:\+91|91|0)?[-.\s]?)?[6-9]\d{9}'
    )

    # UPI ID pattern
    UPI_PATTERN = re.compile(
        r'[\w.-]+@[\w]+'
    )

    # URL patterns
    SUSPICIOUS_URL_PATTERNS = [
        re.compile(r'https?://[^/]*\.(tk|ml|ga|cf|gq)/', re.IGNORECASE),
        re.compile(r'https?://bit\.ly/', re.IGNORECASE),
        re.compile(r'https?://tinyurl\.com/', re.IGNORECASE),
        re.compile(r'https?://[^/]*bank[^/]*\.(?!com|co\.in|in)', re.IGNORECASE),
        re.compile(r'https?://.*\.xyz/', re.IGNORECASE),
        re.compile(r'https?://.*verify.*kyc', re.IGNORECASE),
    ]

    # Legitimate URL patterns
    LEGITIMATE_URL_PATTERNS = [
        re.compile(r'https?://.*\.(com|co\.in|in|org|gov\.in)/', re.IGNORECASE),
        re.compile(r'https?://(www\.)?(google|microsoft|apple|amazon)\.', re.IGNORECASE),
    ]

    def detect(self, message: str) -> StrategyResult:
        """Run rule-based detection on the message."""
        msg_lower = message.lower().strip()
        score = 0
        matched = []
        evidence = []
        scam_type = None

        # ─── Critical keyword detection ───────────────────────────
        for keyword in self.CRITICAL_KEYWORDS:
            if keyword in msg_lower:
                score += 15
                matched.append(f"critical_keyword:{keyword}")
                evidence.append(f"Contains high-risk phrase: '{keyword}'")

        # ─── Moderate keyword detection ───────────────────────────
        for keyword in self.MODERATE_KEYWORDS:
            if keyword in msg_lower:
                score += 8
                matched.append(f"moderate_keyword:{keyword}")
                evidence.append(f"Contains suspicious phrase: '{keyword}'")

        # ─── Safe indicator detection ─────────────────────────────
        safe_count = 0
        for keyword in self.SAFE_KEYWORDS:
            if keyword in msg_lower:
                safe_count += 1
                score -= 10
                matched.append(f"safe_keyword:{keyword}")
                evidence.append(f"Contains legitimate phrase: '{keyword}'")

        # ─── URL analysis ─────────────────────────────────────────
        suspicious_urls = 0
        for pattern in self.SUSPICIOUS_URL_PATTERNS:
            if pattern.search(message):
                suspicious_urls += 1
                score += 12
                matched.append("suspicious_url")
                evidence.append("Contains suspicious URL pattern")

        # ─── Phone number analysis ────────────────────────────────
        phones = self.INDIAN_PHONE_PATTERN.findall(message)
        if len(phones) > 0:
            # Multiple phone numbers is suspicious
            if len(phones) > 1:
                score += 5
                matched.append("multiple_phones")
                evidence.append(f"Contains {len(phones)} phone numbers")
            # Personal contact request is suspicious
            if any(kw in msg_lower for kw in ["call", "whatsapp", "contact", "message"]):
                score += 3
                matched.append("phone_contact_request")
                evidence.append("Requests personal contact via phone")

        # ─── UPI ID detection ─────────────────────────────────────
        upi_ids = self.UPI_PATTERN.findall(message)
        if upi_ids:
            score += 5
            matched.append("upi_id_found")
            evidence.append(f"Contains UPI ID(s): {', '.join(upi_ids[:3])}")

        # ─── Urgency scoring ──────────────────────────────────────
        urgency_patterns = [
            (r'\bwithin\s+\d+\s+hours?\b', 8),
            (r'\bbefore\s+(midnight|today|tomorrow)\b', 6),
            (r'\bonly\s+\d+\s+minutes?\b', 7),
            (r'\bact\s+now\b', 5),
            (r'\bdo\s+not\s+delay\b', 6),
            (r'\bfailing\s+to\s+\w+\b', 7),
            (r'\bwill\s+be\s+(deactivated|blocked|suspended|closed)\b', 10),
        ]
        for pattern, boost in urgency_patterns:
            if re.search(pattern, msg_lower):
                score += boost
                matched.append(f"urgency:{pattern}")
                evidence.append(f"Contains urgency pressure (+'{pattern}')")

        # ─── Scam type classification ─────────────────────────────
        if score >= 30:
            scam_type = self._classify_scam_type(msg_lower)

        # ─── Clamp score ──────────────────────────────────────────
        score = max(0, min(100, score))

        # ─── Determine risk level ─────────────────────────────────
        risk_score = score
        if risk_score >= 70:
            risk_level = "CONFIRMED_SCAM"
        elif risk_score >= 50:
            risk_level = "DANGEROUS"
        elif risk_score >= 30:
            risk_level = "SUSPICIOUS"
        else:
            risk_level = "SAFE"

        confidence = min(95, max(40, 60 + (len(matched) * 5)))

        return StrategyResult(
            strategy_name="rule_based",
            confidence=confidence / 100,
            risk_level=risk_level,
            risk_score=risk_score,
            scam_type=scam_type,
            matched_patterns=matched,
            evidence=evidence,
            reasoning=f"Rule-based analysis found {len(matched)} indicators. Score: {risk_score}/100"
        )

    def _classify_scam_type(self, msg_lower: str) -> str:
        """Classify the specific type of scam based on content."""
        scores = {}
        for cat_id, cat in KNOWLEDGE_BASE.get("scam_categories", {}).items():
            cat_score = 0
            keywords = cat.get("keywords", [])
            for kw in keywords:
                if kw.lower() in msg_lower:
                    cat_score += 1
            patterns = cat.get("patterns", [])
            for pat in patterns:
                try:
                    if re.search(pat, msg_lower):
                        cat_score += 2
                except re.error:
                    continue
            if cat_score > 0:
                scores[cat_id] = cat_score

        if scores:
            best = max(scores, key=scores.get)
            return KNOWLEDGE_BASE.get("scam_categories", {}).get(best, {}).get("name", best)
        return "Unknown Scam"


# ═══════════════════════════════════════════════════════════════════════
# Strategy 2: NLP Linguistic Analysis
# ═══════════════════════════════════════════════════════════════════════

class LinguisticAnalyzer:
    """
    Analyzes linguistic features of the message to detect scam indicators.
    Scam messages have distinctive linguistic patterns:
    - Excessive capitalization
    - Excessive exclamation marks
    - Poor grammar/spelling
    - Emotional manipulation words
    - Social engineering tactics
    """

    # Emotional manipulation words
    EMOTIONAL_TRIGGERS = {
        "fear": ["fear", "scared", "danger", "threat", "police", "arrest", "jail", "legal action",
                 "warning", "urgent", "emergency", "immediately", "last chance"],
        "greed": ["win", "won", "prize", "reward", "cashback", "bonus", "free money", "million",
                  "jackpot", "lottery", "congratulations", "selected"],
        "trust": ["official", "government", "bank representative", "customer care", "verification",
                  "security department", "authorized", "certified"],
        "scarcity": ["limited", "last", "final", "only", "hurry", "expiring", "countdown",
                     "before it's too late", "don't miss", "exclusive"],
        "authority": ["notice", "order", "directive", "compliance", "mandatory", "required by law",
                      "sebi", "rbi", "cybercrime", "department"],
    }

    # Grammar/spelling red flags (common in scam messages)
    GRAMMAR_RED_FLAGS = [
        re.compile(r'\b(dear\s+(customer|user|sir|madam))\b', re.I),
        re.compile(r'\b(your\s+account\s+(will be|is going to be))\b', re.I),
        re.compile(r'\b(verify\s+your\s+(account|identity|kyc))\b', re.I),
        re.compile(r'\b(urgent\s+action\s+(required|needed))\b', re.I),
        re.compile(r'(!{2,})'),  # Multiple exclamation marks
        re.compile(r'([A-Z]\s*){5,}'),  # Excessive caps (words in all caps)
    ]

    # Social engineering tactics
    SOCIAL_ENGINEERING_PATTERNS = {
        "impersonation": [
            re.compile(r'(this is|calling from|representative of)\s+(sbi|hdfc|icici|axis|paytm|google pay|phonepe)', re.I),
            re.compile(r'(bank|police|cybercrime)\s+(department|office|branch)', re.I),
        ],
        "reciprocity": [
            re.compile(r'(you have been|we have|as a)\s+(selected|chosen|awarded|given)', re.I),
            re.compile(r'(special|exclusive|vip)\s+(offer|deal|opportunity|access)', re.I),
        ],
        "commitment_and_consistency": [
            re.compile(r'(as you|you previously|following your)\s+(requested|applied|registered|signed up)', re.I),
            re.compile(r'(completing|finalize|confirm)\s+(your|the)\s+(registration|application|booking)', re.I),
        ],
        "social_proof": [
            re.compile(r'(thousands of|lakhs of|millions of)\s+(people|users|customers)', re.I),
            re.compile(r'(others have|people are|users already)', re.I),
        ],
    }

    def analyze(self, message: str) -> StrategyResult:
        """Perform linguistic analysis on the message."""
        msg_lower = message.lower().strip()
        score = 0
        matched = []
        evidence = []
        linguistic_features = {}

        # ─── Capitalization analysis ──────────────────────────────
        words = message.split()
        if len(words) > 3:
            caps_words = sum(1 for w in words if w.isupper() and len(w) > 1)
            caps_ratio = caps_words / len(words)
            linguistic_features["caps_ratio"] = round(caps_ratio, 3)
            if caps_ratio > 0.3:
                score += 12
                matched.append("excessive_caps")
                evidence.append(f"Excessive capitalization ({caps_ratio:.0%} of words)")

        # ─── Punctuation analysis ─────────────────────────────────
        excl_count = message.count('!')
        linguistic_features["exclamation_count"] = excl_count
        if excl_count > 3:
            score += 8
            matched.append("excessive_exclamations")
            evidence.append(f"Excessive exclamation marks ({excl_count})")

        ellipsis_count = message.count('...')
        if ellipsis_count > 0:
            score += 3
            matched.append("dramatic_ellipsis")
            evidence.append("Uses dramatic ellipsis")

        # ─── Emotional manipulation scoring ───────────────────────
        emotion_scores = {}
        for emotion, triggers in self.EMOTIONAL_TRIGGERS.items():
            count = sum(1 for t in triggers if t in msg_lower)
            if count > 0:
                emotion_scores[emotion] = count
                if count >= 3:
                    score += 15
                    matched.append(f"strong_{emotion}_appeal")
                    evidence.append(f"Strong {emotion} manipulation ({count} triggers)")
                elif count >= 1:
                    score += 5
                    matched.append(f"moderate_{emotion}_appeal")
                    evidence.append(f"Moderate {emotion} language ({count} triggers)")

        linguistic_features["emotion_scores"] = emotion_scores

        # ─── Social engineering pattern detection ─────────────────
        tactics_found = []
        for tactic, patterns in self.SOCIAL_ENGINEERING_PATTERNS.items():
            for pat in patterns:
                if pat.search(message):
                    tactics_found.append(tactic)
                    break

        if tactics_found:
            score += len(tactics_found) * 10
            for tactic in tactics_found:
                matched.append(f"social_engineering:{tactic}")
                evidence.append(f"Social engineering tactic: {tactic}")
        linguistic_features["social_engineering_tactics"] = tactics_found

        # ─── Grammar/spelling analysis ────────────────────────────
        grammar_issues = 0
        for pattern in self.GRAMMAR_RED_FLAGS:
            if pattern.search(message):
                grammar_issues += 1
        linguistic_features["grammar_issues"] = grammar_issues
        if grammar_issues > 0:
            score += grammar_issues * 4
            matched.append("grammar_issues")
            evidence.append(f"{grammar_issues} grammar/spelling red flags")

        # ─── Message length analysis ──────────────────────────────
        linguistic_features["char_count"] = len(message)
        linguistic_features["word_count"] = len(words)

        # Very short messages with urgency are suspicious
        if len(words) < 20 and any(kw in msg_lower for kw in ["urgent", "immediately", "now", "today"]):
            score += 8
            matched.append("short_urgent_message")
            evidence.append("Short message with urgency indicators")

        # ─── Score normalization ──────────────────────────────────
        score = max(0, min(100, score))
        risk_score = score

        if risk_score >= 70:
            risk_level = "CONFIRMED_SCAM"
        elif risk_score >= 50:
            risk_level = "DANGEROUS"
        elif risk_score >= 25:
            risk_level = "SUSPICIOUS"
        else:
            risk_level = "SAFE"

        confidence = min(90, max(30, 50 + (len(matched) * 8)))

        return StrategyResult(
            strategy_name="linguistic_analysis",
            confidence=confidence / 100,
            risk_level=risk_level,
            risk_score=risk_score,
            scam_type=None,
            matched_patterns=matched,
            evidence=evidence,
            reasoning=f"Linguistic analysis found {len(matched)} indicators. Emotions: {emotion_scores}. Tactics: {tactics_found}"
        )


# ═══════════════════════════════════════════════════════════════════════
# Strategy 3: Structural Analysis
# ═══════════════════════════════════════════════════════════════════════

class StructuralAnalyzer:
    """
    Analyzes the structural features of the message:
    - Message formatting patterns
    - Number/amount patterns
    - Date/time pressure patterns
    - Contact information patterns
    - Link analysis
    """

    # Money amount patterns (Indian format)
    MONEY_PATTERNS = [
        re.compile(r'₹\s*[\d,]+(?:\.\d{2})?'),
        re.compile(r'Rs\.?\s*[\d,]+(?:\.\d{2})?'),
        re.compile(r'[\d,]+\s*(?:lakh|lac|crore|cr)\b', re.I),
        re.compile(r'(?:INR|inr)\s*[\d,]+'),
    ]

    # Date patterns that create urgency
    DATE_URGENCY_PATTERNS = [
        re.compile(r'\b(today|tonight|midnight|end of day)\b', re.I),
        re.compile(r'\bwithin\s+\d+\s+(hour|minute|day)s?\b', re.I),
        re.compile(r'\bbefore\s+\d{1,2}[:/]\d{2}\b', re.I),
        re.compile(r'\bexpires?\s+(on|at|in|today)\b', re.I),
    ]

    # Formatting red flags
    FORMATTING_FLAGS = {
        "bullet_points": re.compile(r'[•●◦▪-]\s*\w'),
        "numbered_list": re.compile(r'^\d+[.)]\s+\w', re.M),
        "excessive_spacing": re.compile(r'\s{3,}'),
        "mixed_scripts": re.compile(r'[\u0900-\u097F].*[a-zA-Z]|[a-zA-Z].*[\u0900-\u097F]'),
        "emoji_heavy": re.compile(r'[\U0001F600-\U0001F64F\U0001F300-\U0001F5FF\U0001F680-\U0001F6FF]{3,}'),
    }

    def analyze(self, message: str) -> StrategyResult:
        """Perform structural analysis on the message."""
        score = 0
        matched = []
        evidence = []
        structural_features = {}

        # ─── Money amount detection ───────────────────────────────
        amounts = []
        for pattern in self.MONEY_PATTERNS:
            amounts.extend(pattern.findall(message))
        structural_features["money_amounts"] = amounts
        structural_features["amount_count"] = len(amounts)

        if len(amounts) > 0:
            # Messages with specific large amounts are more suspicious
            score += min(15, len(amounts) * 5)
            matched.append("contains_monetary_amounts")
            evidence.append(f"Contains {len(amounts)} monetary amount(s)")

        # ─── Date urgency detection ───────────────────────────────
        urgency_dates = 0
        for pattern in self.DATE_URGENCY_PATTERNS:
            if pattern.search(message):
                urgency_dates += 1
        structural_features["date_urgency_count"] = urgency_dates

        if urgency_dates > 0:
            score += urgency_dates * 8
            matched.append("date_urgency")
            evidence.append(f"Contains {urgency_dates} time-pressure element(s)")

        # ─── Formatting analysis ──────────────────────────────────
        format_flags = {}
        for flag_name, pattern in self.FORMATTING_FLAGS.items():
            if pattern.search(message):
                format_flags[flag_name] = True
        structural_features["format_flags"] = format_flags

        if format_flags.get("emoji_heavy"):
            score += 5
            matched.append("emoji_heavy")
            evidence.append("Message uses excessive emojis (common in scams)")

        if format_flags.get("mixed_scripts"):
            score += 3
            matched.append("mixed_scripts")
            evidence.append("Message mixes scripts (Hindi + English)")

        # ─── Message structure scoring ────────────────────────────
        lines = message.split('\n')
        structural_features["line_count"] = len(lines)

        # Very long messages with formatting are often copied scam templates
        if len(lines) > 10 and len(message) > 500:
            score += 8
            matched.append("template_message")
            evidence.append("Message appears to be a pre-written template")

        # ─── Contact information density ──────────────────────────
        contact_info = 0
        if re.search(r'[\w.-]+@[\w]+', message):  # Email/UPI
            contact_info += 1
        if re.search(r'https?://', message):  # URLs
            contact_info += 1
        if re.search(r'\b\d{10}\b', message):  # Phone numbers
            contact_info += 1

        structural_features["contact_info_count"] = contact_info
        if contact_info >= 2:
            score += 8
            matched.append("multiple_contact_methods")
            evidence.append(f"Provides {contact_info} contact methods (pressure to respond)")

        # ─── Score normalization ──────────────────────────────────
        score = max(0, min(100, score))
        risk_score = score

        if risk_score >= 65:
            risk_level = "CONFIRMED_SCAM"
        elif risk_score >= 45:
            risk_level = "DANGEROUS"
        elif risk_score >= 25:
            risk_level = "SUSPICIOUS"
        else:
            risk_level = "SAFE"

        confidence = min(85, max(30, 55 + (len(matched) * 6)))

        return StrategyResult(
            strategy_name="structural_analysis",
            confidence=confidence / 100,
            risk_level=risk_level,
            risk_score=risk_score,
            scam_type=None,
            matched_patterns=matched,
            evidence=evidence,
            reasoning=f"Structural analysis found {len(matched)} indicators. Amounts: {amounts}. Urgency: {urgency_dates}"
        )


# ═══════════════════════════════════════════════════════════════════════
# Ensemble Verdict Engine
# ═══════════════════════════════════════════════════════════════════════

class VerdictEngine:
    """
    Combines results from multiple detection strategies into a
    final verdict using weighted ensemble scoring.
    """

    # Strategy weights — LLM is dominant because it catches scams
    # rule-based engines miss (social engineering, novel tactics, context)
    STRATEGY_WEIGHTS = {
        "rule_based": 0.15,
        "linguistic_analysis": 0.10,
        "structural_analysis": 0.10,
        "llm_analysis": 0.65,
    }

    RISK_LEVELS = ["SAFE", "SUSPICIOUS", "DANGEROUS", "CONFIRMED_SCAM"]

    def combine(
        self,
        strategies: list[StrategyResult],
        llm_result: Optional[dict] = None,
    ) -> dict:
        """Combine strategy results into final verdict."""
        weighted_score = 0.0
        total_weight = 0.0
        all_evidence = []
        all_matched = []
        strategy_scores = {}
        risk_votes = Counter()

        # ─── Combine rule-based strategies ────────────────────────
        for strategy in strategies:
            weight = self.STRATEGY_WEIGHTS.get(strategy.strategy_name, 0.15)
            weighted_score += strategy.risk_score * weight
            total_weight += weight
            risk_votes[strategy.risk_level] += weight
            all_evidence.extend(strategy.evidence)
            all_matched.extend(strategy.matched_patterns)
            strategy_scores[strategy.strategy_name] = {
                "risk_score": strategy.risk_score,
                "risk_level": strategy.risk_level,
                "confidence": round(strategy.confidence * 100),
                "evidence_count": len(strategy.evidence),
            }

        # ─── Integrate LLM result ────────────────────────────────
        if llm_result:
            weight = self.STRATEGY_WEIGHTS.get("llm_analysis", 0.20)
            llm_score = llm_result.get("risk_score", 50)
            weighted_score += llm_score * weight
            total_weight += weight

            llm_risk = llm_result.get("risk_level", "SUSPICIOUS")
            risk_votes[llm_risk] += weight

            strategy_scores["llm_analysis"] = {
                "risk_score": llm_score,
                "risk_level": llm_risk,
                "confidence": llm_result.get("confidence", 70),
                "evidence_count": len(llm_result.get("red_flags", [])),
            }

            # LLM evidence
            for flag in llm_result.get("red_flags", []):
                all_evidence.append(f"AI Analysis: {flag}")

        # ─── Compute final score ──────────────────────────────────
        if total_weight > 0:
            final_score = int(weighted_score / total_weight)
        else:
            final_score = 50

        # ─── Majority vote for risk level ─────────────────────────
        if risk_votes:
            final_risk_level = risk_votes.most_common(1)[0][0]
        else:
            final_risk_level = "SUSPICIOUS"

        # ─── LLM Override: if Gemini says it's a scam, trust it ──
        # This catches sophisticated scams that rule-based engines miss
        if llm_result:
            llm_score = llm_result.get("risk_score", 50)
            llm_level = llm_result.get("risk_level", "SAFE")

            # If LLM gives high confidence scam, override the ensemble
            if llm_score >= 70 and final_score < 60:
                final_score = llm_score
                final_risk_level = llm_level
            # If LLM gives moderate-high score, boost the ensemble
            elif llm_score >= 50 and final_score < 40:
                final_score = max(final_score, llm_score - 10)
                if final_risk_level == "SAFE":
                    final_risk_level = "SUSPICIOUS"

        # Override: if score is very high, force CONFIRMED_SCAM
        if final_score >= 80:
            final_risk_level = "CONFIRMED_SCAM"
        elif final_score >= 60 and final_risk_level == "SUSPICIOUS":
            final_risk_level = "DANGEROUS"

        # ─── Scam type (prefer LLM classification, fallback to rules) ──
        scam_type = None
        if llm_result and llm_result.get("scam_type"):
            scam_type = llm_result["scam_type"]
        else:
            for s in strategies:
                if s.scam_type:
                    scam_type = s.scam_type
                    break

        # ─── Confidence computation ───────────────────────────────
        # Higher when strategies agree, lower when they disagree
        if len(risk_votes) > 1:
            max_vote = max(risk_votes.values())
            agreement = max_vote / sum(risk_votes.values())
        else:
            agreement = 1.0

        evidence_quality = min(1.0, len(all_evidence) / 10)
        confidence = int(min(98, (agreement * 60) + (evidence_quality * 30) + 10))

        # Deduplicate evidence
        seen = set()
        unique_evidence = []
        for e in all_evidence:
            key = e.lower().strip()
            if key not in seen:
                seen.add(key)
                unique_evidence.append(e)

        return {
            "risk_level": final_risk_level,
            "risk_score": final_score,
            "scam_type": scam_type,
            "confidence": confidence,
            "strategies_used": [s.strategy_name for s in strategies] + (["llm_analysis"] if llm_result else []),
            "strategy_scores": strategy_scores,
            "evidence": unique_evidence[:20],  # Cap at 20 items
            "all_matched_patterns": list(set(all_matched)),
            "risk_votes": dict(risk_votes),
        }


# ═══════════════════════════════════════════════════════════════════════
# Main Scam Analyzer (Orchestrator)
# ═══════════════════════════════════════════════════════════════════════

SCAM_SYSTEM_PROMPT = """You are FinLens, India's most advanced AI scam detection system.

Your job: Analyze suspicious messages and determine if they are scams.

You have deep knowledge of Indian financial fraud patterns:
- UPI/Payment fraud (QR scams, fake collect requests, PIN sharing)
- Investment scams (guaranteed returns, crypto bots, Ponzi schemes)
- Phishing (fake bank SMS, KYC scams, tax refund fraud)
- OTP fraud (sharing verification codes)
- Loan scams (no-document loans, processing fees)
- Job scams (work from home, registration fees)
- Digital arrest scams (fake CBI/police)
- Social engineering (impersonation, romance scams)

RULES:
1. Be ACCURATE — false positives erode trust, false negatives cause harm
2. Consider CONTEXT — some messages are legitimately urgent
3. Look for COMBINATION of red flags — one alone isn't conclusive
4. Be SPECIFIC — name the exact scam type and technique
5. Give ACTIONABLE advice — what should the user do right now?
6. Consider the Indian context — UPI, Aadhaar, Indian banks, local scam patterns

RESPOND IN VALID JSON with this exact structure:
{
  "risk_level": "SAFE" | "SUSPICIOUS" | "DANGEROUS" | "CONFIRMED_SCAM",
  "risk_score": 0-100,
  "scam_type": "string or null",
  "confidence": 0-100,
  "verdict": "one sentence verdict in simple English",
  "explanation": "detailed 2-3 sentence explanation of why",
  "red_flags": ["list of specific red flags found"],
  "safe_indicators": ["list of safe indicators if any"],
  "action": "specific recommended action for the user",
  "educational_note": "one tip to help user avoid this type of scam next time"
}"""


def _build_context_for_llm(message: str) -> str:
    """Build enhanced context for the LLM including rule-based pre-analysis."""
    rule_detector = RuleBasedDetector()
    rule_result = rule_detector.detect(message)

    context_parts = [
        "Pre-analysis by rule engine:",
        f"Rule-based risk score: {rule_result.risk_score}/100",
        f"Rule-based classification: {rule_result.risk_level}",
        f"Matched patterns: {', '.join(rule_result.matched_patterns[:10])}",
        "",
        "---",
        "",
        "Now perform your deep analysis of this message:",
        "",
    ]

    return "\n".join(context_parts)


def _parse_llm_response(raw_response: str) -> dict:
    """Safely parse JSON from LLM response, handling markdown code blocks."""
    cleaned = raw_response.strip()

    # Remove markdown code fences
    if cleaned.startswith("```"):
        lines = cleaned.split("\n")
        lines = [l for l in lines if not l.strip().startswith("```")]
        cleaned = "\n".join(lines)

    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        # Try to extract JSON from response
        json_match = re.search(r'\{[\s\S]*\}', cleaned)
        if json_match:
            try:
                return json.loads(json_match.group())
            except json.JSONDecodeError:
                pass

    # Fallback if parsing fails
    return {
        "risk_level": "SUSPICIOUS",
        "risk_score": 50,
        "scam_type": None,
        "confidence": 40,
        "verdict": "Could not fully analyze this message",
        "explanation": "The AI system had trouble parsing this message. Manual review recommended.",
        "red_flags": [],
        "safe_indicators": [],
        "action": "Do not act on this message. Verify with official sources.",
        "educational_note": "When in doubt, always verify through official channels."
    }


# ═══════════════════════════════════════════════════════════════════════
# Public API
# ═══════════════════════════════════════════════════════════════════════

# Initialize detectors
_rule_detector = RuleBasedDetector()
_linguistic_analyzer = LinguisticAnalyzer()
_structural_analyzer = StructuralAnalyzer()
_verdict_engine = VerdictEngine()


async def analyze_scam(message: str, llm_call) -> dict:
    """
    Enhanced scam analysis using multiple detection strategies.

    Pipeline:
    1. Rule-based detection (instant, deterministic)
    2. Linguistic analysis (instant, deterministic)
    3. Structural analysis (instant, deterministic)
    4. LLM deep analysis (contextual, ~2s)
    5. Ensemble verdict (weighted combination)

    Args:
        message: The suspicious text to analyze
        llm_call: Async function (system_prompt, user_prompt) -> str

    Returns:
        Complete AnalysisResult as dict
    """
    logger.info(f"Starting scam analysis for message of length {len(message)}")

    # ─── Strategy 1: Rule-Based Detection ────────────────────────
    rule_result = _rule_detector.detect(message)
    logger.debug(f"Rule-based: score={rule_result.risk_score}, level={rule_result.risk_level}")

    # ─── Strategy 2: Linguistic Analysis ──────────────────────────
    linguistic_result = _linguistic_analyzer.analyze(message)
    logger.debug(f"Linguistic: score={linguistic_result.risk_score}, level={linguistic_result.risk_level}")

    # ─── Strategy 3: Structural Analysis ──────────────────────────
    structural_result = _structural_analyzer.analyze(message)
    logger.debug(f"Structural: score={structural_result.risk_score}, level={structural_result.risk_level}")

    # ─── Strategy 4: LLM Deep Analysis ───────────────────────────
    llm_result = None
    try:
        context = _build_context_for_llm(message)
        user_prompt = f"{context}\n\n---\n{message}\n---\n\nRespond with the JSON verdict."
        raw_response = await llm_call(SCAM_SYSTEM_PROMPT, user_prompt)
        if not raw_response:
            raise RuntimeError("Gemini returned no analysis text")
        llm_result = _parse_llm_response(raw_response)
        logger.debug(f"LLM: score={llm_result.get('risk_score')}, level={llm_result.get('risk_level')}")
    except Exception as e:
        from llm import LLMError
        if isinstance(e, LLMError):
            raise
        logger.warning(f"LLM analysis failed: {e}. Using rule-based results only.")

    # ─── Strategy 5: Ensemble Verdict ─────────────────────────────
    strategies = [rule_result, linguistic_result, structural_result]
    ensemble = _verdict_engine.combine(strategies, llm_result)

    # ─── Build Final Result ───────────────────────────────────────
    # Use LLM verdicts where available, fall back to ensemble
    verdict = {
        "risk_level": ensemble["risk_level"],
        "risk_score": ensemble["risk_score"],
        "scam_type": ensemble["scam_type"],
        "confidence": ensemble["confidence"],
        "verdict": llm_result.get("verdict", _default_verdict(ensemble["risk_level"], ensemble["scam_type"])) if llm_result else _default_verdict(ensemble["risk_level"], ensemble["scam_type"]),
        "explanation": llm_result.get("explanation", _default_explanation(ensemble)) if llm_result else _default_explanation(ensemble),
        "red_flags": llm_result.get("red_flags", ensemble["evidence"][:8]) if llm_result else ensemble["evidence"][:8],
        "safe_indicators": llm_result.get("safe_indicators", []) if llm_result else [],
        "action": llm_result.get("action", _default_action(ensemble["risk_level"])) if llm_result else _default_action(ensemble["risk_level"]),
        "educational_note": llm_result.get("educational_note", _default_educational_note(ensemble["scam_type"])) if llm_result else _default_educational_note(ensemble["scam_type"]),
        # ─── Enhanced metadata for PRISM ─────────────────────────
        "strategies_used": ensemble["strategies_used"],
        "strategy_scores": ensemble["strategy_scores"],
        "detection_metadata": {
            "rule_score": rule_result.risk_score,
            "linguistic_score": linguistic_result.risk_score,
            "structural_score": structural_result.risk_score,
            "llm_score": llm_result.get("risk_score") if llm_result else None,
            "ensemble_score": ensemble["risk_score"],
            "risk_votes": ensemble["risk_votes"],
            "total_evidence_count": len(ensemble["evidence"]),
            "patterns_matched": len(ensemble["all_matched_patterns"]),
            "analysis_timestamp": datetime.utcnow().isoformat(),
        }
    }

    # ─── Ensure all required fields exist with defaults ───────────
    defaults = {
        "risk_level": "SUSPICIOUS", "risk_score": 50, "scam_type": None,
        "confidence": 50, "verdict": "Analysis complete",
        "explanation": "", "red_flags": [], "safe_indicators": [],
        "action": "Exercise caution", "educational_note": "Always verify."
    }
    for key, default in defaults.items():
        if key not in verdict or verdict[key] is None:
            verdict[key] = default

    verdict["risk_score"] = max(0, min(100, verdict["risk_score"]))
    verdict["confidence"] = max(0, min(100, verdict["confidence"]))

    logger.info(f"Analysis complete: {verdict['risk_level']} ({verdict['risk_score']}/100)")
    return verdict


# ═══════════════════════════════════════════════════════════════════════
# Default Response Generators
# ═══════════════════════════════════════════════════════════════════════

def _default_verdict(risk_level: str, scam_type: Optional[str]) -> str:
    """Generate a default verdict based on risk level."""
    if risk_level == "CONFIRMED_SCAM":
        st = f" ({scam_type})" if scam_type else ""
        return f"This is a confirmed scam{st}. Do not engage with this message."
    elif risk_level == "DANGEROUS":
        return "This message shows strong scam indicators. Treat with extreme caution."
    elif risk_level == "SUSPICIOUS":
        return "This message has some suspicious elements. Verify before taking any action."
    return "This message appears to be legitimate, but always stay vigilant."


def _default_explanation(ensemble: dict) -> str:
    """Generate explanation from ensemble evidence."""
    evidence = ensemble.get("evidence", [])
    if evidence:
        top_evidence = evidence[:3]
        return f"Analysis detected {len(evidence)} indicators: {'; '.join(top_evidence)}."
    return f"Combined analysis of {len(ensemble.get('strategies_used', []))} detection strategies produced this assessment."


def _default_action(risk_level: str) -> str:
    """Generate recommended action based on risk level."""
    actions = {
        "CONFIRMED_SCAM": "DO NOT respond, click any links, or share any information. Block the sender immediately. If you already shared information, contact your bank right away and file a complaint at cybercrime.gov.in.",
        "DANGEROUS": "Do not take any action based on this message. If it claims to be from your bank, call the number on the back of your card instead.",
        "SUSPICIOUS": "Verify the information through official channels before taking any action. Contact the organization directly using their official website or app.",
        "SAFE": "This appears legitimate, but always verify sensitive requests through a separate, trusted channel."
    }
    return actions.get(risk_level, "Exercise caution.")


def _default_educational_note(scam_type: Optional[str]) -> str:
    """Generate educational note based on scam type."""
    notes = {
        "UPI Payment Fraud": "Never share your UPI PIN with anyone. Banks and payment companies will NEVER ask for it. If someone asks, it's 100% a scam.",
        "Fake Investment Scheme": "No investment can guarantee returns. If it sounds too good to be true, it is. Always verify investment opportunities with SEBI.",
        "Phishing Scam": "Always check sender addresses carefully. Banks never ask you to click links in SMS to verify accounts. Type the URL directly in your browser.",
        "OTP Fraud": "Your OTP is for YOUR eyes only. No bank, merchant, or customer care will ever ask for it. If someone asks, it's always a scam.",
        "Job Scam": "Legitimate employers never charge you to work. If a job requires an upfront fee, it's a scam.",
    }
    return notes.get(scam_type, "When in doubt, always verify through official channels. Never share sensitive information with unsolicited contacts.")
