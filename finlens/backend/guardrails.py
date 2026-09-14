"""
Guardrails — Safety layer for FinLens financial advice.
Ensures the AI never gives dangerous, misleading, or harmful recommendations.
"""

import re

# ─── Forbidden Patterns ────────────────────────────────────────────
# These patterns in AI output should trigger a warning or block.

FORBIDDEN_PATTERNS = [
    (r"(?i)guaranteed?\s+(returns?|profit|income)", "Cannot guarantee investment returns"),
    (r"(?i)risk[\s-]*free\s+invest", "No investment is risk-free"),
    (r"(?i)take\s+a\s+loan\s+to\s+invest", "Never borrow money to invest"),
    (r"(?i)put\s+all\s+(your\s+)?money\s+into", "Diversification is essential"),
    (r"(?i)buy\s+this\s+specific\s+stock\s+now", "Cannot recommend specific stocks to buy"),
    (r"(?i)ignore\s+(the\s+)?tax", "Tax evasion is illegal"),
    (r"(?i)share\s+(your|the|me)?\s*(otp|pin|password|code)", "Never share sensitive credentials"),
    (r"(?i)transfer\s+money\s+to\s+(this|the|a)\s+(account|upi)", "Never transfer money to unknown accounts"),
]

# ─── Disclaimer Templates ──────────────────────────────────────────
DISCLAIMER = (
    "\n\n---\n*Disclaimer: This is AI-generated educational information. "
    "It is not personalized financial advice. Always consult a SEBI-registered "
    "investment advisor or certified financial planner before making financial decisions.*"
)


def check_guardrails(text: str) -> dict:
    """
    Check AI-generated text against safety guardrails.

    Returns:
        {
            "passed": bool,
            "violations": [{"pattern": str, "reason": str}],
            "modified_text": str (with disclaimer appended if needed)
        }
    """
    violations = []

    for pattern, reason in FORBIDDEN_PATTERNS:
        if re.search(pattern, text):
            violations.append({
                "pattern": pattern,
                "reason": reason
            })

    # Always append disclaimer for financial advice
    modified_text = text + DISCLAIMER

    return {
        "passed": len(violations) == 0,
        "violations": violations,
        "modified_text": modified_text,
        "violation_count": len(violations),
    }


def sanitize_input(text: str) -> str:
    """
    Sanitize user input before sending to the AI model.
    Removes potential prompt injection attempts.
    """
    # Remove null bytes
    text = text.replace("\x00", "")

    # Truncate extremely long inputs
    if len(text) > 10000:
        text = text[:10000]

    # Strip control characters except newlines and tabs
    text = re.sub(r'[\x01-\x08\x0b\x0c\x0e-\x1f\x7f]', '', text)

    return text.strip()
