"""
═══════════════════════════════════════════════════════════════════════════════
FinLens Validators
═══════════════════════════════════════════════════════════════════════════════

Input validation utilities for all FinLens data types:
- Indian phone number validation
- UPI ID validation
- PAN card validation
- Aadhaar number validation
- Email validation
- URL safety validation
- Amount validation
- Date validation
"""

import re
from typing import Optional, Tuple


# ═══════════════════════════════════════════════════════════════════════════════
# Phone Validation
# ═══════════════════════════════════════════════════════════════════════════════

INDIAN_PHONE_REGEX = re.compile(r"^(?:\+91|91|0)?[6-9]\d{9}$")


def validate_indian_phone(phone: str) -> Tuple[bool, str]:
    """Validate Indian mobile number format."""
    cleaned = re.sub(r"[\s\-+]", "", phone)
    if cleaned.startswith("91") and len(cleaned) == 12:
        cleaned = cleaned[2:]
    if cleaned.startswith("0") and len(cleaned) == 11:
        cleaned = cleaned[1:]
    if INDIAN_PHONE_REGEX.match(cleaned) or INDIAN_PHONE_REGEX.match(phone):
        return True, ""
    return False, "Invalid Indian phone number (must start with 6-9 and be 10 digits)"


# ═══════════════════════════════════════════════════════════════════════════════
# UPI ID Validation
# ═══════════════════════════════════════════════════════════════════════════════

UPI_HANDLE_PATTERN = re.compile(r"^[\w.\-]{2,}@(oksbi|okicici|okaxis|okhdfcbank|paytm|gpay|phonepe|ybl|ibl|axl|sbi|icici|hdfc|axis|upi)$")


def validate_upi_id(upi_id: str) -> Tuple[bool, str]:
    """Validate UPI ID format."""
    if not upi_id or "@" not in upi_id:
        return False, "UPI ID must contain @ (e.g., name@bank)"
    parts = upi_id.split("@")
    if len(parts) != 2:
        return False, "Invalid UPI ID format"
    user, handle = parts
    if len(user) < 2:
        return False, "UPI ID username must be at least 2 characters"
    if not re.match(r"^[\w.\-]+$", user):
        return False, "UPI ID username can only contain alphanumeric, dots, hyphens"
    return True, ""


# ═══════════════════════════════════════════════════════════════════════════════
# PAN Validation
# ═══════════════════════════════════════════════════════════════════════════════

PAN_REGEX = re.compile(r"^[A-Z]{5}[0-9]{4}[A-Z]$")


def validate_pan(pan: str) -> Tuple[bool, str]:
    """Validate Indian PAN card number."""
    pan = pan.upper().strip()
    if not PAN_REGEX.match(pan):
        return False, "Invalid PAN format (e.g., ABCDE1234F)"
    # Check 4th character indicates entity type
    valid_entity_chars = "ATBPCHFGJALCK"
    if pan[3] not in valid_entity_chars:
        return False, "Invalid PAN entity type"
    return True, ""


# ═══════════════════════════════════════════════════════════════════════════════
# Aadhaar Validation (Verhoeff algorithm)
# ═══════════════════════════════════════════════════════════════════════════════

VERHOEFF_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]

VERHOEFF_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]

VERHOEFF_INV = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]


def validate_aadhaar(aadhaar: str) -> Tuple[bool, str]:
    """Validate Aadhaar number using Verhoeff checksum."""
    digits = re.sub(r"\s", "", aadhaar)
    if len(digits) != 12 or not digits.isdigit():
        return False, "Aadhaar must be exactly 12 digits"
    # Verhoeff check
    c = 0
    for i, d in enumerate(reversed(digits)):
        c = VERHOEFF_D[c][VERHOEFF_P[i % 8][int(d)]]
    if c != 0:
        return False, "Invalid Aadhaar number (checksum mismatch)"
    return True, ""


# ═══════════════════════════════════════════════════════════════════════════════
# Amount & Currency Validation
# ═══════════════════════════════════════════════════════════════════════════════

def validate_amount(amount: float, min_val: float = 0, max_val: float = 1e12) -> Tuple[bool, str]:
    """Validate a monetary amount."""
    if not isinstance(amount, (int, float)):
        return False, "Amount must be a number"
    if amount < min_val:
        return False, f"Amount must be at least ₹{min_val:,.0f}"
    if amount > max_val:
        return False, f"Amount exceeds maximum (₹{max_val:,.0f})"
    return True, ""


def parse_indian_amount(text: str) -> Optional[float]:
    """
    Parse Indian-style amount strings.

    Examples:
        "1.5L" → 150000
        "2.3Cr" → 23000000
        "₹50,000" → 50000
        "15000" → 15000
    """
    text = text.strip().replace(",", "").replace("₹", "").replace("Rs", "").replace("rs", "")
    multiplier = 1

    if text.upper().endswith("CR"):
        multiplier = 10000000
        text = text[:-2].strip()
    elif text.upper().endswith("L"):
        multiplier = 100000
        text = text[:-1].strip()
    elif text.upper().endswith("K"):
        multiplier = 1000
        text = text[:-1].strip()

    try:
        return float(text) * multiplier
    except ValueError:
        return None


# ═══════════════════════════════════════════════════════════════════════════════
# Email Validation
# ═══════════════════════════════════════════════════════════════════════════════

EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")


def validate_email(email: str) -> Tuple[bool, str]:
    """Validate email address."""
    if not email or not EMAIL_REGEX.match(email):
        return False, "Invalid email address"
    return True, ""


# ═══════════════════════════════════════════════════════════════════════════════
# Text Sanitization
# ═══════════════════════════════════════════════════════════════════════════════

PROMPT_INJECTION_PATTERNS = [
    r"ignore\s+(all\s+)?previous\s+instructions",
    r"you\s+are\s+now",
    r"act\s+as\s+if",
    r"disregard\s+(your|all)",
    r"forget\s+(your|all)\s+(rules|instructions)",
    r"system\s*:\s*you",
    r"<\|system\|>",
    r"\[system\]",
]


def detect_prompt_injection(text: str) -> Tuple[bool, list]:
    """Detect potential prompt injection attempts in user input."""
    detections = []
    text_lower = text.lower()
    for pattern in PROMPT_INJECTION_PATTERNS:
        if re.search(pattern, text_lower):
            detections.append(f"Possible prompt injection: '{pattern}'")
    return len(detections) > 0, detections


def sanitize_user_input(text: str, max_length: int = 10000) -> str:
    """Sanitize user input for safety."""
    if not text:
        return ""
    # Remove null bytes
    text = text.replace("\x00", "")
    # Strip control characters
    text = re.sub(r"[\x01-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text)
    # Truncate
    text = text[:max_length]
    return text.strip()
