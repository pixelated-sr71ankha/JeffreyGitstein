"""
═══════════════════════════════════════════════════════════════════════════════
FinLens Crypto Utilities
═══════════════════════════════════════════════════════════════════════════════

Cryptographic utilities:
- Session ID generation
- Message fingerprinting (for deduplication)
- Secure token generation
- HMAC signing
"""

import os
import uuid
import hashlib
import hmac
import secrets
from typing import Optional


def generate_session_id() -> str:
    """Generate a unique session ID."""
    return f"finlens-{uuid.uuid4().hex[:16]}"


def generate_request_id() -> str:
    """Generate a unique request ID for tracing."""
    return f"req-{uuid.uuid4().hex[:12]}"


def generate_message_hash(message: str) -> str:
    """
    Generate a hash of a message for deduplication.
    Same message always produces the same hash.
    """
    normalized = message.strip().lower()
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:32]


def generate_secure_token(length: int = 32) -> str:
    """Generate a cryptographically secure random token."""
    return secrets.token_hex(length)


def hmac_sign(data: str, key: str = None) -> str:
    """Sign data with HMAC-SHA256."""
    if key is None:
        key = os.getenv("JWT_SECRET", "finlens-default-key")
    return hmac.new(
        key.encode("utf-8"),
        data.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def hmac_verify(data: str, signature: str, key: str = None) -> bool:
    """Verify HMAC signature."""
    expected = hmac_sign(data, key)
    return hmac.compare_digest(expected, signature)


def hash_password_simple(password: str) -> str:
    """Simple password hash for demo mode (NOT for production)."""
    salt = "finlens-demo-salt"
    return hashlib.sha256(f"{salt}:{password}".encode()).hexdigest()


def generate_api_key(prefix: str = "fl") -> str:
    """Generate an API key with prefix."""
    random_part = secrets.token_hex(24)
    return f"{prefix}_{random_part}"
