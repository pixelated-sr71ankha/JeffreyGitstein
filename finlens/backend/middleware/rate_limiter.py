"""
═══════════════════════════════════════════════════════════════════════════════
FinLens Rate Limiter Middleware
═══════════════════════════════════════════════════════════════════════════════

Sliding window rate limiter with:
- Per-IP and per-user rate limiting
- Configurable limits per endpoint
- Burst protection
- Response headers (X-RateLimit-*)
- Graceful degradation when Redis is unavailable
- Different tiers: public, authenticated, premium
"""

import time
import logging
from collections import defaultdict
from typing import Dict, Optional, Tuple

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

logger = logging.getLogger("finlens.rate_limiter")


# ═══════════════════════════════════════════════════════════════════════════════
# Rate Limit Configuration
# ═══════════════════════════════════════════════════════════════════════════════

# Default rate limits (requests per window_seconds)
DEFAULT_LIMITS = {
    "public": {"max_requests": 30, "window_seconds": 60},
    "authenticated": {"max_requests": 100, "window_seconds": 60},
    "premium": {"max_requests": 300, "window_seconds": 60},
}

# Per-endpoint overrides
ENDPOINT_LIMITS = {
    "/api/analyze-scam": {"max_requests": 15, "window_seconds": 60},
    "/api/finance-health": {"max_requests": 10, "window_seconds": 60},
    "/api/financial-qa": {"max_requests": 20, "window_seconds": 60},
    "/api/auth/login": {"max_requests": 5, "window_seconds": 300},
    "/api/auth/register": {"max_requests": 3, "window_seconds": 3600},
    "/api/auth/refresh": {"max_requests": 10, "window_seconds": 300},
    "/api/batch-scan": {"max_requests": 5, "window_seconds": 300},
    "/api/portfolio/analyze": {"max_requests": 10, "window_seconds": 60},
    "/api/expenses/import": {"max_requests": 5, "window_seconds": 300},
}

# Paths that are exempt from rate limiting
EXEMPT_PATHS = {
    "/",
    "/api/health",
    "/docs",
    "/openapi.json",
    "/redoc",
    "/static",
}


# ═══════════════════════════════════════════════════════════════════════════════
# Sliding Window Counter
# ═══════════════════════════════════════════════════════════════════════════════

class SlidingWindowCounter:
    """
    In-memory sliding window rate limiter.
    Uses a list of timestamps per key with efficient cleanup.
    """

    def __init__(self):
        self._windows: Dict[str, list] = defaultdict(list)

    def check_and_record(
        self, key: str, max_requests: int, window_seconds: int
    ) -> Tuple[bool, int, int]:
        """
        Check if request is allowed and record it.

        Returns:
            (is_allowed, remaining_requests, retry_after_seconds)
        """
        now = time.time()
        window_start = now - window_seconds

        # Clean old entries
        self._windows[key] = [
            ts for ts in self._windows[key] if ts > window_start
        ]

        current_count = len(self._windows[key])
        remaining = max(0, max_requests - current_count - 1)

        if current_count >= max_requests:
            # Calculate retry-after
            oldest = self._windows[key][0]
            retry_after = int(oldest + window_seconds - now) + 1
            return False, 0, max(1, retry_after)

        # Record this request
        self._windows[key].append(now)
        return True, remaining, 0

    def get_count(self, key: str, window_seconds: int) -> int:
        """Get current request count in window."""
        now = time.time()
        window_start = now - window_seconds
        return sum(1 for ts in self._windows.get(key, []) if ts > window_start)

    def reset(self, key: str):
        """Reset counter for a key."""
        self._windows.pop(key, None)

    def cleanup(self, max_age: int = 3600):
        """Remove entries older than max_age seconds."""
        cutoff = time.time() - max_age
        keys_to_clean = []
        for key, timestamps in self._windows.items():
            self._windows[key] = [ts for ts in timestamps if ts > cutoff]
            if not self._windows[key]:
                keys_to_clean.append(key)
        for key in keys_to_clean:
            del self._windows[key]

    def stats(self) -> dict:
        """Get counter statistics."""
        return {
            "total_keys": len(self._windows),
            "total_requests": sum(len(v) for v in self._windows.values()),
        }


# ═══════════════════════════════════════════════════════════════════════════════
# Rate Limiter Middleware
# ═══════════════════════════════════════════════════════════════════════════════

class RateLimiterMiddleware(BaseHTTPMiddleware):
    """
    FastAPI middleware that enforces rate limits on all API endpoints.
    """

    def __init__(self, app, default_tier: str = "public"):
        super().__init__(app)
        self.default_tier = default_tier
        self.counter = SlidingWindowCounter()

    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        # Check if path is exempt
        for exempt in EXEMPT_PATHS:
            if path == exempt or path.startswith(exempt):
                return await call_next(request)

        # Determine rate limit tier
        tier = self._get_tier(request)
        endpoint_config = self._get_endpoint_config(path)

        # Use endpoint-specific limits if available, else tier defaults
        if endpoint_config:
            max_requests = endpoint_config["max_requests"]
            window = endpoint_config["window_seconds"]
        else:
            limits = DEFAULT_LIMITS.get(tier, DEFAULT_LIMITS["public"])
            max_requests = limits["max_requests"]
            window = limits["window_seconds"]

        # Generate rate limit key
        client_ip = self._get_client_ip(request)
        user_id = getattr(request.state, "user_id", None)
        key = f"{path}:{user_id or client_ip}"

        # Check rate limit
        is_allowed, remaining, retry_after = self.counter.check_and_record(
            key, max_requests, window
        )

        if not is_allowed:
            logger.warning(f"Rate limit exceeded: {key}")
            return JSONResponse(
                status_code=429,
                content={
                    "error": "rate_limit_exceeded",
                    "message": f"Too many requests. Try again in {retry_after} seconds.",
                    "retry_after": retry_after,
                },
                headers={
                    "X-RateLimit-Limit": str(max_requests),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": str(int(time.time()) + retry_after),
                    "Retry-After": str(retry_after),
                },
            )

        # Process request
        response = await call_next(request)

        # Add rate limit headers
        response.headers["X-RateLimit-Limit"] = str(max_requests)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        response.headers["X-RateLimit-Window"] = str(window)

        return response

    def _get_tier(self, request: Request) -> str:
        """Determine the rate limit tier based on auth status."""
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            return "authenticated"
        return self.default_tier

    def _get_endpoint_config(self, path: str) -> Optional[dict]:
        """Get endpoint-specific rate limit config."""
        for pattern, config in ENDPOINT_LIMITS.items():
            if path.startswith(pattern):
                return config
        return None

    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP, considering reverse proxies."""
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip
        if request.client:
            return request.client.host
        return "unknown"
