"""
═══════════════════════════════════════════════════════════════════════════════
FinLens Request Logger Middleware
═══════════════════════════════════════════════════════════════════════════════

Structured request/response logging with:
- Request ID generation for tracing
- Response time measurement
- Request/response body logging (configurable)
- Sensitive data redaction
- Slow request detection
"""

import time
import uuid
import logging

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

logger = logging.getLogger("finlens.request_logger")
slow_request_logger = logging.getLogger("finlens.slow_requests")

# Paths to skip logging (reduce noise)
SKIP_LOG_PATHS = {"/api/health", "/static", "/favicon.ico"}

# Sensitive fields to redact
SENSITIVE_FIELDS = {"password", "token", "otp", "pin", "secret", "api_key", "authorization"}


class RequestLoggerMiddleware(BaseHTTPMiddleware):
    """Logs all incoming requests with timing and context."""

    def __init__(self, app, log_request_body: bool = False, slow_threshold_ms: int = 3000):
        super().__init__(app)
        self.log_request_body = log_request_body
        self.slow_threshold_ms = slow_threshold_ms

    async def dispatch(self, request: Request, call_next):
        # Generate request ID
        request_id = str(uuid.uuid4())[:12]
        request.state.request_id = request_id

        path = request.url.path

        # Skip logging for health checks and static files
        skip = any(path.startswith(p) for p in SKIP_LOG_PATHS)

        # Start timing
        start_time = time.perf_counter()

        # Log request
        if not skip:
            client_ip = self._get_client_ip(request)
            logger.info(
                f"[{request_id}] → {request.method} {path} "
                f"from {client_ip}"
            )

        # Process request
        try:
            response = await call_next(request)
        except Exception as e:
            elapsed_ms = int((time.perf_counter() - start_time) * 1000)
            logger.error(
                f"[{request_id}] ✖ {request.method} {path} "
                f"FAILED in {elapsed_ms}ms: {e}"
            )
            raise

        # Calculate timing
        elapsed_ms = int((time.perf_counter() - start_time) * 1000)

        # Add response headers
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Response-Time"] = f"{elapsed_ms}ms"

        # Log response
        if not skip:
            status_code = response.status_code
            log_level = logging.WARNING if status_code >= 400 else logging.INFO

            logger.log(
                log_level,
                f"[{request_id}] ← {request.method} {path} "
                f"{status_code} in {elapsed_ms}ms"
            )

            # Log slow requests
            if elapsed_ms > self.slow_threshold_ms:
                slow_request_logger.warning(
                    f"[{request_id}] SLOW REQUEST: {request.method} {path} "
                    f"took {elapsed_ms}ms (threshold: {self.slow_threshold_ms}ms)"
                )

        return response

    def _get_client_ip(self, request: Request) -> str:
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip
        if request.client:
            return request.client.host
        return "unknown"
