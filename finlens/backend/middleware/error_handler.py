"""
═══════════════════════════════════════════════════════════════════════════════
FinLens Error Handler Middleware
═══════════════════════════════════════════════════════════════════════════════

Global error handling middleware that catches all unhandled exceptions
and returns consistent, structured error responses.
"""

import traceback
import logging
from datetime import datetime

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

logger = logging.getLogger("finlens.error_handler")


class ErrorHandlerMiddleware(BaseHTTPMiddleware):
    """Global error handler that returns structured JSON error responses."""

    async def dispatch(self, request: Request, call_next):
        try:
            response = await call_next(request)
            return response

        except ValueError as e:
            logger.warning(f"Validation error: {e}")
            return JSONResponse(
                status_code=400,
                content={
                    "success": False,
                    "error": {
                        "code": "VALIDATION_ERROR",
                        "message": str(e),
                    },
                    "metadata": {
                        "timestamp": datetime.utcnow().isoformat(),
                        "path": request.url.path,
                    },
                },
            )

        except PermissionError as e:
            logger.warning(f"Permission denied: {e}")
            return JSONResponse(
                status_code=403,
                content={
                    "success": False,
                    "error": {
                        "code": "FORBIDDEN",
                        "message": "You don't have permission to perform this action.",
                    },
                    "metadata": {
                        "timestamp": datetime.utcnow().isoformat(),
                        "path": request.url.path,
                    },
                },
            )

        except KeyError as e:
            logger.warning(f"Missing key: {e}")
            return JSONResponse(
                status_code=400,
                content={
                    "success": False,
                    "error": {
                        "code": "MISSING_FIELD",
                        "message": f"Required field missing: {e}",
                    },
                    "metadata": {
                        "timestamp": datetime.utcnow().isoformat(),
                        "path": request.url.path,
                    },
                },
            )

        except TimeoutError as e:
            logger.error(f"Timeout: {e}")
            return JSONResponse(
                status_code=504,
                content={
                    "success": False,
                    "error": {
                        "code": "TIMEOUT",
                        "message": "The request timed out. Please try again.",
                    },
                    "metadata": {
                        "timestamp": datetime.utcnow().isoformat(),
                        "path": request.url.path,
                    },
                },
            )

        except ConnectionError as e:
            logger.error(f"Connection error: {e}")
            return JSONResponse(
                status_code=502,
                content={
                    "success": False,
                    "error": {
                        "code": "BAD_GATEWAY",
                        "message": "Unable to connect to external service. Please try again.",
                    },
                    "metadata": {
                        "timestamp": datetime.utcnow().isoformat(),
                        "path": request.url.path,
                    },
                },
            )

        except Exception as e:
            logger.error(f"Unhandled error: {e}\n{traceback.format_exc()}")
            return JSONResponse(
                status_code=500,
                content={
                    "success": False,
                    "error": {
                        "code": "INTERNAL_ERROR",
                        "message": "An unexpected error occurred. Our team has been notified.",
                    },
                    "metadata": {
                        "timestamp": datetime.utcnow().isoformat(),
                        "path": request.url.path,
                        "request_id": getattr(request.state, "request_id", None),
                    },
                },
            )
