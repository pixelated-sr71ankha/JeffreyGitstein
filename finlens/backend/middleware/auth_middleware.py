"""
═══════════════════════════════════════════════════════════════════════════════
FinLens Auth Middleware
═══════════════════════════════════════════════════════════════════════════════

JWT authentication middleware with:
- Optional auth (extracts user if token present, doesn't block)
- Required auth (blocks unauthenticated requests)
- Token verification and user context injection
- Admin role checking
"""

import logging
from typing import Optional

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from services.auth_service import decode_token, is_token_expired, auth_service
from database import User, db_manager

logger = logging.getLogger("finlens.auth_middleware")

# Security scheme
security = HTTPBearer(auto_error=False)


# ═══════════════════════════════════════════════════════════════════════════════
# Dependency: Get Current User (Optional)
# ═══════════════════════════════════════════════════════════════════════════════

async def get_current_user_optional(
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> Optional[User]:
    """
    Extract and verify user from JWT token if present.
    Returns None if no token or invalid token (doesn't block).
    """
    if not credentials:
        return None

    token = credentials.credentials
    payload = decode_token(token)

    if not payload:
        return None

    if is_token_expired(payload):
        return None

    user_id = payload.get("sub")
    if not user_id:
        return None

    try:
        async with db_manager.get_session() as session:
            user = await auth_service.get_current_user(session, user_id)
            return user
    except Exception as e:
        logger.debug(f"Failed to get user: {e}")
        return None


# ═══════════════════════════════════════════════════════════════════════════════
# Dependency: Get Current User (Required)
# ═══════════════════════════════════════════════════════════════════════════════

async def get_current_user_required(
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> User:
    """
    Require a valid JWT token and return the authenticated user.
    Raises 401 if no token or invalid token.
    """
    if not credentials:
        raise HTTPException(
            status_code=401,
            detail="Authentication required. Please provide a valid token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = credentials.credentials
    payload = decode_token(token)

    if not payload:
        raise HTTPException(
            status_code=401,
            detail="Invalid or malformed token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if is_token_expired(payload):
        raise HTTPException(
            status_code=401,
            detail="Token has expired. Please refresh your token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(
            status_code=401,
            detail="Invalid token payload.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        async with db_manager.get_session() as session:
            user = await auth_service.get_current_user(session, user_id)
            if not user:
                raise HTTPException(
                    status_code=401,
                    detail="User account not found or deactivated.",
                )
            return user
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Auth error: {e}")
        raise HTTPException(status_code=500, detail="Authentication service unavailable")


# ═══════════════════════════════════════════════════════════════════════════════
# Dependency: Get Current User (Admin Required)
# ═══════════════════════════════════════════════════════════════════════════════

async def get_admin_user(
    user: User = Depends(get_current_user_required),
) -> User:
    """Require admin privileges."""
    if not user.is_admin:
        raise HTTPException(
            status_code=403,
            detail="Admin access required.",
        )
    return user
