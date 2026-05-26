"""
Authentication service for token-based API access.

Tokens are single-use and deleted immediately after any verification attempt.
Redis TTL of 90 seconds acts only as a safety net for edge cases like server crash.
"""

import logging
import secrets
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional

import redis.asyncio as redis
from jose import jwt, JWTError

from app.core.config import settings

logger = logging.getLogger("middleware")

# EAT timezone offset (UTC+3)
_EAT = timezone(timedelta(hours=3))

# Token safety TTL in seconds (90 seconds = safety net only)
TOKEN_TTL_SECONDS = 90


class AuthService:
    """Handles JWT token creation, verification, and immediate deletion."""

    def __init__(self):
        self._redis: Optional[redis.Redis] = None

    async def _get_redis(self) -> redis.Redis:
        """Get or create Redis connection."""
        if self._redis is None:
            self._redis = redis.from_url(
                settings.REDIS_URL,
                decode_responses=True,
                socket_connect_timeout=5,
                socket_timeout=5,
                health_check_interval=30,
            )
        return self._redis

    async def create_token(
        self,
        client_id: str,
        client_name: str,
        allowed_env: str,
    ) -> str:
        """
        Create a single-use JWT token for the specified client.

        The token is stored in Redis with a 90-second TTL (safety net only).
        Normal flow: token is deleted immediately by delete_token() after use.

        Args:
            client_id: The client identifier (e.g., "kyc_vendor_prod_a3f9b2c1")
            client_name: Human-readable client name for logging
            allowed_env: "prod", "test", or "both" — which environments this token can access

        Returns:
            JWT token string (signed, contains jti claim for Redis lookup)
        """
        # Generate unique token ID (jti)
        jti = secrets.token_urlsafe(32)

        # Current timestamp in EAT
        now = datetime.now(_EAT)
        issued_at = int(now.timestamp())

        # Build JWT payload
        payload: Dict[str, Any] = {
            "sub": client_id,           # Subject (client_id)
            "jti": jti,                 # Unique token ID for Redis
            "iat": issued_at,           # Issued at
            "name": client_name,        # Client name for logging
            "env": allowed_env,         # Allowed environment(s)
            "type": "single_use",       # Token type
        }

        # Sign with HS256 (symmetric key - in production use asymmetric RS256)
        # Using client_id + admin_secret as composite key for simplicity
        secret = f"{settings.ADMIN_SECRET_KEY}:{client_id}"
        token = jwt.encode(payload, secret, algorithm="HS256")

        # Store jti in Redis with 90-second safety TTL
        redis_conn = await self._get_redis()
        key = f"token:{jti}"
        await redis_conn.setex(key, TOKEN_TTL_SECONDS, client_id)

        logger.info(f"Token issued for client: {client_name}")

        return token

    async def verify_token(self, token: str, required_env: str) -> Dict[str, Any]:
        """
        Verify a JWT token and check it's valid for the requested environment.

        Args:
            token: The JWT token from Authorization header
            required_env: "prod" or "test" — the endpoint environment being accessed

        Returns:
            Decoded token payload dict with keys: sub, jti, name, env, etc.

        Raises:
            HTTPException: 401 if token is invalid, expired, or not found in Redis
            HTTPException: 403 if token not authorized for this environment
        """
        # Decode without verification first to get client_id for key lookup
        try:
            unverified = jwt.get_unverified_claims(token)
            client_id = unverified.get("sub")
            jti = unverified.get("jti")
            token_env = unverified.get("env", "both")
        except JWTError as e:
            logger.warning(f"Token rejected: decode failed")
            raise ValueError("Invalid token format")

        if not client_id or not jti:
            logger.warning(f"Token rejected: missing claims")
            raise ValueError("Invalid token claims")

        # Verify token exists in Redis (not already used/deleted)
        redis_conn = await self._get_redis()
        key = f"token:{jti}"
        stored_client_id = await redis_conn.get(key)

        if stored_client_id is None:
            logger.warning(f"Token rejected: already used or expired")
            raise ValueError("Token has already been used or has expired")

        # Now verify signature
        secret = f"{settings.ADMIN_SECRET_KEY}:{client_id}"
        try:
            payload = jwt.decode(token, secret, algorithms=["HS256"])
        except JWTError as e:
            logger.warning(f"Token rejected: invalid signature")
            raise ValueError("Invalid token signature")

        # Check environment authorization
        if token_env != "both" and token_env != required_env:
            logger.warning(f"Token rejected: environment not authorized")
            raise ValueError(f"Token not authorized for {required_env} environment")

        logger.info(f"Token verified for client: {client_id}")

        return payload

    async def delete_token(self, jti: str) -> None:
        """
        Permanently deletes token from Redis immediately after any verification attempt.
        Called by route handlers after every request completes — success or failure.

        Args:
            jti: The JWT ID (jti claim) from the verified token payload
        """
        redis_conn = await self._get_redis()
        key = f"token:{jti}"
        await redis_conn.delete(key)
        logger.info(f"Token deleted: jti={jti[:8]}...")


# Application-wide singleton
auth_service = AuthService()
