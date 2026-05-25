"""
Token authentication dependencies for FastAPI routes.

Each environment has its own dependency:
  - verify_prod_token: validates token allows "prod" or "both"
  - verify_test_token: validates token allows "test" or "both"

All dependencies extract the Authorization: Bearer <token> header,
verify the token with auth_service, and return the decoded payload.
"""

import logging
from typing import Dict, Any
from fastapi import Header, HTTPException, status, Request
from fastapi.responses import JSONResponse

from app.services.auth_service import auth_service
from app.api.deps.ip_whitelist import get_client_ip

logger = logging.getLogger("middleware")


async def verify_prod_token(
    request: Request,
    authorization: str = Header(..., alias="Authorization"),
) -> Dict[str, Any]:
    """
    FastAPI dependency — verifies token is valid and authorized for production.

    Header required: Authorization: Bearer <jwt_token>

    Returns:
        Decoded token payload dict

    Raises:
        HTTPException 401 if token missing, invalid, or expired
        HTTPException 403 if token not authorized for production environment
    """
    client_ip = get_client_ip(request)

    # Extract Bearer token
    if not authorization.startswith("Bearer "):
        logger.warning(
            f"Invalid authorization header format from {client_ip}",
            extra={"service": "auth", "action": "auth_failed", "reason": "invalid_header", "client_ip": client_ip},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "success": False,
                "error": True,
                "message": "Invalid authorization header. Use: Bearer <token>",
                "status_code": 401,
            },
        )

    token = authorization[7:]  # Remove "Bearer " prefix

    try:
        payload = await auth_service.verify_token(token, required_env="prod")
    except ValueError as e:
        logger.warning(
            f"Token verification failed from {client_ip}: {str(e)}",
            extra={"service": "auth", "action": "auth_failed", "reason": str(e), "client_ip": client_ip},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "success": False,
                "error": True,
                "message": str(e),
                "status_code": 401,
            },
        )

    return payload


async def verify_test_token(
    request: Request,
    authorization: str = Header(..., alias="Authorization"),
) -> Dict[str, Any]:
    """
    FastAPI dependency — verifies token is valid and authorized for test environment.

    Header required: Authorization: Bearer <jwt_token>

    Returns:
        Decoded token payload dict

    Raises:
        HTTPException 401 if token missing, invalid, or expired
        HTTPException 403 if token not authorized for test environment
    """
    client_ip = get_client_ip(request)

    # DEBUG: log exactly what we received
    logger.info(f"DEBUG auth header: repr={repr(authorization)}, len={len(authorization)}, first20={authorization[:20]}")

    # Extract Bearer token
    if not authorization.startswith("Bearer "):
        logger.warning(
            f"Invalid authorization header format from {client_ip}",
            extra={"service": "auth", "action": "auth_failed", "reason": "invalid_header", "client_ip": client_ip},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "success": False,
                "error": True,
                "message": "Invalid authorization header. Use: Bearer <token>",
                "status_code": 401,
            },
        )

    token = authorization[7:]  # Remove "Bearer " prefix

    try:
        payload = await auth_service.verify_token(token, required_env="test")
    except ValueError as e:
        logger.warning(
            f"Token verification failed from {client_ip}: {str(e)}",
            extra={"service": "auth", "action": "auth_failed", "reason": str(e), "client_ip": client_ip},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "success": False,
                "error": True,
                "message": str(e),
                "status_code": 401,
            },
        )

    return payload
