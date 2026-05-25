"""
Authentication API routes — Token generation for API clients.

Endpoint:
  POST /auth/token  — Exchange client credentials for a single-use token

Tokens are single-use and deleted immediately after any verification attempt.
Redis TTL of 90 seconds acts only as a safety net for edge cases.
"""

import logging
import hmac
import secrets
from typing import Dict, Any
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from app.core.config import settings
from app.services.auth_service import auth_service

logger = logging.getLogger("middleware")

router = APIRouter(tags=["Authentication"])


# ─────────────────────────────────────────────────────── request/response models

class TokenRequest(BaseModel):
    """Request body for obtaining an access token."""

    client_id: str = Field(
        ...,
        description="Client ID issued by admin",
        example="kyc_vendor_production_a3f9b2c1",
    )
    client_secret: str = Field(
        ...,
        description="Client secret issued by admin (shown only during generation)",
        example="Xk92mNpQr8vLs3TjKd0WqYnBfGhM2cPz",
    )

    model_config = {
        "json_schema_extra": {
            "example": {
                "client_id": "kyc_vendor_production_a3f9b2c1",
                "client_secret": "Xk92mNpQr8vLs3TjKd0WqYnBfGhM2cPz",
            }
        }
    }


class TokenResponse(BaseModel):
    """Response containing access token and usage instructions."""

    access_token: str = Field(..., description="JWT token — use in Authorization: Bearer <token> header")
    token_type: str = Field(..., description="Token type (always 'Bearer')")
    expires_in: int = Field(..., description="Token safety TTL in seconds (90s)")
    environment: str = Field(..., description="Which environments this token can access")
    instruction: str = Field(..., description="How to use this token")


# ─────────────────────────────────────────────────────── token endpoint

@router.post(
    "/token",
    summary="Get single-use access token",
    description=(
        "Exchange valid client_id and client_secret for a single-use JWT token. "
        "Token must be used within 90 seconds and can only be used once. "
        "Include the token in Authorization header: 'Bearer <token>'"
    ),
    response_model=TokenResponse,
)
async def get_token(body: TokenRequest) -> Dict[str, Any]:
    """
    POST /auth/token

    Validates client credentials and issues a single-use JWT token.
    Token is deleted immediately after any verification attempt.
    """
    # Find client in registered clients
    clients = settings.get_all_clients()
    matching_client = None

    for client in clients:
        if client["client_id"] == body.client_id:
            # Constant-time comparison for secret
            if hmac.compare_digest(client["client_secret"], body.client_secret):
                matching_client = client
                break

    if matching_client is None:
        logger.warning(
            f"Token request failed — invalid credentials for client_id: {body.client_id[:20]}...",
            extra={
                "service": "auth",
                "action": "token_request_failed",
                "reason": "invalid_credentials",
                "client_id_prefix": body.client_id[:20] if len(body.client_id) > 20 else body.client_id,
            },
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "success": False,
                "error": True,
                "message": "Invalid client credentials",
                "status_code": 401,
            },
        )

    # Generate token
    token = await auth_service.create_token(
        client_id=matching_client["client_id"],
        client_name=matching_client["client_name"],
        allowed_env=matching_client["allowed_env"],
    )

    logger.info(
        f"Token issued for client: {matching_client['client_name']} ({matching_client['client_id'][:20]}...)",
        extra={
            "service": "auth",
            "action": "token_issued",
            "client_id": matching_client["client_id"],
            "client_name": matching_client["client_name"],
            "allowed_env": matching_client["allowed_env"],
        },
    )

    return {
        "access_token": token,
        "token_type": "Bearer",
        "expires_in": 90,
        "environment": matching_client["allowed_env"],
        "instruction": (
            "Use this token in the Authorization header: 'Bearer <token>'. "
            "Token is single-use — it will be deleted immediately after your verification request, "
            "whether success or failure. Token expires in 90 seconds if not used."
        ),
    }
