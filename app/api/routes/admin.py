"""
Admin API routes — Internal credential management.

All endpoints require X-Admin-Key header for authentication.
These endpoints are for internal admin use only to generate and manage client credentials.

IMPORTANT SECURITY NOTES:
  - This endpoint ONLY generates credentials — it does NOT store them
  - Admin must manually add generated credentials to .env file
  - Application must be restarted after adding credentials to .env
  - Client secrets are shown ONLY ONCE during generation
  - Never log client_secret or admin key
"""

import logging
import secrets
import hmac
from typing import Dict, Any, List
from fastapi import APIRouter, Header, HTTPException, status, Request, Depends
from pydantic import BaseModel, Field

from app.core.config import settings
from app.api.deps.ip_whitelist import get_client_ip

logger = logging.getLogger("middleware")

router = APIRouter(tags=["Admin"])


# ─────────────────────────────────────────────────────── admin auth dependency

def verify_admin_key(request: Request, x_admin_key: str = Header(..., alias="X-Admin-Key")) -> bool:
    """
    All admin endpoints require header:
      X-Admin-Key: <ADMIN_SECRET_KEY from .env>

    Returns True if valid, raises HTTPException 401 if invalid.
    Logs access attempts with client IP.
    """
    client_ip = get_client_ip(request)

    if not hmac.compare_digest(settings.ADMIN_SECRET_KEY, x_admin_key):
        logger.warning(
            f"Admin access denied — invalid admin key from {client_ip}",
            extra={
                "service": "admin",
                "action": "access_denied",
                "reason": "invalid_admin_key",
                "client_ip": client_ip,
            },
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "success": False,
                "error": True,
                "message": "Invalid admin key",
                "status_code": 401,
            },
        )

    logger.info(
        f"Admin access granted from {client_ip}",
        extra={
            "service": "admin",
            "action": "access_granted",
            "client_ip": client_ip,
        },
    )
    return True


# ─────────────────────────────────────────────────────── request/response models

class GenerateClientRequest(BaseModel):
    """Request body for generating new client credentials."""

    client_name: str = Field(
        ...,
        description="Human-readable client label (e.g., 'KYC Vendor Production')",
        example="KYC Vendor Production",
    )
    allowed_env: str = Field(
        ...,
        description="Which environments this client can access: 'prod', 'test', or 'both'",
        example="prod",
    )

    model_config = {
        "json_schema_extra": {
            "example": {
                "client_name": "KYC Vendor Production",
                "allowed_env": "prod",
            }
        }
    }


class GenerateClientResponse(BaseModel):
    """Response containing new client credentials — SECRET SHOWN ONLY ONCE."""

    client_id: str = Field(..., description="Unique client identifier")
    client_secret: str = Field(..., description="Client secret — COPY NOW, will not be shown again")
    allowed_env: str = Field(..., description="Allowed environment(s)")
    client_name: str = Field(..., description="Human-readable client name")
    instruction: str = Field(..., description="Next steps for admin")


# ─────────────────────────────────────────────────────── ENDPOINT 1: Generate credentials

@router.post(
    "/clients/generate",
    summary="Generate new client credentials",
    description=(
        "Generates new client_id and client_secret for a new API client. "
        "Requires X-Admin-Key header. "
        "The client_secret is shown ONLY in this response — copy it immediately. "
        "Admin must manually add credentials to .env and restart the application."
    ),
    response_model=GenerateClientResponse,
)
async def generate_client(
    request: Request,
    body: GenerateClientRequest,
    _: bool = Depends(verify_admin_key),
) -> Dict[str, Any]:
    """
    POST /admin/clients/generate

    Generates new client credentials. Secret is shown only once.
    Does NOT store credentials — admin must add to .env manually.
    """
    client_ip = get_client_ip(request)

    # Validate allowed_env
    if body.allowed_env not in ("prod", "test", "both"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "success": False,
                "error": True,
                "message": "allowed_env must be 'prod', 'test', or 'both'",
                "status_code": 400,
            },
        )

    # Generate client_id from sanitized name + random hex
    sanitized = body.client_name.lower().replace(" ", "_").replace("-", "_")
    # Remove any non-alphanumeric characters except underscore
    sanitized = "".join(c for c in sanitized if c.isalnum() or c == "_")
    random_suffix = secrets.token_hex(4)
    client_id = f"{sanitized}_{random_suffix}"

    # Generate client_secret
    client_secret = secrets.token_urlsafe(32)

    # Log generation (never log the secret)
    logger.info(
        f"Credentials generated for: {body.client_name}, env: {body.allowed_env}, client_id: {client_id}",
        extra={
            "service": "admin",
            "action": "credentials_generated",
            "client_name": body.client_name,
            "client_id": client_id,
            "allowed_env": body.allowed_env,
            "client_ip": client_ip,
        },
    )

    return {
        "client_id": client_id,
        "client_secret": client_secret,
        "allowed_env": body.allowed_env,
        "client_name": body.client_name,
        "instruction": (
            "Copy these credentials now. The secret will not be shown again. "
            f"Add them to your .env file as CLIENT_{sanitized.upper()}_ID and "
            f"CLIENT_{sanitized.upper()}_SECRET, then restart the application."
        ),
    }


# ─────────────────────────────────────────────────────── ENDPOINT 2: List clients

@router.get(
    "/clients",
    summary="List registered clients",
    description=(
        "Returns all registered clients from environment variables. "
        "Requires X-Admin-Key header. "
        "Client secrets are NOT returned — this is a read-only list."
    ),
)
async def list_clients(
    request: Request,
    _: bool = Depends(verify_admin_key),
) -> Dict[str, Any]:
    """
    GET /admin/clients

    Returns list of all registered clients without their secrets.
    """
    client_ip = get_client_ip(request)

    clients_raw = settings.get_all_clients()

    # Remove client_secret from each client before returning
    clients_safe: List[Dict[str, Any]] = []
    for client in clients_raw:
        clients_safe.append({
            "client_id": client["client_id"],
            "client_name": client["client_name"],
            "allowed_env": client["allowed_env"],
        })

    logger.info(
        f"Client list retrieved by admin from {client_ip}, total: {len(clients_safe)}",
        extra={
            "service": "admin",
            "action": "clients_listed",
            "total_clients": len(clients_safe),
            "client_ip": client_ip,
        },
    )

    return {
        "clients": clients_safe,
        "total": len(clients_safe),
    }


# ─────────────────────────────────────────────────────── ENDPOINT 3: Admin ping

@router.get(
    "/ping",
    summary="Health check for admin access",
    description="Simple endpoint to verify admin key is working. Returns 200 if X-Admin-Key is valid.",
)
async def admin_ping(
    request: Request,
    _: bool = Depends(verify_admin_key),
) -> Dict[str, str]:
    """
    GET /admin/ping

    Verifies admin authentication is working.
    Returns success message if X-Admin-Key header is valid.
    """
    client_ip = get_client_ip(request)

    logger.info(
        f"Admin ping from {client_ip}",
        extra={
            "service": "admin",
            "action": "ping",
            "client_ip": client_ip,
        },
    )

    return {"status": "admin access confirmed"}
