"""NIRA MOSIP authentication operations relayed through the UCC gateway."""

from typing import Any

from fastapi import APIRouter, Body, Depends, Header, HTTPException, status

from app.api.deps.auth import require_api_key
from app.core.config import settings

router = APIRouter(prefix="/nira", tags=["NIRA"])


def _require_ucc_forwarding() -> None:
    if not settings.UCC_FORWARDING_ENABLED:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "status": "error",
                "error_code": "UCC_FORWARDING_DISABLED",
                "message": "NIRA operations require UCC forwarding to be enabled",
            },
        )


@router.post(
    "/token",
    summary="Obtain a NIRA token through UCC",
    description=(
        "Uses the operator's NIRA client credentials. Reuse the returned token "
        "until it expires; obtain another only when no valid token is available. "
        "The NIRA token is returned in the Authorization response header."
    ),
    responses={
        200: {
            "description": "NIRA response; token, when issued, is in Authorization.",
            "headers": {
                "Authorization": {
                    "description": "NIRA token in NIRA's form: Authorization=<token>.",
                    "schema": {"type": "string"},
                },
                "Cache-Control": {
                    "description": "Token-bearing responses are not cacheable.",
                    "schema": {"type": "string"},
                },
            },
        },
        401: {"description": "Missing or invalid UCC API key or NIRA credentials."},
        403: {"description": "UCC API key is not linked to an operator."},
        422: {"description": "Missing or invalid NIRA token credentials."},
        429: {"description": "Rate limit exceeded."},
        502: {"description": "UCC could not reach NIRA."},
        503: {"description": "UCC forwarding is disabled."},
    },
)
async def obtain_nira_token(
    _api_key: str = Depends(require_api_key),
    x_client_id: str = Header(..., alias="X-Client-ID", description="NIRA-issued client ID."),
    x_secret_key: str = Header(..., alias="X-Secret-Key", description="NIRA-issued client secret."),
    x_app_id: str = Header(..., alias="X-App-ID", description="NIRA-issued app ID, normally ida."),
) -> None:
    _require_ucc_forwarding()


@router.get(
    "/certificate",
    summary="Obtain NIRA's encryption certificate through UCC",
    description=(
        "Fetch a fresh certificate before each AUTH request. Validate it against "
        "the CA certificate obtained directly from NIRA before encrypting to it. "
        "Send the NIRA token as `Authorization: Authorization=<token>`."
    ),
    responses={
        200: {
            "description": "NIRA response containing response.certificate.",
            "headers": {
                "Cache-Control": {
                    "description": "Certificate responses are not cacheable.",
                    "schema": {"type": "string"},
                }
            },
        },
        401: {"description": "Missing or invalid UCC API key or NIRA token."},
        403: {"description": "UCC API key is not linked to an operator."},
        422: {"description": "Missing or invalid NIRA token."},
        429: {"description": "Rate limit exceeded."},
        502: {"description": "UCC could not reach NIRA."},
        503: {"description": "UCC forwarding is disabled."},
    },
)
async def obtain_nira_certificate(
    _api_key: str = Depends(require_api_key),
    authorization: str = Header(
        ...,
        alias="Authorization",
        description="NIRA token in NIRA's form: `Authorization=<token>`.",
    ),
) -> None:
    _require_ucc_forwarding()


@router.post(
    "/auth",
    summary="Verify a National ID through NIRA",
    description=(
        "Forwards the signed NIRA AUTH request unchanged. Supply the NIRA token "
        "and all three NIRA AUTH credentials. Call immediately after biometric "
        "capture; the device-signed block is fresh for about 30 seconds. On a "
        "successful authentication, UCC returns X-Verification-Reference."
    ),
    responses={
        200: {
            "description": (
                "NIRA authentication response. Check response.authStatus and errors; "
                "a positive result also returns X-Verification-Reference."
            ),
            "headers": {
                "X-Verification-Reference": {
                    "description": "UCC reference for successful National ID verification.",
                    "schema": {"type": "string"},
                }
            },
        },
        401: {"description": "Missing or invalid UCC API key or NIRA token."},
        403: {"description": "UCC API key is not linked to an operator."},
        422: {"description": "Missing/invalid NIRA credentials or invalid JSON body."},
        429: {"description": "Rate limit exceeded."},
        502: {"description": "UCC could not reach NIRA."},
        503: {"description": "UCC forwarding is disabled."},
    },
)
async def authenticate_nira_identity(
    _api_key: str = Depends(require_api_key),
    x_misp_license_key: str = Header(
        ...,
        alias="X-MISP-License-Key",
        description="NIRA-issued MISP licence key.",
    ),
    x_partner_id: str = Header(
        ...,
        alias="X-Partner-ID",
        description="NIRA-issued partner ID; include it on every AUTH request.",
    ),
    x_partner_api_key: str = Header(
        ...,
        alias="X-Partner-API-Key",
        description="NIRA-issued partner API key.",
    ),
    authorization: str = Header(
        ...,
        alias="Authorization",
        description="NIRA token in NIRA's form: `Authorization=<token>`.",
    ),
    signature: str = Header(
        ...,
        alias="Signature",
        description="Required detached JWS signature over the request body.",
    ),
    body: dict[str, Any] = Body(
        ...,
        description="NIRA AUTH request, encrypted and signed by the operator.",
    ),
) -> None:
    _require_ucc_forwarding()
