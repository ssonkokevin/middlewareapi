"""
NIRA API routes — Uganda National ID verification.

Endpoints:
  POST /api/nira/prod/verify  — production (allowed caller: 10.20.20.1 + valid token)
  POST /api/nira/test/verify  — test       (allowed caller: 10.20.20.4 + valid token)

Each endpoint uses its own IP dependency, token dependency, and NIRA config.
Cross-environment calls are blocked with 403.
Tokens are single-use: deleted immediately after any verification attempt.
"""

import logging
from typing import Dict, Any
import httpx
from fastapi import APIRouter, Depends, HTTPException, status, Request
from pydantic import BaseModel, Field
from app.api.deps.ip_whitelist import (
    validate_nira_prod_ip,
    validate_nira_test_ip,
    get_client_ip,
)
from app.api.deps.auth import verify_prod_token, verify_test_token
from app.core.config import settings
from app.services.nira_service import nira_service
from app.services.auth_service import auth_service


logger = logging.getLogger("middleware")

router = APIRouter(tags=["NIRA"])


# ─────────────────────────────────────────────────────── shared request model

class NiraVerifyRequest(BaseModel):
    """
    Request body for NIRA National ID verification.
    Field names and values match the real NIRA SOAP payload from production logs.
    """

    nationalId: str = Field(
        ...,
        description="Uganda National ID number",
        example="CM9900910UKVUL",
    )
    dateOfBirth: str = Field(
        ...,
        description="Date of birth in DD/MM/YYYY format",
        example="11/11/1999",
    )
    documentId: str = Field(
        default="",
        description="Physical card document number (optional)",
        example="022815224",
    )
    givenNames: str = Field(
        default="",
        description="First / given names (optional)",
        example="",
    )
    otherNames: str = Field(
        default="?",
        description="Middle names; use '?' when unknown",
        example="?",
    )
    surname: str = Field(
        default="",
        description="Family / last name (optional)",
        example="",
    )

    model_config = {
        "json_schema_extra": {
            "example": {
                "nationalId":  "CM9900910UKVUL",
                "dateOfBirth": "11/11/1999",
                "documentId":  "022815224",
                "givenNames":  "",
                "otherNames":  "?",
                "surname":     "",
            }
        }
    }


# ──────────────────────────────────────────────── POST /prod/verify

@router.post(
    "/prod/verify",
    summary="[PRODUCTION] Verify Uganda National ID via NIRA",
    description=(
        "Production endpoint. Allowed caller: 10.20.20.1 only. "
        "Requires valid Bearer token. "
        "Token is invalidated immediately after this request — success or failure. "
        "Builds a SOAP/XML request with WS-Security PasswordDigest, "
        "calls the NIRA production endpoint, and returns parsed JSON."
    ),
)
async def verify_nira_prod(
    request: Request,
    body: NiraVerifyRequest,
    token_payload: Dict[str, Any] = Depends(verify_prod_token),
    _: bool = Depends(validate_nira_prod_ip),
) -> Dict[str, Any]:
    """
    POST /api/nira/prod/verify — NIRA production verification.
    Token is deleted from Redis immediately in ALL cases (success, timeout, error).
    """
    client_ip = get_client_ip(request)
    config    = settings.get_nira_config("prod")
    jti       = token_payload["jti"]

    logger.info(
        "NIRA PROD verification request received",
        extra={
            "service":     "nira",
            "environment": "production",
            "client_ip":   client_ip,
            "client_id":   token_payload.get("sub"),
            "nationalId":  body.nationalId,
            "dateOfBirth": body.dateOfBirth,
            "path":        "/api/nira/prod/verify",
        },
    )

    try:
        result = await nira_service.verify_person(
            national_id=body.nationalId,
            date_of_birth=body.dateOfBirth,
            document_id=body.documentId,
            given_names=body.givenNames,
            other_names=body.otherNames,
            surname=body.surname,
            url=config["url"],
            username=config["username"],
            password=config["password"],
            environment="production",
        )
        # SUCCESS → delete token immediately
        await auth_service.delete_token(jti)
        logger.info(
            f"Token deleted after successful NIRA PROD verification, jti: {jti[:8]}...",
            extra={"service": "auth", "action": "token_deleted", "reason": "success", "jti_prefix": jti[:8]},
        )
        return {
            "success":     True,
            "environment": "production",
            "client_id":   token_payload.get("sub"),
            "data":        result,
        }

    except httpx.TimeoutException:
        # TIMEOUT → still delete token, no retry with same token
        await auth_service.delete_token(jti)
        logger.info(
            f"Token deleted after NIRA PROD timeout, jti: {jti[:8]}...",
            extra={"service": "auth", "action": "token_deleted", "reason": "timeout", "jti_prefix": jti[:8]},
        )
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail={
                "success":     False,
                "error":       True,
                "environment": "production",
                "message":     "NIRA did not respond in time. Your token has been invalidated. Request a new token from POST /auth/token and retry.",
                "status_code": 504,
                "path":        "/api/nira/prod/verify",
            },
        )

    except HTTPException:
        # HTTP errors from deps (403 IP, 401 token, etc.) → delete token
        await auth_service.delete_token(jti)
        logger.info(
            f"Token deleted after HTTP error in NIRA PROD, jti: {jti[:8]}...",
            extra={"service": "auth", "action": "token_deleted", "reason": "http_error", "jti_prefix": jti[:8]},
        )
        raise

    except Exception as e:
        # ANY other error → still delete token
        await auth_service.delete_token(jti)
        logger.info(
            f"Token deleted after NIRA PROD error, jti: {jti[:8]}...",
            extra={"service": "auth", "action": "token_deleted", "reason": "error", "jti_prefix": jti[:8]},
        )
        logger.error(
            "NIRA PROD verification failed",
            extra={
                "service":     "nira",
                "environment": "production",
                "client_ip":   client_ip,
                "nationalId":  body.nationalId,
                "error":       str(e),
            },
        )
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail={
                "success":     False,
                "error":       True,
                "environment": "production",
                "message":     f"Verification system error. Your token has been invalidated. Request a new token from POST /auth/token and retry.",
                "status_code": 502,
                "path":        "/api/nira/prod/verify",
            },
        )


# ──────────────────────────────────────────────── POST /test/verify

@router.post(
    "/test/verify",
    summary="[TEST] Verify Uganda National ID via NIRA",
    description=(
        "Test endpoint. Allowed caller: 10.20.20.4 only. "
        "Requires valid Bearer token. "
        "Token is invalidated immediately after this request — success or failure. "
        "Builds a SOAP/XML request with WS-Security PasswordDigest, "
        "calls the NIRA test endpoint, and returns parsed JSON."
    ),
)
async def verify_nira_test(
    request: Request,
    body: NiraVerifyRequest,
    token_payload: Dict[str, Any] = Depends(verify_test_token),
    _: bool = Depends(validate_nira_test_ip),
) -> Dict[str, Any]:
    """
    POST /api/nira/test/verify — NIRA test verification.
    Token is deleted from Redis immediately in ALL cases (success, timeout, error).
    """
    client_ip = get_client_ip(request)
    config    = settings.get_nira_config("test")
    jti       = token_payload["jti"]

    logger.info(
        "NIRA TEST verification request received",
        extra={
            "service":     "nira",
            "environment": "test",
            "client_ip":   client_ip,
            "client_id":   token_payload.get("sub"),
            "nationalId":  body.nationalId,
            "dateOfBirth": body.dateOfBirth,
            "path":        "/api/nira/test/verify",
        },
    )

    try:
        result = await nira_service.verify_person(
            national_id=body.nationalId,
            date_of_birth=body.dateOfBirth,
            document_id=body.documentId,
            given_names=body.givenNames,
            other_names=body.otherNames,
            surname=body.surname,
            url=config["url"],
            username=config["username"],
            password=config["password"],
            environment="test",
        )
        # SUCCESS → delete token immediately
        await auth_service.delete_token(jti)
        logger.info(
            f"Token deleted after successful NIRA TEST verification, jti: {jti[:8]}...",
            extra={"service": "auth", "action": "token_deleted", "reason": "success", "jti_prefix": jti[:8]},
        )
        return {
            "success":     True,
            "environment": "test",
            "client_id":   token_payload.get("sub"),
            "data":        result,
        }

    except httpx.TimeoutException:
        # TIMEOUT → still delete token, no retry with same token
        await auth_service.delete_token(jti)
        logger.info(
            f"Token deleted after NIRA TEST timeout, jti: {jti[:8]}...",
            extra={"service": "auth", "action": "token_deleted", "reason": "timeout", "jti_prefix": jti[:8]},
        )
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail={
                "success":     False,
                "error":       True,
                "environment": "test",
                "message":     "NIRA did not respond in time. Your token has been invalidated. Request a new token from POST /auth/token and retry.",
                "status_code": 504,
                "path":        "/api/nira/test/verify",
            },
        )

    except HTTPException:
        # HTTP errors from deps (403 IP, 401 token, etc.) → delete token
        await auth_service.delete_token(jti)
        logger.info(
            f"Token deleted after HTTP error in NIRA TEST, jti: {jti[:8]}...",
            extra={"service": "auth", "action": "token_deleted", "reason": "http_error", "jti_prefix": jti[:8]},
        )
        raise

    except Exception as e:
        # ANY other error → still delete token
        await auth_service.delete_token(jti)
        logger.info(
            f"Token deleted after NIRA TEST error, jti: {jti[:8]}...",
            extra={"service": "auth", "action": "token_deleted", "reason": "error", "jti_prefix": jti[:8]},
        )
        logger.error(
            "NIRA TEST verification failed",
            extra={
                "service":     "nira",
                "environment": "test",
                "client_ip":   client_ip,
                "nationalId":  body.nationalId,
                "error":       str(e),
            },
        )
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail={
                "success":     False,
                "error":       True,
                "environment": "test",
                "message":     f"Verification system error. Your token has been invalidated. Request a new token from POST /auth/token and retry.",
                "status_code": 502,
                "path":        "/api/nira/test/verify",
            },
        )
