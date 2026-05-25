"""
Refugee API routes — UCC refugee identity verification via biometric fingerprint.

Endpoints:
  POST /api/refugee/prod/verify  — production (allowed caller: 192.168.168.10 + valid token)
  POST /api/refugee/test/verify  — test       (allowed caller: 192.168.168.12 + valid token)

Each endpoint uses its own IP dependency, token dependency, and UCC config.
Cross-environment calls are blocked with 403.
Fingerprint payloads can be 50-200 KB — never logged, only character count is recorded.
Tokens are single-use: deleted immediately after any verification attempt.
"""

import logging
from typing import Dict, Any
import httpx
from fastapi import APIRouter, Depends, HTTPException, status, Request
from pydantic import BaseModel, Field
from app.api.deps.ip_whitelist import (
    validate_refugee_prod_ip,
    validate_refugee_test_ip,
    get_client_ip,
)
from app.api.deps.auth import verify_prod_token, verify_test_token
from app.core.config import settings
from app.services.refugee_service import refugee_service
from app.services.auth_service import auth_service


logger = logging.getLogger("middleware")

router = APIRouter(tags=["Refugee"])


# ─────────────────────────────────────────────────────── shared request model

class RefugeeVerifyRequest(BaseModel):
    """
    Request body for UCC refugee biometric verification.
    Field names match the real UCC API payload observed in production logs.
    """

    individualId: str = Field(
        ...,
        description="UCC refugee individual ID",
        example="PCS-00077251",
    )
    sex: str = Field(
        ...,
        description="Sex of the individual: 'Male' or 'Female'",
        example="Male",
    )
    yearOfBirth: int = Field(
        ...,
        description="Year of birth as a 4-digit integer",
        example=1987,
    )
    fingerprint: str = Field(
        ...,
        description=(
            "Base64-encoded WSQ fingerprint image. "
            "Large string (50-200 KB) — passed through to UCC as-is. Never logged."
        ),
        example="/6D/qAB6TklT... (WSQ fingerprint)",
    )

    model_config = {
        "json_schema_extra": {
            "example": {
                "individualId": "PCS-00077251",
                "sex":          "Male",
                "yearOfBirth":  1987,
                "fingerprint":  "/6D/qAB6TklT... (WSQ fingerprint)",
            }
        }
    }


# ──────────────────────────────────────────────── POST /prod/verify

@router.post(
    "/prod/verify",
    summary="[PRODUCTION] Verify refugee identity via UCC biometric API",
    description=(
        "Production endpoint. Allowed caller: 192.168.168.10 only. "
        "Requires valid Bearer token. "
        "Token is invalidated immediately after this request — success or failure. "
        "Logs in to UCC to obtain a Bearer token, then posts the biometric "
        "payload to the UCC production validate endpoint."
    ),
)
async def verify_refugee_prod(
    request: Request,
    body: RefugeeVerifyRequest,
    token_payload: Dict[str, Any] = Depends(verify_prod_token),
    _: bool = Depends(validate_refugee_prod_ip),
) -> Dict[str, Any]:
    """
    POST /api/refugee/prod/verify — UCC production refugee verification.
    Token is deleted from Redis immediately in ALL cases (success, timeout, error).
    """
    client_ip       = get_client_ip(request)
    fingerprint_len = len(body.fingerprint)
    config          = settings.get_refugee_config("prod")
    jti             = token_payload["jti"]

    logger.info(
        "REFUGEE PROD verification request received",
        extra={
            "service":      "refugee",
            "environment":  "production",
            "client_ip":    client_ip,
            "client_id":    token_payload.get("sub"),
            "individualId": body.individualId,
            "sex":          body.sex,
            "yearOfBirth":  body.yearOfBirth,
            "fingerprint":  f"[PRESENT, {fingerprint_len} chars]",
            "path":         "/api/refugee/prod/verify",
        },
    )

    try:
        result = await refugee_service.verify_refugee(
            individual_id=body.individualId,
            sex=body.sex,
            year_of_birth=body.yearOfBirth,
            fingerprint=body.fingerprint,
            validate_url=config["validate_url"],
            login_url=config["login_url"],
            username=config["username"],
            password=config["password"],
            environment="production",
        )
        # SUCCESS → delete token immediately
        await auth_service.delete_token(jti)
        logger.info(
            f"Token deleted after successful REFUGEE PROD verification, jti: {jti[:8]}...",
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
            f"Token deleted after REFUGEE PROD timeout, jti: {jti[:8]}...",
            extra={"service": "auth", "action": "token_deleted", "reason": "timeout", "jti_prefix": jti[:8]},
        )
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail={
                "success":     False,
                "error":       True,
                "environment": "production",
                "message":     "UCC did not respond in time. Your token has been invalidated. Request a new token from POST /auth/token and retry.",
                "status_code": 504,
                "path":        "/api/refugee/prod/verify",
            },
        )

    except HTTPException:
        # HTTP errors from deps (403 IP, 401 token, etc.) → delete token
        await auth_service.delete_token(jti)
        logger.info(
            f"Token deleted after HTTP error in REFUGEE PROD, jti: {jti[:8]}...",
            extra={"service": "auth", "action": "token_deleted", "reason": "http_error", "jti_prefix": jti[:8]},
        )
        raise

    except Exception as e:
        # ANY other error → still delete token
        await auth_service.delete_token(jti)
        logger.info(
            f"Token deleted after REFUGEE PROD error, jti: {jti[:8]}...",
            extra={"service": "auth", "action": "token_deleted", "reason": "error", "jti_prefix": jti[:8]},
        )
        logger.error(
            "REFUGEE PROD verification failed",
            extra={
                "service":      "refugee",
                "environment":  "production",
                "client_ip":    client_ip,
                "individualId": body.individualId,
                "error":        str(e),
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
                "path":        "/api/refugee/prod/verify",
            },
        )


# ──────────────────────────────────────────────── POST /test/verify

@router.post(
    "/test/verify",
    summary="[TEST] Verify refugee identity via UCC biometric API",
    description=(
        "Test endpoint. Allowed caller: 192.168.168.12 only. "
        "Requires valid Bearer token. "
        "Token is invalidated immediately after this request — success or failure. "
        "Logs in to UCC to obtain a Bearer token, then posts the biometric "
        "payload to the UCC test validate endpoint."
    ),
)
async def verify_refugee_test(
    request: Request,
    body: RefugeeVerifyRequest,
    token_payload: Dict[str, Any] = Depends(verify_test_token),
    _: bool = Depends(validate_refugee_test_ip),
) -> Dict[str, Any]:
    """
    POST /api/refugee/test/verify — UCC test refugee verification.
    Token is deleted from Redis immediately in ALL cases (success, timeout, error).
    """
    client_ip       = get_client_ip(request)
    fingerprint_len = len(body.fingerprint)
    config          = settings.get_refugee_config("test")
    jti             = token_payload["jti"]

    logger.info(
        "REFUGEE TEST verification request received",
        extra={
            "service":      "refugee",
            "environment":  "test",
            "client_ip":    client_ip,
            "client_id":    token_payload.get("sub"),
            "individualId": body.individualId,
            "sex":          body.sex,
            "yearOfBirth":  body.yearOfBirth,
            "fingerprint":  f"[PRESENT, {fingerprint_len} chars]",
            "path":         "/api/refugee/test/verify",
        },
    )

    try:
        result = await refugee_service.verify_refugee(
            individual_id=body.individualId,
            sex=body.sex,
            year_of_birth=body.yearOfBirth,
            fingerprint=body.fingerprint,
            validate_url=config["validate_url"],
            login_url=config["login_url"],
            username=config["username"],
            password=config["password"],
            environment="test",
        )
        # SUCCESS → delete token immediately
        await auth_service.delete_token(jti)
        logger.info(
            f"Token deleted after successful REFUGEE TEST verification, jti: {jti[:8]}...",
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
            f"Token deleted after REFUGEE TEST timeout, jti: {jti[:8]}...",
            extra={"service": "auth", "action": "token_deleted", "reason": "timeout", "jti_prefix": jti[:8]},
        )
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail={
                "success":     False,
                "error":       True,
                "environment": "test",
                "message":     "UCC did not respond in time. Your token has been invalidated. Request a new token from POST /auth/token and retry.",
                "status_code": 504,
                "path":        "/api/refugee/test/verify",
            },
        )

    except HTTPException:
        # HTTP errors from deps (403 IP, 401 token, etc.) → delete token
        await auth_service.delete_token(jti)
        logger.info(
            f"Token deleted after HTTP error in REFUGEE TEST, jti: {jti[:8]}...",
            extra={"service": "auth", "action": "token_deleted", "reason": "http_error", "jti_prefix": jti[:8]},
        )
        raise

    except Exception as e:
        # ANY other error → still delete token
        await auth_service.delete_token(jti)
        logger.info(
            f"Token deleted after REFUGEE TEST error, jti: {jti[:8]}...",
            extra={"service": "auth", "action": "token_deleted", "reason": "error", "jti_prefix": jti[:8]},
        )
        logger.error(
            "REFUGEE TEST verification failed",
            extra={
                "service":      "refugee",
                "environment":  "test",
                "client_ip":    client_ip,
                "individualId": body.individualId,
                "error":        str(e),
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
                "path":        "/api/refugee/test/verify",
            },
        )
