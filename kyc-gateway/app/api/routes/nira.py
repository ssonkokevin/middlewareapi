"""NIRA authentication operations relayed through the UCC gateway.

Includes:
- Three-step NIRA AUTH flow for NEW National ID (token → certificate → auth)
- Legacy NIRA TPI for OLD National ID cards (9-digit card number, card data only, no biometric)
- Helper endpoint for vendor-friendly legacy verification (auto-generates WS-Security)
"""

from typing import Any

import base64
import hashlib
import secrets
from datetime import datetime, timezone, timedelta

import httpx
from fastapi import APIRouter, Body, Depends, Header, HTTPException, Request, Response, status
from pydantic import BaseModel, Field

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


@router.post(
    "/legacy",
    summary="Call NIRA's legacy TPI service through UCC (OLD National ID cards)",
    description=(
        "Verifies holders of older national ID cards (9-digit card number) or changes "
        "the NIRA TPI account password. Uses SOAP 1.1 with WS-Security UsernameToken "
        "(PasswordDigest). No biometric is sent — this is a card-data check only. "
        "On successful match with a Valid card, UCC returns X-Verification-Reference."
    ),
    responses={
        200: {
            "description": (
                "NIRA SOAP response relayed unchanged. A successful verification "
                "also returns X-Verification-Reference header."
            ),
            "headers": {
                "X-Verification-Reference": {
                    "description": "UCC reference for successful legacy National ID verification.",
                    "schema": {"type": "string"},
                }
            },
        },
        401: {"description": "Missing or invalid UCC API key."},
        403: {"description": "UCC API key is not linked to an operator."},
        422: {"description": "Invalid SOAP envelope, missing fields, or documentId not 9 digits."},
        429: {"description": "Rate limit exceeded."},
        502: {"description": "UCC could not reach NIRA legacy service."},
        503: {"description": "UCC forwarding is disabled."},
    },
)
async def call_nira_legacy(
    request: Request,
    _api_key: str = Depends(require_api_key),
    soap_action: str = Header(
        default="",
        alias="SOAPAction",
        description="SOAPAction header as specified by NIRA TPI client.",
    ),
) -> Response:
    _require_ucc_forwarding()
    # This endpoint is handled by the UCC forwarding middleware in main.py
    # The middleware forwards the raw SOAP body to UCC and returns the response
    pass


# ============================================================
# HELPER ENDPOINT — Vendor-friendly legacy verification
# ============================================================

# EAT timezone (UTC+3)
_EAT = timezone(timedelta(hours=3))


class LegacyVerifyRequest(BaseModel):
    """Vendor-friendly request for old National ID verification."""
    national_id: str = Field(..., description="14-character NIN", example="CM9903610CN5AK")
    document_id: str = Field(..., description="9-digit card number (old card only)", example="020841233")
    given_names: str = Field(..., description="Given names", example="KEVIN")
    surname: str = Field(..., description="Surname", example="SSONKO")
    date_of_birth: str = Field(..., description="Date of birth DD/MM/YYYY", example="11/04/1999")
    other_names: str = Field(default="", description="Other names (optional)", example="")


class LegacyVerifyResponse(BaseModel):
    """Response from legacy verification."""
    success: bool
    transaction_status: str
    matching_status: bool
    card_status: str
    verification_reference: str | None = None
    password_days_left: str | None = None
    execution_cost: str | None = None
    raw_soap_response: str


def _generate_wsse_token(username: str, password: str) -> dict:
    """Generate WS-Security UsernameToken with PasswordDigest."""
    nonce_bytes = secrets.token_bytes(16)
    nonce_b64 = base64.b64encode(nonce_bytes).decode("utf-8")

    now = datetime.now(_EAT)
    ms = f"{now.microsecond // 1000:03d}"
    created = now.strftime("%Y-%m-%dT%H:%M:%S.") + ms + "+03:00"
    created_for_digest = now.strftime("%Y-%m-%dT%H:%M:%S.") + ms + "+0300"

    sha1_password = hashlib.sha1(password.encode("utf-8")).digest()
    created_bytes = created_for_digest.encode("utf-8")
    raw_digest = hashlib.sha1(nonce_bytes + created_bytes + sha1_password).digest()
    digest_b64 = base64.b64encode(raw_digest).decode("utf-8")

    return {
        "username": username,
        "digest": digest_b64,
        "nonce": nonce_b64,
        "created": created,
    }


def _build_soap_envelope(token: dict, req: LegacyVerifyRequest) -> str:
    """Build SOAP 1.1 envelope for verifyPersonInformation."""
    return f'''<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
                   xmlns:fac="http://facade.server.pilatus.thirdparty.tidis.muehlbauer.de/"
                   xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
  <soapenv:Header>
    <wsse:UsernameToken>
      <wsse:Username>{token["username"]}</wsse:Username>
      <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">{token["digest"]}</wsse:Password>
      <wsse:Nonce>{token["nonce"]}</wsse:Nonce>
      <wsse:Created>{token["created"]}</wsse:Created>
    </wsse:UsernameToken>
  </soapenv:Header>
  <soapenv:Body>
    <fac:verifyPersonInformation>
      <request>
        <dateOfBirth>{req.date_of_birth}</dateOfBirth>
        <documentId>{req.document_id}</documentId>
        <givenNames>{req.given_names}</givenNames>
        <nationalId>{req.national_id}</nationalId>
        <otherNames>{req.other_names}</otherNames>
        <surname>{req.surname}</surname>
      </request>
    </fac:verifyPersonInformation>
  </soapenv:Body>
</soapenv:Envelope>'''


def _parse_nira_response(soap_xml: str) -> dict:
    """Parse NIRA SOAP response for verifyPersonInformation."""
    import xml.etree.ElementTree as ET

    ns = {
        "soap": "http://schemas.xmlsoap.org/soap/envelope/",
        "ns2": "http://facade.server.pilatus.thirdparty.tidis.muehlbauer.de/",
    }

    root = ET.fromstring(soap_xml)
    body = root.find("soap:Body", ns)
    if body is None:
        return {"error": "No SOAP Body in response"}

    return_el = body.find(".//ns2:verifyPersonInformationResponse/return", ns)
    if return_el is None:
        return {"error": "No return element in response"}

    tx_status_el = return_el.find("transactionStatus")
    transaction_status = ""
    password_days_left = ""
    execution_cost = ""

    if tx_status_el is not None:
        tx_inner = tx_status_el.find("transactionStatus")
        transaction_status = tx_inner.text if tx_inner is not None else ""

        pdays = tx_status_el.find("passwordDaysLeft")
        password_days_left = pdays.text if pdays is not None else ""

        cost = tx_status_el.find("executionCost")
        execution_cost = cost.text if cost is not None else ""

        error_el = tx_status_el.find("error")
        error_code = ""
        error_message = ""
        if error_el is not None:
            code_el = error_el.find("code")
            error_code = code_el.text if code_el is not None else ""
            msg_el = error_el.find("message")
            error_message = msg_el.text if msg_el is not None else ""

    matching_el = return_el.find("matchingStatus")
    matching_status = matching_el.text == "true" if matching_el is not None else False

    card_el = return_el.find("cardStatus")
    card_status = card_el.text if card_el is not None else ""

    return {
        "transaction_status": transaction_status,
        "matching_status": matching_status,
        "card_status": card_status,
        "password_days_left": password_days_left,
        "execution_cost": execution_cost,
        "error_code": error_code,
        "error_message": error_message,
    }


@router.post(
    "/legacy/helper",
    summary="Verify old National ID via NIRA TPI (helper — auto-generates WS-Security)",
    description=(
        "Vendor-friendly endpoint for verifying old National ID cards (9-digit card number). "
        "Provide identity details in JSON; the middleware generates WS-Security UsernameToken "
        "with PasswordDigest, calls NIRA TPI via UCC, and returns parsed response. "
        "On successful match with Valid card, returns verification_reference."
    ),
    responses={
        200: {
            "description": "Verification completed. Check matching_status and card_status.",
        },
        401: {"description": "Missing or invalid API key."},
        403: {"description": "API key not linked to operator."},
        422: {"description": "Missing NIRA TPI credentials in gateway config."},
        502: {"description": "Could not reach UCC/NIRA."},
        503: {"description": "UCC forwarding disabled."},
    },
)
async def verify_legacy_helper(
    request: Request,
    body: LegacyVerifyRequest,
    _api_key: str = Depends(require_api_key),
) -> LegacyVerifyResponse:
    _require_ucc_forwarding()

    # Check NIRA TPI credentials are configured
    if not settings.NIRA_TPI_USERNAME or not settings.NIRA_TPI_PASSWORD:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "status": "error",
                "error_code": "NIRA_TPI_NOT_CONFIGURED",
                "message": "NIRA TPI credentials not configured on gateway (NIRA_TPI_USERNAME, NIRA_TPI_PASSWORD)",
            },
        )

    # Generate WS-Security token
    token = _generate_wsse_token(settings.NIRA_TPI_USERNAME, settings.NIRA_TPI_PASSWORD)

    # Build SOAP envelope
    soap_body = _build_soap_envelope(token, body)

    # Forward to UCC /nira/legacy
    url = f"{settings.UCC_BASE_URL.rstrip('/')}/api/v1/kyc/nira/legacy"
    headers = {
        "X-API-Key": settings.UCC_API_KEY,
        "Content-Type": "text/xml; charset=utf-8",
        "SOAPAction": '""',
    }

    try:
        async with httpx.AsyncClient(timeout=settings.TIMEOUT, verify=settings.UCC_TLS_VERIFY) as client:
            resp = await client.post(url, content=soap_body.encode("utf-8"), headers=headers)

    except httpx.HTTPError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail={
                "status": "error",
                "error_code": "UCC_UPSTREAM_UNAVAILABLE",
                "message": f"Unable to reach UCC KYC service: {exc}",
            },
        )

    # Parse NIRA response
    parsed = _parse_nira_response(resp.text)

    # Check for verification reference header
    x_vref = resp.headers.get("x-verification-reference")

    return LegacyVerifyResponse(
        success=parsed.get("transaction_status") == "Ok" and parsed.get("matching_status") and parsed.get("card_status") == "Valid",
        transaction_status=parsed.get("transaction_status", ""),
        matching_status=parsed.get("matching_status", False),
        card_status=parsed.get("card_status", ""),
        verification_reference=x_vref,
        password_days_left=parsed.get("password_days_left"),
        execution_cost=parsed.get("execution_cost"),
        raw_soap_response=resp.text,
    )