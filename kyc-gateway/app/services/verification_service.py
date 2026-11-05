"""
POST /identity_verification service logic.

Processing order per the spec:
  1. Validate the request payload (handled by Pydantic schema)
  2. Select the provider from id_type
  3. Relay the identity and biometric to that provider
     - NATIONAL ID: full three-step NIRA flow (token → certificate → auth)
       executed internally by app.services.nira_service.NIRAAuthenticator.
       The vendor never handles NIRA credentials, certificates, or crypto.
     - REFUGEE ID: relay to UNHCR via simulated provider
     - PASSPORT/COI/REGISTRY_PENDING: VERIFICATION_UNAVAILABLE
  4. Return the outcome and, on success, a verification_reference

This endpoint does NOT evaluate the ownership limit for individuals — that
is ownership_service's job (POST /ownership_check, and the check performed
again at registration commit). Biometric payloads are read only to select
and validate shape; they are never written to the verification_references
store or to any log line.
"""

import base64
import json
from datetime import datetime, timezone

from app.core.config import settings
from app.schemas.kyc import (
    IdentityVerificationData,
    IdentityVerificationRequest,
    IsoImageBiometric,
)
from app.services.biometric_converter import convert_biometric_if_wsq
from app.services.db import store
from app.services.exceptions import KycServiceError
from app.services.nira_service import get_nira_authenticator
from app.services.provider_stub import resolve_provider, verify_with_provider

_ORG_ID_TYPES = {"COI", "REGISTRY_PENDING"}


def _validate_biometric_shape(payload: IdentityVerificationRequest) -> None:
    """
    Confirms the biometric format matches what the provider for this id_type
    expects. Individual id_types other than PASSPORT require a biometric;
    PASSPORT and every organisation id_type must not carry one (NCIC/URSB/
    REGISTRY_PENDING are not integrated, and an organisation has no
    biometric at all).
    """
    provider = resolve_provider(payload.id_type)

    if payload.id_type in _ORG_ID_TYPES or payload.id_type == "PASSPORT":
        if payload.biometric is not None:
            raise KycServiceError(
                422, "INVALID_BIOMETRIC",
                f"{payload.id_type} does not accept a biometric object",
            )
        return

    if payload.biometric is None:
        raise KycServiceError(422, "MISSING_FIELD", "biometric is required for this id_type")

    if payload.id_type == "NATIONAL ID":
        if payload.biometric.format != "MOSIP_SBI_SIGNED":
            raise KycServiceError(
                422, "INVALID_BIOMETRIC", "NATIONAL ID requires format MOSIP_SBI_SIGNED"
            )
    elif payload.id_type == "REFUGEE ID":
        if payload.biometric.format not in ("ISO_19794_4", "ISO_19794_6", "JPEG", "WSQ"):
            raise KycServiceError(
                422, "INVALID_BIOMETRIC",
                "REFUGEE ID requires format ISO_19794_4, ISO_19794_6, JPEG, or WSQ"
            )


def _decode_block_jwt_payload(data_b64url: str) -> dict:
    """Decode the base64url-encoded JWT payload of a biometric block (no verification).

    The block's `data` field is a JWT: header.payload.signature. We only need the
    payload claims (transactionId, env).
    """
    parts = data_b64url.split(".")
    if len(parts) < 2:
        raise KycServiceError(
            422, "INVALID_BIOMETRIC", "Block data is not a valid JWT (missing payload)"
        )
    payload_b64 = parts[1]
    padding = 4 - len(payload_b64) % 4
    if padding != 4:
        payload_b64 += "=" * padding
    try:
        payload_json = base64.urlsafe_b64decode(payload_b64)
        return json.loads(payload_json)
    except Exception as exc:
        raise KycServiceError(
            422, "INVALID_BIOMETRIC", f"Failed to decode block JWT payload: {exc}"
        )


def _extract_block_metadata(blocks: list) -> tuple:
    """Extract transactionId and env from the first block's JWT data field.

    Returns: (transaction_id, env) — either may be None if not present in the JWT.
    """
    first_block = blocks[0]
    data_jwt = first_block.get("data", "")
    if not data_jwt:
        return None, None
    claims = _decode_block_jwt_payload(data_jwt)
    return claims.get("transactionId"), claims.get("env")


async def verify_identity(payload: IdentityVerificationRequest) -> IdentityVerificationData:
    _validate_biometric_shape(payload)

    # NATIONAL ID requires the three-step NIRA flow via UCC
    # (/nira/token → /nira/certificate → /nira/auth). The middleware executes
    # the entire flow internally using stored NIRA credentials and crypto;
    # the vendor only supplies identity + biometric blocks.
    if payload.id_type == "NATIONAL ID":
        return await _verify_national_id(payload)

    # Convert WSQ biometric to JPEG before provider call — UCC requires JPEG
    # for REFUGEE ID. The conversion is transparent; the stored payload still
    # reflects the original client-submitted format.
    biometric = payload.biometric
    if biometric is not None and biometric.format == "WSQ":
        converted = convert_biometric_if_wsq(biometric.model_dump())
        payload.biometric = IsoImageBiometric(
            biometric_type=converted["biometric_type"],
            format=converted["format"],
            data=converted["data"],
        )

    result = verify_with_provider(payload.id_type, payload.id_number)

    verified_at = datetime.now(timezone.utc).isoformat() if result.verified else None
    issue_reference = result.reason_code != "IDENTITY_REJECTED"

    reference = None
    expires_at = None
    if issue_reference:
        entry = store.create_verification_reference(
            id_type=payload.id_type,
            id_number=payload.id_number,
            provider=result.provider,
            verified=result.verified,
            reason_code=result.reason_code,
            ttl_hours=settings.VERIFICATION_REFERENCE_TTL_HOURS,
            verified_at=verified_at,
        )
        reference = entry.reference
        expires_at = datetime.fromtimestamp(entry.expires_at, tz=timezone.utc).isoformat()

    return IdentityVerificationData(
        verified=result.verified,
        reason_code=result.reason_code,
        message=result.message,
        provider=result.provider,
        provider_status=result.provider_status,
        verification_reference=reference,
        verified_at=verified_at,
        expires_at=expires_at,
        matched_attributes=result.matched_attributes,
    )


async def _verify_national_id(payload: IdentityVerificationRequest) -> IdentityVerificationData:
    """
    Execute the full three-step NIRA AUTH flow internally on behalf of the
    vendor. Returns IdentityVerificationData with the verification_reference
    from NIRA's X-Verification-Reference response header.

    Biometric blocks come from the request body (payload.biometric.blocks).
    The transaction_id is taken from the block JWT's data field if not
    provided in the request body; env is validated against NIRA_ENV.
    """
    authenticator = get_nira_authenticator()
    try:
        blocks = (
            payload.biometric.blocks
            if payload.biometric and hasattr(payload.biometric, "blocks")
            else []
        )
        if not isinstance(blocks, list) or not blocks:
            raise KycServiceError(
                422, "MISSING_FIELD",
                "NATIONAL ID requires at least one signed biometric block in the request body",
            )

        block_transaction_id, block_env = _extract_block_metadata(blocks)

        # Prefer block JWT transactionId over body; fall back to body
        transaction_id = block_transaction_id or payload.transaction_id
        if not transaction_id:
            raise KycServiceError(
                422, "MISSING_FIELD",
                "transaction_id is required (block JWT must contain one or provide it in the body)",
            )

        # If both are present, they must match
        if block_transaction_id and transaction_id != block_transaction_id:
            raise KycServiceError(
                422, "INVALID_BIOMETRIC",
                f"transaction_id '{transaction_id}' does not match block JWT "
                f"transactionId '{block_transaction_id}'",
            )

        # Validate block env against configured NIRA env (case-insensitive)
        if block_env and authenticator.env:
            if block_env.lower() != authenticator.env.lower():
                raise KycServiceError(
                    422, "INVALID_BIOMETRIC",
                    f"MOSIP SBI block environment '{block_env}' does not match "
                    f"configured NIRA environment '{authenticator.env}'"
                )

        result = await authenticator.authenticate_national_id(
            transaction_id=transaction_id,
            nin=payload.id_number,
            date_of_birth=payload.date_of_birth or "",
            surname=payload.last_name or "",
            given_names=payload.first_name or "",
            biometric_blocks=blocks,
        )
    except KycServiceError:
        raise
    except Exception as exc:
        raise KycServiceError(
            502, "NIRA_AUTH_ERROR", f"NIRA authentication failed: {exc}"
        )

    verified_at = datetime.now(timezone.utc).isoformat() if result["auth_status"] else None
    issue_reference = result["auth_status"] and result["verification_reference"] is not None

    reference = None
    expires_at = None
    if issue_reference and result["verification_reference"]:
        entry = store.create_verification_reference(
            id_type=payload.id_type,
            id_number=payload.id_number,
            provider="NIRA",
            verified=result["auth_status"],
            reason_code="IDENTITY_ACCEPTED" if result["auth_status"] else "IDENTITY_REJECTED",
            ttl_hours=settings.VERIFICATION_REFERENCE_TTL_HOURS,
            verified_at=verified_at,
        )
        reference = entry.reference
        expires_at = datetime.fromtimestamp(entry.expires_at, tz=timezone.utc).isoformat()

    return IdentityVerificationData(
        verified=result["auth_status"],
        reason_code=(
            "IDENTITY_ACCEPTED" if result["auth_status"] else "IDENTITY_REJECTED"
        ),
        message=(
            "Identity verified via NIRA"
            if result["auth_status"]
            else "NIRA authentication rejected"
        ),
        provider="NIRA",
        provider_status="LIVE",
        verification_reference=reference,
        verified_at=verified_at,
        expires_at=expires_at,
        matched_attributes=None,
    )
