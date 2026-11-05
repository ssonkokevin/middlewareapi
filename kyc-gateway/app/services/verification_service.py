"""
POST /identity_verification service logic.

Processing order per the spec:
  1. Validate the request payload (handled by Pydantic schema)
  2. Select the provider from id_type
  3. Relay the identity and biometric to that provider
     - NATIONAL ID: full three-step NIRA flow (token → certificate → auth)
       executed internally by app.services.nira_service.NIRAAuthenticator.
       The vendor never handles NIRA credentials, certificates, or crypto.
       Biometric blocks may be supplied in the request body or read from
       blocks.json on the server (vendor pastes the captured block there).
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
import binascii
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

from app.core.config import settings
from app.schemas.kyc import (
    IdentityVerificationData,
    IdentityVerificationRequest,
    IsoImageBiometric,
    SignedBlockBiometric,
)
from app.services.biometric_converter import convert_biometric_if_wsq
from app.services.db import store
from app.services.exceptions import KycServiceError
from app.services.nira_service import get_nira_authenticator
from app.services.provider_stub import resolve_provider, verify_with_provider

_ORG_ID_TYPES = {"COI", "REGISTRY_PENDING"}
_BLOCKS_JSON_PATH = Path("blocks.json")


def _read_blocks_from_file() -> list[dict]:
    """Read signed MOSIP SBI blocks from blocks.json on the server.

    The vendor pastes the captured fingerprint block into blocks.json before
    calling POST /identity_verification. The middleware reads it here so the
    vendor never needs to send biometric data in the request body.
    """
    if not _BLOCKS_JSON_PATH.exists():
        return []
    try:
        with open(_BLOCKS_JSON_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return []
    if isinstance(data, dict) and "biometrics" in data:
        blocks = data["biometrics"]
    elif isinstance(data, list):
        blocks = data
    else:
        return []
    return blocks if isinstance(blocks, list) else []


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
        if payload.id_type == "NATIONAL ID" and _BLOCKS_JSON_PATH.exists():
            return
        raise KycServiceError(422, "MISSING_FIELD", "biometric is required for this id_type")

    if payload.id_type == "NATIONAL ID":
        if payload.biometric.format != "MOSIP_SBI_SIGNED":
            raise KycServiceError(
                422, "INVALID_BIOMETRIC", "NATIONAL ID requires format MOSIP_SBI_SIGNED"
            )
        if not payload.transaction_id and not _BLOCKS_JSON_PATH.exists():
            raise KycServiceError(
                422, "MISSING_FIELD",
                "transaction_id is required when format is MOSIP_SBI_SIGNED",
            )
    elif payload.id_type == "REFUGEE ID":
        if payload.biometric.format not in ("ISO_19794_4", "ISO_19794_6", "JPEG", "WSQ"):
            raise KycServiceError(
                422, "INVALID_BIOMETRIC",
                "REFUGEE ID requires format ISO_19794_4, ISO_19794_6, JPEG, or WSQ"
            )


async def verify_identity(payload: IdentityVerificationRequest) -> IdentityVerificationData:
    _validate_biometric_shape(payload)

    # NATIONAL ID requires the three-step NIRA flow via UCC
    # (/nira/token → /nira/certificate → /nira/auth). The middleware executes
    # the entire flow internally using stored NIRA credentials and crypto;
    # the vendor only supplies identity + biometric blocks.
    if payload.id_type == "NATIONAL ID":
        if not payload.first_name or not payload.last_name or not payload.date_of_birth:
            raise KycServiceError(
                422,
                "MISSING_FIELD",
                "first_name, last_name, and date_of_birth are required for NATIONAL ID verification",
            )
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
    vendor.     Returns IdentityVerificationData with a locally stored verification
    reference, which registration endpoints can validate and reuse.
    """
    authenticator = get_nira_authenticator()

    # Resolve biometric blocks: from request body, or from blocks.json on the server
    biometric_blocks: list[dict] = []
    if payload.biometric and isinstance(payload.biometric, SignedBlockBiometric):
        biometric_blocks = payload.biometric.blocks
    if not biometric_blocks:
        biometric_blocks = _read_blocks_from_file()
    if not biometric_blocks:
        raise KycServiceError(
            422, "MISSING_FIELD",
            "No biometric blocks supplied — paste the signed MOSIP SBI block into blocks.json",
        )

    # Resolve transaction_id: from request body, or extract from the first block's JWT
    transaction_id = payload.transaction_id
    block_env_debug = None
    if not transaction_id:
        first_block = biometric_blocks[0] if biometric_blocks else {}
        data_jwt = first_block.get("data")
        if isinstance(data_jwt, str):
            parts = data_jwt.split(".")
            if len(parts) == 3:
                try:
                    encoded_payload = parts[1]
                    payload_bytes = base64.urlsafe_b64decode(
                        encoded_payload + "=" * (-len(encoded_payload) % 4)
                    )
                    claims = json.loads(payload_bytes)
                    if isinstance(claims, dict):
                        transaction_id = claims.get("transactionId")
                        block_env_debug = claims.get("env")
                except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError, ValueError):
                    pass
    if not transaction_id:
        raise KycServiceError(
            422, "MISSING_FIELD",
            "transaction_id is required — could not read it from the signed block",
        )

    try:
        result = await authenticator.authenticate_national_id(
            transaction_id=str(transaction_id),
            nin=payload.id_number,
            date_of_birth=payload.date_of_birth or "",
            surname=payload.last_name or "",
            given_names=payload.first_name or "",
            biometric_blocks=biometric_blocks,
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
