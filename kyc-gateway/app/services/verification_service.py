"""
POST /identity_verification service logic.

Processing order per the spec:
  1. Validate the request payload (handled by Pydantic schema)
  2. Select the provider from id_type
  3. Relay the identity and biometric to that provider (simulated)
  4. Return the outcome and, on success, a verification_reference

This endpoint does NOT evaluate the ownership limit for individuals — that
is ownership_service's job (POST /ownership_check, and the check performed
again at registration commit). Biometric payloads are read only to select
and validate shape; they are never written to the verification_references
store or to any log line.
"""

from datetime import datetime, timezone

from app.core.config import settings
from app.schemas.kyc import IdentityVerificationData, IdentityVerificationRequest
from app.services.db import store
from app.services.exceptions import KycServiceError
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
        if not payload.transaction_id:
            raise KycServiceError(
                422, "MISSING_FIELD",
                "transaction_id is required when format is MOSIP_SBI_SIGNED",
            )
        # NIRA's ~30-second freshness window cannot be enforced here: the
        # 2.0.0 IdentityVerificationRequest schema exposes no capture
        # timestamp field to compare against arrival time (only an opaque
        # transaction_id). Documented gap — see config.NIRA_FRESHNESS_WINDOW_SECONDS.
    elif payload.id_type == "REFUGEE ID":
        if payload.biometric.format not in ("ISO_19794_4", "ISO_19794_6"):
            raise KycServiceError(
                422, "INVALID_BIOMETRIC", "REFUGEE ID requires format ISO_19794_4 or ISO_19794_6"
            )


def verify_identity(payload: IdentityVerificationRequest) -> IdentityVerificationData:
    _validate_biometric_shape(payload)

    result = verify_with_provider(payload.id_type, payload.id_number)

    verified_at = datetime.now(timezone.utc).isoformat() if result.verified else None
    # A verification_reference is issued whenever a provider decision was
    # reached at all — including VERIFICATION_UNAVAILABLE — so registration
    # can proceed and be recorded as unverified. It is withheld only for a
    # live-provider non-match (IDENTITY_REJECTED), matching the "not_verified"
    # example in the spec, which carries no verification_reference.
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
