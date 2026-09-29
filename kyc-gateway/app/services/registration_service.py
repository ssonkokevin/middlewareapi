"""
Registration services, v2.0.0: individual/corporate create, PUT update,
PATCH amendment, ownership_change and deregistration.

Every entry point here that carries a verification_reference validates it
against app.services.db.store.validate_reference — never single-use, always
bound to the id_type + id_number (or registration_number, for the
organisation) that was verified. No biometric appears anywhere below; that
lives only in verification_service.py.
"""

from datetime import date, datetime, timezone

from app.core.config import settings
from app.schemas.kyc import (
    AmendmentRequest,
    AmendmentResponse,
    CorporateRegistrationRequest,
    DeregistrationRequest,
    DeregistrationResponse,
    IndividualRegistrationRecord,
    IndividualRegistrationRequest,
    OwnershipChangeRequest,
    OwnershipChangeResponse,
    PreviousOwnerSummary,
    StandardResponse,
)
from app.services.exceptions import KycServiceError
from app.services.db import store

_REFERENCE_ERROR_MESSAGES = {
    "VERIFICATION_REQUIRED": "A verification_reference from identity_verification is required",
    "VERIFICATION_REFERENCE_INVALID": "Verification reference is not recognised",
    "VERIFICATION_REFERENCE_EXPIRED": "Verification reference expired; re-verify the subscriber",
    "VERIFICATION_REFERENCE_MISMATCH": "Verification reference does not match the supplied identity",
}


def _raise_reference_error(code: str, message: str = None) -> None:
    raise KycServiceError(403, code, message or _REFERENCE_ERROR_MESSAGES[code])


def _isoformat(value) -> str:
    if isinstance(value, (date, datetime)):
        return value.isoformat()
    return str(value)


# ------------------------------------------------------------------ individual create

def register_individual(payload: IndividualRegistrationRequest, mno: str) -> StandardResponse:
    if store.is_active_registration(payload.msisdn):
        raise KycServiceError(409, "DUPLICATE_REQUEST", "SIM already registered")

    error = store.validate_reference(payload.verification_reference, payload.id_type, payload.id_number)
    if error:
        _raise_reference_error(error)

    count = store.individual_ownership_count(payload.id_type, payload.id_number)
    limit = store.resolve_limit(f"individual:{payload.id_number}", settings.GLOBAL_INDIVIDUAL_OWNERSHIP_LIMIT)
    if count >= limit:
        raise KycServiceError(403, "LIMIT_EXCEEDED", "Subscriber has exceeded SIM ownership limit")

    store.upsert_registration(
        msisdn=payload.msisdn, kind="individual", id_type=payload.id_type,
        id_number=payload.id_number, mno=mno, surname=payload.surname,
        given_name=payload.given_name, gender=payload.gender,
        id_validity=_isoformat(payload.id_validity) if payload.id_validity else None,
        visa_validity=_isoformat(payload.visa_validity) if payload.visa_validity else None,
        visa_permit_number=payload.visa_permit_number,
        last_verification_reference=payload.verification_reference,
    )
    return StandardResponse(
        status="accepted", reason_code="REGISTRATION_ACCEPTED", message="SIM registration stored"
    )


# ------------------------------------------------------------------ corporate create

def register_corporate(payload: CorporateRegistrationRequest, mno: str) -> StandardResponse:
    if store.is_active_registration(payload.msisdn):
        raise KycServiceError(409, "DUPLICATE_REQUEST", "Corporate SIM already registered")

    # verification_reference is organisation-bound (id_type + registration_number),
    # NOT the representative's identity — see the field description on
    # CorporateRegistrationRecord.verification_reference in app/schemas/kyc.py.
    error = store.validate_reference(
        payload.verification_reference, payload.id_type, payload.registration_number
    )
    if error:
        if error == "VERIFICATION_REQUIRED":
            _raise_reference_error(error, "A verification_reference for the organisation is required")
        if error == "VERIFICATION_REFERENCE_MISMATCH":
            _raise_reference_error(
                error, "Verification reference does not match the organisation identity"
            )
        if error == "VERIFICATION_REFERENCE_EXPIRED":
            _raise_reference_error(error, "Verification reference expired; re-verify the organisation")
        _raise_reference_error(error)

    count = store.corporate_ownership_count(payload.registration_number)
    limit = store.resolve_limit(
        f"corporate:{payload.registration_number}", settings.GLOBAL_CORPORATE_OWNERSHIP_LIMIT
    )
    if count >= limit:
        raise KycServiceError(403, "LIMIT_EXCEEDED", "Subscriber has exceeded SIM ownership limit")

    rep = payload.representative
    store.upsert_registration(
        msisdn=payload.msisdn, kind="corporate", id_type=payload.id_type,
        id_number=payload.registration_number, mno=mno, surname=rep.surname,
        given_name=rep.given_name,
        last_verification_reference=payload.verification_reference,
    )
    return StandardResponse(
        status="accepted", reason_code="REGISTRATION_ACCEPTED",
        message="Corporate SIM registration recorded",
    )


# ------------------------------------------------------------------ PUT update (full re-verification)

def update_individual_registration(
    msisdn: str, payload: IndividualRegistrationRecord, mno: str
) -> StandardResponse:
    if payload.msisdn != msisdn:
        raise KycServiceError(422, "INVALID_MSISDN", "MSISDN in path and body must match")

    existing = store.get_registration(msisdn)
    if existing is None or existing["status"] != "active" or existing["mno"] != mno:
        raise KycServiceError(404, "NOT_FOUND", "Subscriber not found")

    if existing["id_number"] != payload.id_number:
        # A different id_number here is a transfer, not an update — spec
        # gives no explicit error_code example for this case (only
        # missing_reference / invalid_msisdn are documented), so
        # INVALID_FIELD is used with a message pointing at the right endpoint.
        raise KycServiceError(
            422, "INVALID_FIELD",
            "id_number does not match the current record; use "
            "/individual_registrations/{msisdn}/ownership_change to transfer this SIM",
        )

    # A fresh reference is required — reusing the one that authorised the
    # current state of THIS msisdn's record is explicitly disallowed by the
    # spec. References remain reusable in general (e.g. to register a
    # different msisdn for the same identity, or retry a failed commit), so
    # the check is scoped to this msisdn's last_verification_reference
    # rather than a blanket single-use rule on the reference itself.
    error = store.validate_reference(payload.verification_reference, payload.id_type, payload.id_number)
    if error:
        if error == "VERIFICATION_REQUIRED":
            _raise_reference_error(error, "A fresh verification_reference is required for updates")
        _raise_reference_error(error)

    if payload.verification_reference == existing["last_verification_reference"]:
        _raise_reference_error(
            "VERIFICATION_REFERENCE_INVALID",
            "This verification_reference has already been used for this subscriber's "
            "current record; run identity_verification again for a fresh one",
        )

    count = store.individual_ownership_count(payload.id_type, payload.id_number)
    limit = store.resolve_limit(f"individual:{payload.id_number}", settings.GLOBAL_INDIVIDUAL_OWNERSHIP_LIMIT)
    # The subscriber's own existing registration should not count against
    # itself when re-evaluating the limit for this same MSISDN.
    if count - 1 >= limit:
        raise KycServiceError(403, "LIMIT_EXCEEDED", "Subscriber has exceeded SIM ownership limit")

    store.upsert_registration(
        msisdn=payload.msisdn, kind="individual", id_type=payload.id_type,
        id_number=payload.id_number, mno=mno, surname=payload.surname,
        given_name=payload.given_name, gender=payload.gender,
        id_validity=_isoformat(payload.id_validity) if payload.id_validity else None,
        visa_validity=_isoformat(payload.visa_validity) if payload.visa_validity else None,
        visa_permit_number=payload.visa_permit_number,
        last_verification_reference=payload.verification_reference,
    )
    return StandardResponse(
        status="updated", reason_code="REGISTRATION_ACCEPTED",
        message="Subscriber information successfully updated",
    )


# ------------------------------------------------------------------ PATCH amendment (no verification)

def amend_individual_registration(
    msisdn: str, payload: AmendmentRequest, mno: str
) -> AmendmentResponse:
    existing = store.get_registration(msisdn)
    if existing is None or existing["mno"] != mno:
        # Deliberately identical to the "no record at all" case — a record
        # held by another operator must not be revealed to exist.
        raise KycServiceError(404, "NOT_FOUND", "Subscriber not found")
    if existing["status"] != "active":
        raise KycServiceError(409, "REGISTRATION_NOT_ACTIVE", "The registration is not active")

    changes = payload.changes.model_dump(exclude_none=True)
    db_fields = {}
    for key, value in changes.items():
        db_fields[key] = _isoformat(value) if isinstance(value, date) else value

    previous = store.amend_registration_fields(msisdn, **db_fields)
    return AmendmentResponse(
        status="amended", reason_code="REGISTRATION_AMENDED",
        message="Subscriber details amended", previous_values=previous or None,
    )


# ------------------------------------------------------------------ Ownership change

def change_ownership(msisdn: str, payload: OwnershipChangeRequest, mno: str) -> OwnershipChangeResponse:
    existing = store.get_registration(msisdn)
    if existing is None or existing["mno"] != mno:
        raise KycServiceError(404, "NOT_FOUND", "Subscriber not found")
    if existing["status"] != "active":
        raise KycServiceError(409, "REGISTRATION_NOT_ACTIVE", "The registration is not active")

    new_owner = payload.new_owner
    error = store.validate_reference(payload.verification_reference, new_owner.id_type, new_owner.id_number)
    if error:
        _raise_reference_error(error)

    if payload.previous_owner_consent is None:
        raise KycServiceError(403, "CONSENT_REQUIRED", "previous_owner_consent is required")

    count = store.individual_ownership_count(new_owner.id_type, new_owner.id_number)
    limit = store.resolve_limit(
        f"individual:{new_owner.id_number}", settings.GLOBAL_INDIVIDUAL_OWNERSHIP_LIMIT
    )
    if count >= limit:
        raise KycServiceError(403, "LIMIT_EXCEEDED", "New owner has exceeded SIM ownership limit")

    previous_owner = PreviousOwnerSummary(id_type=existing["id_type"], id_number=existing["id_number"])

    store.upsert_registration(
        msisdn=msisdn, kind="individual", id_type=new_owner.id_type, id_number=new_owner.id_number,
        mno=mno, surname=new_owner.surname, given_name=new_owner.given_name, gender=new_owner.gender,
        id_validity=_isoformat(new_owner.id_validity) if new_owner.id_validity else None,
        visa_validity=_isoformat(new_owner.visa_validity) if new_owner.visa_validity else None,
        last_verification_reference=payload.verification_reference,
    )
    return OwnershipChangeResponse(
        status="transferred", reason_code="OWNERSHIP_CHANGED", message="SIM ownership transferred",
        previous_owner=previous_owner, effective_date=payload.effective_date,
    )


# ------------------------------------------------------------------ Deregistration

def deregister_individual(msisdn: str, payload: DeregistrationRequest, mno: str) -> DeregistrationResponse:
    existing = store.get_registration(msisdn)
    if existing is None or existing["mno"] != mno:
        raise KycServiceError(404, "NOT_FOUND", "Subscriber not found")
    if existing["status"] != "active":
        raise KycServiceError(409, "DUPLICATE_REQUEST", "Registration is already deregistered")

    store.deregister(msisdn)
    return DeregistrationResponse(
        status="deregistered", reason_code="REGISTRATION_DEREGISTERED",
        message="SIM registration ended", effective_date=payload.effective_date, released_count=1,
    )
