"""
Ownership eligibility service (POST /ownership_check), v2.0.0.

Implements the limit resolution order from the spec:
  1. Subscriber-specific override
  2. Subscriber-type default
  3. Global fallback

No token is minted in 2.0.0 — this endpoint returns only the eligibility
decision plus the resolved current_count/limit. Proceed to
POST /identity_verification next; the ownership limit is re-evaluated
independently at registration commit time regardless of this result.
"""

from app.core.config import settings
from app.schemas.kyc import OwnershipCheckRequest, OwnershipCheckData
from app.services.exceptions import KycServiceError
from app.services.db import store


def check_ownership(payload: OwnershipCheckRequest) -> OwnershipCheckData:
    if payload.subscriber_type == "individual":
        if not payload.id_type:
            raise KycServiceError(422, "MISSING_FIELD", "id_type is required")
        if not payload.id_number:
            raise KycServiceError(422, "MISSING_FIELD", "id_number is required")

        count = store.individual_ownership_count(payload.id_type, payload.id_number)
        limit = store.resolve_limit(
            f"individual:{payload.id_number}", settings.GLOBAL_INDIVIDUAL_OWNERSHIP_LIMIT
        )
        allowed = count < limit

        if allowed:
            return OwnershipCheckData(
                allowed=True,
                reason_code="LIMIT_NOT_EXCEEDED",
                message="Subscriber can register SIM",
                current_count=count,
                limit=limit,
            )
        return OwnershipCheckData(
            allowed=False,
            reason_code="LIMIT_EXCEEDED",
            message="Subscriber has exceeded SIM ownership limit",
            current_count=count,
            limit=limit,
        )

    # corporate
    if not payload.registration_number:
        raise KycServiceError(422, "MISSING_FIELD", "registration_number is required")

    count = store.corporate_ownership_count(payload.registration_number)
    limit = store.resolve_limit(
        f"corporate:{payload.registration_number}", settings.GLOBAL_CORPORATE_OWNERSHIP_LIMIT
    )
    allowed = count < limit

    if allowed:
        return OwnershipCheckData(
            allowed=True,
            reason_code="LIMIT_NOT_EXCEEDED",
            message="Subscriber can register SIM",
            current_count=count,
            limit=limit,
        )
    return OwnershipCheckData(
        allowed=False,
        reason_code="LIMIT_EXCEEDED",
        message="Subscriber has exceeded SIM ownership limit",
        current_count=count,
        limit=limit,
    )
