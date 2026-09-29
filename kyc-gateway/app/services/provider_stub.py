"""
Simulated identity-provider responses for POST /identity_verification.

No production or test endpoint has been confirmed for any provider yet (see
app/core/config.py: NIRA_VALIDATE_URL, UNHCR_VALIDATE_URL, etc). This module
stands in for the real relay call and returns the outcome described in the
spec for each id_type:

  NATIONAL ID (NIRA)      — live: simulated match/no-match decision
  REFUGEE ID  (UNHCR)     — live: simulated match/no-match + matched_attributes
  PASSPORT    (NCIC)      — always VERIFICATION_UNAVAILABLE, PLANNED
  COI         (URSB)      — always VERIFICATION_UNAVAILABLE, PLANNED (corporate)
  REGISTRY_PENDING        — always VERIFICATION_UNAVAILABLE, PLANNED (corporate)

Simulation rule for the two "live" providers (deterministic, for local
testing only, mirrors the old NIRA stub): an id_number ending in "0" is
treated as "not found" / no match.

Biometric bytes are read only to decide the simulated verdict; they are
never written to any store or log line.
"""

from dataclasses import dataclass
from typing import Optional

PROVIDER_BY_ID_TYPE = {
    "NATIONAL ID": "NIRA",
    "REFUGEE ID": "UNHCR",
    "PASSPORT": "NCIC",
    "COI": "URSB",
    "REGISTRY_PENDING": None,  # no routed authority at all yet
}

LIVE_PROVIDERS = {"NIRA", "UNHCR"}


@dataclass
class ProviderResult:
    verified: bool
    reason_code: str
    message: str
    provider: str
    provider_status: Optional[str] = None
    matched_attributes: Optional[dict] = None


def resolve_provider(id_type: str) -> str:
    """
    REGISTRY_PENDING has no routed authority at all yet — UCC hasn't decided
    which body verifies it. The response schema's `provider` field is a
    fixed 4-value enum (NIRA/UNHCR/NCIC/URSB) with no "undecided" option, so
    URSB is used as a technical placeholder here purely to satisfy that
    enum. This is NOT an assertion that URSB is the real authority for
    REGISTRY_PENDING organisations — flagged as an open item pending UCC
    naming a registry (see kyc_api_v2.yml OrganisationIdType description).
    """
    provider = PROVIDER_BY_ID_TYPE.get(id_type)
    return provider or "URSB"


def verify_with_provider(id_type: str, id_number: str) -> ProviderResult:
    provider = resolve_provider(id_type)

    if provider not in LIVE_PROVIDERS:
        return ProviderResult(
            verified=False,
            reason_code="VERIFICATION_UNAVAILABLE",
            message=f"No verification provider is currently available for {id_type}",
            provider=provider,
            provider_status="PLANNED",
        )

    if id_number.endswith("0"):
        return ProviderResult(
            verified=False,
            reason_code="IDENTITY_REJECTED",
            message="Biometric did not match the identity record",
            provider=provider,
        )

    matched_attributes = {"date_of_birth": "MATCH", "sex": "F"} if provider == "UNHCR" else None
    return ProviderResult(
        verified=True,
        reason_code="IDENTITY_ACCEPTED",
        message="Identity verified",
        provider=provider,
        matched_attributes=matched_attributes,
    )
