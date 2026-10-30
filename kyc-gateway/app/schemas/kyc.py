"""
Pydantic schemas for the KYC Verification API v2.0.0.

Generated field-by-field from the decoded OpenAPI source at
`kyc_api_v2.yml` (components.schemas) — not from prose/inference. See
README.md "v2.0.0 migration notes" for the two spec-level inconsistencies
found while doing this (corporate verification_reference ownership, and the
OwnershipChangeRequest.required list referencing a `previous_owner` property
that does not exist under `properties` — implemented as
`previous_owner_consent`, matching the only property actually defined).
"""

from datetime import date, datetime
from typing import Any, Dict, List, Literal, Optional, Union
from pydantic import BaseModel, Field, model_validator
from typing_extensions import Annotated

# ------------------------------------------------------------------ ReasonCode

ReasonCode = Literal[
    "LIMIT_EXCEEDED",
    "LIMIT_NOT_EXCEEDED",
    "IDENTITY_ACCEPTED",
    "IDENTITY_REJECTED",
    "REGISTRATION_ACCEPTED",
    "VERIFICATION_UNAVAILABLE",
    "VERIFICATION_REQUIRED",
    "VERIFICATION_REFERENCE_INVALID",
    "VERIFICATION_REFERENCE_MISMATCH",
    "VERIFICATION_REFERENCE_EXPIRED",
    "REGISTRATION_AMENDED",
    "REGISTRATION_DEREGISTERED",
    "OWNERSHIP_CHANGED",
    "FIELD_NOT_AMENDABLE",
    "REGISTRATION_NOT_ACTIVE",
    "CONSENT_REQUIRED",
    "UNAUTHORIZED",
    "INVALID_FIELD",
    "INVALID_ID",
    "INVALID_MSISDN",
    "INVALID_AGENT",
    "INVALID_BIOMETRIC",
    "MISSING_FIELD",
    "DUPLICATE_REQUEST",
    "INVALID_PAYLOAD",
    "NOT_FOUND",
    "SYSTEM_ERROR",
]

# Reduced from seven values to three in 2.0.0. ALIEN ID, ATTESTATION, ASYLUM
# and DIPLOMAT ID were removed. UCC's migration note with replacement values
# for the latter two has not been issued yet (open item — see
# settings.LEGACY_ID_TYPES_ENABLED / app/core/config.py).
IndividualIdType = Literal["NATIONAL ID", "REFUGEE ID", "PASSPORT"]

# COI -> URSB (COMPANY/BUSINESS only). REGISTRY_PENDING -> every other
# organisation_type; UCC has not named a routing authority for these yet.
OrganisationIdType = Literal["COI", "REGISTRY_PENDING"]

# Union of both, used only where a request may carry either subscriber kind
# (POST /ownership_check, POST /identity_verification).
IdType = Literal["NATIONAL ID", "REFUGEE ID", "PASSPORT", "COI", "REGISTRY_PENDING"]

Gender = Literal["MALE", "FEMALE", "UNDEFINED"]
SimType = Literal["SIM", "ESIM", "ISIM"]
IndividualSimRegistrationType = Literal["NEW", "SIM SWAP", "RE_REGISTRATION"]
CorporateSimRegistrationType = Literal["NEW", "SIM SWAP"]
OrganisationType = Literal[
    "COMPANY",
    "BUSINESS",
    "TRUST",
    "COOPERATIVE",
    "NGO",
    "GOVERNMENT AGENCY",
    "MINISTRY",
    "DEPARTMENT",
    "AUTHORITY",
    "FOREIGN MISSION",
    "REGIONAL ORGANISATION",
    "INTERNATIONAL ORGANISATION",
]
Provider = Literal["NIRA", "UNHCR", "NCIC", "URSB"]
ProviderStatus = Literal["LIVE", "PLANNED"]


# ------------------------------------------------------------------ Ownership

class OwnershipCheckRequest(BaseModel):
    subscriber_type: Literal["individual", "corporate"] = Field(..., example="individual")
    id_type: Optional[IdType] = Field(None, example="NATIONAL ID")
    id_number: Optional[str] = Field(None, example="CF123456789ABCDE")
    registration_number: Optional[str] = Field(None, example="80020001234")


class OwnershipCheckData(BaseModel):
    allowed: bool = Field(..., example=True)
    reason_code: ReasonCode = Field(..., example="LIMIT_NOT_EXCEEDED")
    message: str = Field(..., example="Subscriber can register SIM")
    # No eligibility_token in 2.0.0 — this endpoint returns nothing to carry
    # forward. current_count/limit are informational (source of truth for
    # the resolved policy, per the API description's OWNERSHIP LIMIT POLICY).
    current_count: Optional[int] = Field(None, example=2)
    limit: Optional[int] = Field(None, example=5)


class OwnershipCheckResponse(BaseModel):
    status: str = Field(..., example="success")
    data: OwnershipCheckData


# ------------------------------------------------------------------ Biometric
# Appears ONLY on IdentityVerificationRequest — never on a registration
# endpoint. `format` discriminates the two provider-specific shapes.

class IsoImageBiometric(BaseModel):
    """UNHCR (and future ISO-based providers). A base64 image record, NOT a
    minutiae template — ISO_19794_4 for fingerprint, ISO_19794_6 for iris."""

    biometric_type: Literal["FINGERPRINT", "IRIS"] = Field(..., example="FINGERPRINT")
    format: Literal["ISO_19794_4", "ISO_19794_6", "JPEG", "WSQ"] = Field(..., example="ISO_19794_4")
    data: str = Field(..., example="Uk9OQVBJU08xOTc5NDQAAAAA...")


class SignedBlockBiometric(BaseModel):
    """NIRA. The `biometrics` array exactly as produced by a MOSIP-certified
    SBI capture device — relayed opaquely, never parsed or reshaped."""

    biometric_type: Literal["FINGERPRINT", "IRIS"] = Field(..., example="FINGERPRINT")
    format: Literal["MOSIP_SBI_SIGNED"] = Field(..., example="MOSIP_SBI_SIGNED")
    blocks: List[Dict[str, Any]] = Field(..., min_length=1)


BiometricData = Annotated[
    Union[IsoImageBiometric, SignedBlockBiometric], Field(discriminator="format")
]


# ------------------------------------------------------------------ Identity verification

class IdentityVerificationRequest(BaseModel):
    id_type: IdType
    id_number: str = Field(..., example="CF123456789ABCDE")
    first_name: Optional[str] = Field(None, example="JOHN", description="Required by UCC for REFUGEE ID type")
    last_name: Optional[str] = Field(None, example="KATO", description="Required by UCC for REFUGEE ID type")
    transaction_id: Optional[str] = Field(
        None,
        pattern=r"^[0-9]{10}$",
        description="Required when biometric.format is MOSIP_SBI_SIGNED; "
        "must equal the block's signed transactionId.",
        example="9181672570",
    )
    visa_validity: Optional[date] = Field(None, example="2027-06-30")
    # Optional at the schema level: required for live providers (NIRA/UNHCR)
    # but absent for PASSPORT/COI/REGISTRY_PENDING, which have no integrated
    # provider to send it to.
    biometric: Optional[BiometricData] = None


class IdentityVerificationData(BaseModel):
    verified: bool = Field(..., example=True)
    reason_code: ReasonCode
    message: str = Field(..., example="Identity verified")
    provider: Provider = Field(..., example="NIRA")
    provider_status: Optional[ProviderStatus] = Field(None, example="PLANNED")
    verification_reference: Optional[str] = Field(None, example="vrf_01JBK2QX7M4T8ZC3")
    verified_at: Optional[datetime] = Field(None, example="2026-08-24T09:14:22.481Z")
    expires_at: Optional[datetime] = Field(None, example="2026-08-25T09:14:22.481Z")
    matched_attributes: Optional[Dict[str, Any]] = Field(
        None, example={"date_of_birth": "MATCH", "sex": "F"}
    )


class IdentityVerificationResponse(BaseModel):
    status: str = Field(..., example="success")
    data: IdentityVerificationData


# ------------------------------------------------------------------ Individual registration

class IndividualRegistrationRecord(BaseModel):
    """Full individual SIM registration payload. Used by POST
    /individual_registrations, PUT updates, and as the record shape inside
    POST /individual_registrations/batch. No biometric data — ever."""

    verification_reference: str = Field(..., example="vrf_01JBK2QX7M4T8ZC3")
    msisdn: str = Field(..., pattern=r"^2567\d{8}$", example="256712345678")
    sim_registration_type: IndividualSimRegistrationType = Field(..., example="NEW")
    sim_type: SimType = Field(..., example="SIM")
    sim_registration_datetime: datetime = Field(..., example="2025-11-01T10:22:00Z")
    id_type: IndividualIdType
    id_number: str = Field(..., example="CF123456789ABCDE")
    nationality: str = Field(..., example="UGANDAN")
    id_validity: Optional[date] = Field(None, example="2030-12-31")
    visa_permit_number: Optional[str] = Field(None, example="VISA12345")
    visa_validity: Optional[date] = Field(None, example="2027-06-30")
    surname: str = Field(..., example="KATO")
    given_name: str = Field(..., example="JOHN")
    gender: Gender
    date_of_birth: date = Field(..., example="1995-05-12")
    agent_code: str = Field(..., pattern=r"^[A-Z0-9]+$", example="AGT001")
    agent_number: str = Field(..., pattern=r"^2567\d{8}$", example="256712345678")
    sales_district: str = Field(..., example="KAMPALA")
    gps_coordinates: str = Field(..., example="32.5825,0.3476")
    activation_date: date = Field(..., example="2025-10-01")


class IndividualRegistrationRequest(IndividualRegistrationRecord):
    """Identical to IndividualRegistrationRecord — the eligibility_token that
    previously distinguished them was removed in 2.0.0."""


# ------------------------------------------------------------------ Corporate registration

class CorporateRepresentative(BaseModel):
    """RECORDED BUT NOT VERIFIED in 2.0.0 — no identity/biometric check is
    performed on this person. Kept as the sole accountability anchor."""

    id_type: IndividualIdType
    id_number: str = Field(..., example="CF123456789ABCDE")
    validity: Optional[date] = Field(None, example="2030-12-31")
    nationality: str = Field(..., example="UGANDAN")
    surname: str = Field(..., example="KATO")
    given_name: str = Field(..., example="JOHN")
    gender: Gender
    date_of_birth: date = Field(..., example="1983-05-12")


class CorporateRegistrationRecord(BaseModel):
    """Full corporate SIM registration record. Used by POST
    /corporate_registrations and as the record shape inside POST
    /corporate_registrations/batch."""

    verification_reference: str = Field(
        ...,
        example="vrf_01JBK8XS4U7B1DJ6",
        description="Reference issued by POST /identity_verification for the "
        "ORGANISATION. It is NOT the representative's reference — the "
        "representative is no longer verified. (The batch endpoint's prose "
        "description and the 403 example elsewhere in the spec use language "
        "implying it's the representative's reference; this field's own "
        "description is authoritative and is what's implemented here.)",
    )
    id_type: OrganisationIdType
    msisdn: str = Field(..., pattern=r"^2567\d{8}$", example="256712345679")
    sim_type: SimType = Field(..., example="SIM")
    sim_registration_type: CorporateSimRegistrationType = Field(..., example="NEW")
    sim_registration_datetime: datetime = Field(..., example="2025-11-01T10:22:00Z")
    organisation_type: OrganisationType = Field(..., example="COMPANY")
    registration_number: str = Field(..., example="80020012345678")
    registration_validity: Optional[date] = Field(None, example="2028-12-31")
    organisation_name: str = Field(..., example="ABC LIMITED")
    registered_address: str = Field(..., example="KAMPALA ROAD")
    tax_identification_number: str = Field(..., example="TIN123456")
    contact_number: str = Field(..., pattern=r"^2567\d{8}$", example="256712345679")
    representative: CorporateRepresentative
    agent_code: str = Field(..., pattern=r"^[A-Z0-9]+$", example="AGT001")
    agent_number: str = Field(..., pattern=r"^2567\d{8}$", example="256712345678")
    sales_district: str = Field(..., example="KAMPALA")
    gps_coordinates: str = Field(..., example="32.5825,0.3476")
    activation_date: date = Field(..., example="2025-10-01")


class CorporateRegistrationRequest(CorporateRegistrationRecord):
    """Identical to CorporateRegistrationRecord."""


# ------------------------------------------------------------------ Batch

class IndividualBatchRegistrationRequest(BaseModel):
    records: List[IndividualRegistrationRecord] = Field(..., min_length=1, max_length=1000)


class CorporateBatchRegistrationRequest(BaseModel):
    records: List[CorporateRegistrationRecord] = Field(..., min_length=1, max_length=1000)


class BatchAcceptedResponse(BaseModel):
    status: str = Field(..., example="accepted")
    job_id: str = Field(..., example="batch_123456")
    message: str = Field(..., example="Batch accepted for processing")


class BatchResultItem(BaseModel):
    msisdn: str = Field(..., example="256712345678")
    status: Literal["accepted", "rejected"] = Field(..., example="accepted")
    reason_code: ReasonCode
    verification_reference: Optional[str] = Field(None, example="vrf_01JBK2QX7M4T8ZC3")
    error_message: Optional[str] = Field(None, example="Invalid MSISDN format")


class BatchStatusResponse(BaseModel):
    job_id: str = Field(..., example="batch_123456")
    status: Literal["pending", "processing", "completed", "failed"] = Field(
        ..., example="completed"
    )
    total_records: int = Field(..., example=100)
    processed_records: int = Field(..., example=100)
    successful_records: int = Field(..., example=95)
    failed_records: int = Field(..., example=5)
    results: List[BatchResultItem] = Field(default_factory=list)


class BatchCompletedEvent(BaseModel):
    """Body of the batch completion webhook POSTed to the operator's
    registered callback URL. Summary counters only."""

    event: Literal["batch.completed"] = "batch.completed"
    job_id: str = Field(..., example="batch_123456")
    status: Literal["completed", "failed"] = Field(..., example="completed")
    total_records: int = Field(..., example=100)
    processed_records: int = Field(..., example=100)
    successful_records: int = Field(..., example=95)
    failed_records: int = Field(..., example=5)
    timestamp: datetime = Field(..., example="2026-07-31T10:25:00Z")


# ------------------------------------------------------------------ Amendment (PATCH)

class AmendableFields(BaseModel):
    """The complete set of fields an amendment may change. date_of_birth,
    nationality, id_type, id_number, msisdn and mno_id are deliberately
    absent — changing any of those is a different operation entirely."""

    model_config = {"extra": "forbid"}

    surname: Optional[str] = Field(None, example="MUKASA")
    given_name: Optional[str] = Field(None, example="GRACE")
    gender: Optional[Gender] = Field(None, example="FEMALE")
    id_validity: Optional[date] = Field(None, example="2031-12-31")
    visa_validity: Optional[date] = Field(None, example="2028-06-30")
    visa_permit_number: Optional[str] = Field(None, example="VISA67890")

    @model_validator(mode="after")
    def _at_least_one_field(self):
        if not self.model_dump(exclude_none=True):
            raise ValueError("changes must include at least one amendable field")
        return self


class AmendmentRequest(BaseModel):
    change_reason: Literal["LEGAL_NAME_CHANGE", "CORRECTION", "DOCUMENT_RENEWAL"] = Field(
        ..., example="LEGAL_NAME_CHANGE"
    )
    evidence_reference: Optional[str] = Field(None, example="MC/2026/004412")
    changes: AmendableFields


class AmendmentResponse(BaseModel):
    status: str = Field(..., example="amended")
    reason_code: ReasonCode
    message: str = Field(..., example="Subscriber details amended")
    previous_values: Optional[Dict[str, Any]] = Field(None, example={"surname": "AYO"})


# ------------------------------------------------------------------ Ownership change

class PreviousOwnerConsent(BaseModel):
    method: Literal[
        "SUBSCRIBER_CONFIRMED", "SIGNED_FORM", "SUCCESSION", "OPERATOR_ATTESTED"
    ] = Field(..., example="SUBSCRIBER_CONFIRMED")
    reference: Optional[str] = Field(None, example="USSD-8837721")
    obtained_at: datetime = Field(..., example="2026-08-26T09:14:00Z")


class NewOwner(BaseModel):
    id_type: IndividualIdType
    id_number: str = Field(..., example="CM20000000001")
    nationality: str = Field(..., example="UGANDAN")
    surname: str = Field(..., example="OKELLO")
    given_name: str = Field(..., example="PETER")
    gender: Gender
    date_of_birth: date = Field(..., example="1990-03-04")
    id_validity: Optional[date] = Field(None, example="2031-06-30")
    visa_validity: Optional[date] = Field(None, example="2028-06-30")


class OwnershipChangeRequest(BaseModel):
    """Transfer of a SIM to a different subscriber. The reference belongs to
    the NEW owner; no biometric is taken from the previous owner.

    NOTE: the spec's `required` list for this schema names a `previous_owner`
    property, but only `previous_owner_consent` is defined under
    `properties` — a spec-level typo. Implemented as `previous_owner_consent`
    (required), which is the only property that actually exists and is
    consistent with the endpoint's documented CONSENT_REQUIRED error."""

    verification_reference: str = Field(..., example="vrf_01JBK7WR3T6A0CH5")
    effective_date: date = Field(..., example="2026-08-26")
    new_owner: NewOwner
    previous_owner_consent: PreviousOwnerConsent
    agent_code: str = Field(..., pattern=r"^[A-Z0-9]+$", example="AGT001")
    agent_number: str = Field(..., pattern=r"^2567\d{8}$", example="256712345678")


class PreviousOwnerSummary(BaseModel):
    id_type: Optional[IndividualIdType] = None
    id_number: Optional[str] = Field(None, example="CF123456789ABCDE")


class OwnershipChangeResponse(BaseModel):
    status: str = Field(..., example="transferred")
    reason_code: ReasonCode
    message: str = Field(..., example="SIM ownership transferred")
    previous_owner: Optional[PreviousOwnerSummary] = None
    effective_date: Optional[date] = Field(None, example="2026-08-26")


# ------------------------------------------------------------------ Deregistration

class DeregistrationRequest(BaseModel):
    reason_code: Literal[
        "SUBSCRIBER_REQUEST", "CHURN", "FRAUD", "DECEASED", "SIM_RECYCLED"
    ] = Field(..., example="SUBSCRIBER_REQUEST")
    effective_date: date = Field(..., example="2026-08-26")
    agent_code: str = Field(..., pattern=r"^[A-Z0-9]+$", example="AGT001")
    agent_number: str = Field(..., pattern=r"^2567\d{8}$", example="256712345678")
    notes: Optional[str] = Field(None, example="Subscriber reported the handset as stolen")


class DeregistrationResponse(BaseModel):
    status: str = Field(..., example="deregistered")
    reason_code: ReasonCode
    message: str = Field(..., example="SIM registration ended")
    effective_date: Optional[date] = Field(None, example="2026-08-26")
    released_count: Optional[int] = Field(None, example=1)


# ------------------------------------------------------------------ History (schema only — no endpoint yet)

class RegistrationHistoryEntry(BaseModel):
    """Backs a history endpoint the spec itself calls 'still an open item'.
    Modeled for forward compatibility; no route exposes it yet."""

    status: Literal["active", "superseded", "deregistered"]
    id_type: IndividualIdType
    id_number: str = Field(..., example="CF123456789ABCDE")
    surname: Optional[str] = Field(None, example="KATO")
    given_name: Optional[str] = Field(None, example="JOHN")
    effective_from: datetime = Field(..., example="2025-11-01T10:22:00Z")
    ended_at: Optional[datetime] = Field(None, example="2026-08-26T09:20:00Z")
    supersede_reason: Optional[
        Literal["RE_REGISTRATION", "AMENDMENT", "OWNERSHIP_CHANGE", "DEREGISTRATION"]
    ] = None


# ------------------------------------------------------------------ Compliance

class ComplianceReportData(BaseModel):
    valid_records: int = Field(..., example=12000)
    invalid_records: int = Field(..., example=340)
    missing_information: int = Field(..., example=87)


class ComplianceReportResponse(BaseModel):
    status: str = Field(..., example="success")
    data: ComplianceReportData


# ------------------------------------------------------------------ Generic responses

class StandardResponse(BaseModel):
    status: str = Field(..., example="accepted")
    reason_code: ReasonCode
    message: str = Field(..., example="SIM registration successful")


class ErrorResponse(BaseModel):
    status: str = Field(..., example="error")
    error_code: ReasonCode
    message: str = Field(..., example="Invalid MSISDN format")
