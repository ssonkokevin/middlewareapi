"""
Configuration module for the KYC Verification API gateway (v2.0.0).
Loads all settings from environment variables / .env file using pydantic-settings.

NOTE: There is no confirmed production or test upstream URL yet for this API.
KYC_UPSTREAM_URL and related provider integration settings are left as
empty/placeholder values until UCC/NIRA/UNHCR/NCIC/URSB confirm the real
endpoints. Until then, the service layer runs fully self-contained using the
SQLite-backed store and provider simulation in app/services/.
"""

import os
from typing import Dict, List
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="allow",
    )

    # ---------------------------------------------------------------- General
    DEBUG: bool = True
    TIMEOUT: int = 60

    # -------------------------------------------------------- Upstream (TBD)
    # No production or test URL has been confirmed yet for any provider.
    # Leave blank until UCC/NIRA/UNHCR/NCIC/URSB provide real base URL(s).
    # The gateway does not fail to start if these are empty — the service
    # layer uses simulated provider logic instead (see provider_stub.py).
    KYC_UPSTREAM_URL: str = ""          # e.g. https://{production-url}/api/v1/kyc — TBD
    NIRA_VALIDATE_URL: str = ""         # NIRA identity + biometric validation endpoint — TBD
    UNHCR_VALIDATE_URL: str = ""        # UNHCR identity + biometric validation endpoint — TBD
    NCIC_VALIDATE_URL: str = ""         # NCIC — not yet integrated per spec (PASSPORT)
    URSB_VALIDATE_URL: str = ""         # URSB — not yet integrated per spec (COI)

    # ---------------------------------------------------------------- Auth
    # Comma-separated list of accepted API keys for the X-API-Key header.
    # Each key identifies the calling MNO. Example: "mno-alpha-key,mno-beta-key"
    KYC_API_KEYS: str = "dev-local-key"

    # ------------------------------------------------------------- Policy
    # verification_reference lifetime — 24 hours per spec, NOT the old
    # 10-minute eligibility_token TTL. Named config value, not a magic
    # number scattered across files.
    VERIFICATION_REFERENCE_TTL_HOURS: float = 24.0
    # Documented gap (see app/services/verification_service.py): the 2.0.0
    # IdentityVerificationRequest schema exposes no capture-timestamp field,
    # only `transaction_id` (an opaque 10-digit number bound into the signed
    # block, not a timestamp). The ~30s NIRA freshness window therefore
    # CANNOT be enforced server-side against this schema — this setting is
    # kept for when/if UCC adds such a field, but is currently unused.
    NIRA_FRESHNESS_WINDOW_SECONDS: int = 30
    GLOBAL_INDIVIDUAL_OWNERSHIP_LIMIT: int = 10        # global fallback, per spec
    GLOBAL_CORPORATE_OWNERSHIP_LIMIT: int = 100        # global fallback, per spec
    MAX_BATCH_SIZE: int = 1000

    # Feature flag for the two IndividualIdType values removed in 2.0.0
    # (ASYLUM, DIPLOMAT ID). UCC's migration note with replacement values
    # has not been issued yet — do not hardcode a guess. When false (default),
    # these values are rejected with a clear VERIFICATION_UNAVAILABLE-style
    # message rather than a generic INVALID_ID or a 500.
    LEGACY_ID_TYPES_ENABLED: bool = False

    # ----------------------------------------------------------- Persistence
    SQLITE_PATH: str = "kyc_gateway.db"

    # ------------------------------------------------------------- Webhook
    # Outbound batch-completion notification (BATCH COMPLETION WEBHOOK in the
    # spec). Configured out-of-band with UCC in the real system; here it's a
    # plain env var since there's no onboarding endpoint in this API.
    KYC_WEBHOOK_URL: str = ""
    KYC_WEBHOOK_SECRET: str = ""
    KYC_WEBHOOK_MAX_RETRIES: int = 5
    KYC_WEBHOOK_TIMEOUT_SECONDS: float = 10.0

    # --------------------------------------------------------------- Redis
    # Optional — not currently used now that verification_references and
    # batch jobs are SQLite-backed. Kept for a possible future swap.
    REDIS_URL: str = "redis://localhost:6379/1"

    # ----------------------------------------------------------- Helper methods

    def get_api_keys(self) -> List[str]:
        """Returns the list of valid API keys, identified by the MNO they belong to."""
        return [k.strip() for k in self.KYC_API_KEYS.split(",") if k.strip()]

    def resolve_api_key_owner(self, api_key: str) -> str:
        """
        Resolve which MNO an API key belongs to. In this stub implementation,
        the key itself is used as the MNO identifier. Replace with a real
        lookup (DB/Redis) once client provisioning is defined.
        """
        return api_key


# Single application-wide settings instance
settings = Settings()
