"""
POST /identity_verification — Verify subscriber identity and biometric.

New in v2.0.0. A non-match is a successful request (HTTP 200,
verified=false) — never inferred from HTTP status alone.
"""

from fastapi import APIRouter, Depends, HTTPException

from app.api.deps.auth import require_api_key
from app.schemas.kyc import IdentityVerificationRequest, IdentityVerificationResponse
from app.services.exceptions import KycServiceError
from app.services.verification_service import verify_identity

router = APIRouter(tags=["Verification"])


@router.post(
    "/identity_verification",
    response_model=IdentityVerificationResponse,
    operation_id="verifyIdentity",
    summary="Verify subscriber identity and biometric",
)
async def identity_verification(
    payload: IdentityVerificationRequest, mno: str = Depends(require_api_key)
):
    try:
        data = verify_identity(payload)
    except KycServiceError as exc:
        raise HTTPException(
            status_code=exc.status_code,
            detail={"status": "error", "error_code": exc.error_code, "message": exc.message},
        )
    return IdentityVerificationResponse(status="success", data=data)
