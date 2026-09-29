"""
POST /ownership_check — Verify SIM ownership eligibility (v2.0.0: returns no
token, only the decision plus current_count/limit).
"""

from fastapi import APIRouter, Depends, HTTPException
from app.api.deps.auth import require_api_key
from app.schemas.kyc import OwnershipCheckRequest, OwnershipCheckResponse
from app.services.exceptions import KycServiceError
from app.services.ownership_service import check_ownership

router = APIRouter(tags=["Ownership"])


@router.post(
    "/ownership_check",
    response_model=OwnershipCheckResponse,
    operation_id="verifyOwnershipEligibility",
    summary="Verify SIM ownership eligibility",
)
async def ownership_check(payload: OwnershipCheckRequest, mno: str = Depends(require_api_key)):
    try:
        data = check_ownership(payload)
    except KycServiceError as exc:
        raise HTTPException(
            status_code=exc.status_code,
            detail={"status": "error", "error_code": exc.error_code, "message": exc.message},
        )
    return OwnershipCheckResponse(status="success", data=data)
