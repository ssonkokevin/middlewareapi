"""
GET /compliance_report — Retrieve compliance report.
"""

from fastapi import APIRouter, Depends
from app.api.deps.auth import require_api_key
from app.schemas.kyc import ComplianceReportResponse
from app.services.compliance_service import get_compliance_report

router = APIRouter(tags=["Compliance"])


@router.get(
    "/compliance_report",
    response_model=ComplianceReportResponse,
    operation_id="getComplianceReport",
    summary="Retrieve compliance report",
)
async def compliance_report(mno: str = Depends(require_api_key)):
    return get_compliance_report(mno)
