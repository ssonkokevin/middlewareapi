"""
Compliance reporting service.

Real implementation should cache the result for 5 minutes per the spec
("very recent registrations may not be reflected yet"). This stub computes
counts on demand from the in-memory store.
"""

from app.schemas.kyc import ComplianceReportResponse, ComplianceReportData
from app.services.db import store


def get_compliance_report(mno: str) -> ComplianceReportResponse:
    counts = store.compliance_counts(mno)
    return ComplianceReportResponse(status="success", data=ComplianceReportData(**counts))
