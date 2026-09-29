"""
Domain exceptions mapped to the standardized ReasonCode/ErrorResponse envelope.
Raised by service-layer functions and translated to HTTPException by routes.
"""

from app.schemas.kyc import ReasonCode


class KycServiceError(Exception):
    """Base error carrying an HTTP status code and standardized reason/error code."""

    def __init__(self, status_code: int, error_code: ReasonCode, message: str):
        self.status_code = status_code
        self.error_code = error_code
        self.message = message
        super().__init__(message)
