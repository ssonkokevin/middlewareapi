"""
X-API-Key authentication dependency.

Every KYC endpoint requires an API key supplied in the `X-API-Key` request
header. A missing or unrecognised key returns HTTP 401 with error_code
UNAUTHORIZED. The key identifies the calling MNO; data-scoped endpoints
(e.g. compliance report) are automatically filtered to that MNO.
"""

from fastapi import Header, HTTPException
from app.core.config import settings


async def require_api_key(x_api_key: str | None = Header(default=None, alias="X-API-Key")) -> str:
    """
    Validates the X-API-Key header and returns the resolved MNO identifier
    for use by downstream services (e.g. to scope the compliance report).
    """
    if not x_api_key or x_api_key not in settings.get_api_keys():
        raise HTTPException(
            status_code=401,
            detail={
                "status": "error",
                "error_code": "UNAUTHORIZED",
                "message": "Invalid or missing API key",
            },
        )
    return settings.resolve_api_key_owner(x_api_key)
