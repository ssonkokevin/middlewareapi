"""
KYC Verification API Gateway — FastAPI implementation of kyc_api_v2.yml (v2.0.0).

Routes:
  POST   /ownership_check                              — Verify SIM ownership eligibility
  POST   /identity_verification                        — Verify subscriber identity and biometric
  POST   /individual_registrations                     — Register individual SIM
  POST   /corporate_registrations                       — Register corporate SIM
  PUT    /individual_registrations/{msisdn}             — Update subscriber registration
  PATCH  /individual_registrations/{msisdn}             — Amend subscriber details
  POST   /individual_registrations/{msisdn}/ownership_change — Transfer a SIM to a new subscriber
  POST   /individual_registrations/{msisdn}/deregistration   — End a SIM registration
  POST   /individual_registrations/batch                — Submit batch SIM registrations
  GET    /individual_registrations/batch/{job_id}        — Retrieve batch processing status
  POST   /corporate_registrations/batch                  — Submit batch corporate registrations
  GET    /corporate_registrations/batch/{job_id}         — Retrieve corporate batch processing status
  GET    /compliance_report                             — Retrieve compliance report
  GET    /health                                        — Service health check
  GET    /docs                                          — Swagger UI

NOTE: No production or test upstream URL has been confirmed yet for any
provider (see app/core/config.py: KYC_UPSTREAM_URL, NIRA_VALIDATE_URL,
UNHCR_VALIDATE_URL, etc). Until those are provided, all business logic runs
against the SQLite-backed store and simulated provider logic in
app/services/. Swap the stubs for real integrations once endpoints are
confirmed — the request/response contracts here already match the spec.

Every endpoint requires an API key in the `X-API-Key` header (see
app/api/deps/auth.py).
"""

import logging
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone, timedelta

from fastapi import FastAPI, Request, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.core.logger import setup_logging
from app.api.routes import ownership, verification, registration, compliance

_EAT = timezone(timedelta(hours=3))

setup_logging()
logger = logging.getLogger("kyc_gateway")


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info(
        "KYC Gateway starting",
        extra={
            "debug": settings.DEBUG,
            "kyc_upstream_url": settings.KYC_UPSTREAM_URL or "TBD — not yet confirmed",
            "nira_validate_url": settings.NIRA_VALIDATE_URL or "TBD — not yet confirmed",
            "unhcr_validate_url": settings.UNHCR_VALIDATE_URL or "TBD — not yet confirmed",
            "sqlite_path": settings.SQLITE_PATH,
            "webhook_configured": bool(settings.KYC_WEBHOOK_URL),
        },
    )
    yield
    logger.info("KYC Gateway shutting down")


app = FastAPI(
    title="KYC Verification API",
    description="UCC Central Equipment Identity Register (CEIR) — KYC Verification API gateway.",
    version="2.0.0",
    debug=settings.DEBUG,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def log_requests(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    duration_ms = (time.time() - start_time) * 1000

    client_ip = request.headers.get(
        "X-Forwarded-For", request.client.host if request.client else "unknown"
    )

    if response.status_code >= 400:
        logger.warning(
            f"HTTP {response.status_code} {request.method} {request.url.path} "
            f"| IP={client_ip} | Duration={duration_ms:.0f}ms"
        )
    else:
        logger.info(
            f"HTTP {request.method} {request.url.path} responded {response.status_code} "
            f"in {duration_ms:.4f} ms"
        )
    return response


# Register routers (no shared prefix — paths match the spec exactly)
app.include_router(ownership.router)
app.include_router(verification.router)
app.include_router(registration.router)
app.include_router(compliance.router)


@app.get("/", include_in_schema=False)
async def root():
    return {
        "status": "ok",
        "service": "KYC Verification API",
        "timestamp": datetime.now(_EAT).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+03:00",
    }


@app.get("/health", tags=["Health"])
async def health_check():
    return {
        "status": "ok",
        "service": "KYC Verification API",
        "timestamp": datetime.now(_EAT).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+03:00",
    }


# ------------------------------------------------------------------ global error handlers

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Passes through structured {status, error_code, message} details unchanged."""
    logger.warning(
        f"HTTP {exc.status_code}: {exc.detail}",
        extra={"status_code": exc.status_code, "path": request.url.path, "method": request.method},
    )
    if isinstance(exc.detail, dict):
        return JSONResponse(status_code=exc.status_code, content=exc.detail)
    return JSONResponse(
        status_code=exc.status_code,
        content={"status": "error", "error_code": "SYSTEM_ERROR", "message": str(exc.detail)},
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """
    Converts Pydantic/FastAPI request validation errors into the spec's
    ErrorResponse envelope, using MISSING_FIELD for absent required fields
    and INVALID_FIELD for values that fail type/enum/pattern constraints.
    """
    errors = exc.errors()
    first = errors[0] if errors else {}
    field_name = ".".join(str(p) for p in first.get("loc", [])[1:]) or "payload"
    error_type = first.get("type", "")

    if error_type in ("missing",):
        error_code = "MISSING_FIELD"
        message = f"{field_name} is required"
    else:
        error_code = "INVALID_FIELD"
        message = f"{field_name}: {first.get('msg', 'invalid value')}"

    logger.warning(f"Validation error on {request.url.path}: {errors}")
    return JSONResponse(
        status_code=422,
        content={"status": "error", "error_code": error_code, "message": message},
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    logger.error(
        f"Unhandled exception: {exc}",
        extra={"exception_type": type(exc).__name__, "path": request.url.path, "method": request.method},
        exc_info=True,
    )
    return JSONResponse(
        status_code=500,
        content={"status": "error", "error_code": "SYSTEM_ERROR", "message": "Unable to complete request at this time"},
    )


# ------------------------------------------------------------------ local dev entry-point

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8001,
        reload=True,
        reload_dirs=["app"],
        timeout_keep_alive=60,
    )
