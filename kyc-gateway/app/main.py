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
  POST   /nira/token                                     — Obtain a NIRA token through UCC
  GET    /nira/certificate                               — Fetch NIRA certificate before each AUTH
  POST   /nira/auth                                      — Authenticate a National ID through NIRA
  GET    /health                                        — Service health check
  GET    /docs                                          — Swagger UI

NOTE: UCC forwarding is enabled. Vendor requests are forwarded to UCC_BASE_URL
while the middleware re-authenticates to UCC with UCC_API_KEY (not the
vendor's X-API-Key). The vendor's key is validated locally against
KYC_API_KEYS.

The NIRA token (Authorization header) and verification reference
(X-Verification-Reference header) are returned in response headers. CORS is
placed outside the proxy middleware and exposes only those headers so
browser-based clients can read them.

Every endpoint requires an API key in the `X-API-Key` header (see
app/api/deps/auth.py).
"""

import logging
import time
import json
from contextlib import asynccontextmanager
from datetime import datetime, timezone, timedelta

import httpx
from fastapi import FastAPI, Request, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.core.logger import setup_logging
from app.api.routes import ownership, verification, registration, compliance
from app.services.biometric_converter import convert_biometric_if_wsq

_EAT = timezone(timedelta(hours=3))

setup_logging()
logger = logging.getLogger("kyc_gateway")


_UCC_PROXY_PATHS = (
    "/ownership_check",
    "/identity_verification",
    "/individual_registrations",
    "/corporate_registrations",
    "/compliance_report",
    "/nira/token",
    "/nira/certificate",
    "/nira/auth",
)


def _is_ucc_proxy_path(path: str) -> bool:
    """Return whether a request path is a vendor KYC operation for UCC."""
    return any(path == route or path.startswith(f"{route}/") for route in _UCC_PROXY_PATHS)


def _ucc_request_headers(request: Request, ucc_api_key: str) -> dict[str, str]:
    """Forward contract headers to UCC. The vendor's X-API-Key is replaced
    with the middleware's own UCC_API_KEY so UCC authenticates the gateway,
    not the partner. NIRA-specific headers are passed through unchanged."""
    names = (
        "Content-Type", "Accept", "Idempotency-Key", "X-Request-ID",
        "X-Client-ID", "X-Secret-Key", "X-App-ID",
        "X-MISP-License-Key", "X-Partner-ID", "X-Partner-API-Key", "Signature",
    )
    headers = {
        name: value
        for name in names
        if (value := request.headers.get(name)) is not None
    }
    # The middleware authenticates to UCC with its own key, never the partner's.
    headers["X-API-Key"] = ucc_api_key
    return headers


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info(
        f"KYC Gateway starting | DEBUG={settings.DEBUG} | PUBLIC_BASE_URL={settings.PUBLIC_BASE_URL} | UCC_BASE_URL={settings.UCC_BASE_URL} | UCC_API_KEY=**{settings.UCC_API_KEY[-4:] if settings.UCC_API_KEY else 'MISSING'} | UCC_FORWARDING_ENABLED={settings.UCC_FORWARDING_ENABLED}",
        extra={"detailed": True},
    )
    yield
    logger.info("KYC Gateway shutting down", extra={"detailed": True})


app = FastAPI(
    title="KYC Verification API",
    description="UCC Central Equipment Identity Register (CEIR) — KYC Verification API gateway.",
    version="2.0.0",
    debug=settings.DEBUG,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    servers=[
        {
            "url": settings.PUBLIC_BASE_URL.rstrip("/"),
            "description": "Vendor-facing UCC KYC Gateway",
        }
    ],
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    # Expose the NIRA token and verification reference response headers so
    # browser-based clients (as well as server clients) can read them.
    expose_headers=["Authorization", "X-Verification-Reference"],
)


@app.middleware("http")
async def log_requests(request: Request, call_next):
    start_time = time.time()
    
    # Get client info
    client_ip = request.headers.get(
        "X-Forwarded-For", request.headers.get("X-Real-IP", request.client.host if request.client else "unknown")
    )
    if "," in str(client_ip):
        client_ip = str(client_ip).split(",")[0].strip()
    
    # Get API key info (masked for security)
    api_key = request.headers.get("X-API-Key", "")
    user_info = "anonymous"
    if api_key:
        if api_key in settings.get_api_keys():
            user_info = f"vendor({api_key[:8]}...)"
        else:
            user_info = f"unauthorized({api_key[:8]}...)"
    
    method = request.method
    path = request.url.path
    query = str(request.url.query) if request.url.query else ""
    
    # Log request details for non-health endpoints
    if path not in ["/health", "/", "/docs", "/openapi.json", "/redoc"]:
        try:
            body = await request.body()
            if body:
                body_str = body.decode('utf-8', errors='replace')
                # Truncate very long bodies
                if len(body_str) > 500:
                    body_str = body_str[:500] + "...[truncated]"
                logger.info(
                    f"HTTP {method} {path}{'?' + query if query else ''} | User={user_info} IP={client_ip} | Request Body: {body_str}",
                    extra={"detailed": True},
                )
        except Exception as e:
            logger.debug(f"Could not log request body: {e}", extra={"detailed": True})
    
    try:
        response = await call_next(request)
    except Exception as e:
        duration_ms = (time.time() - start_time) * 1000
        logger.error(
            f"HTTP {method} {path} | User={user_info} IP={client_ip} | Duration={duration_ms:.0f}ms | Exception: {str(e)}",
            extra={"detailed": True},
        )
        raise
    
    duration_ms = (time.time() - start_time) * 1000
    
    # Log response
    if response.status_code >= 400:
        logger.warning(
            f"HTTP {response.status_code} {method} {path} | User={user_info} IP={client_ip} | Duration={duration_ms:.0f}ms",
            extra={"detailed": True},
        )
    else:
        logger.info(
            f"HTTP {method} {path} responded {response.status_code} in {duration_ms:.4f} ms",
            extra={"detailed": True},
        )
    
    # Detailed response logging for API calls
    if path not in ["/health", "/", "/docs", "/openapi.json", "/redoc"]:
        try:
            # Note: we can't easily read response body here without consuming it
            # For detailed response logging, it would need to be captured differently
            logger.info(
                f"HTTP {method} {path} | Status={response.status_code} | User={user_info} IP={client_ip} | Duration={duration_ms:.4f}ms | Headers: {dict(response.headers)}",
                extra={"detailed": True},
            )
        except Exception:
            pass
    
    return response


@app.middleware("http")
async def forward_ucc_requests(request: Request, call_next):
    """
    Relay authenticated vendor KYC calls to UCC and return UCC's response.

    PUBLIC_BASE_URL is only the vendor-facing address. This middleware makes
    the outbound call to UCC_BASE_URL while preserving the vendor's
    X-API-Key, content type, request body, query string, and idempotency key.
    """
    if not settings.UCC_FORWARDING_ENABLED or not _is_ucc_proxy_path(request.url.path):
        return await call_next(request)

    # Let CORS handle preflight OPTIONS before any auth check — preflight
    # requests carry no auth headers.
    if request.method == "OPTIONS":
        return await call_next(request)

    # Retain the gateway's local allow-list. Invalid/missing keys are rejected
    # here with 401 so proxy paths without route handlers (e.g. /nira/*)
    # still get a proper unauthorized response instead of 404.
    api_key = request.headers.get("X-API-Key")
    if not api_key or api_key not in settings.get_api_keys():
        logger.warning(
            f"UCC Forward: Unauthorized key rejected locally | Path={request.url.path} | IP={request.headers.get('X-Forwarded-For', 'unknown')}",
            extra={"detailed": True},
        )
        return JSONResponse(
            status_code=401,
            content={
                "status": "error",
                "error_code": "UNAUTHORIZED",
                "message": "Invalid or missing API key",
            },
        )

    base_url = settings.UCC_BASE_URL.rstrip("/")
    target_url = f"{base_url}{request.url.path}"
    if request.url.query:
        target_url = f"{target_url}?{request.url.query}"

    # Log forwarding details
    client_ip = request.headers.get("X-Forwarded-For", request.headers.get("X-Real-IP", "unknown"))
    if "," in str(client_ip):
        client_ip = str(client_ip).split(",")[0].strip()
    
    logger.info(
        f"UCC Forward: {request.method} {request.url.path} -> {target_url} | User=vendor({api_key[:8]}...) | UCC key=**{settings.UCC_API_KEY[-4:] if settings.UCC_API_KEY else 'MISSING'} | IP={client_ip}",
        extra={"detailed": True},
    )
    # Log NIRA-specific headers being forwarded (never their values).
    nira_headers = [
        name for name in ("X-Client-ID", "X-Secret-Key", "X-App-ID",
                          "X-MISP-License-Key", "X-Partner-ID", "X-Partner-API-Key", "Signature")
        if request.headers.get(name)
    ]
    if nira_headers:
        logger.info(
            f"UCC Forward NIRA headers: {', '.join(nira_headers)} | Path={request.url.path}",
            extra={"detailed": True},
        )
    
    try:
        body = await request.body()

        # Convert WSQ biometric → JPEG before forwarding to UCC, which
        # requires JPEG format for REFUGEE ID verification.
        if request.url.path == "/identity_verification" and body:
            try:
                import json as _json
                body_json = _json.loads(body)
                biometric = body_json.get("biometric")
                if biometric and biometric.get("format") == "WSQ":
                    converted = convert_biometric_if_wsq(biometric)
                    body_json["biometric"] = converted
                    body = _json.dumps(body_json).encode("utf-8")
            except Exception:
                pass

        if body and request.url.path not in ["/health"]:
            try:
                body_str = body.decode('utf-8', errors='replace')
                if len(body_str) > 1000:
                    body_str = body_str[:1000] + "...[truncated]"
                logger.info(
                    f"UCC Forward Request Body: {body_str}",
                    extra={"detailed": True},
                )
            except:
                pass
        
        async with httpx.AsyncClient(
            timeout=settings.TIMEOUT,
            verify=settings.UCC_TLS_VERIFY,
        ) as client:
            upstream_response = await client.request(
                request.method,
                target_url,
                content=body,
                headers=_ucc_request_headers(request, settings.UCC_API_KEY),
            )
        
        logger.info(
            f"UCC Forward Response: {request.method} {request.url.path} <- {upstream_response.status_code} | Duration tracked separately",
            extra={"detailed": True},
        )
        
        # Log response body details
        try:
            resp_body = upstream_response.content
            if resp_body:
                resp_str = resp_body.decode('utf-8', errors='replace')
                if len(resp_str) > 1000:
                    resp_str = resp_str[:1000] + "...[truncated]"
                logger.info(
                    f"UCC Forward Response Body: {resp_str}",
                    extra={"detailed": True},
                )
        except Exception as e:
            logger.debug(f"Could not log UCC response body: {e}", extra={"detailed": True})
            
    except httpx.HTTPError as exc:
        logger.error(f"UCC upstream request failed: {exc} | Target: {target_url}", extra={"detailed": True})
        return JSONResponse(
            status_code=502,
            content={
                "status": "error",
                "error_code": "UCC_UPSTREAM_UNAVAILABLE",
                "message": "Unable to reach the UCC KYC service",
            },
        )

    response_headers = {}
    if content_type := upstream_response.headers.get("content-type"):
        response_headers["content-type"] = content_type
    if request_id := upstream_response.headers.get("x-request-id"):
        response_headers["x-request-id"] = request_id
    # Forward NIRA response headers so clients can read the token and reference.
    if auth := upstream_response.headers.get("authorization"):
        response_headers["authorization"] = auth
    if x_vref := upstream_response.headers.get("x-verification-reference"):
        response_headers["x-verification-reference"] = x_vref
    # Forward other important headers
    for h in ["x-correlation-id", "x-trace-id"]:
        if v := upstream_response.headers.get(h):
            response_headers[h] = v

    return Response(
        status_code=upstream_response.status_code,
        content=upstream_response.content,
        headers=response_headers,
    )


# Register routers (no shared prefix — paths match the spec exactly)
app.include_router(ownership.router)
app.include_router(verification.router)
app.include_router(registration.router)
app.include_router(compliance.router)


@app.get("/", include_in_schema=False)
async def root():
    logger.info("HTTP GET / | Service info requested", extra={"detailed": True})
    return {
        "status": "ok",
        "service": "KYC Verification API",
        "timestamp": datetime.now(_EAT).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+03:00",
    }


@app.get("/health", tags=["Health"])
async def health_check():
    logger.info("HTTP GET /health | Health check requested", extra={"detailed": True})
    return {
        "status": "ok",
        "service": "KYC Verification API",
        "timestamp": datetime.now(_EAT).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+03:00",
    }


# ------------------------------------------------------------------ global error handlers

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Passes through structured {status, error_code, message} details unchanged."""
    client_ip = request.headers.get("X-Forwarded-For", request.headers.get("X-Real-IP", "unknown"))
    if "," in str(client_ip):
        client_ip = str(client_ip).split(",")[0].strip()
    api_key = request.headers.get("X-API-Key", "")
    user_info = f"vendor({api_key[:8]}...)" if api_key else "anonymous"
    
    logger.warning(
        f"HTTP {exc.status_code} {request.method} {request.url.path} | User={user_info} IP={client_ip} | Error: {exc.detail}",
        extra={"detailed": True},
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
    client_ip = request.headers.get("X-Forwarded-For", request.headers.get("X-Real-IP", "unknown"))
    if "," in str(client_ip):
        client_ip = str(client_ip).split(",")[0].strip()
    api_key = request.headers.get("X-API-Key", "")
    user_info = f"vendor({api_key[:8]}...)" if api_key else "anonymous"
    
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

    logger.warning(
        f"HTTP 422 {request.method} {request.url.path} | User={user_info} IP={client_ip} | Validation Error: {error_code} - {message} | Details: {errors}",
        extra={"detailed": True},
    )
    return JSONResponse(
        status_code=422,
        content={"status": "error", "error_code": error_code, "message": message},
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    client_ip = request.headers.get("X-Forwarded-For", request.headers.get("X-Real-IP", "unknown"))
    if "," in str(client_ip):
        client_ip = str(client_ip).split(",")[0].strip()
    api_key = request.headers.get("X-API-Key", "")
    user_info = f"vendor({api_key[:8]}...)" if api_key else "anonymous"
    
    logger.error(
        f"HTTP 500 {request.method} {request.url.path} | User={user_info} IP={client_ip} | Unhandled Exception: {exc}",
        extra={"detailed": True, "exception_type": type(exc).__name__},
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
