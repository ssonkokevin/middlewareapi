"""
Main FastAPI application — Hamilton Middleware API Gateway.

Routes:
  POST /auth/token               — Get single-use token (client_id + client_secret)
  POST /api/nira/prod/verify     — NIRA production (token + IP: 10.20.20.1)
  POST /api/nira/test/verify     — NIRA test       (token + IP: 10.20.20.4)
  POST /api/refugee/prod/verify  — UCC  production   (token + IP: 192.168.168.10)
  POST /api/refugee/test/verify  — UCC  test         (token + IP: 192.168.168.12)
  POST /admin/clients/generate   — Generate client credentials (admin only)
  GET  /admin/clients            — List clients (admin only)
  GET  /admin/ping               — Test admin access (admin only)
  GET  /health                   — Service health check (no restrictions)
  GET  /docs                     — Swagger UI (no restrictions)

Security Model:
  1. Client obtains single-use token via POST /auth/token
  2. Token is deleted IMMEDIATELY after any verification attempt (success/failure/timeout)
  3. Each verify endpoint requires both valid token AND allowed source IP
  4. Cross-environment requests are blocked (403)

Notes:
  - Tokens have 90s safety TTL in Redis (safety net for server crash only)
  - Fingerprint payloads can be 50-200 KB; uvicorn uses --timeout-keep-alive 60
  - All errors return consistent JSON: {success, error, environment, message, status_code, path}
"""

import logging
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone, timedelta
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import settings
from app.core.logger import setup_logging
from app.api.routes import nira, refugee, admin, auth

_EAT = timezone(timedelta(hours=3))


# Initialise logging before anything else runs
setup_logging()
logger = logging.getLogger("middleware")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Log startup/shutdown events and validate critical configuration."""
    logger.info(
        "Middleware API Gateway starting",
        extra={
            "debug":                      settings.DEBUG,
            "nira_prod_url":              settings.NIRA_PROD_URL,
            "nira_prod_allowed_ip":       settings.NIRA_PROD_ALLOWED_IP,
            "nira_test_url":              settings.NIRA_TEST_URL,
            "nira_test_allowed_ip":       settings.NIRA_TEST_ALLOWED_IP,
            "refugee_prod_validate_url":  settings.REFUGEE_PROD_VALIDATE_URL,
            "refugee_prod_allowed_ip":    settings.REFUGEE_PROD_ALLOWED_IP,
            "refugee_test_validate_url":  settings.REFUGEE_TEST_VALIDATE_URL,
            "refugee_test_allowed_ip":    settings.REFUGEE_TEST_ALLOWED_IP,
            "timeout_s":                  settings.TIMEOUT,
        },
    )
    yield
    logger.info("Middleware API Gateway shutting down")


app = FastAPI(
    title="Hamilton Verification Middleware",
    description="API Gateway for NIRA and UCC Refugee verification",
    version="1.0.0",
    debug=settings.DEBUG,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

# CORS — restrict origins in production if the gateway is exposed to a browser
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Request/response logging middleware
@app.middleware("http")
async def log_requests(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    duration_ms = (time.time() - start_time) * 1000
    
    msg = (
        f"HTTP {request.method} {request.url.path} "
        f"responded {response.status_code} "
        f"in {duration_ms:.4f} ms"
    )
    
    client_ip = request.headers.get("X-Forwarded-For", 
                request.client.host if request.client else "unknown")
    
    if response.status_code >= 400:
        logger.warning(
            f"HTTP {response.status_code} {request.method} "
            f"{request.url.path} | IP={client_ip} | "
            f"Duration={duration_ms:.0f}ms"
        )
    else:
        logger.info(msg)
    
    return response

# Register API routers
# Auth router (no prefix — provides POST /auth/token)
app.include_router(auth.router, prefix="/auth")

# Verification routers (prefixed — provides /api/nira/prod/verify etc.)
app.include_router(nira.router,    prefix="/api/nira")
app.include_router(refugee.router, prefix="/api/refugee")

# Admin router (prefixed — provides /admin/clients/generate etc.)
app.include_router(admin.router, prefix="/admin")


# ------------------------------------------------------------------ utility endpoints

@app.get("/", include_in_schema=False)
async def root():
    return {
        "status": "ok",
        "service": "Hamilton Middleware",
        "timestamp": datetime.now(_EAT).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+03:00",
    }


@app.get("/health", tags=["Health"])
async def health_check():
    """Returns 200 when the gateway process is alive."""
    return {
        "status": "ok",
        "service": "Hamilton Middleware",
        "timestamp": datetime.now(_EAT).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+03:00",
    }


# ------------------------------------------------------------------ global error handlers

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """
    Converts all FastAPI HTTPExceptions into a consistent JSON error envelope.
    This catches 400, 403, 404, 502, 504, etc. raised anywhere in the app.
    """
    logger.warning(
        f"HTTP {exc.status_code}: {exc.detail}",
        extra={
            "status_code": exc.status_code,
            "path": request.url.path,
            "method": request.method,
        },
    )
    # If the route handler already set a structured dict as the detail, pass it
    # through unchanged so the client gets the full {environment, path, ...} shape.
    if isinstance(exc.detail, dict):
        return JSONResponse(status_code=exc.status_code, content=exc.detail)
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "success":     False,
            "error":       True,
            "message":     exc.detail,
            "status_code": exc.status_code,
            "path":        request.url.path,
        },
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """
    Safety net — catches any unhandled exception so the app never returns
    an empty 500 or exposes a Python traceback to the client.
    """
    logger.error(
        f"Unhandled exception: {exc}",
        extra={
            "exception_type": type(exc).__name__,
            "path": request.url.path,
            "method": request.method,
            "error": str(exc),
        },
        exc_info=True,
    )
    return JSONResponse(
        status_code=500,
        content={
            "success": False,
            "error": True,
            "message": "Internal server error",
            "status_code": 500,
            "path": request.url.path,
        },
    )


# ------------------------------------------------------------------ local dev entry-point

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        reload_dirs=["app"],        # watch ONLY the app/ folder
        timeout_keep_alive=60,
    )
