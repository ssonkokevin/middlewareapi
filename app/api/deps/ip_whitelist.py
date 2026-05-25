"""
IP whitelisting dependencies for FastAPI.

One dependency function per endpoint — each locked to a single allowed caller IP:
  validate_nira_prod_ip    → only 10.20.20.1   (/api/nira/prod/verify)
  validate_nira_test_ip    → only 10.20.20.4   (/api/nira/test/verify)
  validate_refugee_prod_ip → only 192.168.168.10 (/api/refugee/prod/verify)
  validate_refugee_test_ip → only 192.168.168.12 (/api/refugee/test/verify)

Cross-environment calls are blocked:
  10.20.20.1 → /api/nira/test/verify   = 403
  10.20.20.4 → /api/nira/prod/verify   = 403
  etc.

CIDR checking uses Python's built-in ipaddress module (no external libraries).
Plain IPs like "10.20.20.1" are treated as /32 host networks automatically.
"""

import ipaddress
import logging
from typing import List

from fastapi import Request, HTTPException, status

from app.core.config import settings

logger = logging.getLogger("middleware")


# ─────────────────────────────────────────────────────── IP extraction

def get_client_ip(request: Request) -> str:
    """
    Resolve the real client IP address from the request.

    Checks headers in priority order:
      1. X-Forwarded-For  (proxy / load balancer — take only the first entry)
      2. X-Real-IP        (nginx proxy header)
      3. request.client.host (direct TCP connection)

    Returns "unknown" if none are available (e.g. test client with no socket).
    """
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()

    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        return real_ip.strip()

    if request.client is not None:
        return request.client.host

    return "unknown"


# ─────────────────────────────────────────────────────── CIDR matching

def is_ip_in_subnet(client_ip: str, subnet: str) -> bool:
    """
    Return True if client_ip falls inside the network defined by subnet.

    Works for plain host IPs ("10.20.20.1" → treated as /32) and CIDR
    notation ("192.168.168.0/29").  Returns False and logs a warning on
    any parse error so a bad .env value never crashes the service.
    """
    try:
        network = ipaddress.ip_network(subnet, strict=False)
        address = ipaddress.ip_address(client_ip)
        return address in network
    except ValueError as exc:
        logger.warning(
            "Invalid IP or subnet in whitelist config",
            extra={"client_ip": client_ip, "subnet": subnet, "error": str(exc)},
        )
        return False


def is_ip_allowed(client_ip: str, allowed_list: List[str]) -> bool:
    """
    Return True if client_ip matches any entry in allowed_list.
    Each entry may be a plain IP or a CIDR subnet string.
    """
    for entry in allowed_list:
        if is_ip_in_subnet(client_ip, entry):
            return True
    return False


# ─────────────────────────────────────── shared 403 raise helper

def _deny(client_ip: str, environment: str, service: str, path: str) -> None:
    """
    Log a DENIED result and raise HTTP 403 with a structured detail dict.
    The detail dict is returned as-is by the global HTTPException handler.
    """
    logger.warning(
        f"{service.upper()} {environment.upper()} access DENIED for IP: {client_ip}",
        extra={
            "service": service,
            "environment": environment,
            "client_ip": client_ip,
            "result": "DENIED",
            "path": path,
        },
    )
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail={
            "success":     False,
            "error":       True,
            "environment": environment,
            "message":     f"Access denied. IP {client_ip} is not authorised for {service} {environment}.",
            "status_code": 403,
            "path":        path,
        },
    )


# ─────────────────────────────────── FastAPI dependencies — NIRA production

def validate_nira_prod_ip(request: Request) -> bool:
    """
    Dependency for POST /api/nira/prod/verify.
    Only 10.20.20.1 (NIRA prod app server) is allowed.
    """
    client_ip = get_client_ip(request)
    allowed   = settings.NIRA_PROD_ALLOWED_IP

    if is_ip_in_subnet(client_ip, allowed):
        logger.info(
            f"NIRA PROD access GRANTED for IP: {client_ip}",
            extra={
                "service": "nira", "environment": "production",
                "client_ip": client_ip, "expected_ip": allowed,
                "result": "GRANTED", "path": request.url.path,
            },
        )
        return True

    _deny(client_ip, "production", "nira", "/api/nira/prod/verify")


# ─────────────────────────────────────── FastAPI dependencies — NIRA test

def validate_nira_test_ip(request: Request) -> bool:
    """
    Dependency for POST /api/nira/test/verify.
    Only 10.20.20.4 (NIRA test app server) is allowed.
    """
    client_ip = get_client_ip(request)
    allowed   = settings.NIRA_TEST_ALLOWED_IP

    if is_ip_in_subnet(client_ip, allowed):
        logger.info(
            f"NIRA TEST access GRANTED for IP: {client_ip}",
            extra={
                "service": "nira", "environment": "test",
                "client_ip": client_ip, "expected_ip": allowed,
                "result": "GRANTED", "path": request.url.path,
            },
        )
        return True

    _deny(client_ip, "test", "nira", "/api/nira/test/verify")


# ─────────────────────────────────── FastAPI dependencies — Refugee production

def validate_refugee_prod_ip(request: Request) -> bool:
    """
    Dependency for POST /api/refugee/prod/verify.
    Only 192.168.168.10 (Refugee prod app server) is allowed.
    """
    client_ip = get_client_ip(request)
    allowed   = settings.REFUGEE_PROD_ALLOWED_IP

    if is_ip_in_subnet(client_ip, allowed):
        logger.info(
            f"REFUGEE PROD access GRANTED for IP: {client_ip}",
            extra={
                "service": "refugee", "environment": "production",
                "client_ip": client_ip, "expected_ip": allowed,
                "result": "GRANTED", "path": request.url.path,
            },
        )
        return True

    _deny(client_ip, "production", "refugee", "/api/refugee/prod/verify")


# ─────────────────────────────────────── FastAPI dependencies — Refugee test

def validate_refugee_test_ip(request: Request) -> bool:
    """
    Dependency for POST /api/refugee/test/verify.
    Only 192.168.168.12 (Refugee test app server) is allowed.
    """
    client_ip = get_client_ip(request)
    allowed   = settings.REFUGEE_TEST_ALLOWED_IP

    if is_ip_in_subnet(client_ip, allowed):
        logger.info(
            f"REFUGEE TEST access GRANTED for IP: {client_ip}",
            extra={
                "service": "refugee", "environment": "test",
                "client_ip": client_ip, "expected_ip": allowed,
                "result": "GRANTED", "path": request.url.path,
            },
        )
        return True

    _deny(client_ip, "test", "refugee", "/api/refugee/test/verify")
