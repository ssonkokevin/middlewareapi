"""
Refugee service — UCC (Uganda Comprehensive Refugee) verification.

Protocol details:
  - Step 1 : POST to login URL with username/password → receive Bearer token
  - Step 2 : POST to validate URL with Bearer token + verification payload
  - Timeout : 60 s (fingerprint biometric matching typically takes ~4 s)
  - Payload : includes a large base64 WSQ fingerprint image — passed through as-is
  - IMPORTANT: Never log the raw fingerprint string (biometric PII)
"""

import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, Any

import httpx

from app.core.config import settings

logger = logging.getLogger("middleware")

# EAT timezone offset (UTC+3)
_EAT = timezone(timedelta(hours=3))


class RefugeeService:
    """Handles the two-step UCC login → verify flow for refugee verification."""

    # ------------------------------------------------------------------ private helpers

    async def _login(
        self,
        client: httpx.AsyncClient,
        login_url: str,
        username: str,
        password: str,
        environment: str = "production",
    ) -> str:
        """
        Authenticate with the UCC API and return the Bearer token.

        Posts username + password to the login endpoint, then extracts the
        token from the JSON response. The response field name may vary
        (token / access_token / accessToken) so we try all three.

        Args:
            client      : A shared httpx.AsyncClient for connection reuse.
            login_url   : UCC login endpoint URL for this environment.
            username    : UCC username for this environment.
            password    : UCC password for this environment.
            environment : "production" or "test" (for logging only).

        Returns:
            Bearer token string.

        Raises:
            Exception: If login fails or token is missing in the response.
        """
        logger.info(
            "Authenticating with UCC login endpoint",
            extra={"service": "refugee", "environment": environment, "url": login_url},
        )

        response = await client.post(
            login_url,
            json={"username": username, "password": password},
            headers={"Content-Type": "application/json"},
        )

        if response.status_code not in (200, 201):
            raise Exception(
                f"UCC login failed with HTTP {response.status_code}: {response.text[:200]}"
            )

        try:
            body: Dict[str, Any] = response.json()
        except Exception:
            raise Exception("UCC login returned non-JSON response")

        # Try known token field names in order of likelihood
        token: str = (
            body.get("token")
            or body.get("access_token")
            or body.get("accessToken")
            or ""
        )

        if not token:
            raise Exception(
                f"UCC login succeeded but no token found in response. Keys: {list(body.keys())}"
            )

        logger.info(
            "UCC authentication successful",
            extra={"service": "refugee", "environment": environment, "token_length": len(token)},
        )

        return token

    # ------------------------------------------------------------------ public API

    async def verify_refugee(
        self,
        individual_id: str,
        sex: str,
        year_of_birth: int,
        fingerprint: str,
        validate_url: str = None,
        login_url: str = None,
        username: str = None,
        password: str = None,
        environment: str = "production",
    ) -> Dict[str, Any]:
        """
        Verify a refugee's identity against the UCC API.

        Flow:
            1. Login  → obtain Bearer token from login_url
            2. Verify → POST biometric payload with token to validate_url

        Args:
            individual_id : UCC refugee ID, e.g. "PCS-00077251"
            sex           : "Male" or "Female"
            year_of_birth : integer year, e.g. 1987
            fingerprint   : Base64-encoded WSQ fingerprint image (can be 50-200 KB)
            validate_url  : UCC validate endpoint for this environment
            login_url     : UCC login endpoint for this environment
            username      : UCC username for this environment
            password      : UCC password for this environment
            environment   : "production" or "test" (for logging only)

        Returns:
            dict — typically {"result": "Match"} or {"result": "No Match"}

        Raises:
            Exception: wraps login failures, timeouts, HTTP errors
        """
        start_time = datetime.now(_EAT)

        # Log with fingerprint size only — never log the actual biometric data
        fingerprint_chars = len(fingerprint)
        logger.info(
            "Starting UCC refugee verification",
            extra={
                "service": "refugee",
                "environment": environment,
                "individualId": individual_id,
                "sex": sex,
                "yearOfBirth": year_of_birth,
                "fingerprint": f"[PRESENT, {fingerprint_chars} chars]",
            },
        )

        try:
            async with httpx.AsyncClient(timeout=settings.TIMEOUT) as client:

                # ---- Step 1: Login ----
                token = await self._login(
                    client,
                    login_url=login_url,
                    username=username,
                    password=password,
                    environment=environment,
                )

                # ---- Step 2: Verify ----
                payload: Dict[str, Any] = {
                    "individualId": individual_id,
                    "sex": sex,
                    "yearOfBirth": year_of_birth,
                    "fingerprint": fingerprint,
                }

                logger.info(
                    "Posting to UCC validate endpoint",
                    extra={
                        "service": "refugee",
                        "environment": environment,
                        "url": validate_url,
                        "individualId": individual_id,
                    },
                )

                validate_response = await client.post(
                    validate_url,
                    json=payload,
                    headers={
                        "Content-Type": "application/json",
                        "Authorization": f"Bearer {token}",
                        "User-Agent": "Middleware-API-Gateway/1.0.0",
                    },
                )

            duration_ms = round(
                (datetime.now(_EAT) - start_time).total_seconds() * 1000, 2
            )

            logger.info(
                "UCC validate response received",
                extra={
                    "service": "refugee",
                    "environment": environment,
                    "status_code": validate_response.status_code,
                    "duration_ms": duration_ms,
                    "individualId": individual_id,
                },
            )

            if validate_response.status_code not in (200, 201):
                raise Exception(
                    f"UCC validate returned HTTP {validate_response.status_code}: "
                    f"{validate_response.text[:200]}"
                )

            try:
                result: Dict[str, Any] = validate_response.json()
            except Exception:
                raise Exception("UCC validate returned non-JSON response")

            logger.info(
                "UCC refugee verification completed",
                extra={
                    "service": "refugee",
                    "environment": environment,
                    "individualId": individual_id,
                    "result": result.get("result", "unknown"),
                    "duration_ms": duration_ms,
                },
            )

            return result

        except httpx.TimeoutException:
            duration_ms = round(
                (datetime.now(_EAT) - start_time).total_seconds() * 1000, 2
            )
            logger.error(
                "UCC request timed out",
                extra={
                    "service": "refugee",
                    "environment": environment,
                    "individualId": individual_id,
                    "timeout_s": settings.TIMEOUT,
                    "duration_ms": duration_ms,
                },
            )
            raise Exception(f"UCC timed out after {settings.TIMEOUT} seconds")

        except httpx.RequestError as exc:
            duration_ms = round(
                (datetime.now(_EAT) - start_time).total_seconds() * 1000, 2
            )
            logger.error(
                "UCC connection error",
                extra={
                    "service": "refugee",
                    "environment": environment,
                    "individualId": individual_id,
                    "error": str(exc),
                    "duration_ms": duration_ms,
                },
            )
            raise Exception(f"UCC connection error: {exc}")

        except Exception:
            raise


# Application-wide singleton
refugee_service = RefugeeService()
