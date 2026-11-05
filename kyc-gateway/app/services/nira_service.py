"""Internal orchestration for National ID verification through NIRA."""

import asyncio
import base64
import binascii
import hashlib
import json
import os
import time
from datetime import datetime, timezone
from typing import Any, Optional

import httpx
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.x509 import load_pem_x509_certificate

from app.core.config import settings
from app.services.exceptions import KycServiceError

_GCM_NONCE_SIZE = 16
_PREPROD_DOMAIN_URI = "https://api-internal-preprod.nsis.nira.go.ug"


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _load_file(path: str) -> str:
    with open(path, "r", encoding="utf-8") as file:
        return file.read()


def _token_expiry(token: str) -> Optional[float]:
    """Return a JWT exp claim if available; opaque tokens are never cached."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        encoded_payload = parts[1]
        payload_bytes = base64.urlsafe_b64decode(
            encoded_payload + "=" * (-len(encoded_payload) % 4)
        )
        payload = json.loads(payload_bytes)
    except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError, ValueError):
        return None
    if not isinstance(payload, dict):
        return None
    expiry = payload.get("exp")
    return float(expiry) if isinstance(expiry, (int, float)) else None


def _decode_block_metadata(blocks: list[dict[str, Any]]) -> tuple[Optional[str], Optional[str]]:
    """Read transactionId and env from the first SBI block's signed data JWT."""
    if not blocks:
        return None, None
    data_jwt = blocks[0].get("data")
    if not isinstance(data_jwt, str):
        return None, None
    parts = data_jwt.split(".")
    if len(parts) != 3:
        return None, None
    try:
        encoded_payload = parts[1]
        payload_bytes = base64.urlsafe_b64decode(
            encoded_payload + "=" * (-len(encoded_payload) % 4)
        )
        claims = json.loads(payload_bytes)
    except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError, ValueError):
        return None, None
    if not isinstance(claims, dict):
        return None, None
    transaction_id = claims.get("transactionId")
    env = claims.get("env")
    return (
        transaction_id if isinstance(transaction_id, str) else None,
        env if isinstance(env, str) else None,
    )


def _normalized_environment(value: str) -> str:
    return "".join(character for character in value.casefold() if character.isalnum())


def _environment_label(value: str) -> str:
    normalized = _normalized_environment(value)
    if normalized == "preproduction":
        return "Pre-Production"
    if normalized == "production":
        return "Production"
    return value


class NIRAAuthenticator:
    """Fetch NIRA credentials/certificate and submit the signed AUTH request."""

    def __init__(self) -> None:
        self.client_id = settings.NIRA_CLIENT_ID
        self.secret_key = settings.NIRA_SECRET_KEY
        self.app_id = settings.NIRA_APP_ID
        self.misp_license_key = settings.NIRA_MISP_LICENSE_KEY
        self.partner_id = settings.NIRA_PARTNER_ID
        self.partner_api_key = settings.NIRA_PARTNER_API_KEY
        self.partner_key_path = settings.NIRA_PARTNER_KEY_PATH
        self.partner_cert_path = settings.NIRA_PARTNER_CERT_PATH
        self.env = settings.NIRA_ENV
        self.domain_uri = settings.NIRA_DOMAIN_URI or (
            _PREPROD_DOMAIN_URI if _normalized_environment(self.env) == "preproduction" else ""
        )
        self._token: Optional[str] = None
        self._token_expires_at = 0.0
        self._token_lock = asyncio.Lock()
        self._validate_config()

    def _validate_config(self) -> None:
        missing = []
        for name, value in (
            ("NIRA_CLIENT_ID", self.client_id),
            ("NIRA_SECRET_KEY", self.secret_key),
            ("NIRA_APP_ID", self.app_id),
            ("NIRA_MISP_LICENSE_KEY", self.misp_license_key),
            ("NIRA_PARTNER_ID", self.partner_id),
            ("NIRA_PARTNER_API_KEY", self.partner_api_key),
            ("NIRA_DOMAIN_URI", self.domain_uri),
        ):
            if not value:
                missing.append(name)
        for name, path in (
            ("NIRA_PARTNER_KEY_PATH", self.partner_key_path),
            ("NIRA_PARTNER_CERT_PATH", self.partner_cert_path),
        ):
            if not path or not os.path.isfile(path):
                missing.append(f"{name} (file not found)")
        if missing:
            raise KycServiceError(
                503,
                "SYSTEM_ERROR",
                f"NIRA verification is not configured: {', '.join(missing)}",
            )

    async def _get_token(self, client: httpx.AsyncClient) -> str:
        """Use a cached, unexpired JWT when possible; otherwise request one."""
        async with self._token_lock:
            if self._token and time.time() + 60 < self._token_expires_at:
                return self._token

            url = f"{settings.UCC_BASE_URL.rstrip('/')}/api/v1/kyc/nira/token"
            headers = {
                "X-API-Key": settings.UCC_API_KEY,
                "X-Client-ID": self.client_id,
                "X-Secret-Key": self.secret_key,
                "X-App-ID": self.app_id,
            }
            try:
                response = await client.post(url, headers=headers)
            except httpx.HTTPError as exc:
                raise KycServiceError(
                    502, "VERIFICATION_UNAVAILABLE", "Unable to obtain a NIRA token"
                ) from exc
            if response.status_code != 200:
                raise KycServiceError(
                    502,
                    "VERIFICATION_UNAVAILABLE",
                    f"NIRA token request failed with HTTP {response.status_code}",
                )

            authorization = response.headers.get("authorization")
            if not authorization:
                raise KycServiceError(
                    502,
                    "VERIFICATION_UNAVAILABLE",
                    "NIRA token response did not contain an Authorization header",
                )
            token = (
                authorization[len("Authorization="):]
                if authorization.startswith("Authorization=")
                else authorization
            )
            if not token:
                raise KycServiceError(
                    502, "VERIFICATION_UNAVAILABLE", "NIRA returned an empty token"
                )
            self._token = token
            self._token_expires_at = _token_expiry(token) or 0.0
            return token

    async def _get_certificate(self, client: httpx.AsyncClient, token: str) -> str:
        url = f"{settings.UCC_BASE_URL.rstrip('/')}/api/v1/kyc/nira/certificate"
        try:
            response = await client.get(
                url,
                headers={
                    "X-API-Key": settings.UCC_API_KEY,
                    "Authorization": f"Authorization={token}",
                },
            )
        except httpx.HTTPError as exc:
            raise KycServiceError(
                502, "VERIFICATION_UNAVAILABLE", "Unable to fetch the NIRA certificate"
            ) from exc
        if response.status_code != 200:
            raise KycServiceError(
                502,
                "VERIFICATION_UNAVAILABLE",
                f"NIRA certificate request failed with HTTP {response.status_code}",
            )
        if not response.text.strip():
            raise KycServiceError(
                502, "VERIFICATION_UNAVAILABLE", "NIRA returned an empty certificate"
            )
        return response.text

    @staticmethod
    def _compute_thumbprint(cert_pem: str) -> str:
        cert = load_pem_x509_certificate(cert_pem.encode("utf-8"))
        der = cert.public_bytes(serialization.Encoding.DER)
        return hashlib.sha256(der).hexdigest().lower()

    @staticmethod
    def _encrypt_session_key(session_key: bytes, cert_pem: str) -> str:
        cert = load_pem_x509_certificate(cert_pem.encode("utf-8"))
        encrypted = cert.public_key().encrypt(
            session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return _b64url_encode(encrypted)

    @staticmethod
    def _aes_gcm_encrypt(plaintext: bytes, key: bytes) -> str:
        nonce = os.urandom(_GCM_NONCE_SIZE)
        ciphertext_and_tag = AESGCM(key).encrypt(nonce, plaintext, None)
        return _b64url_encode(ciphertext_and_tag + nonce)

    @staticmethod
    def _make_jws(payload: bytes, private_key_pem: str, partner_cert_pem: str) -> str:
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode("utf-8"), password=None
        )
        partner_cert = load_pem_x509_certificate(partner_cert_pem.encode("utf-8"))
        cert_der = partner_cert.public_bytes(serialization.Encoding.DER)
        header = {
            "alg": "RS256",
            "x5c": [base64.b64encode(cert_der).decode("ascii")],
        }
        header_b64 = _b64url_encode(
            json.dumps(header, separators=(",", ":")).encode("utf-8")
        )
        payload_b64 = _b64url_encode(payload)
        signing_input = (header_b64 + "." + payload_b64).encode("ascii")
        signature = private_key.sign(
            signing_input, padding.PKCS1v15(), hashes.SHA256()
        )
        return header_b64 + ".." + _b64url_encode(signature)

    async def authenticate_national_id(
        self,
        transaction_id: str,
        nin: str,
        date_of_birth: str,
        surname: str,
        given_names: str,
        biometric_blocks: list[dict[str, Any]],
    ) -> dict[str, Any]:
        block_transaction_id, block_env = _decode_block_metadata(biometric_blocks)
        if not block_transaction_id:
            raise KycServiceError(
                422,
                "INVALID_BIOMETRIC",
                "The MOSIP SBI block does not contain a readable signed transactionId",
            )
        if block_transaction_id != transaction_id:
            raise KycServiceError(
                422,
                "INVALID_BIOMETRIC",
                "transaction_id must match the signed MOSIP SBI block",
            )
        if block_env and _normalized_environment(block_env) != _normalized_environment(self.env):
            raise KycServiceError(
                422,
                "INVALID_BIOMETRIC",
                "The MOSIP SBI block environment does not match the configured NIRA environment",
            )

        env = block_env or _environment_label(self.env)
        request_time = datetime.now(timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%S.%f"
        )[:-3] + "Z"
        inner_request = {
            "id": "mosip.identity.auth",
            "version": "1.0",
            "transactionID": transaction_id,
            "timestamp": request_time,
            "env": env,
            "domainUri": self.domain_uri,
            "individualId": nin.lower() + "@nin",
            "individualIdType": "HANDLE",
            "consentObtained": True,
            "demographic": {
                "surname": surname,
                "givenName": given_names,
                "dateOfBirth": date_of_birth,
                "nin": nin.upper(),
            },
            # The signed SBI blocks are forwarded as captured; do not reshape them.
            "biometrics": biometric_blocks,
        }
        inner_request_json = json.dumps(
            inner_request, separators=(",", ":")
        ).encode("utf-8")

        async with httpx.AsyncClient(
            timeout=settings.TIMEOUT, verify=settings.UCC_TLS_VERIFY
        ) as client:
            token = await self._get_token(client)
            cert_pem = await self._get_certificate(client, token)
            try:
                session_key = os.urandom(32)
                outer_body = {
                    "id": "mosip.identity.auth",
                    "version": "1.0",
                    "transactionID": transaction_id,
                    "requestTime": request_time,
                    "env": env,
                    "domainUri": self.domain_uri,
                    "individualId": nin.lower() + "@nin",
                    "individualIdType": "HANDLE",
                    "consentObtained": True,
                    "requestedAuth": {"otp": False, "demo": False, "bio": True},
                    "thumbprint": self._compute_thumbprint(cert_pem),
                    "requestSessionKey": self._encrypt_session_key(session_key, cert_pem),
                    "requestHMAC": self._aes_gcm_encrypt(
                        hashlib.sha256(inner_request_json).hexdigest().upper().encode("utf-8"),
                        session_key,
                    ),
                    "request": self._aes_gcm_encrypt(inner_request_json, session_key),
                }
                outer_body_json = json.dumps(
                    outer_body, separators=(",", ":")
                ).encode("utf-8")
                signature = self._make_jws(
                    outer_body_json,
                    _load_file(self.partner_key_path),
                    _load_file(self.partner_cert_path),
                )
            except (OSError, TypeError, ValueError, UnsupportedAlgorithm) as exc:
                raise KycServiceError(
                    502,
                    "VERIFICATION_UNAVAILABLE",
                    "Unable to prepare the signed NIRA AUTH request",
                ) from exc
            url = f"{settings.UCC_BASE_URL.rstrip('/')}/api/v1/kyc/nira/auth"
            headers = {
                "X-API-Key": settings.UCC_API_KEY,
                "X-MISP-License-Key": self.misp_license_key,
                "X-Partner-ID": self.partner_id,
                "X-Partner-API-Key": self.partner_api_key,
                "Authorization": f"Authorization={token}",
                "Content-Type": "application/json",
                "Signature": signature,
            }
            try:
                response = await client.post(url, headers=headers, content=outer_body_json)
            except httpx.HTTPError as exc:
                raise KycServiceError(
                    502, "VERIFICATION_UNAVAILABLE", "Unable to submit NIRA AUTH request"
                ) from exc

        if response.status_code != 200:
            raise KycServiceError(
                502,
                "VERIFICATION_UNAVAILABLE",
                f"NIRA AUTH request failed with HTTP {response.status_code}",
            )
        try:
            body = response.json()
        except (ValueError, json.JSONDecodeError) as exc:
            raise KycServiceError(
                502, "VERIFICATION_UNAVAILABLE", "NIRA returned an invalid AUTH response"
            ) from exc
        if not isinstance(body, dict) or not isinstance(body.get("response"), dict):
            raise KycServiceError(
                502, "VERIFICATION_UNAVAILABLE", "NIRA AUTH response is missing response data"
            )

        auth_status = body["response"].get("authStatus")
        if not isinstance(auth_status, bool):
            raise KycServiceError(
                502, "VERIFICATION_UNAVAILABLE", "NIRA AUTH response is missing authStatus"
            )
        errors = body.get("errors")
        if errors:
            if not isinstance(errors, list):
                raise KycServiceError(
                    502,
                    "VERIFICATION_UNAVAILABLE",
                    "NIRA AUTH response contains an invalid errors field",
                )
            codes = [
                error.get("errorCode")
                for error in errors
                if isinstance(error, dict) and isinstance(error.get("errorCode"), str)
            ]
            error_codes = ", ".join(codes) if codes else "unspecified NIRA error"
            raise KycServiceError(
                502,
                "VERIFICATION_UNAVAILABLE",
                f"NIRA AUTH returned errors: {error_codes}",
            )

        verification_reference = response.headers.get("x-verification-reference")
        if auth_status and not verification_reference:
            raise KycServiceError(
                502,
                "VERIFICATION_UNAVAILABLE",
                "NIRA verified the identity but did not return a verification reference",
            )
        return {
            "auth_status": auth_status,
            "verification_reference": verification_reference,
        }


_nira_authenticator: Optional[NIRAAuthenticator] = None


def get_nira_authenticator() -> NIRAAuthenticator:
    global _nira_authenticator
    if _nira_authenticator is None:
        _nira_authenticator = NIRAAuthenticator()
    return _nira_authenticator
