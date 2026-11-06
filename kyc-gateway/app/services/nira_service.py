"""
NIRA three-step authentication service (token → certificate → auth).

The middleware performs the entire NIRA AUTH flow internally on behalf of the
KYC vendor. The vendor calls POST /identity_verification with id_type
"NATIONAL ID" plus their biometric blocks; this service:

1. POST /nira/token      — obtains a NIRA bearer token using stored credentials
2. GET  /nira/certificate — fetches NIRA's encryption certificate
3. Computes all client-side crypto (thumbprint, RSA-OAEP session key,
   AES-GCM requestHMAC/request, detached JWS RS256 signature)
4. POST /nira/auth       — submits the signed request and returns the
   X-Verification-Reference

NIRA partner credentials, PEM files, and crypto logic never leave the
middleware. Vendors never see or handle them.
"""

import base64
import hashlib
import json
import os
import uuid
from datetime import datetime, timezone

import httpx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.x509 import load_pem_x509_certificate

from app.core.config import settings
from app.services.exceptions import KycServiceError

GCM_NONCE_SIZE = 16


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _load_file(path: str) -> str:
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def _normalize_certificate_pem(certificate: str) -> str:
    """Normalize plain, JSON-string, and literal-escaped PEM line endings."""
    try:
        decoded = json.loads(certificate)
    except json.JSONDecodeError:
        decoded = certificate

    if isinstance(decoded, str):
        certificate = decoded
    else:
        raise KycServiceError(
            502,
            "NIRA_CERT_INVALID",
            "NIRA certificate response is not a PEM certificate",
        )

    certificate = certificate.strip()
    if "\\n" in certificate or "\\r" in certificate:
        certificate = (
            certificate.replace("\\r\\n", "\n")
            .replace("\\n", "\n")
            .replace("\\r", "\n")
            .strip()
        )

    if not (
        certificate.startswith("-----BEGIN CERTIFICATE-----")
        and "-----END CERTIFICATE-----" in certificate
    ):
        raise KycServiceError(
            502,
            "NIRA_CERT_INVALID",
            "NIRA certificate response is not a PEM certificate",
        )
    return certificate + "\n"


class NIRAAuthenticator:
    """Orchestrates the three-step NIRA AUTH flow using stored credentials."""

    def __init__(self) -> None:
        self.client_id = settings.NIRA_CLIENT_ID
        self.secret_key = settings.NIRA_SECRET_KEY
        self.app_id = settings.NIRA_APP_ID
        self.misp_license_key = settings.NIRA_MISP_LICENSE_KEY
        self.partner_id = settings.NIRA_PARTNER_ID
        self.partner_api_key = settings.NIRA_PARTNER_API_KEY
        self.domain_uri = settings.NIRA_DOMAIN_URI or (
            "https://api-internal-preprod.nsis.nira.go.ug"
        )
        self.env = settings.NIRA_ENV

        self.partner_key_path = settings.NIRA_PARTNER_KEY_PATH
        self.partner_cert_path = settings.NIRA_PARTNER_CERT_PATH

        self._validate_config()

    def _validate_config(self) -> None:
        missing = []
        if not self.client_id:
            missing.append("NIRA_CLIENT_ID")
        if not self.secret_key:
            missing.append("NIRA_SECRET_KEY")
        if not self.app_id:
            missing.append("NIRA_APP_ID")
        if not self.misp_license_key:
            missing.append("NIRA_MISP_LICENSE_KEY")
        if not self.partner_id:
            missing.append("NIRA_PARTNER_ID")
        if not self.partner_api_key:
            missing.append("NIRA_PARTNER_API_KEY")
        if not self.partner_key_path or not os.path.exists(self.partner_key_path):
            missing.append("NIRA_PARTNER_KEY_PATH (file not found)")
        if not self.partner_cert_path or not os.path.exists(self.partner_cert_path):
            missing.append("NIRA_PARTNER_CERT_PATH (file not found)")
        if missing:
            raise KycServiceError(
                503,
                "NIRA_NOT_CONFIGURED",
                f"NIRA auth is not configured on the middleware: {', '.join(missing)}",
            )

    # ------------------------------------------------------------------ step A: token

    async def get_token(self, client: httpx.AsyncClient) -> str:
        """POST /nira/token via UCC. Returns the NIRA bearer token."""
        url = f"{settings.UCC_BASE_URL.rstrip('/')}/api/v1/kyc/nira/token"
        headers = {
            "X-API-Key": settings.UCC_API_KEY,
            "X-Client-ID": self.client_id,
            "X-Secret-Key": self.secret_key,
            "X-App-ID": self.app_id,
        }
        resp = await client.post(url, headers=headers, timeout=settings.TIMEOUT)
        if resp.status_code != 200:
            raise KycServiceError(
                502,
                "NIRA_TOKEN_FAILED",
                f"NIRA token request failed: HTTP {resp.status_code}",
            )
        auth = resp.headers.get("authorization") or resp.headers.get("Authorization")
        if not auth:
            raise KycServiceError(
                502, "NIRA_TOKEN_MISSING", "NIRA token not returned in Authorization header"
            )
        # NIRA returns Authorization: Authorization=<token>
        if auth.startswith("Authorization="):
            return auth[len("Authorization=") :]
        return auth

    # ------------------------------------------------------------------ step B: certificate

    async def get_certificate(self, client: httpx.AsyncClient, token: str) -> str:
        """GET /nira/certificate via UCC. Returns the NIRA certificate PEM."""
        url = f"{settings.UCC_BASE_URL.rstrip('/')}/api/v1/kyc/nira/certificate"
        headers = {
            "X-API-Key": settings.UCC_API_KEY,
            "Authorization": f"Authorization={token}",
        }
        resp = await client.get(url, headers=headers, timeout=settings.TIMEOUT)
        if resp.status_code != 200:
            raise KycServiceError(
                502,
                "NIRA_CERT_FAILED",
                f"NIRA certificate request failed: HTTP {resp.status_code}",
            )
        return _normalize_certificate_pem(resp.text)

    # ------------------------------------------------------------------ crypto

    def compute_thumbprint(self, cert_pem: str) -> str:
        """SHA-256 of the DER-encoded certificate, lowercase hex (spec section 6)."""
        try:
            cert = load_pem_x509_certificate(cert_pem.encode("utf-8"))
        except ValueError as exc:
            raise KycServiceError(
                502,
                "NIRA_CERT_INVALID",
                "UCC returned a malformed NIRA encryption certificate",
            ) from exc
        der = cert.public_bytes(serialization.Encoding.DER)
        return hashlib.sha256(der).hexdigest().lower()

    def encrypt_session_key(self, session_key: bytes, cert_pem: str) -> str:
        """RSA-OAEP (SHA-256) encrypt the AES session key to NIRA cert public key."""
        cert = load_pem_x509_certificate(cert_pem.encode("utf-8"))
        public_key = cert.public_key()
        encrypted = public_key.encrypt(
            session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return _b64url_encode(encrypted)

    def aes_gcm_encrypt(self, plaintext: bytes, key: bytes) -> str:
        """AES-256-GCM encrypt. Layout: ciphertext || tag || nonce (nonce at END)."""
        aesgcm = AESGCM(key)
        nonce = os.urandom(GCM_NONCE_SIZE)
        ct_and_tag = aesgcm.encrypt(nonce, plaintext, None)
        return _b64url_encode(ct_and_tag + nonce)

    def make_jws(self, payload: bytes, private_key_pem: str, partner_cert_pem: str) -> str:
        """Detached JWS (RS256) over the request body per spec section 11.5."""
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode("utf-8"), password=None
        )
        partner_cert = load_pem_x509_certificate(partner_cert_pem.encode("utf-8"))
        cert_der = partner_cert.public_bytes(serialization.Encoding.DER)
        cert_b64_standard = base64.b64encode(cert_der).decode("ascii")

        header = {"alg": "RS256", "x5c": [cert_b64_standard]}
        header_b64 = _b64url_encode(
            json.dumps(header, separators=(",", ":")).encode("utf-8")
        )
        payload_b64 = _b64url_encode(payload)
        signing_input = (header_b64 + "." + payload_b64).encode("ascii")
        signature = private_key.sign(
            signing_input, padding.PKCS1v15(), hashes.SHA256()
        )
        sig_b64 = _b64url_encode(signature)
        return header_b64 + ".." + sig_b64

    # ------------------------------------------------------------------ step C: auth

    def build_inner_request(
        self,
        transaction_id: str,
        nin: str,
        date_of_birth: str,
        surname: str,
        given_names: str,
        blocks,
        domain_uri: str,
        env: str,
        timestamp: str,
    ) -> dict:
        """Build the inner (plaintext) NIRA AUTH request per spec section 8."""
        biometric_blocks = (
            blocks.get("biometrics", []) if isinstance(blocks, dict) else blocks
        )
        if not isinstance(biometric_blocks, list) or not biometric_blocks:
            raise KycServiceError(
                422, "MISSING_FIELD", "NIRA AUTH requires at least one signed biometric block"
            )
        return {
            "id": "mosip.identity.auth",
            "version": "1.0",
            "transactionID": transaction_id,
            "timestamp": timestamp,
            "env": env,
            "domainUri": domain_uri,
            "individualId": nin.lower() + "@nin",
            "individualIdType": "HANDLE",
            "consentObtained": True,
            "demographic": {
                "surname": surname,
                "givenName": given_names,
                "dateOfBirth": date_of_birth,
                "nin": nin.upper(),
            },
            "biometrics": biometric_blocks,
        }

    async def authenticate_national_id(
        self,
        transaction_id: str,
        nin: str,
        date_of_birth: str,
        surname: str,
        given_names: str,
        biometric_blocks,
    ) -> dict:
        """
        Execute the full three-step NIRA AUTH flow.

        Returns a dict with verification_reference, auth_status, auth_token,
        and the raw NIRA response body.
        """
        async with httpx.AsyncClient(
            timeout=settings.TIMEOUT, verify=settings.UCC_TLS_VERIFY
        ) as client:
            # Step A: token
            token = await self.get_token(client)

            # Step B: certificate
            cert_pem = await self.get_certificate(client, token)

            # Compute thumbprint
            thumbprint = self.compute_thumbprint(cert_pem)

            # Step C: generate AES session key and encrypt it
            session_key = os.urandom(32)  # AES-256
            request_session_key = self.encrypt_session_key(session_key, cert_pem)

            # Build inner request
            request_time = datetime.now(timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%S.%f"
            )[:-3] + "Z"
            inner_request = self.build_inner_request(
                transaction_id, nin, date_of_birth, surname, given_names,
                biometric_blocks, self.domain_uri, self.env, request_time,
            )
            inner_request_json = json.dumps(
                inner_request, separators=(",", ":")
            ).encode("utf-8")

            # Compute requestHMAC and encrypted request
            digest = hashlib.sha256(inner_request_json).hexdigest().upper()
            request_hmac = self.aes_gcm_encrypt(digest.encode("utf-8"), session_key)
            request_field = self.aes_gcm_encrypt(inner_request_json, session_key)

            # Build outer request body
            outer_body = {
                "id": "mosip.identity.auth",
                "version": "1.0",
                "transactionID": transaction_id,
                "requestTime": request_time,
                "env": self.env,
                "domainUri": self.domain_uri,
                "individualId": nin.lower() + "@nin",
                "individualIdType": "HANDLE",
                "consentObtained": True,
                "requestedAuth": {"bio": True},
                "thumbprint": thumbprint,
                "requestSessionKey": request_session_key,
                "requestHMAC": request_hmac,
                "request": request_field,
            }
            outer_body_json = json.dumps(outer_body, separators=(",", ":")).encode("utf-8")

            # Create JWS signature
            partner_key_pem = _load_file(self.partner_key_path)
            partner_cert_pem = _load_file(self.partner_cert_path)
            signature = self.make_jws(outer_body_json, partner_key_pem, partner_cert_pem)

            # Step D: POST /nira/auth via UCC
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
            resp = await client.post(
                url, headers=headers, content=outer_body_json, timeout=settings.TIMEOUT
            )
            if resp.status_code != 200:
                raise KycServiceError(
                    502,
                    "NIRA_AUTH_FAILED",
                    f"NIRA auth request failed: HTTP {resp.status_code} {resp.text[:200]}",
                )

            body = resp.json()
            x_vref = resp.headers.get("x-verification-reference")
            response_obj = body.get("response", {}) or {}

            return {
                "verification_reference": x_vref,
                "auth_status": response_obj.get("authStatus", False),
                "auth_token": response_obj.get("authToken"),
                "errors": body.get("errors"),
                "transaction_id": body.get("transactionID"),
                "raw_response": body,
            }


# Module-level placeholder; the authenticator is created lazily on first use
# so the app can start even if NIRA PEM files/credentials aren't configured yet.
_nira_authenticator = None


def get_nira_authenticator() -> NIRAAuthenticator:
    """Return a lazily-initialized NIRAAuthenticator singleton."""
    global _nira_authenticator
    if _nira_authenticator is None:
        _nira_authenticator = NIRAAuthenticator()
    return _nira_authenticator
