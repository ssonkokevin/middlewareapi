import asyncio
import base64
import json
import time
import unittest
from unittest.mock import patch

from app.services.nira_service import NIRAAuthenticator
from app.services.exceptions import KycServiceError


def _jwt(claims: dict) -> str:
    payload = base64.urlsafe_b64encode(
        json.dumps(claims).encode("utf-8")
    ).rstrip(b"=").decode("ascii")
    return f"header.{payload}.signature"


class _Response:
    def __init__(self, status_code=200, headers=None, text="", body=None):
        self.status_code = status_code
        self.headers = headers or {}
        self.text = text
        self._body = body

    def json(self):
        return self._body


class _FakeClient:
    calls = []
    token = ""
    auth_requests = []
    auth_body = {"response": {"authStatus": True}, "errors": []}

    def __init__(self, **_kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return None

    async def post(self, url, headers=None, content=None):
        self.calls.append(("POST", url))
        if url.endswith("/nira/token"):
            return _Response(
                headers={"authorization": f"Authorization={self.token}"}
            )
        self.auth_requests.append(json.loads(content))
        return _Response(
            headers={"x-verification-reference": "vrf_nira_test"},
            body=self.auth_body,
        )

    async def get(self, url, headers=None):
        self.calls.append(("GET", url))
        return _Response(text="certificate")


class NIRAAuthenticatorTests(unittest.IsolatedAsyncioTestCase):
    async def test_token_certificate_auth_order_and_sbi_blocks_are_preserved(self):
        authenticator = object.__new__(NIRAAuthenticator)
        authenticator.client_id = "client"
        authenticator.secret_key = "secret"
        authenticator.app_id = "app"
        authenticator.misp_license_key = "license"
        authenticator.partner_id = "partner"
        authenticator.partner_api_key = "partner-key"
        authenticator.partner_key_path = "partner-key.pem"
        authenticator.partner_cert_path = "partner-cert.pem"
        authenticator.env = "pre-production"
        authenticator.domain_uri = "https://nira.example"
        authenticator._token = None
        authenticator._token_expires_at = 0
        authenticator._token_lock = asyncio.Lock()

        _FakeClient.calls = []
        _FakeClient.auth_requests = []
        _FakeClient.auth_body = {"response": {"authStatus": True}, "errors": []}
        _FakeClient.token = _jwt({"exp": time.time() + 300})
        claims = {"transactionId": "1234567890", "env": "Pre-Production"}
        signed_block = {
            "specVersion": "0.9.5",
            "data": _jwt(claims),
            "sessionKey": "preserve-this-value",
        }

        with (
            patch("app.services.nira_service.httpx.AsyncClient", _FakeClient),
            patch.object(NIRAAuthenticator, "_compute_thumbprint", return_value="thumb"),
            patch.object(NIRAAuthenticator, "_encrypt_session_key", return_value="encrypted-key"),
            patch.object(
                NIRAAuthenticator,
                "_aes_gcm_encrypt",
                side_effect=lambda plaintext, _key: plaintext.decode("utf-8"),
            ),
            patch.object(NIRAAuthenticator, "_make_jws", return_value="detached-signature"),
            patch("app.services.nira_service._load_file", return_value="pem"),
        ):
            result = await authenticator.authenticate_national_id(
                transaction_id="1234567890",
                nin="CM702356039748",
                date_of_birth="11/06/1970",
                surname="SSONKO",
                given_names="KEVIN",
                biometric_blocks=[signed_block],
            )
            # A still-valid JWT is reused; the certificate and AUTH are fresh.
            await authenticator.authenticate_national_id(
                transaction_id="1234567890",
                nin="CM702356039748",
                date_of_birth="11/06/1970",
                surname="SSONKO",
                given_names="KEVIN",
                biometric_blocks=[signed_block],
            )

        self.assertTrue(result["auth_status"])
        self.assertEqual(result["verification_reference"], "vrf_nira_test")
        self.assertEqual(
            [call[0] for call in _FakeClient.calls],
            ["POST", "GET", "POST", "GET", "POST"],
        )
        first_inner_request = json.loads(_FakeClient.auth_requests[0]["request"])
        self.assertEqual(first_inner_request["biometrics"], [signed_block])
        self.assertEqual(first_inner_request["transactionID"], "1234567890")
        self.assertEqual(_FakeClient.auth_requests[0]["requestedAuth"], {
            "otp": False,
            "demo": False,
            "bio": True,
        })

    async def test_upstream_balance_error_is_not_reported_as_biometric_mismatch(self):
        authenticator = object.__new__(NIRAAuthenticator)
        authenticator.client_id = "client"
        authenticator.secret_key = "secret"
        authenticator.app_id = "app"
        authenticator.misp_license_key = "license"
        authenticator.partner_id = "partner"
        authenticator.partner_api_key = "partner-key"
        authenticator.partner_key_path = "partner-key.pem"
        authenticator.partner_cert_path = "partner-cert.pem"
        authenticator.env = "pre-production"
        authenticator.domain_uri = "https://nira.example"
        authenticator._token = None
        authenticator._token_expires_at = 0
        authenticator._token_lock = asyncio.Lock()
        _FakeClient.calls = []
        _FakeClient.auth_requests = []
        _FakeClient.token = _jwt({"exp": time.time() + 300})
        _FakeClient.auth_body = {
            "response": {"authStatus": False},
            "errors": [{"errorCode": "IDA-MPA-041"}],
        }
        block = {
            "data": _jwt(
                {"transactionId": "1234567890", "env": "Pre-Production"}
            )
        }

        with (
            patch("app.services.nira_service.httpx.AsyncClient", _FakeClient),
            patch.object(NIRAAuthenticator, "_compute_thumbprint", return_value="thumb"),
            patch.object(NIRAAuthenticator, "_encrypt_session_key", return_value="encrypted-key"),
            patch.object(
                NIRAAuthenticator,
                "_aes_gcm_encrypt",
                side_effect=lambda plaintext, _key: plaintext.decode("utf-8"),
            ),
            patch.object(NIRAAuthenticator, "_make_jws", return_value="detached-signature"),
            patch("app.services.nira_service._load_file", return_value="pem"),
        ):
            with self.assertRaisesRegex(KycServiceError, "IDA-MPA-041"):
                await authenticator.authenticate_national_id(
                    transaction_id="1234567890",
                    nin="CM702356039748",
                    date_of_birth="11/06/1970",
                    surname="SSONKO",
                    given_names="KEVIN",
                    biometric_blocks=[block],
                )

    async def test_rejects_transaction_id_that_differs_from_signed_block(self):
        authenticator = object.__new__(NIRAAuthenticator)
        authenticator.env = "pre-production"
        authenticator.domain_uri = "https://nira.example"
        block = {
            "data": _jwt({"transactionId": "9999999999", "env": "Pre-Production"})
        }
        with self.assertRaisesRegex(
            KycServiceError, "must match the signed MOSIP SBI block"
        ):
            await authenticator.authenticate_national_id(
                transaction_id="1234567890",
                nin="CM702356039748",
                date_of_birth="11/06/1970",
                surname="SSONKO",
                given_names="KEVIN",
                biometric_blocks=[block],
            )


if __name__ == "__main__":
    unittest.main()
