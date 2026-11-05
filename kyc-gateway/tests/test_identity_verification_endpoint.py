import json
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from app.core.config import settings
from app.main import app, _request_body_for_log, _response_headers_for_log


class _Authenticator:
    def __init__(self):
        self.calls = []

    async def authenticate_national_id(self, **kwargs):
        self.calls.append(kwargs)
        return {
            "auth_status": True,
            "verification_reference": "vrf_nira_test",
        }


class IdentityVerificationEndpointTests(unittest.TestCase):
    def setUp(self):
        self.original_forwarding = settings.UCC_FORWARDING_ENABLED
        settings.UCC_FORWARDING_ENABLED = True
        self.client = TestClient(app)

    def tearDown(self):
        settings.UCC_FORWARDING_ENABLED = self.original_forwarding

    def test_national_id_uses_one_local_endpoint_and_redacts_biometrics(self):
        authenticator = _Authenticator()
        blocks = [{"data": "signed-sbi-block", "sessionKey": "captured-key"}]
        payload = {
            "id_type": "NATIONAL ID",
            "id_number": "CM702356039748",
            "first_name": "KEVIN",
            "last_name": "SSONKO",
            "date_of_birth": "11/06/1970",
            "transaction_id": "1234567890",
            "biometric": {
                "biometric_type": "FINGERPRINT",
                "format": "MOSIP_SBI_SIGNED",
                "blocks": blocks,
            },
        }

        with (
            patch(
                "app.services.verification_service.get_nira_authenticator",
                return_value=authenticator,
            ),
            patch("app.main.httpx.AsyncClient", side_effect=AssertionError("unexpected proxy call")),
        ):
            response = self.client.post(
                "/identity_verification",
                headers={"X-API-Key": settings.get_api_keys()[0]},
                json=payload,
            )

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["data"]["verified"])
        self.assertNotIn("authorization", response.headers)
        self.assertEqual(
            authenticator.calls[0]["biometric_blocks"],
            blocks,
        )
        logged_body = _request_body_for_log(
            "/identity_verification", json.dumps(payload).encode("utf-8")
        )
        self.assertNotIn("signed-sbi-block", logged_body)
        self.assertNotIn("CM702356039748", logged_body)
        self.assertEqual(
            _response_headers_for_log({"authorization": "sensitive-token"}),
            {"authorization": "[redacted]"},
        )
        self.assertEqual(
            _response_headers_for_log({"Authorization": "sensitive-token"}),
            {"Authorization": "[redacted]"},
        )


if __name__ == "__main__":
    unittest.main()
