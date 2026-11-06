import base64
import json
import unittest
from types import SimpleNamespace
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
        encoded_claims = base64.urlsafe_b64encode(
            json.dumps({"transactionId": "1234567890"}).encode("utf-8")
        ).rstrip(b"=").decode("ascii")
        blocks = [
            {
                "data": f"header.{encoded_claims}.signature",
                "sessionKey": "captured-key",
            }
        ]
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
            patch(
                "app.services.verification_service.store.create_verification_reference",
                return_value=SimpleNamespace(
                    reference="vrf_local_test",
                    expires_at=1_999_999_999,
                ),
            ) as store_reference,
            patch("app.main.httpx.AsyncClient", side_effect=AssertionError("unexpected proxy call")),
        ):
            response = self.client.post(
                "/identity_verification",
                headers={"X-API-Key": settings.get_api_keys()[0]},
                json=payload,
            )

        self.assertEqual(response.status_code, 200)
        self.assertGreaterEqual(
            float(response.headers["X-Response-Time-Ms"]),
            0,
        )
        self.assertTrue(response.json()["data"]["verified"])
        self.assertEqual(
            response.json()["data"]["verification_reference"],
            "vrf_local_test",
        )
        store_reference.assert_called_once()
        self.assertNotIn("authorization", response.headers)
        self.assertEqual(
            authenticator.calls[0]["biometric_blocks"],
            blocks,
        )
        self.assertEqual(
            authenticator.calls[0]["date_of_birth"],
            payload["date_of_birth"],
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

    def test_rejects_transaction_id_that_differs_from_signed_block(self):
        encoded_claims = base64.urlsafe_b64encode(
            json.dumps({"transactionId": "1234567890"}).encode("utf-8")
        ).rstrip(b"=").decode("ascii")
        payload = {
            "id_type": "NATIONAL ID",
            "id_number": "CM702356039748",
            "transaction_id": "9999999999",
            "biometric": {
                "biometric_type": "FINGERPRINT",
                "format": "MOSIP_SBI_SIGNED",
                "blocks": [{"data": f"header.{encoded_claims}.signature"}],
            },
        }

        authenticator = _Authenticator()
        with patch(
            "app.services.verification_service.get_nira_authenticator",
            return_value=authenticator,
        ) as get_authenticator:
            response = self.client.post(
                "/identity_verification",
                headers={"X-API-Key": settings.get_api_keys()[0]},
                json=payload,
            )

        self.assertEqual(response.status_code, 422)
        self.assertEqual(
            response.json()["error_code"],
            "INVALID_BIOMETRIC",
        )
        get_authenticator.assert_called_once()
        self.assertEqual(authenticator.calls, [])


if __name__ == "__main__":
    unittest.main()
