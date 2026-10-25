# KYC Gateway: Vendor Integration Guide

## Connection details

| Item | Value |
| --- | --- |
| API base URL | `http://192.168.5.18:8001` |
| Interactive API documentation | `http://192.168.5.18:8001/docs` |
| OpenAPI definition | `http://192.168.5.18:8001/openapi.json` or `kyc_api_v2.yml` |
| Health check | `GET /health` |
| Authentication | `X-API-Key: <assigned vendor key>` |
| Content type | `application/json` |

The vendor must be issued a unique API key by the gateway administrator over a
separate secure channel. A key is required for every KYC business operation.
Do not use the development key shown in sample configuration, and do not send
keys in source code, email, chat, screenshots, or the API URL.

## Standard request headers

```http
X-API-Key: <assigned vendor key>
Content-Type: application/json
```

## Registration flow

1. **Check ownership** — `POST /ownership_check`. This should be called
   before biometric capture and registration.
2. **Verify identity** — `POST /identity_verification`. Send the required
   identity fields and the provider-specific biometric object specified in the
   OpenAPI contract. Treat `verified: false` as a verification failure even
   when the HTTP status is 200.
3. **Register** — send the verified identity details and the
   `verification_reference` from step 2 to `POST /individual_registrations`
   or `POST /corporate_registrations`.

Use the same pattern for batch records: each record carries its own valid
`verification_reference`. Include a unique `Idempotency-Key` header on each
batch submission. Repeating a used key returns `409 DUPLICATE_REQUEST`.

For a SIM-swap confirmation, call `/identity_verification` again, then use its
new reference in `PUT /individual_registrations/{msisdn}`. The gateway rejects
the reference that was last used for the current record, preventing replay.

## Endpoint summary

| Method | Endpoint | Use |
| --- | --- | --- |
| POST | `/ownership_check` | Ownership eligibility result |
| POST | `/identity_verification` | Identity/biometric decision and reference |
| POST | `/individual_registrations` | Individual SIM registration |
| POST | `/corporate_registrations` | Corporate SIM registration |
| PUT | `/individual_registrations/{msisdn}` | Full individual-record replacement |
| PATCH | `/individual_registrations/{msisdn}` | Partial permitted amendment |
| POST | `/individual_registrations/{msisdn}/ownership_change` | Transfer ownership |
| POST | `/individual_registrations/{msisdn}/deregistration` | Deregister the SIM |
| POST | `/individual_registrations/batch` | Submit an individual batch |
| GET | `/individual_registrations/batch/{job_id}` | Poll an individual batch |
| POST | `/corporate_registrations/batch` | Submit a corporate batch |
| GET | `/corporate_registrations/batch/{job_id}` | Poll a corporate batch |
| GET | `/compliance_report` | Report scoped to the calling key |

Exact required fields, permitted values, and response schemas are defined by
the Swagger UI/OpenAPI contract. Generate a client from that contract rather
than copying old v1.x `sim_registrations` examples: v2.0.0 uses
`individual_registrations` and separates biometric verification from
registration.

## Common responses

| HTTP status | Meaning |
| --- | --- |
| 200/201/202 | Request accepted or completed; inspect the response body |
| 401 `UNAUTHORIZED` | Missing or invalid `X-API-Key` |
| 403 `VERIFICATION_REFERENCE_INVALID` | Invalid/replayed last-used reference; verify again |
| 409 `DUPLICATE_REQUEST` | A batch idempotency key was already used |
| 422 | Missing or invalid request field |

## Go-live checklist

- Confirm that the vendor server can reach `192.168.5.18:8001`.
- Give the vendor one newly generated, unique API key through a secure secret
  channel; set that exact key in `KYC_API_KEYS` on the gateway.
- Confirm that the vendor has the v2.0.0 OpenAPI contract and is not using a
  v1.x `sim_registrations` payload.
- Use HTTPS via a trusted reverse proxy before using this connection outside a
  controlled private network.
