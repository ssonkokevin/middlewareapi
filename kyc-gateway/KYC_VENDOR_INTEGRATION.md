# KYC Gateway: Vendor Integration Guide

## Connection details

| Item | Value |
| --- | --- |
| API base URL | `http://10.33.33.30:8001` |
| Interactive API documentation | `http://10.33.33.30:8001/docs` |
| OpenAPI definition | `http://10.33.33.30:8001/openapi.json` or `kyc_api_v2.yml` |
| Health check | `GET /health` |
| Authentication | `X-API-Key: <assigned vendor key>` |
| Content type | `application/json` |

The vendor must be issued a unique API key by the gateway administrator over a separate secure channel. A key is required for every KYC business operation. Do not use the development key shown in sample configuration, and do not send keys in source code, email, chat, screenshots, or the API URL.

## Network routing

The vendor application connects only to the middleware endpoint:

```
Vendor application -> http://10.33.33.30:8001 -> KYC middleware -> UCC
```

The UCC upstream address is internal and must not be used by the vendor as its API base URL. The middleware validates your provisioned vendor key, injects all provider credentials (NIRA partner keys, certificates, and signing logic) internally, forwards to UCC, and returns the response to you. You never handle NIRA certificates, partner keys, or client-side cryptography.

## Standard request headers

```http
X-API-Key: <assigned vendor key>
Content-Type: application/json
```

## Two identity paths

The gateway supports two identity provider paths, selected by `id_type`:

| ID Type | Provider | What you send | What the middleware does |
| --- | --- | --- | --- |
| `NATIONAL ID` | NIRA | Identity + signed MOSIP SBI biometric blocks | Executes the full 3-step NIRA flow internally (token → certificate → signed auth). Returns `verification_reference` in the response body on success. |
| `REFUGEE ID` | UNHCR | Identity + fingerprint biometric (WSQ or JPEG) | Forwards to UNHCR; WSQ is auto-converted to JPEG. Returns a `verification_reference` in the response body. |
| `PASSPORT` | NCIC | Not yet integrated | Returns `VERIFICATION_UNAVAILABLE` |

## National ID flow (NIRA) — single call

**Step 1: Check ownership (optional but recommended)**

```http
POST /ownership_check
X-API-Key: <vendor-key>

{
  "subscriber_type": "individual",
  "id_type": "NATIONAL ID",
  "id_number": "<NIN>"
}
```

**Step 2: Verify identity (one call — middleware handles NIRA internally)**

```http
POST /identity_verification
X-API-Key: <vendor-key>
Content-Type: application/json

{
  "id_type": "NATIONAL ID",
  "id_number": "<NIN>",
  "first_name": "<given names>",
  "last_name": "<surname>",
  "date_of_birth": "11/06/1970",
  "transaction_id": "<10-digit ID from biometric block>",
  "biometric": {
    "biometric_type": "FINGERPRINT",
    "format": "MOSIP_SBI_SIGNED",
    "blocks": [<signed biometric blocks from MOSIP SBI capture>]
  }
}
```

The middleware internally:
1. Obtains a NIRA token using stored partner credentials when no valid cached JWT is available
2. Fetches a fresh NIRA encryption certificate for this AUTH request
3. Computes thumbprint, RSA-OAEP session key, AES-GCM requestHMAC/request, and detached JWS RS256 signature
4. Submits the signed auth request to UCC/NIRA
5. Returns a locally stored `verification_reference` in the response body

**Success response (200):**
```json
{
  "status": "success",
  "data": {
    "verified": true,
    "reason_code": "IDENTITY_ACCEPTED",
    "message": "Identity verified via NIRA",
    "provider": "NIRA",
    "verification_reference": "vrf_...",
    "expires_at": "2026-11-04T09:18:00Z"
  }
}
```

The `verification_reference` in the response body is valid for 24 hours and is the value to submit during registration.

**Failure response (200):**
```json
{
  "status": "success",
  "data": {
    "verified": false,
    "reason_code": "IDENTITY_REJECTED",
    "message": "NIRA authentication rejected",
    "provider": "NIRA",
    "verification_reference": null
  }
}
```

## Refugee ID flow (UNHCR) — single call

**Step 1: Check ownership (optional but recommended)**

```http
POST /ownership_check
X-API-Key: <vendor-key>

{
  "subscriber_type": "individual",
  "id_type": "REFUGEE ID",
  "id_number": "<refugee ID>"
}
```

**Step 2: Verify identity**

```http
POST /identity_verification
X-API-Key: <vendor-key>
Content-Type: application/json

{
  "id_type": "REFUGEE ID",
  "id_number": "<refugee ID>",
  "first_name": "<first name>",
  "last_name": "<last name>",
  "biometric": {
    "biometric_type": "FINGERPRINT",
    "format": "WSQ",
    "data": "<base64 fingerprint image>"
  }
}
```

If your capture device produces WSQ data, send it with `"format": "WSQ"` — the gateway automatically converts it to JPEG before forwarding to UCC. Send `"format": "JPEG"` if your data is already JPEG.

**Response:** includes `verification_reference` in the response body (valid 24 hours).

## Registration — both paths converge here

**Step 3: Register the SIM**

```http
POST /individual_registrations
X-API-Key: <vendor-key>
Content-Type: application/json

{
  "verification_reference": "vrf_...",
  "msisdn": "256712345678",
  "sim_registration_type": "NEW",
  "sim_type": "SIM",
  "sim_registration_datetime": "2026-11-04T09:18:00Z",
  "id_type": "NATIONAL ID",
  "id_number": "<NIN or refugee ID>",
  "nationality": "UGANDAN",
  "surname": "<surname>",
  "given_name": "<given names>",
  "gender": "MALE",
  "date_of_birth": "YYYY-MM-DD",
  "agent_code": "AGENT11",
  "agent_number": "256712345678",
  "sales_district": "KAMPALA",
  "gps_coordinates": "0.331476, 32.586047",
  "activation_date": "2026-11-04",
  "id_validity": "2030-12-31"
}
```

The `verification_reference` is bound to the verified identity and valid for 24 hours. It is consumed by one successful registration; a failed registration does not consume it.

## Endpoint summary

| Method | Endpoint | Use |
| --- | --- | --- |
| POST | `/ownership_check` | Ownership eligibility check |
| POST | `/identity_verification` | Identity + biometric verification (NATIONAL ID via NIRA, REFUGEE ID via UNHCR) |
| POST | `/individual_registrations` | Individual SIM registration |
| POST | `/corporate_registrations` | Corporate SIM registration |
| PUT | `/individual_registrations/{msisdn}` | Full individual-record replacement |
| PATCH | `/individual_registrations/{msisdn}` | Partial permitted amendment |
| POST | `/individual_registrations/{msisdn}/ownership_change` | Transfer ownership |
| POST | `/individual_registrations/{msisdn}/deregistration` | Deregister the SIM |
| POST | `/individual_registrations/batch` | Submit individual batch |
| GET | `/individual_registrations/batch/{job_id}` | Poll batch status |
| POST | `/corporate_registrations/batch` | Submit corporate batch |
| GET | `/corporate_registrations/batch/{job_id}` | Poll corporate batch status |
| GET | `/compliance_report` | Report scoped to your API key |
| GET | `/health` | Health check (no auth) |

Exact required fields, permitted values, and response schemas are defined by the Swagger UI/OpenAPI contract at `http://10.33.33.30:8001/docs`.

## What we keep internal (not shared with you)

The following are middleware operator secrets and are **never shared** with vendors:

- NIRA partner private key and certificate (JWS signing)
- NIRA encryption certificate (thumbprint + session key encryption)
- NIRA client ID, secret key, app ID
- NIRA MISP license key, partner ID, partner API key
- Client-side cryptography implementation (RSA-OAEP, AES-GCM, JWS RS256)
- UCC upstream URL and middleware's UCC API key

Your integration surface is limited to the endpoints above with your `X-API-Key`.

## Common responses

| HTTP status | Meaning |
| --- | --- |
| 200/201/202 | Request accepted; inspect response body for `verified` / `reason_code` |
| 401 `UNAUTHORIZED` | Missing or invalid `X-API-Key` |
| 403 `VERIFICATION_REFERENCE_INVALID` | Invalid/replayed/expired reference; verify again |
| 403 `LIMIT_EXCEEDED` | Subscriber has exceeded SIM ownership limit |
| 409 `DUPLICATE_REQUEST` | SIM already registered or idempotency key reused |
| 422 | Missing or invalid request field |
| 502 | UCC upstream unavailable |

## Go-live checklist

- Confirm your server can reach `10.33.33.30:8001`; you do not need direct access to UCC.
- Obtain one unique API key through a secure channel from the middleware operator.
- Use the v2.0.0 OpenAPI contract at `http://10.33.33.30:8001/openapi.json`.
- For NATIONAL ID: capture a fresh MOSIP SBI biometric block and send it within ~30 seconds of the auth call.
- Use HTTPS via a trusted reverse proxy before using this connection outside a controlled private network.
