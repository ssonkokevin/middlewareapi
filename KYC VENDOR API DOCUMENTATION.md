# KYC Vendor API Documentation

**Version:** 2.0.0
**Date:** November 2026
**Vendor-Facing Endpoint:** `http://10.33.33.30:8001`

---

## 1. Overview

This document is for vendors integrating with the UCC KYC Verification API through the KYC Gateway. Vendors connect to the gateway endpoint, which validates the vendor API key and routes requests to the appropriate local integration or UCC service.

> **Important:** Vendors must NOT connect directly to `192.168.5.18`. Only use `http://10.33.33.30:8001`.

---

## 2. Connection Details

| Item | Value |
| --- | --- |
| **Base URL** | `http://10.33.33.30:8001` |
| **Health Check** | `GET http://10.33.33.30:8001/health` |
| **Interactive Docs** | `http://10.33.33.30:8001/docs` |
| **OpenAPI Spec** | `http://10.33.33.30:8001/openapi.json` |
| **Authentication** | `X-API-Key: <assigned-vendor-key>` (required for all business endpoints) |
| **Content-Type** | `application/json` |

**Network Flow:**
```
Vendor App → http://10.33.33.30:8001 (Gateway) → https://192.168.5.18:443 (UCC)
```

---

## 3. Authentication

All KYC business operations require an API key in the `X-API-Key` header.

- Keys are issued by the gateway administrator via a secure channel (separately from this document)
- Each key identifies the calling MNO/vendor
- Missing or invalid keys will be rejected with `401 UNAUTHORIZED` without contacting UCC
- **Do not** share keys, commit them to source control, or include them in URLs

**Example Header:**
```http
X-API-Key: your-assigned-vendor-key
Content-Type: application/json
```

---

## 4. KYC Registration Flow

Follow this sequence for a complete individual SIM registration:

| Step | Endpoint | Purpose |
| --- | --- | --- |
| **1. Ownership Check** | `POST /ownership_check` | Verify SIM ownership eligibility before capturing biometrics. Returns ownership status and may include eligibility information. |
| **2. Identity Verification** | `POST /identity_verification` | Verify subscriber identity against the appropriate provider (NIRA/UNHCR etc.) using identity details and biometric data. Returns `verification_reference` if successful. **Treat `verified: false` as failure even if HTTP status is 200.** |
| **3. Registration** | `POST /individual_registrations` or `POST /corporate_registrations` | Register the SIM using verified identity details and the `verification_reference` from step 2. |

### National ID Verification (NIRA)

For a Ugandan National ID, capture the fingerprint using the supported MOSIP SBI
device, then call `POST /identity_verification` once. The gateway internally
obtains a NIRA token, fetches a fresh NIRA encryption certificate
for each authentication request, creates the signed AUTH request, and returns
the verification result. Vendors do not call the `/nira/token`,
`/nira/certificate`, or `/nira/auth` endpoints for this integrated workflow and
must not send NIRA partner credentials or tokens.

The gateway returns `X-Response-Time-Ms` on API responses. This is server-side
processing time in milliseconds; use curl's `time_total` to include network
latency in the measurement. The `verification_reference` is returned in the
JSON response body, not in an `X-Verification-Reference` response header.

The request must include:

- `id_type`: `NATIONAL ID`
- `id_number`, `first_name`, `last_name`, and `date_of_birth` (use the date
  representation NIRA expects, e.g. `11/06/1970`)
- `transaction_id`: the 10-digit transaction ID bound into the SBI capture
- `biometric.format`: `MOSIP_SBI_SIGNED`
- `biometric.blocks`: the complete signed blocks from the capture, passed
  through without editing

Send this request immediately after capture. The transaction ID must match the
ID inside the signed SBI block, and NIRA's capture freshness window applies.
Check both the HTTP status and `data.verified`; only use the returned
`data.verification_reference` for registration when verification succeeds.

Example request shape (replace the block with the exact captured block):

```json
{
  "id_type": "NATIONAL ID",
  "id_number": "CF123456789ABCDE",
  "first_name": "KEVIN",
  "last_name": "SSONKO",
  "date_of_birth": "11/06/1970",
  "transaction_id": "9181672570",
  "biometric": {
    "biometric_type": "FINGERPRINT",
    "format": "MOSIP_SBI_SIGNED",
    "blocks": [
      {
        "specVersion": "0.9.5",
        "data": "<complete device-signed data>",
        "hash": "<signed hash>",
        "sessionKey": "<signed session key>",
        "thumbprint": "<device certificate thumbprint>"
      }
    ]
  }
}
```

### Special Cases

- **Individual SIM Swap**: Call `POST /identity_verification` for fresh identity proof, then use its `verification_reference` in `PUT /individual_registrations/{msisdn}`. The reference is bound to the verified identity and may be reused within its 24-hour validity period.
- **Changed Identity Number**: A different `id_number` is an ownership transfer, not a normal full update. Use `POST /individual_registrations/{msisdn}/ownership_change` with the new owner's verification reference and required consent.
- **Corporate Registration**: Verify the organisation through `POST /identity_verification` and use the organisation's `verification_reference` with `POST /corporate_registrations`. The nominated representative's details are recorded for traceability but are not identity- or biometric-verified.
- **Company SIM Swap**: No dedicated corporate SIM-swap endpoint is documented. Do not use the individual `PUT` or `ownership_change` endpoint for a company line; confirm the supported operation and payload with UCC before implementation.
- **Batch Processing**: Include a unique `Idempotency-Key` header on each batch submission. Reusing a key returns `409 DUPLICATE_REQUEST`. Each record in the batch must have its own valid `verification_reference`.

---

## 5. API Endpoints Summary

### Ownership & Identity
| Method | Endpoint | Description |
| --- | --- | --- |
| `POST` | `/ownership_check` | Check SIM ownership eligibility for an individual or corporate subscriber. |
| `POST` | `/identity_verification` | Verify subscriber identity and biometrics. Returns verification decision and `verification_reference`. |

### Individual Registrations
| Method | Endpoint | Description |
| --- | --- | --- |
| `POST` | `/individual_registrations` | Register a new individual SIM. Requires valid `verification_reference` from identity verification. |
| `PUT` | `/individual_registrations/{msisdn}` | Full replacement/update of an existing individual registration (e.g. SIM swap). Requires new `verification_reference`. |
| `PATCH` | `/individual_registrations/{msisdn}` | Partial amendment of permitted fields on an existing registration. |
| `POST` | `/individual_registrations/{msisdn}/ownership_change` | Transfer SIM ownership to a new subscriber. |
| `POST` | `/individual_registrations/{msisdn}/deregistration` | Deregister/end a SIM registration. |

### Corporate Registrations
| Method | Endpoint | Description |
| --- | --- | --- |
| `POST` | `/corporate_registrations` | Register a new corporate SIM. Requires a valid `verification_reference` for the organisation; representative details are recorded but not verified. |

### Batch Operations
| Method | Endpoint | Description |
| --- | --- | --- |
| `POST` | `/individual_registrations/batch` | Submit multiple individual registrations in one request. Include `Idempotency-Key` header. |
| `GET` | `/individual_registrations/batch/{job_id}` | Poll status and results of an individual batch job. |
| `POST` | `/corporate_registrations/batch` | Submit multiple corporate registrations in one request. Include `Idempotency-Key` header. |
| `GET` | `/corporate_registrations/batch/{job_id}` | Poll status and results of a corporate batch job. |

### Reporting
| Method | Endpoint | Description |
| --- | --- | --- |
| `GET` | `/compliance_report` | Retrieve compliance report scoped to the calling vendor's API key. |

### System
| Method | Endpoint | Description |
| --- | --- | --- |
| `GET` | `/health` | Health check (no authentication required). |
| `GET` | `/docs` | Interactive Swagger UI documentation. |

---

## 6. Common HTTP Responses

| HTTP Status | Error Code | Meaning |
| --- | --- | --- |
| `200 OK` / `201 Created` / `202 Accepted` | - | Request successful. Always inspect the response body for business logic results. |
| `401 Unauthorized` | `UNAUTHORIZED` | Missing or invalid `X-API-Key`. |
| `403 Forbidden` | `VERIFICATION_REFERENCE_INVALID` | Verification reference is not recognised. Perform identity verification again if the reference is invalid. |
| `409 Conflict` | `DUPLICATE_REQUEST` | Idempotency key already used for a batch submission. |
| `422 Unprocessable Entity` | `MISSING_FIELD` / `INVALID_FIELD` | Missing required field or invalid field value/format. |
| `502 Bad Gateway` | `UCC_UPSTREAM_UNAVAILABLE` | Gateway could not reach UCC upstream service. |
| `500 Internal Server Error` | `SYSTEM_ERROR` | Unexpected system error. |

---

## 7. Important Notes

- **National ID Routing:** `POST /identity_verification` for `NATIONAL ID` is handled by the gateway's internal NIRA integration. Other forwarded operations use the gateway-to-UCC credentials; vendors use only their assigned `X-API-Key`.
- **Local Validation:** The gateway validates your vendor API key locally before processing or forwarding the request.
- **v2.0.0 API:** This uses `individual_registrations`/`corporate_registrations` (not the old v1.x `sim_registrations`). Biometric verification is separate via `identity_verification`.
- **Idempotency:** Use `Idempotency-Key` header for batch submissions to prevent duplicates.
- **Verification References:** Are bound to the `id_type` and `id_number` (or organisation registration identity) verified in step 2. They are valid for 24 hours and reusable within that period; use a new verification for full individual updates such as SIM swaps.
- **Corporate SIM Swap:** The documented API supports corporate registration but does not document a corporate update or swap endpoint. A `SIM SWAP` value in a registration record does not establish that a corporate swap operation is supported. Confirm the endpoint, eligibility rules, required reference, and payload with UCC; do not substitute an individual endpoint.

---

## 8. Detailed API Specification

For complete details including all request/response schemas, field validations, enums, and examples, refer to the separate document:

**`KYC API v2.0.0.html`**

This HTML document contains the full OpenAPI specification with all endpoints, models, and detailed field descriptions. You can also access it interactively at `http://10.33.33.30:8001/docs` once connected.
