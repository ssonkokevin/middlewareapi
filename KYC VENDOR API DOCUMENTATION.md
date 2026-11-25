# KYC Vendor API Documentation

**Version:** 2.0.0
**Date:** November 2026
**Vendor-Facing Endpoint:** `http://10.33.33.30:8001`

---

## 1. Overview

This guide explains how to integrate with our KYC Gateway for SIM registration. UCC, as the regulator, requires ownership and identity checks as applicable before registration. Vendors use the gateway for these checks and to submit registration records.

> **Important:** Use only our vendor-facing gateway at `http://10.33.33.30:8001`.

---

## 2. Connection Details

| Item | Value |
| --- | --- |
| **Base URL** | `http://10.33.33.30:8001` |
| **Health Check** | `GET http://10.33.33.30:8001/health` |
| **Interactive Docs** | `http://10.33.33.30:8001/docs` |
| **ReDoc** | `http://10.33.33.30:8001/redoc` |
| **OpenAPI Spec** | `http://10.33.33.30:8001/openapi.json` |
| **Authentication** | `X-API-Key: <assigned-vendor-key>` (required for all business endpoints) |
| **Content-Type** | `application/json` |

**Network Flow:**
```
Vendor App → http://10.33.33.30:8001 (KYC Gateway)
```

---

## 3. Authentication

All KYC business operations require an API key in the `X-API-Key` header.

- Keys are issued by the gateway administrator via a secure channel (separately from this document)
- Each key identifies the calling MNO/vendor
- Missing or invalid keys will be rejected with `401 UNAUTHORIZED`
- **Do not** share keys, commit them to source control, or include them in URLs

**Example Header:**
```http
X-API-Key: your-assigned-vendor-key
Content-Type: application/json
```

---

## 4. KYC Registration Flow

Follow this sequence for a SIM registration:

| Step | Endpoint | Purpose |
| --- | --- | --- |
| **1. Ownership Check** | `POST /ownership_check` | Verify SIM ownership eligibility before capturing biometrics. Returns ownership status and may include eligibility information. |
| **2. Identity Verification** | `POST /identity_verification` | Verify an individual using the appropriate provider and biometric data, or request organisation verification without biometrics. Inspect `data.verified`, `data.reason_code`, and `data.verification_reference`; provider availability differs. |
| **3. Registration** | `POST /individual_registrations` or `POST /corporate_registrations` | Submit the registration with its matching `verification_reference`. For high-volume corporate registration, submit records as a batch and poll the returned job. |

For corporate registrations, follow the full sequence in **Corporate
Registration Flow** below: ownership check → identity verification →
registration (single or batch). For a batch, poll the returned job for results.
Corporate identity verification is currently unavailable; see the status note
in that flow.

SIM swaps are handled internally for our records. The regulator does not
support SIM-swap submissions; do not treat an internal update as a regulator
filing.

### National ID Verification

For a Ugandan National ID, capture the fingerprint using a supported MOSIP SBI
device, then call `POST /identity_verification` with the signed capture. The
gateway handles the verification request; vendors must not send partner
credentials or call provider-specific authentication endpoints.

The gateway returns `X-Response-Time-Ms` on API responses. This is server-side
processing time in milliseconds; use curl's `time_total` to include network
latency in the measurement. The `verification_reference` is returned in the
JSON response body, not in an `X-Verification-Reference` response header.

The request must include:

- `id_type`: `NATIONAL ID`
- `id_number`, `first_name`, `last_name`, and `date_of_birth` (for example,
  `11/06/1970`)
- `transaction_id`: the 10-digit transaction ID bound into the SBI capture
- `biometric.format`: `MOSIP_SBI_SIGNED`
- `biometric.blocks`: the complete signed blocks from the capture, passed
  through without editing

Send this request immediately after capture. The transaction ID must match the
ID inside the signed SBI block, and the capture freshness window applies.
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

### Refugee ID Verification (UNHCR)

For Refugee ID verification, send a **JPEG fingerprint image** as
Base64-encoded image data. Do not send an ISO image or iris record. Use
`biometric_type: "FINGERPRINT"`.

If the capture device supplies JPEG, send it with `format: "JPEG"`. If it
supplies WSQ, send the Base64 WSQ data with `format: "WSQ"`; the gateway
conversion helper converts WSQ data to Base64 JPEG. WSQ is the only non-JPEG
format converted by that helper; do not assume other formats are converted.

```json
{
  "id_type": "REFUGEE ID",
  "id_number": "UGA-2024-0098765",
  "first_name": "GRACE",
  "last_name": "AYO",
  "biometric": {
    "biometric_type": "FINGERPRINT",
    "format": "WSQ",
    "data": "<base64-encoded WSQ fingerprint image>"
  }
}
```

**Current integration status:** although WSQ-to-JPEG conversion is present,
the gateway currently handles Refugee ID verification with a simulated
provider response; it does not make a live UNHCR request. Do not interpret a
successful response as confirmation that a live UNHCR lookup occurred. The
live provider connection must be enabled before this can be represented as
production Refugee verification.

### Corporate Registration Flow

Complete the following steps for each organisation. The organisation is the
identity being checked; the representative's details are included in the
registration record. This flow does not verify the representative or require
their biometrics.

1. **Check ownership eligibility.** Use the organisation's registration number
   and proceed only when `data.allowed` is `true`.

```http
POST /ownership_check
```

```json
{
  "subscriber_type": "corporate",
  "id_type": "COI",
  "registration_number": "80020012345678"
}
```

2. **Verify the organisation.** `id_number` must contain the same
   organisation registration number used in the ownership check and later
      registration. Use `COI` for registered companies/businesses; use
      `REGISTRY_PENDING` for organisation types whose registry has not been
      assigned.

```http
POST /identity_verification
```

```json
{
  "id_type": "COI",
  "id_number": "80020012345678"
}
```

**Current status:** a corporate identity verification provider is not
connected to the gateway. The current response is therefore
`verified: false` with `reason_code: "VERIFICATION_UNAVAILABLE"`. A
`verification_reference` may still be returned for the registration workflow,
but it does **not** mean the organisation's identity was confirmed. Follow
your onboarding instructions before proceeding with the current workflow.
Example response:

```json
{
  "status": "success",
  "data": {
    "verified": false,
    "reason_code": "VERIFICATION_UNAVAILABLE",
    "verification_reference": "<organisation verification_reference>",
    "verified_at": null,
    "expires_at": "<reference expiry timestamp>",
    "matched_attributes": null
  }
}
```

3. **Submit registration.** For a single SIM, submit the
   organisation-bound reference and full corporate registration record:

```http
POST /corporate_registrations
```

```json
{
  "verification_reference": "<organisation verification_reference>",
  "id_type": "COI",
  "msisdn": "256712345679",
  "sim_type": "SIM",
  "sim_registration_type": "NEW",
  "sim_registration_datetime": "2026-11-06T08:30:00Z",
  "organisation_type": "COMPANY",
  "registration_number": "80020012345678",
  "registration_validity": "2028-12-31",
  "organisation_name": "ABC LIMITED",
  "registered_address": "KAMPALA ROAD",
  "tax_identification_number": "TIN123456",
  "contact_number": "256712345679",
  "representative": {
    "id_type": "NATIONAL ID",
    "id_number": "CF123456789ABCDE",
    "validity": "2030-12-31",
    "nationality": "UGANDAN",
    "surname": "KATO",
    "given_name": "JOHN",
    "gender": "MALE",
    "date_of_birth": "1983-05-12"
  },
  "agent_code": "AGT001",
  "agent_number": "256712345678",
  "sales_district": "KAMPALA",
  "gps_coordinates": "32.5825,0.3476",
  "activation_date": "2026-11-06"
}
```

The `verification_reference` must match both `id_type` and
`registration_number`, and must be within its 24-hour validity period. The
representative fields are required for the registration record, but are only
recorded for traceability. The API does not verify the representative or
require their biometric in this corporate flow.

For high-volume onboarding, use the batch path as part of the same flow:

4. **Submit the corporate batch.** Obtain a verification reference for each
   organisation, then include a complete registration record and its matching
   reference in each item sent to `POST /corporate_registrations/batch`. Send a
   unique `Idempotency-Key` header.
5. **Track processing.** Read the returned `job_id` and poll
   `GET /corporate_registrations/batch/{job_id}` until the job is complete.
   Review each record's result; a completed batch can contain failed records.

### Special Cases

- **Changed Identity Number**: A different `id_number` is an ownership transfer, not a normal full update. Use `POST /individual_registrations/{msisdn}/ownership_change` with the new owner's verification reference and required consent.
- **Corporate Registration**: Follow the corporate flow above. Organisation verification is currently unavailable; an issued reference is workflow-bound and is not evidence that the organisation has been verified.
- **Batch Processing**: Include a unique `Idempotency-Key` header on each batch submission. Reusing a key returns `409 DUPLICATE_REQUEST`. Each record in the batch must have its own valid `verification_reference`.

---

## 5. Endpoint Requests and Responses

All business endpoint requests below require `X-API-Key` and use the public
gateway base URL from Section 2. Send `Content-Type: application/json` with
JSON request bodies. Examples use placeholder verification references and
identity data; replace them with the values from the actual workflow.

For `GET` endpoints, there is no request body. Their request examples show the
path and required headers, followed by the response body or representation.

### 5.1 Check ownership — `POST /ownership_check`

Individual request:

```json
{
  "subscriber_type": "individual",
  "id_type": "NATIONAL ID",
  "id_number": "CF123456789ABCDE"
}
```

Corporate requests use `"subscriber_type": "corporate"`, the applicable
organisation `id_type`, and `registration_number` instead of `id_number`; see
the corporate flow in Section 4.

Example eligible response (`200 OK`):

```json
{
  "status": "success",
  "data": {
    "allowed": true,
    "reason_code": "LIMIT_NOT_EXCEEDED",
    "message": "Subscriber can register SIM",
    "current_count": 2,
    "limit": 5
  }
}
```

An ineligible subscriber is also returned as `200 OK`, with `allowed: false`
and `reason_code: "LIMIT_EXCEEDED"`. Do not continue to registration when
`allowed` is false.

### 5.2 Verify identity — `POST /identity_verification`

Send the provider-specific body shown in Section 4: the complete signed MOSIP
block for a National ID, JPEG or WSQ fingerprint data for a Refugee ID, or
organisation identity data without a biometric for corporate entities.

Example National ID success response (`200 OK`; `X-Response-Time-Ms` is also
returned):

```json
{
  "status": "success",
  "data": {
    "verified": true,
    "reason_code": "IDENTITY_ACCEPTED",
    "message": "Identity verified via NIRA",
    "provider": "NIRA",
    "provider_status": "LIVE",
    "verification_reference": "vrf_01JBK2QX7M4T8ZC3",
    "verified_at": "2026-11-06T08:30:00Z",
    "expires_at": "2026-11-07T08:30:00Z",
    "matched_attributes": null
  }
}
```

Example Refugee response shape (`200 OK`; the current provider path is
simulated, as noted in Section 4):

```json
{
  "status": "success",
  "data": {
    "verified": true,
    "reason_code": "IDENTITY_ACCEPTED",
    "message": "Identity verified",
    "provider": "UNHCR",
    "provider_status": null,
    "verification_reference": "vrf_01JBK3RM9P2W6YD1",
    "verified_at": "2026-11-06T08:30:00Z",
    "expires_at": "2026-11-07T08:30:00Z",
    "matched_attributes": {
      "date_of_birth": "MATCH",
      "sex": "F"
    }
  }
}
```

### 5.3 Register an individual — `POST /individual_registrations`

```json
{
  "verification_reference": "vrf_01JBK2QX7M4T8ZC3",
  "msisdn": "256712345678",
  "sim_registration_type": "NEW",
  "sim_type": "SIM",
  "sim_registration_datetime": "2026-11-06T08:30:00Z",
  "id_type": "NATIONAL ID",
  "id_number": "CF123456789ABCDE",
  "nationality": "UGANDAN",
  "surname": "KATO",
  "given_name": "JOHN",
  "gender": "MALE",
  "date_of_birth": "1995-05-12",
  "id_validity": "2030-12-31",
  "agent_code": "AGT001",
  "agent_number": "256712345678",
  "sales_district": "KAMPALA",
  "gps_coordinates": "32.5825,0.3476",
  "activation_date": "2026-11-06"
}
```

Do not include biometric data. Example response (`200 OK`):

```json
{
  "status": "accepted",
  "reason_code": "REGISTRATION_ACCEPTED",
  "message": "SIM registration stored"
}
```

### 5.4 Register a corporate entity — `POST /corporate_registrations`

Use the complete request body shown in Section 4, including the organisation's
`verification_reference` and `representative` record. The reference must match
the organisation `id_type` and `registration_number`.

Example response (`200 OK`):

```json
{
  "status": "accepted",
  "reason_code": "REGISTRATION_ACCEPTED",
  "message": "Corporate SIM registration recorded"
}
```

### 5.5 Fully update an individual registration — `PUT /individual_registrations/{msisdn}`

SIM swaps are handled internally for our records because the regulator does
not support SIM-swap submissions. This endpoint updates the record in our
system; it is not a regulator filing. The path MSISDN must match the body
MSISDN. Submit a fresh verification reference and the full registration
record; do not send a partial body.

```json
{
  "verification_reference": "vrf_01JBK6VQ2S5Z9BG4",
  "msisdn": "256712345678",
  "sim_registration_type": "SIM SWAP",
  "sim_type": "SIM",
  "sim_registration_datetime": "2026-11-07T08:30:00Z",
  "id_type": "NATIONAL ID",
  "id_number": "CF123456789ABCDE",
  "nationality": "UGANDAN",
  "surname": "KATO",
  "given_name": "JOHN PAUL",
  "gender": "MALE",
  "date_of_birth": "1994-05-12",
  "id_validity": "2030-12-31",
  "agent_code": "AGT001",
  "agent_number": "256712345678",
  "sales_district": "KAMPALA",
  "gps_coordinates": "32.5825,0.3476",
  "activation_date": "2026-11-06"
}
```

Example response (`200 OK`):

```json
{
  "status": "updated",
  "reason_code": "REGISTRATION_ACCEPTED",
  "message": "Subscriber information successfully updated"
}
```

### 5.6 Amend permitted subscriber details — `PATCH /individual_registrations/{msisdn}`

No identity verification is required. Only amendable fields may be sent; the
identity number and MSISDN cannot be changed here.

```json
{
  "change_reason": "LEGAL_NAME_CHANGE",
  "evidence_reference": "MC/2026/004412",
  "changes": {
    "surname": "MUKASA"
  }
}
```

Example response (`200 OK`):

```json
{
  "status": "amended",
  "reason_code": "REGISTRATION_AMENDED",
  "message": "Subscriber details amended",
  "previous_values": {
    "surname": "KATO"
  }
}
```

### 5.7 Transfer individual SIM ownership — `POST /individual_registrations/{msisdn}/ownership_change`

The verification reference must belong to the new owner. No biometric from the
previous owner is required.

```json
{
  "verification_reference": "vrf_01JBK7WR3T6A0CH5",
  "effective_date": "2026-11-07",
  "new_owner": {
    "id_type": "NATIONAL ID",
    "id_number": "CM20000000001",
    "nationality": "UGANDAN",
    "surname": "OKELLO",
    "given_name": "PETER",
    "gender": "MALE",
    "date_of_birth": "1990-03-04",
    "id_validity": "2031-06-30"
  },
  "previous_owner_consent": {
    "method": "SUBSCRIBER_CONFIRMED",
    "reference": "USSD-8837721",
    "obtained_at": "2026-11-07T08:20:00Z"
  },
  "agent_code": "AGT001",
  "agent_number": "256712345678"
}
```

Example response (`200 OK`):

```json
{
  "status": "transferred",
  "reason_code": "OWNERSHIP_CHANGED",
  "message": "SIM ownership transferred",
  "previous_owner": {
    "id_type": "NATIONAL ID",
    "id_number": "CF123456789ABCDE"
  },
  "effective_date": "2026-11-07"
}
```

### 5.8 Deregister an individual SIM — `POST /individual_registrations/{msisdn}/deregistration`

```json
{
  "reason_code": "SUBSCRIBER_REQUEST",
  "effective_date": "2026-11-07",
  "agent_code": "AGT001",
  "agent_number": "256712345678",
  "notes": "Subscriber requested deregistration"
}
```

Example response (`200 OK`):

```json
{
  "status": "deregistered",
  "reason_code": "REGISTRATION_DEREGISTERED",
  "message": "SIM registration ended",
  "effective_date": "2026-11-07",
  "released_count": 1
}
```

### 5.9 Submit an individual batch — `POST /individual_registrations/batch`

Include a unique `Idempotency-Key` header. Each record must be a complete
individual registration with its own matching verification reference and no
biometric data.

```json
{
  "records": [
    {
      "verification_reference": "vrf_01JBK2QX7M4T8ZC3",
      "msisdn": "256712345678",
      "sim_registration_type": "NEW",
      "sim_type": "SIM",
      "sim_registration_datetime": "2026-11-06T08:30:00Z",
      "id_type": "NATIONAL ID",
      "id_number": "CF123456789ABCDE",
      "nationality": "UGANDAN",
      "surname": "KATO",
      "given_name": "JOHN",
      "gender": "MALE",
      "date_of_birth": "1995-05-12",
      "agent_code": "AGT001",
      "agent_number": "256712345678",
      "sales_district": "KAMPALA",
      "gps_coordinates": "32.5825,0.3476",
      "activation_date": "2026-11-06"
    }
  ]
}
```

Example response (`202 Accepted`):

```json
{
  "status": "accepted",
  "job_id": "batch_123456",
  "message": "Batch accepted for processing"
}
```

### 5.10 Get individual batch status — `GET /individual_registrations/batch/{job_id}`

Request body: **none**. Supply the `job_id` returned from the batch submission
in the URL path.

```http
GET /individual_registrations/batch/batch_123456
X-API-Key: <assigned-vendor-key>
```

Example response (`200 OK`):

```json
{
  "job_id": "batch_123456",
  "status": "completed",
  "total_records": 1,
  "processed_records": 1,
  "successful_records": 1,
  "failed_records": 0,
  "results": [
    {
      "msisdn": "256712345678",
      "status": "accepted",
      "reason_code": "REGISTRATION_ACCEPTED",
      "verification_reference": "vrf_01JBK2QX7M4T8ZC3",
      "error_message": null
    }
  ]
}
```

### 5.11 Submit a corporate batch — `POST /corporate_registrations/batch`

Include a unique `Idempotency-Key` header. Each `records` item is a complete
corporate registration body as shown in Section 4, with a matching
organisation-bound verification reference.

```json
{
  "records": [
    {
      "verification_reference": "vrf_01JBK8XS4U7B1DJ6",
      "id_type": "COI",
      "msisdn": "256712345679",
      "sim_type": "SIM",
      "sim_registration_type": "NEW",
      "sim_registration_datetime": "2026-11-06T08:30:00Z",
      "organisation_type": "COMPANY",
      "registration_number": "80020012345678",
      "organisation_name": "ABC LIMITED",
      "registered_address": "KAMPALA ROAD",
      "tax_identification_number": "TIN123456",
      "contact_number": "256712345679",
      "representative": {
        "id_type": "NATIONAL ID",
        "id_number": "CF123456789ABCDE",
        "nationality": "UGANDAN",
        "surname": "KATO",
        "given_name": "JOHN",
        "gender": "MALE",
        "date_of_birth": "1983-05-12"
      },
      "agent_code": "AGT001",
      "agent_number": "256712345678",
      "sales_district": "KAMPALA",
      "gps_coordinates": "32.5825,0.3476",
      "activation_date": "2026-11-06"
    }
  ]
}
```

Example response (`202 Accepted`):

```json
{
  "status": "accepted",
  "job_id": "cbatch_123456",
  "message": "Batch accepted for processing"
}
```

### 5.12 Get corporate batch status — `GET /corporate_registrations/batch/{job_id}`

Request body: **none**. Supply the corporate `job_id` in the URL path.

```http
GET /corporate_registrations/batch/cbatch_123456
X-API-Key: <assigned-vendor-key>
```

Example response (`200 OK`):

```json
{
  "job_id": "cbatch_123456",
  "status": "completed",
  "total_records": 1,
  "processed_records": 1,
  "successful_records": 1,
  "failed_records": 0,
  "results": [
    {
      "msisdn": "256712345679",
      "status": "accepted",
      "reason_code": "REGISTRATION_ACCEPTED",
      "verification_reference": "vrf_01JBK8XS4U7B1DJ6",
      "error_message": null
    }
  ]
}
```

### 5.13 Get compliance report — `GET /compliance_report`

Request body: **none**. The report is scoped to the vendor API key.

```http
GET /compliance_report
X-API-Key: <assigned-vendor-key>
```

Example response (`200 OK`):

```json
{
  "status": "success",
  "data": {
    "valid_records": 12000,
    "invalid_records": 340,
    "missing_information": 87
  }
}
```

### 5.14 Health check — `GET /health`

Request body: **none**. This endpoint does not require an API key.

```http
GET /health
```

Example response (`200 OK`):

```json
{
  "status": "ok",
  "service": "KYC Verification API",
  "timestamp": "2026-11-06T11:30:00.000+03:00"
}
```

### 5.15 Interactive API documentation — `GET /docs`

Request body: **none**. This endpoint does not require an API key.

```http
GET /docs
```

Response: `200 OK`, `Content-Type: text/html`; an interactive Swagger UI page
for the API (not a JSON response).

### 5.16 OpenAPI document — `GET /openapi.json`

Request body: **none**. This endpoint does not require an API key.

```http
GET /openapi.json
```

Example response (`200 OK`, excerpt):

```json
{
  "openapi": "3.1.0",
  "info": {
    "title": "KYC Verification API",
    "version": "2.0.0"
  },
  "paths": {
    "/ownership_check": {},
    "/identity_verification": {}
  }
}
```

The live response contains the full path and schema definitions; the excerpt
above is illustrative.

### 5.17 ReDoc API documentation — `GET /redoc`

Request body: **none**. This endpoint does not require an API key.

```http
GET /redoc
```

Response: `200 OK`, `Content-Type: text/html`; an interactive ReDoc page for
the API (not a JSON response).

### 5.18 Optional batch-completion callback (vendor-hosted)

If a callback URL is registered for the vendor, the gateway sends a
`POST` request to that vendor-hosted URL when a batch finishes. No callback
URL is supplied in the batch request. Callback delivery is optional and does
not replace polling the batch status endpoint.

The vendor endpoint must validate `X-KYC-Signature` as an HMAC-SHA256 signature
over the **raw** request body, using the webhook secret issued for this
integration. Verify the signature before parsing the JSON body.

Example callback request body:

```json
{
  "event": "batch.completed",
  "job_id": "batch_123456",
  "status": "completed",
  "total_records": 100,
  "processed_records": 100,
  "successful_records": 95,
  "failed_records": 5,
  "timestamp": "2026-11-06T11:30:00Z"
}
```

The request includes `Content-Type: application/json` and
`X-KYC-Signature: sha256=<hex-digest>`. Return any `2xx` response (for example
`204 No Content`) to acknowledge it. Failed deliveries may be retried, so
handle duplicate events safely.

The standalone `/nira/token`, `/nira/certificate`, and `/nira/auth` proxy
operations are not part of the vendor flow documented here. For National ID
verification, vendors call only `POST /identity_verification`.

---

## 6. Common HTTP Responses

| HTTP Status | Error Code | Meaning |
| --- | --- | --- |
| `200 OK` / `201 Created` / `202 Accepted` | - | Request successful. Always inspect the response body for business logic results. |
| `401 Unauthorized` | `UNAUTHORIZED` | Missing or invalid `X-API-Key`. |
| `403 Forbidden` | `VERIFICATION_REQUIRED`, `VERIFICATION_REFERENCE_INVALID`, `VERIFICATION_REFERENCE_EXPIRED`, `VERIFICATION_REFERENCE_MISMATCH`, `LIMIT_EXCEEDED`, `CONSENT_REQUIRED` | Verification reference, policy limit, or required consent prevented the operation. |
| `404 Not Found` | `NOT_FOUND` | Registration or batch job was not found for the vendor. |
| `409 Conflict` | `DUPLICATE_REQUEST`, `REGISTRATION_NOT_ACTIVE` | Duplicate submission/registration or invalid registration state. |
| `422 Unprocessable Entity` | `MISSING_FIELD` / `INVALID_FIELD` | Missing required field or invalid field value/format. |
| `502 Bad Gateway` | `UCC_UPSTREAM_UNAVAILABLE` or a provider-specific error such as `NIRA_AUTH_ERROR` | The gateway or a verification provider could not complete the request. |
| `503 Service Unavailable` | `NIRA_NOT_CONFIGURED` / `UCC_FORWARDING_DISABLED` | A required upstream integration is not configured or enabled. |
| `500 Internal Server Error` | `SYSTEM_ERROR` | Unexpected system error. |

Error response example:

```json
{
  "status": "error",
  "error_code": "VERIFICATION_REFERENCE_EXPIRED",
  "message": "Verification reference expired; re-verify the subscriber"
}
```

Identity verification can return `200 OK` with `data.verified: false`. This is a
business result, not a successful identity match. Follow the provider-status
notes in Section 4 before relying on any verification result.

---

## 7. Important Notes

- **Identity provider status:** National ID verification is handled by the gateway. Refugee ID verification currently uses a simulated provider response and is not connected to a live provider; do not interpret a successful response as a live external verification.
- **Local Validation:** The gateway validates your vendor API key locally before processing or forwarding the request.
- **Idempotency:** Use `Idempotency-Key` header for batch submissions to prevent duplicates.
- **Verification References:** Are bound to the `id_type` and `id_number` (or organisation registration identity) verified in step 2. They are valid for 24 hours and reusable within that period.

---

## 8. Detailed API Specification

For complete details including all request/response schemas, field validations, enums, and examples, refer to the separate document:

**`KYC API v2.0.0.html`**

This HTML document contains the full OpenAPI specification with all endpoints, models, and detailed field descriptions. You can also access it interactively at `http://10.33.33.30:8001/docs` once connected.
