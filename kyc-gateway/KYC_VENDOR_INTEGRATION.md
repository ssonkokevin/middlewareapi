# KYC Verification API — Vendor Integration Documentation

**Version:** 2.0.0  
**Date:** November 2026  
**Vendor-Facing Base URL:** `http://10.33.33.30:8001`  
**Authentication:** `X-API-Key` header (vendor-assigned key)

---

## 1. Overview

The KYC Verification API enables Mobile Network Operators (MNOs) and vendors to submit SIM registration information for validation and compliance. The gateway acts as a secure reverse proxy between your application and UCC:

- You connect only to `http://10.33.33.30:8001`
- The gateway validates your API key locally
- The gateway injects all provider credentials (NIRA partner keys, certificates, signing logic) internally
- Requests are forwarded to UCC; responses are returned to you unchanged

> **Important:** You must NOT connect directly to `192.168.5.18`. Only use `http://10.33.33.30:8001`. The UCC upstream address is internal.

### Network Flow

```
Vendor Application → http://10.33.33.30:8001 (KYC Gateway) → UCC (https://192.168.5.18:443)
```

---

## 2. Authentication

Every business endpoint requires an API key supplied in the `X-API-Key` request header. A missing or unrecognised key returns HTTP 401 with `error_code: UNAUTHORIZED`. The key identifies your MNO/vendor and is scoped to your data.

### Request Header

```http
X-API-Key: <your-assigned-vendor-key>
Content-Type: application/json
```

- Keys are issued by the gateway administrator via a separate secure channel
- Do not share keys, commit them to source control, or include them in URLs
- `GET /health`, `/docs`, `/redoc`, and `/openapi.json` do not require authentication

---

## 3. Identity Providers and Biometric Formats

The `id_type` field selects the authority that verifies the subscriber. Each provider requires a specific biometric format:

| ID Type | Provider | Status | Biometric Format | Freshness Window |
|---|---|---|---|---|
| `NATIONAL ID` | NIRA | Live | `MOSIP_SBI_SIGNED` (device-signed block) | ~30 seconds |
| `REFUGEE ID` | UNHCR | Live | `WSQ` or `JPEG` (fingerprint image) | Not time-critical |
| `PASSPORT` | NCIC | Planned | Not applicable | N/A |
| `COI` | URSB | Planned | None (organisation has no biometric) | N/A |
| `REGISTRY_PENDING` | Undecided | Planned | None | N/A |

### NATIONAL ID — NIRA (MOSIP_SBI_SIGNED)

NIRA does not accept a bare template. It requires the block produced and signed by a MOSIP-certified SBI capture device. Submit that block exactly as the device produced it, inside `biometric.blocks`. UCC relays it to NIRA unmodified — it does not parse, validate, or reshape it. Altering the block after capture will fail signature verification at NIRA.

Two constraints:
1. The signed block must reach NIRA within about **30 seconds** of capture — capture immediately before calling `/identity_verification`
2. The block's signed `transactionId` must equal the `transaction_id` sent in the request

### REFUGEE ID — UNHCR

Send a fingerprint image record in `biometric.data`, Base64 encoded. Accepted formats: `WSQ`, `JPEG`, `ISO_19794_4`, `ISO_19794_6`. If you send `WSQ`, the gateway automatically converts it to JPEG before forwarding to UCC — no client-side change is required.

### Important Biometric Handling Rules

- Biometric data is processed transiently and is **never persisted** by this API
- Biometric data appears **only** on `POST /identity_verification` — never on a registration endpoint
- Application logs must never record biometric data
- Fingerprint is the only modality currently submitted; IRIS is reserved in the schema

---

## 4. Two-Step Registration Flow

Registration is a two-step operation: verification first, registration second.

```
STEP 1: POST /ownership_check          → ownership eligibility decision
STEP 2: POST /identity_verification    → identity + biometric verification, returns verification_reference
STEP 3: POST /individual_registrations → register SIM using verification_reference
```

### `verification_reference` Rules

- Bound to the `id_type` + `id_number` verified in step 2; presenting it with a different identity returns `VERIFICATION_REFERENCE_MISMATCH`
- Valid for **24 hours**; after that, `VERIFICATION_REFERENCE_EXPIRED`
- Reusable within its lifetime — a failed SIM provisioning does not force the subscriber to present a finger again. Every use is recorded
- Required by every registration endpoint, including PUT updates and every record inside a batch

---

## 5. Endpoint Specifications

### 5.1 POST /ownership_check

Checks whether a subscriber is eligible to register a new SIM card. Call this **before** capturing a biometric.

#### Request

| Field | Type | Required | Description |
|---|---|---|---|
| `subscriber_type` | string | Yes | `"individual"` or `"corporate"` |
| `id_type` | string | Yes (individual) | `"NATIONAL ID"`, `"REFUGEE ID"`, `"PASSPORT"`, `"COI"`, `"REGISTRY_PENDING"` |
| `id_number` | string | Yes (individual) | National ID number or refugee ID number |
| `registration_number` | string | Yes (corporate) | Company/business registration number |

#### Request Example — Individual (National ID)

```json
{
  "subscriber_type": "individual",
  "id_type": "NATIONAL ID",
  "id_number": "CF123456789ABCDE"
}
```

#### Request Example — Individual (Refugee ID)

```json
{
  "subscriber_type": "individual",
  "id_type": "REFUGEE ID",
  "id_number": "WA9-00115526"
}
```

#### Request Example — Corporate

```json
{
  "subscriber_type": "corporate",
  "id_type": "COI",
  "registration_number": "80020001234"
}
```

#### Response — Eligible

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

#### Response — Not Eligible

```json
{
  "status": "success",
  "data": {
    "allowed": false,
    "reason_code": "LIMIT_EXCEEDED",
    "message": "Subscriber has exceeded SIM ownership limit",
    "current_count": 5,
    "limit": 5
  }
}
```

---

### 5.2 POST /identity_verification

Verifies a subscriber against the relevant identity registry (NIRA, UNHCR, URSB, NCIC) and returns a `verification_reference` for use at registration.

**Important:** A failure to match is **not** an HTTP error. It is HTTP 200 with `verified: false` and `reason_code: IDENTITY_REJECTED`. Branch on `data.verified` and `data.reason_code`, never on the HTTP status alone.

Every response includes `X-Response-Time-Ms`, the gateway's server-side
processing duration in milliseconds. Use curl's `time_total` separately to
measure end-to-end latency including the network.

#### Request — NATIONAL ID (NIRA)

The middleware executes the full three-step NIRA flow internally (token → certificate → signed auth). You supply only identity and biometric blocks — no NIRA credentials, certificates, or cryptography are required from you.

| Field | Type | Required | Description |
|---|---|---|---|
| `id_type` | string | Yes | `"NATIONAL ID"` |
| `id_number` | string | Yes | National ID number (e.g., `CM702356039748`) |
| `first_name` | string | No | Given names (e.g., `KEVIN`) |
| `last_name` | string | No | Surname (e.g., `SSONKO`) |
| `date_of_birth` | string | Yes | Date of birth in `YYYY-MM-DD` format |
| `transaction_id` | string | Yes | 10-digit transaction ID from the signed biometric block |
| `biometric` | object | Yes | Signed MOSIP SBI block object |
| `biometric.biometric_type` | string | Yes | `"FINGERPRINT"` |
| `biometric.format` | string | Yes | `"MOSIP_SBI_SIGNED"` |
| `biometric.blocks` | array | Yes | Array of signed biometric blocks from MOSIP SBI capture |

#### Request Example — NATIONAL ID

```json
{
  "id_type": "NATIONAL ID",
  "id_number": "CM702356039748",
  "first_name": "KEVIN",
  "last_name": "SSONKO",
  "date_of_birth": "1970-11-06",
  "transaction_id": "1234567890",
  "biometric": {
    "biometric_type": "FINGERPRINT",
    "format": "MOSIP_SBI_SIGNED",
    "blocks": [
      {
        "specVersion": "0.9.5",
        "data": "eyJhbGciOiJSUzI1NiIsIng1YyI6WyJNSUlE...",
        "hash": "A1B2C3...",
        "sessionKey": "kR9dP...",
        "thumbprint": "3f5a9c..."
      }
    ]
  }
}
```

#### Request — REFUGEE ID (UNHCR)

| Field | Type | Required | Description |
|---|---|---|---|
| `id_type` | string | Yes | `"REFUGEE ID"` |
| `id_number` | string | Yes | Refugee ID number (e.g., `WA9-00115526`) |
| `first_name` | string | Yes | First name (e.g., `SAMSON`) |
| `last_name` | string | Yes | Last name (e.g., `LADU`) |
| `biometric` | object | Yes | Fingerprint image object |
| `biometric.biometric_type` | string | Yes | `"FINGERPRINT"` |
| `biometric.format` | string | Yes | `"WSQ"`, `"JPEG"`, `"ISO_19794_4"`, or `"ISO_19794_6"` |
| `biometric.data` | string | Yes | Base64-encoded fingerprint image data |

#### Request Example — REFUGEE ID (WSQ)

```json
{
  "id_type": "REFUGEE ID",
  "id_number": "WA9-00115526",
  "first_name": "SAMSON",
  "last_name": "LADU",
  "biometric": {
    "biometric_type": "FINGERPRINT",
    "format": "WSQ",
    "data": "/6D/qAB6TklTVF9DT00gOQpQSVhfV0lEVEggMjk2..."
  }
}
```

#### Request — PASSPORT (NCIC — Not Yet Integrated)

```json
{
  "id_type": "PASSPORT",
  "id_number": "P12345678",
  "visa_validity": "2027-06-30"
}
```

Returns `verified: false` with `reason_code: VERIFICATION_UNAVAILABLE`. A `verification_reference` is still issued so registration can proceed as unverified.

#### Response — Verified (NATIONAL ID)

```json
{
  "status": "success",
  "data": {
    "verified": true,
    "reason_code": "IDENTITY_ACCEPTED",
    "message": "Identity verified via NIRA",
    "provider": "NIRA",
    "provider_status": "LIVE",
    "verification_reference": "vrf_FSMUJHVL3Z7QEMIZ",
    "verified_at": "2026-11-03T18:44:08.461Z",
    "expires_at": "2026-11-04T18:44:08.461Z",
    "matched_attributes": null
  }
}
```

The response includes `X-Response-Time-Ms` for gateway processing duration.
The `verification_reference` is in the JSON response body.

#### Response — Verified (REFUGEE ID)

```json
{
  "status": "success",
  "data": {
    "verified": true,
    "reason_code": "IDENTITY_ACCEPTED",
    "message": "Identity verified",
    "provider": "UNHCR",
    "provider_status": "LIVE",
    "verification_reference": "vrf_01JBK3RM9P2W6YD1",
    "verified_at": "2026-08-24T09:14:22.481Z",
    "expires_at": "2026-08-25T09:14:22.481Z",
    "matched_attributes": {
      "date_of_birth": "MATCH",
      "sex": "F"
    }
  }
}
```

#### Response — Not Verified

```json
{
  "status": "success",
  "data": {
    "verified": false,
    "reason_code": "IDENTITY_REJECTED",
    "message": "Biometric did not match the identity record",
    "provider": "NIRA",
    "provider_status": "LIVE",
    "verification_reference": null,
    "verified_at": null,
    "expires_at": null,
    "matched_attributes": null
  }
}
```

#### Response — Provider Unavailable

```json
{
  "status": "success",
  "data": {
    "verified": false,
    "reason_code": "VERIFICATION_UNAVAILABLE",
    "message": "No verification provider is currently available for PASSPORT",
    "provider": "NCIC",
    "provider_status": "PLANNED",
    "verification_reference": "vrf_01JBK4TN0Q3X7ZE2",
    "expires_at": "2026-08-25T09:14:22.481Z",
    "matched_attributes": null
  }
}
```

#### Validation Error Examples

| Error Code | Message | Scenario |
|---|---|---|
| `INVALID_BIOMETRIC` | `NATIONAL ID requires format MOSIP_SBI_SIGNED` | Wrong biometric format for provider |
| `MISSING_FIELD` | `transaction_id is required when format is MOSIP_SBI_SIGNED` | Missing transaction_id for signed block |
| `INVALID_ID` | `Invalid id_type` | Unrecognised id_type value |
| `MISSING_FIELD` | `biometric is required for this id_type` | Biometric omitted for NATIONAL ID or REFUGEE ID |

---

### 5.3 POST /individual_registrations

Registers a SIM for an individual subscriber. Call `POST /identity_verification` first and send the `verification_reference` it returned.

**This endpoint does NOT carry a biometric and does NOT call a provider.** Identity was already established in step 2, and the reference is the proof of it.

#### Request Fields

| Field | Type | Required | Description | Example |
|---|---|---|---|---|
| `verification_reference` | string | Yes | Reference from identity verification | `vrf_01JBK2QX7M4T8ZC3` |
| `msisdn` | string | Yes | MSISDN in international format | `256712345678` |
| `sim_registration_type` | string | Yes | `"NEW"`, `"SIM SWAP"`, `"RE_REGISTRATION"` | `NEW` |
| `sim_type` | string | Yes | `"SIM"`, `"ESIM"`, `"ISIM"` | `SIM` |
| `sim_registration_datetime` | string | Yes | ISO 8601 datetime | `2025-11-01T10:22:00Z` |
| `id_type` | string | Yes | `"NATIONAL ID"`, `"REFUGEE ID"`, `"PASSPORT"` | `NATIONAL ID` |
| `id_number` | string | Yes | ID number | `CM702356039748` |
| `nationality` | string | Yes | Subscriber nationality | `UGANDAN` |
| `surname` | string | Yes | Surname | `KATO` |
| `given_name` | string | Yes | Given names | `JOHN` |
| `gender` | string | Yes | `"MALE"`, `"FEMALE"`, `"UNDEFINED"` | `MALE` |
| `date_of_birth` | string | Yes | Date of birth (`YYYY-MM-DD`) | `1995-05-12` |
| `id_validity` | string | No | ID expiry date (`YYYY-MM-DD`) | `2030-12-31` |
| `visa_permit_number` | string | No | Visa/permit number | `VISA12345` |
| `visa_validity` | string | No | Visa expiry date (`YYYY-MM-DD`) | `2027-06-30` |
| `agent_code` | string | Yes | Agent code (uppercase alphanumeric) | `AGT001` |
| `agent_number` | string | Yes | Agent MSISDN | `256712345678` |
| `sales_district` | string | Yes | Sales district | `KAMPALA` |
| `gps_coordinates` | string | Yes | GPS coordinates (lat,lon) | `32.5825,0.3476` |
| `activation_date` | string | Yes | Activation date (`YYYY-MM-DD`) | `2025-10-01` |

#### Request Example — NATIONAL ID

```json
{
  "verification_reference": "vrf_FSMUJHVL3Z7QEMIZ",
  "msisdn": "256724072418",
  "sim_registration_type": "NEW",
  "sim_type": "SIM",
  "sim_registration_datetime": "2026-11-04T10:53:00Z",
  "id_type": "NATIONAL ID",
  "id_number": "CM702356039748",
  "nationality": "UGANDAN",
  "surname": "SSONKO",
  "given_name": "KEVIN",
  "gender": "MALE",
  "date_of_birth": "1970-11-06",
  "agent_code": "AGENT11",
  "agent_number": "256724072418",
  "sales_district": "KAMPALA",
  "gps_coordinates": "0.33147638683656766, 32.58604725173673",
  "activation_date": "2026-11-04",
  "id_validity": "2030-12-31"
}
```

#### Request Example — REFUGEE ID

```json
{
  "verification_reference": "vrf_01JBK3RM9P2W6YD1",
  "msisdn": "256724184554",
  "sim_registration_type": "NEW",
  "sim_type": "SIM",
  "sim_registration_datetime": "2026-11-04T10:53:00Z",
  "id_type": "REFUGEE ID",
  "id_number": "WA9-00115526",
  "nationality": "SOUTH SUDAN",
  "surname": "LADU",
  "given_name": "SAMSON",
  "gender": "MALE",
  "date_of_birth": "2001-01-01",
  "agent_code": "AGENT11",
  "agent_number": "256724072418",
  "sales_district": "KAMPALA",
  "gps_coordinates": "0.33147638683656766, 32.58604725173673",
  "activation_date": "2026-11-04",
  "id_validity": "2027-07-28"
}
```

#### Response — Accepted

```json
{
  "status": "accepted",
  "reason_code": "REGISTRATION_ACCEPTED",
  "message": "SIM registration stored"
}
```

#### Error Responses

| Error Code | Message | Scenario |
|---|---|---|
| `VERIFICATION_REQUIRED` | `A verification_reference from identity_verification is required` | No reference supplied |
| `VERIFICATION_REFERENCE_INVALID` | `Verification reference is not recognised` | Reference not found |
| `VERIFICATION_REFERENCE_EXPIRED` | `Verification reference expired; re-verify the subscriber` | Reference older than 24 hours |
| `VERIFICATION_REFERENCE_MISMATCH` | `Verification reference does not match the supplied identity` | Reference bound to different identity |
| `LIMIT_EXCEEDED` | `Subscriber has exceeded SIM ownership limit` | Ownership limit reached at commit time |
| `DUPLICATE_REQUEST` | `SIM already registered` | MSISDN already has active registration |
| `INVALID_MSISDN` | `Invalid MSISDN format` | MSISDN doesn't match `^2567\d{8}$` |
| `INVALID_AGENT` | `Agent number format is invalid` | Agent number invalid |

---

### 5.4 PUT /individual_registrations/{msisdn}

Fully replaces an existing subscriber registration. This is a **full re-verification** event — a fresh `verification_reference` is required.

#### Path Parameter

| Name | Type | Required | Description |
|---|---|---|---|
| `msisdn` | string | Yes | Subscriber MSISDN in international format |

#### Request Body

Same fields as `POST /individual_registrations`, including a fresh `verification_reference`.

#### Request Example

```json
{
  "verification_reference": "vrf_01JBK6VQ2S5Z9BG4",
  "msisdn": "256712345678",
  "sim_registration_type": "SIM SWAP",
  "sim_type": "SIM",
  "sim_registration_datetime": "2025-12-01T09:00:00Z",
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
  "activation_date": "2025-10-01"
}
```

#### Response — Updated

```json
{
  "status": "updated",
  "reason_code": "REGISTRATION_ACCEPTED",
  "message": "Subscriber information successfully updated"
}
```

> **Note:** To correct a detail without re-proving identity (e.g., surname change after marriage, typing error), use `PATCH /individual_registrations/{msisdn}` instead. That operation needs no verification and no biometric.

---

### 5.5 PATCH /individual_registrations/{msisdn}

Partial amendment of permitted fields on an existing registration. No verification reference or biometric is required.

#### Amendable Fields

| Field | Type | Description |
|---|---|---|
| `surname` | string | Subscriber surname |
| `given_name` | string | Subscriber given names |
| `gender` | string | `"MALE"`, `"FEMALE"`, `"UNDEFINED"` |
| `id_validity` | string | ID expiry date (`YYYY-MM-DD`) |
| `visa_validity` | string | Visa expiry date (`YYYY-MM-DD`) |
| `visa_permit_number` | string | Visa/permit number |

#### Request Example

```json
{
  "change_reason": "LEGAL_NAME_CHANGE",
  "evidence_reference": "MC/2026/004412",
  "changes": {
    "surname": "MUKASA",
    "given_name": "GRACE"
  }
}
```

#### Response — Amended

```json
{
  "status": "amended",
  "reason_code": "REGISTRATION_AMENDED",
  "message": "Subscriber details amended",
  "previous_values": {
    "surname": "AYO"
  }
}
```

---

### 5.6 POST /individual_registrations/{msisdn}/ownership_change

Transfers SIM ownership to a new subscriber.

#### Request Fields

| Field | Type | Required | Description |
|---|---|---|---|
| `verification_reference` | string | Yes | Reference for the **new owner** |
| `effective_date` | string | Yes | Transfer effective date (`YYYY-MM-DD`) |
| `new_owner` | object | Yes | New owner identity details |
| `new_owner.id_type` | string | Yes | `"NATIONAL ID"`, `"REFUGEE ID"`, `"PASSPORT"` |
| `new_owner.id_number` | string | Yes | New owner ID number |
| `new_owner.nationality` | string | Yes | New owner nationality |
| `new_owner.surname` | string | Yes | New owner surname |
| `new_owner.given_name` | string | Yes | New owner given names |
| `new_owner.gender` | string | Yes | `"MALE"`, `"FEMALE"`, `"UNDEFINED"` |
| `new_owner.date_of_birth` | string | Yes | New owner date of birth (`YYYY-MM-DD`) |
| `new_owner.id_validity` | string | No | New owner ID expiry date |
| `new_owner.visa_validity` | string | No | New owner visa expiry date |
| `previous_owner_consent` | object | Yes | Evidence of previous owner consent |
| `previous_owner_consent.method` | string | Yes | `"SUBSCRIBER_CONFIRMED"`, `"SIGNED_FORM"`, `"SUCCESSION"`, `"OPERATOR_ATTESTED"` |
| `previous_owner_consent.reference` | string | No | Consent reference (e.g., USSD code) |
| `previous_owner_consent.obtained_at` | string | Yes | Consent obtained datetime (ISO 8601) |
| `agent_code` | string | Yes | Agent code (uppercase alphanumeric) |
| `agent_number` | string | Yes | Agent MSISDN |

#### Request Example

```json
{
  "verification_reference": "vrf_01JBK7WR3T6A0CH5",
  "effective_date": "2026-08-26",
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
    "obtained_at": "2026-08-26T09:14:00Z"
  },
  "agent_code": "AGT001",
  "agent_number": "256712345678"
}
```

#### Response — Transferred

```json
{
  "status": "transferred",
  "reason_code": "OWNERSHIP_CHANGED",
  "message": "SIM ownership transferred",
  "previous_owner": {
    "id_type": "NATIONAL ID",
    "id_number": "CF123456789ABCDE"
  },
  "effective_date": "2026-08-26"
}
```

---

### 5.7 POST /individual_registrations/{msisdn}/deregistration

Deregisters/ends a SIM registration.

#### Request Example

```json
{
  "reason_code": "SUBSCRIBER_REQUEST",
  "effective_date": "2026-08-26",
  "agent_code": "AGT001",
  "agent_number": "256712345678",
  "notes": "Subscriber reported the handset as stolen"
}
```

#### Response — Deregistered

```json
{
  "status": "deregistered",
  "reason_code": "REGISTRATION_DEREGISTERED",
  "message": "SIM registration ended",
  "effective_date": "2026-08-26",
  "released_count": 1
}
```

---

### 5.8 POST /corporate_registrations

Registers a SIM card for a corporate entity. Verify the organisation first through `POST /identity_verification`.

**Note:** The nominated representative is **recorded, not verified**. No identity or biometric check is performed on them.

#### Request Fields (subset)

| Field | Type | Required | Description | Example |
|---|---|---|---|---|
| `verification_reference` | string | Yes | Reference for the organisation | `vrf_01JBK8XS4U7B1DJ6` |
| `msisdn` | string | Yes | MSISDN | `256712345679` |
| `sim_type` | string | Yes | `"SIM"`, `"ESIM"`, `"ISIM"` | `SIM` |
| `sim_registration_type` | string | Yes | `"NEW"`, `"SIM SWAP"` | `NEW` |
| `sim_registration_datetime` | string | Yes | ISO 8601 datetime | `2025-11-01T10:22:00Z` |
| `id_type` | string | Yes | `"COI"` or `"REGISTRY_PENDING"` | `COI` |
| `organisation_type` | string | Yes | `"COMPANY"`, `"BUSINESS"`, etc. | `COMPANY` |
| `organisation_name` | string | Yes | Organisation name | `ABC LIMITED` |
| `registration_number` | string | Yes | Registration number | `80020012345678` |
| `registration_validity` | string | No | Registration expiry date | `2028-12-31` |
| `registered_address` | string | Yes | Registered address | `KAMPALA ROAD` |
| `tax_identification_number` | string | Yes | TIN | `TIN123456` |
| `contact_number` | string | Yes | Contact MSISDN | `256712345679` |
| `representative` | object | Yes | Representative details (recorded, not verified) | — |
| `agent_code` | string | Yes | Agent code | `AGT001` |
| `agent_number` | string | Yes | Agent MSISDN | `256712345678` |
| `sales_district` | string | Yes | Sales district | `KAMPALA` |
| `gps_coordinates` | string | Yes | GPS coordinates | `32.5825,0.3476` |
| `activation_date` | string | Yes | Activation date (`YYYY-MM-DD`) | `2025-10-01` |

#### Request Example

```json
{
  "verification_reference": "vrf_01JBK8XS4U7B1DJ6",
  "msisdn": "256712345679",
  "sim_type": "SIM",
  "sim_registration_type": "NEW",
  "sim_registration_datetime": "2025-11-01T10:22:00Z",
  "id_type": "COI",
  "organisation_type": "COMPANY",
  "organisation_name": "ABC LIMITED",
  "registration_number": "80020012345678",
  "registration_validity": "2028-12-31",
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
    "date_of_birth": "1983-05-12",
    "validity": "2030-12-31"
  },
  "agent_code": "AGT001",
  "agent_number": "256712345678",
  "sales_district": "KAMPALA",
  "gps_coordinates": "32.5825,0.3476",
  "activation_date": "2025-10-01"
}
```

---

### 5.9 Batch Operations

Submit multiple registrations in one request. Include a unique `Idempotency-Key` header to prevent duplicates.

#### POST /individual_registrations/batch

```json
{
  "records": [
    {
      "verification_reference": "vrf_01JBK2QX7M4T8ZC3",
      "msisdn": "256712345678",
      "sim_registration_type": "NEW",
      "sim_type": "SIM",
      "sim_registration_datetime": "2025-11-01T10:22:00Z",
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
      "activation_date": "2025-10-01"
    }
  ]
}
```

#### Response — Batch Accepted

```json
{
  "status": "accepted",
  "job_id": "batch_123456",
  "message": "Batch accepted for processing"
}
```

#### GET /individual_registrations/batch/{job_id}

Poll batch status and results.

#### Response — Batch Status

```json
{
  "job_id": "batch_123456",
  "status": "completed",
  "total_records": 100,
  "processed_records": 100,
  "successful_records": 95,
  "failed_records": 5,
  "results": [
    {
      "msisdn": "256712345678",
      "status": "accepted",
      "reason_code": "REGISTRATION_ACCEPTED",
      "verification_reference": "vrf_01JBK2QX7M4T8ZC3",
      "error_message": null
    },
    {
      "msisdn": "256712345679",
      "status": "rejected",
      "reason_code": "INVALID_MSISDN",
      "verification_reference": null,
      "error_message": "Invalid MSISDN format"
    }
  ]
}
```

---

### 5.10 GET /compliance_report

Retrieve a compliance report scoped to your API key.

#### Response

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

---

### 5.11 GET /health

Health check (no authentication required).

#### Response

```json
{
  "status": "ok",
  "service": "KYC Verification API",
  "timestamp": "2026-11-04T10:53:00.000+03:00"
}
```

---

## 6. Complete Workflow Examples

### Example A: NATIONAL ID Registration

**Step 1 — Ownership Check:**
```http
POST /ownership_check
X-API-Key: your-key
{"subscriber_type": "individual", "id_type": "NATIONAL ID", "id_number": "CM702356039748"}
```
→ `{"allowed": true, "reason_code": "LIMIT_NOT_EXCEEDED", ...}`

**Step 2 — Identity Verification (NIRA flow handled by middleware):**
```http
POST /identity_verification
X-API-Key: your-key
{
  "id_type": "NATIONAL ID",
  "id_number": "CM702356039748",
  "first_name": "KEVIN",
  "last_name": "SSONKO",
  "date_of_birth": "1970-11-06",
  "transaction_id": "1234567890",
  "biometric": {
    "biometric_type": "FINGERPRINT",
    "format": "MOSIP_SBI_SIGNED",
    "blocks": [<signed MOSIP SBI block>]
  }
}
```
→ Response header: `X-Response-Time-Ms: <gateway duration in milliseconds>`
→ Response body: `data.verification_reference`
→ Body: `{"verified": true, "reason_code": "IDENTITY_ACCEPTED", ...}`

**Step 3 — Registration:**
```http
POST /individual_registrations
X-API-Key: your-key
{
  "verification_reference": "vrf_FSMUJHVL3Z7QEMIZ",
  "msisdn": "256724072418",
  ...
}
```
→ `{"status": "accepted", "reason_code": "REGISTRATION_ACCEPTED", ...}`

### Example B: REFUGEE ID Registration

**Step 2 — Identity Verification:**
```http
POST /identity_verification
X-API-Key: your-key
{
  "id_type": "REFUGEE ID",
  "id_number": "WA9-00115526",
  "first_name": "SAMSON",
  "last_name": "LADU",
  "biometric": {
    "biometric_type": "FINGERPRINT",
    "format": "WSQ",
    "data": "<base64 WSQ fingerprint>"
  }
}
```
→ Body: `{"verified": true, "reason_code": "IDENTITY_ACCEPTED", "verification_reference": "vrf_...", ...}`

**Step 3 — Registration:** Same as Example A, using the refugee verification reference.

---

## 7. Common HTTP Responses

| HTTP Status | Error Code | Meaning |
|---|---|---|
| `200 OK` / `201 Created` / `202 Accepted` | — | Request successful. Always inspect the response body for business logic results. |
| `401 Unauthorized` | `UNAUTHORIZED` | Missing or invalid `X-API-Key`. |
| `403 Forbidden` | `LIMIT_EXCEEDED` | Subscriber has exceeded SIM ownership limit. |
| `403 Forbidden` | `VERIFICATION_REFERENCE_INVALID` | Reference is not recognised, or a full update reused the reference already recorded for that subscriber. Full updates require a fresh verification reference; references remain reusable for other registrations within their validity period. |
| `403 Forbidden` | `VERIFICATION_REFERENCE_EXPIRED` | Reference is older than 24 hours. |
| `403 Forbidden` | `VERIFICATION_REFERENCE_MISMATCH` | Reference was issued for a different identity. |
| `403 Forbidden` | `CONSENT_REQUIRED` | `previous_owner_consent` is required for ownership change. |
| `404 Not Found` | `NOT_FOUND` | Subscriber record not found. |
| `409 Conflict` | `DUPLICATE_REQUEST` | SIM already registered or batch idempotency key reused. |
| `422 Unprocessable Entity` | `MISSING_FIELD` | Missing required field. |
| `422 Unprocessable Entity` | `INVALID_FIELD` | Invalid field value/format. |
| `422 Unprocessable Entity` | `INVALID_BIOMETRIC` | Biometric format does not match provider requirements. |
| `502 Bad Gateway` | `UCC_UPSTREAM_UNAVAILABLE` | Gateway could not reach UCC upstream service. |
| `500 Internal Server Error` | `SYSTEM_ERROR` | Unexpected system error. |

---

## 8. What the Middleware Handles Internally (Not Your Concern)

The following are **middleware operator secrets** and are never shared with vendors:

| Item | Description |
|---|---|
| NIRA partner private key & certificate | Used for JWS signing of `/nira/auth` |
| NIRA encryption certificate | Used for thumbprint + session key encryption |
| NIRA client ID, secret key, app ID | NIRA partner credentials |
| NIRA MISP license key, partner ID, partner API key | NIRA auth headers |
| Client-side cryptography | RSA-OAEP, AES-GCM, JWS RS256 implementation |
| UCC upstream URL | Internal routing (`https://192.168.5.18`) |

Your integration surface is limited to the endpoints documented above with your `X-API-Key`.

---

## 9. Go-Live Checklist

- [ ] Confirm your server can reach `10.33.33.30:8001` (you do not need direct access to `192.168.5.18`)
- [ ] Obtain a unique `X-API-Key` from the middleware operator via a secure channel
- [ ] Review the OpenAPI contract at `http://10.33.33.30:8001/openapi.json`
- [ ] For NATIONAL ID: capture a fresh MOSIP SBI biometric block and send it within ~30 seconds of the auth call
- [ ] Use HTTPS via a trusted reverse proxy before using this connection outside a controlled private network

---

## 10. Interactive Documentation

When the gateway is running, interactive Swagger UI documentation is available at:

```
http://10.33.33.30:8001/docs
```

OpenAPI JSON schema:

```
http://10.33.33.30:8001/openapi.json
```

---
