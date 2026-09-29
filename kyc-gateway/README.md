# KYC Verification API Gateway

FastAPI implementation of the **KYC Verification API v1.9.0** (UCC Central
Equipment Identity Register — CEIR), based on the `kyc_api.html` specification.

> **Upstream status:** No production or test URL has been confirmed yet for
> NIRA identity/fingerprint validation or any external KYC backend. This
> gateway is fully self-contained — all business rules (ownership limits,
> eligibility tokens, NIRA validation, batch processing, compliance
> reporting) run against in-memory stub services in `app/services/`. Swap the
> stubs for real integrations once endpoints are confirmed; the request/
> response contracts already match the spec, so callers won't need to change.

---

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/ownership_check` | Verify SIM ownership eligibility |
| `POST` | `/sim_registrations` | Register individual SIM |
| `POST` | `/corporate_registrations` | Register corporate SIM |
| `PUT` | `/sim_registrations/{msisdn}` | Update subscriber registration (full re-validation) |
| `POST` | `/sim_registrations/batch` | Submit batch SIM registrations |
| `GET` | `/sim_registrations/batch/{job_id}` | Retrieve batch processing status |
| `GET` | `/compliance_report` | Retrieve compliance report |
| `GET` | `/health` | Service liveness check |
| `GET` | `/docs` | Swagger UI |

All endpoints except `/health` and `/docs` require an `X-API-Key` header.

---

## Project Structure

```
kyc-gateway/
├── app/
│   ├── main.py                        # FastAPI app, middleware, error handlers
│   ├── api/
│   │   ├── routes/
│   │   │   ├── ownership.py           # POST /ownership_check
│   │   │   ├── registration.py        # SIM/corporate registration + batch
│   │   │   └── compliance.py          # GET /compliance_report
│   │   └── deps/
│   │       └── auth.py                # X-API-Key dependency
│   ├── schemas/
│   │   └── kyc.py                     # All Pydantic models from the spec
│   ├── services/
│   │   ├── ownership_service.py       # Ownership limit resolution + token minting
│   │   ├── registration_service.py    # Individual/corporate registration + update
│   │   ├── batch_service.py           # Batch submission + status
│   │   ├── compliance_service.py      # Compliance report aggregation
│   │   ├── nira_stub.py               # NIRA identity/biometric validation (STUB)
│   │   ├── store.py                   # In-memory data store (tokens, records, jobs)
│   │   └── exceptions.py              # KycServiceError -> ErrorResponse mapping
│   └── core/
│       ├── config.py                  # Pydantic settings (loads .env)
│       └── logger.py                  # JSON structured logging
├── .env.example
├── requirements.txt
└── README.md
```

---

## Running Locally

```bash
# 1. Create and activate a virtual environment
python -m venv venv
venv\Scripts\activate        # Windows

# 2. Install dependencies
pip install -r requirements.txt

# 3. Copy environment file
copy .env.example .env

# 4. Start the server (port 8001 to avoid clashing with middleware-api on 8000)
uvicorn app.main:app --host 0.0.0.0 --port 8001 --reload
```

Visit **http://localhost:8001/docs** for interactive Swagger docs.

---

## Authentication

Every request (except `/health`, `/docs`) must include:

```
X-API-Key: dev-local-key
```

Valid keys are configured via the `KYC_API_KEYS` env var (comma-separated).
The key identifies the calling MNO and scopes data-specific endpoints (e.g.
`/compliance_report`) to that MNO.

---

## Eligibility Token Flow

1. `POST /ownership_check` with `subscriber_type: individual` and `allowed: true`
   returns an `eligibility_token` (single-use, 10-minute TTL by default —
   see `ELIGIBILITY_TOKEN_TTL_SECONDS`).
2. Submit that token in `POST /sim_registrations` (`eligibility_token` field),
   matching the same `id_type` + `id_number`.
3. For corporate registrations, run an **individual** ownership check on the
   nominated representative and use that token in `POST /corporate_registrations`.
4. `PUT /sim_registrations/{msisdn}` (update) and batch records do **not**
   require a token.

---

## NIRA / Biometric Validation (Stub)

`app/services/nira_stub.py` simulates NIRA's identity + fingerprint decision
since no real endpoint is confirmed yet:

- `id_number` ending in `"0"` → simulated "not found" (`IDENTITY_REJECTED`)
- `biometric.template == "MISMATCH"` → simulated fingerprint mismatch
- everything else → accepted

Replace this module with a real HTTP integration once `NIRA_VALIDATE_URL` is
confirmed. **Fingerprint templates must never be logged** — only presence /
byte length.

---

## Example Requests

### Ownership check (individual)

```bash
curl -X POST http://localhost:8001/ownership_check \
  -H "X-API-Key: dev-local-key" \
  -H "Content-Type: application/json" \
  -d '{
    "subscriber_type": "individual",
    "id_type": "NATIONAL ID",
    "id_number": "CF123456789ABCDE"
  }'
```

### Individual SIM registration

```bash
curl -X POST http://localhost:8001/sim_registrations \
  -H "X-API-Key: dev-local-key" \
  -H "Content-Type: application/json" \
  -d '{
    "eligibility_token": "<token from ownership_check>",
    "msisdn": "256712345678",
    "sim_registration_type": "NEW",
    "sim_type": "SIM",
    "sim_registration_datetime": "2025-11-01T10:22:00Z",
    "biometric": {"biometric_type": "FINGERPRINT", "format": "ISO_19794_2", "template": "SAMPLE"},
    "id_type": "NATIONAL ID",
    "id_number": "CF123456789ABCDE",
    "nationality": "UGANDAN",
    "surname": "KATO",
    "given_name": "JOHN",
    "age": 30,
    "gender": "MALE",
    "date_of_birth": "1995-05-12",
    "agent_code": "AGT001",
    "agent_number": "256712345678",
    "sales_district": "KAMPALA",
    "gps_coordinates": "32.5825,0.3476",
    "activation_date": "2025-10-01"
  }'
```

---

## Standardized Reason Codes

`LIMIT_EXCEEDED`, `LIMIT_NOT_EXCEEDED`, `IDENTITY_ACCEPTED`, `IDENTITY_REJECTED`,
`INVALID_FIELD`, `INVALID_ID`, `INVALID_MSISDN`, `INVALID_AGENT`,
`INVALID_BIOMETRIC`, `MISSING_FIELD`, `DUPLICATE_REQUEST`, `INVALID_PAYLOAD`,
`NOT_FOUND`, `SYSTEM_ERROR`, `UNAUTHORIZED`, `ELIGIBILITY_TOKEN_REQUIRED`,
`ELIGIBILITY_TOKEN_MISMATCH`.

---

## Known Limitations (stub implementation)

- In-memory store (`app/services/store.py`) is single-process only — data is
  lost on restart and not shared across multiple uvicorn workers.
- Batch processing runs synchronously within the request instead of as a
  background job; the `job_id` polling contract is preserved for future
  compatibility with a real async worker.
- Compliance report is computed on demand rather than cached for 5 minutes.
- No upstream URL is configured yet (`KYC_UPSTREAM_URL`, `NIRA_VALIDATE_URL`).
