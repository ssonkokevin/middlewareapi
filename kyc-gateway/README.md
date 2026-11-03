# UCC KYC Gateway API v2.0.0

The KYC Gateway exposes the UCC SIM-registration API to authorised client
applications. The deployed base URL is:

```
http://10.33.33.30:8001
```

The full vendor handoff is in [KYC_VENDOR_INTEGRATION.md](KYC_VENDOR_INTEGRATION.md).
The machine-readable contract is [kyc_api_v2.yml](kyc_api_v2.yml). When the
service is running, interactive documentation is available at
`http://10.33.33.30:8001/docs` and the OpenAPI JSON at
`http://10.33.33.30:8001/openapi.json`.

## Authentication

All business endpoints require a provisioned API key:

```http
X-API-Key: <vendor-provided-key>
Content-Type: application/json
```

`GET /health`, `/docs`, `/redoc`, and `/openapi.json` do not require a key.
Keys are configured by the gateway operator with `KYC_API_KEYS`; do not use
or distribute the example `dev-local-key` outside local development.
For each accepted vendor key, the gateway forwards the same `X-API-Key` to
the UCC upstream at `UCC_BASE_URL` and returns the UCC response to the vendor.

## Main endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| POST | `/ownership_check` | Check ownership eligibility before registration |
| POST | `/identity_verification` | Verify identity and biometric; returns a 24-hour `verification_reference` |
| POST | `/individual_registrations` | Create an individual registration |
| POST | `/corporate_registrations` | Create a corporate registration |
| PUT | `/individual_registrations/{msisdn}` | Fully replace an individual registration with fresh verification |
| PATCH | `/individual_registrations/{msisdn}` | Amend permitted details |
| POST | `/individual_registrations/{msisdn}/ownership_change` | Change SIM ownership |
| POST | `/individual_registrations/{msisdn}/deregistration` | Deregister a SIM |
| POST/GET | `/individual_registrations/batch` | Submit or poll an individual batch |
| POST/GET | `/corporate_registrations/batch` | Submit or poll a corporate batch |
| GET | `/compliance_report` | Retrieve the caller's compliance report |
| GET | `/health` | Service liveness check |
| POST | `/nira/token` | Obtain NIRA token via UCC proxy |
| GET | `/nira/certificate` | Fetch NIRA certificate via UCC proxy |
| POST | `/nira/auth` | Signed NIRA AUTH request via UCC proxy |

## Required workflow

1. Call `POST /ownership_check` before the registration process.
2. Call `POST /identity_verification` with the subscriber identity and
   biometric. A successful HTTP response can still contain `verified: false`;
   check the response body.
   - For `id_type: "REFUGEE ID"`: send `first_name` and `last_name` (required
     by UCC). Biometric `format` accepts `ISO_19794_4`, `ISO_19794_6`, `JPEG`,
     or `WSQ`. WSQ data is auto-converted to JPEG by the gateway before
     forwarding to UCC — send whatever you have and let the gateway handle it.
   - For `id_type: "NATIONAL ID"`: the gateway returns `VERIFICATION_REQUIRED`
     with `provider_status: "NIRA_FLOW_REQUIRED"`. The vendor must complete the
     three-step NIRA flow through UCC (`POST /nira/token` →
     `GET /nira/certificate` → `POST /nira/auth`) and then submit the
     resulting `verification_reference` to registration.
   - For all other id_types: simulated provider decision.
3. Submit the returned `verification_reference` in the individual, corporate,
   batch, ownership-change, or full-update request. The reference is bound to
   the verified identity and expires after 24 hours.
4. For a SIM-swap confirmation using `PUT`, first obtain a new verification
   reference. Reusing the reference that established the current record for
   that MSISDN is rejected with `403 VERIFICATION_REFERENCE_INVALID`.

## Environment Variables

Copy `.env.example` to `.env` and configure:

| Variable | Required | Description | Example |
|----------|----------|-------------|---------|
| `UCC_BASE_URL` | ✅ | Private UCC upstream URL (vendors use `PUBLIC_BASE_URL`) | `http://192.168.5.18` |
| `UCC_API_KEY` | ✅ | Middleware's key for authenticating to UCC upstream | `9feb2e05b...c60bd` |
| `UCC_FORWARDING_ENABLED` | — | Forward vendor requests to UCC (`true`) or simulate locally (`false`) | `true` |
| `UCC_TLS_VERIFY` | — | Validate UCC TLS certificate | `false` |
| `KYC_API_KEYS` | ✅ | Comma-separated vendor API keys (validated locally) | `dev-local-key` |
| `DEBUG` | — | Debug logging and uvicorn reload | `true` |
| `TIMEOUT` | — | HTTP request timeout in seconds | `60` |
| `PUBLIC_BASE_URL` | — | Vendor-facing base URL for OpenAPI/Swagger | `http://10.33.33.30:8001` |
| `SQLITE_PATH` | — | SQLite database file path | `kyc_gateway.db` |
| `VERIFICATION_REFERENCE_TTL_HOURS` | — | Verification reference lifetime in hours | `24.0` |
| `NIRA_CLIENT_ID` | — | NIRA vendor client ID (from NIRA/UCC) | *(vendor-provided)* |
| `NIRA_SECRET_KEY` | — | NIRA vendor secret key | *(vendor-provided)* |
| `NIRA_APP_ID` | — | NIRA vendor app ID | *(vendor-provided)* |
| `NIRA_MISP_LICENSE_KEY` | — | NIRA MISP license key | *(vendor-provided)* |
| `NIRA_PARTNER_ID` | — | NIRA partner ID | *(vendor-provided)* |
| `NIRA_PARTNER_API_KEY` | — | NIRA partner API key | *(vendor-provided)* |
| `NIRA_KEYSTORE_PATH` | — | Path to PKCS#12 keystore (if middleware signs) | *(vendor-provided)* |
| `NIRA_KEYSTORE_PASSWORD` | — | PKCS#12 keystore password | *(vendor-provided)* |
| `NIRA_ENV` | — | NIRA environment | `pre-production` |
| `NIRA_DOMAIN_URI` | — | NIRA domain URI | *(vendor-provided)* |
| `REDIS_URL` | — | Redis URL (unused; kept for future swap) | `redis://localhost:6379/1` |

`.env` is gitignored — never commit real credentials.

## Deployment

Copy `.env.example` to `.env`, set a strong unique `KYC_API_KEYS` value, and
run the service on all interfaces:

```powershell
uvicorn app.main:app --host 0.0.0.0 --port 8001
```

For Docker Compose, the `kyc-gateway` service already publishes port 8001.
Ensure the middleware server owns `10.33.33.30`, TCP/8001 is permitted by the
firewall, and the vendor server can route to it. The intended private route is
vendor application -> `10.33.33.30:8001` -> middleware -> UCC
`https://192.168.5.18` (port 443). Use a TLS-terminating reverse proxy and
an HTTPS DNS name before exposing the gateway beyond the trusted internal
network, because API keys must not travel over an untrusted plain-HTTP path.

## NIRA Flow (NATIONAL ID)

When `id_type: "NATIONAL ID"`, `POST /identity_verification` does not perform
a simulated match. Instead it returns `200` with `verified: false`,
`provider_status: "NIRA_FLOW_REQUIRED"`, and `reason_code:
"VERIFICATION_REQUIRED"`. The vendor must complete the three-step flow through
UCC proxy endpoints:

1. `POST /nira/token` — obtain NIRA token. Send `X-Client-ID`,
   `X-Secret-Key`, `X-App-ID` headers. UCC returns an `Authorization` header.
2. `GET /nira/certificate` — fetch NIRA encryption certificate. Send the
   `Authorization: Bearer <token>` header.
3. `POST /nira/auth` — signed AUTH request. Send `X-MISP-License-Key`,
   `X-Partner-ID`, `X-Partner-API-Key`, `Signature`, and `Authorization`
   headers plus the signed biometric body. UCC returns an
   `X-Verification-Reference` header.
4. Submit that `verification_reference` to `POST /individual_registrations`.

The middleware validates the vendor `X-API-Key` locally, then re-authenticates
to UCC with `UCC_API_KEY`. All three `/nira/*` paths are already in
`_UCC_PROXY_PATHS` and are forwarded unchanged to UCC. Response headers
`Authorization` and `X-Verification-Reference` are exposed via CORS.

NIRA vendor credentials (`NIRA_CLIENT_ID`, `NIRA_SECRET_KEY`, `NIRA_APP_ID`,
`NIRA_MISP_LICENSE_KEY`, `NIRA_PARTNER_ID`, `NIRA_PARTNER_API_KEY`,
`NIRA_KEYSTORE_PATH`, `NIRA_KEYSTORE_PASSWORD`, `NIRA_ENV`, `NIRA_DOMAIN_URI`)
are configured in `.env` and loaded via `app/core/config.py`. Never commit real
secrets — `.env` is gitignored.

## Biometric Format Conversion (WSQ → JPEG)

UCC requires `JPEG` fingerprint images for `REFUGEE ID` verification. If your
capture device produces `WSQ` data, send it with `"format": "WSQ"` — the
gateway automatically decodes the base64 WSQ image and re-encodes it as base64
JPEG before forwarding to UCC. The conversion is transparent; no client-side
change is required.

If your data is already JPEG, send `"format": "JPEG"` directly — no conversion
step runs for non-WSQ payloads. Supported `format` values for `REFUGEE ID`:
`ISO_19794_4`, `ISO_19794_6`, `JPEG`, `WSQ`.

Accepted format values are defined in `app/schemas/kyc.py` (`IsoImageBiometric`)
and the conversion logic lives in `app/services/biometric_converter.py`
(`convert_biometric_if_wsq`). The forwarding middleware in `app/main.py`
also intercepts `/identity_verification` bodies and converts WSQ → JPEG before
the outbound UCC call.
