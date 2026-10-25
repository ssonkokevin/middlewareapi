# UCC KYC Gateway API v2.0.0

The KYC Gateway exposes the UCC SIM-registration API to authorised client
applications. The deployed base URL is:

```
http://192.168.5.18:8001
```

The full vendor handoff is in [KYC_VENDOR_INTEGRATION.md](KYC_VENDOR_INTEGRATION.md).
The machine-readable contract is [kyc_api_v2.yml](kyc_api_v2.yml). When the
service is running, interactive documentation is available at
`http://192.168.5.18:8001/docs` and the OpenAPI JSON at
`http://192.168.5.18:8001/openapi.json`.

## Authentication

All business endpoints require a provisioned API key:

```http
X-API-Key: <vendor-provided-key>
Content-Type: application/json
```

`GET /health`, `/docs`, `/redoc`, and `/openapi.json` do not require a key.
Keys are configured by the gateway operator with `KYC_API_KEYS`; do not use
or distribute the example `dev-local-key` outside local development.

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

## Required workflow

1. Call `POST /ownership_check` before the registration process.
2. Call `POST /identity_verification` with the subscriber identity and
   biometric. A successful HTTP response can still contain `verified: false`;
   check the response body.
3. Submit the returned `verification_reference` in the individual, corporate,
   batch, ownership-change, or full-update request. The reference is bound to
   the verified identity and expires after 24 hours.
4. For a SIM-swap confirmation using `PUT`, first obtain a new verification
   reference. Reusing the reference that established the current record for
   that MSISDN is rejected with `403 VERIFICATION_REFERENCE_INVALID`.

## Deployment

Copy `.env.example` to `.env`, set a strong unique `KYC_API_KEYS` value, and
run the service on all interfaces:

```powershell
uvicorn app.main:app --host 0.0.0.0 --port 8001
```

For Docker Compose, the `kyc-gateway` service already publishes port 8001.
Ensure the server owns `192.168.5.18`, TCP/8001 is permitted by the firewall,
and the vendor server can route to it. Use a TLS-terminating reverse proxy and
an HTTPS DNS name before exposing the gateway beyond the trusted internal
network, because API keys must not travel over an untrusted plain-HTTP path.
