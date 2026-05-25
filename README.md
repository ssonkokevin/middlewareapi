# Hamilton Verification Middleware

This middleware sits between Hamilton's internal applications and two external
government verification systems. Third-party developers send simple JSON to this
gateway — it handles all SOAP/XML building, WS-Security token generation, XML
parsing, and UCC login flows transparently.

---

## Architecture

```
                     ┌────────────────────────────────────────┐
                     │       Hamilton Middleware (port 8000)   │
                     │                                         │
  Internal apps ───► │  POST /api/nira/verify                  │──► NIRA SOAP endpoint
  (IP: 10.20.20.x)   │    └─ IP check: 10.20.20.1 / .4        │    (SOAP/XML + WS-Security)
                     │                                         │
  Internal apps ───► │  POST /api/refugee/verify               │──► UCC REST endpoint
  (IP: 192.168.168.x)│    └─ IP check: 192.168.168.8-.15 /29  │    (Login → Validate)
                     │                                         │
  Anyone     ──────► │  GET /health  GET /docs                 │
                     └────────────────────────────────────────┘
```

---

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/nira/verify` | Verify Uganda National ID via NIRA SOAP |
| `POST` | `/api/refugee/verify` | Verify refugee identity via UCC biometric |
| `GET` | `/health` | Service liveness check |
| `GET` | `/docs` | Swagger interactive documentation |
| `GET` | `/redoc` | ReDoc documentation |

---

## Project Structure

```
middleware-api/
├── app/
│   ├── main.py                    # FastAPI app, middleware, error handlers
│   ├── api/
│   │   ├── routes/
│   │   │   ├── nira.py            # POST /api/nira/verify
│   │   │   └── refugee.py         # POST /api/refugee/verify
│   │   └── deps/
│   │       └── ip_whitelist.py    # IP whitelist FastAPI dependency
│   ├── services/
│   │   ├── nira_service.py        # SOAP envelope builder + XML parser
│   │   └── refugee_service.py     # UCC login → validate flow
│   └── core/
│       ├── config.py              # Pydantic settings (loads .env)
│       └── logger.py              # JSON structured logging
├── .env                           # Environment variables (do not commit)
├── requirements.txt
├── Dockerfile
└── README.md
```

---

## Environment Variables

| Variable | Required | Description | Example |
|----------|----------|-------------|---------|
| `NIRA_URL` | ✅ | Full NIRA SOAP endpoint URL | `http://192.168.14.126:14460/...` |
| `NIRA_USERNAME` | ✅ | NIRA WS-Security username | `Hamiltel@TPI` |
| `NIRA_PASSWORD` | ✅ | NIRA WS-Security password (used in PasswordDigest) | `5gt!80MN` |
| `NIRA_CERT_PATH` | — | Path to NIRA TLS certificate (informational; `verify=False` on internal network) | `wwwroot/certificates/niragoug.crt` |
| `NIRA_ALLOWED_IPS` | — | Comma-separated individual IPs allowed for NIRA endpoint | `10.20.20.1,10.20.20.4` |
| `REFUGEE_LOGIN_URL` | ✅ | UCC login endpoint | `http://192.168.1.124/refugees/api/login/` |
| `REFUGEE_VALIDATE_URL` | ✅ | UCC validate endpoint | `http://192.168.1.124/refugees/api/validate/` |
| `REFUGEE_USERNAME` | ✅ | UCC username | `hamilton` |
| `REFUGEE_PASSWORD` | ✅ | UCC password | *(see .env)* |
| `REFUGEE_ALLOWED_SUBNETS` | — | Comma-separated CIDR subnets allowed for Refugee endpoint | `192.168.168.10/29` |
| `GLOBAL_ALLOWED_IPS` | — | Fallback IPs for dev/testing | `127.0.0.1` |
| `TIMEOUT` | — | HTTP timeout in seconds (default `60`). UCC fingerprint matching takes ~4 s. | `60` |
| `DEBUG` | — | `true` enables debug logging and uvicorn `--reload` | `true` |

---

## How NIRA SOAP Works

Every call to NIRA requires a fresh **WS-Security PasswordDigest** token:

```
1. Generate 16 random bytes  →  Nonce
2. Get current EAT timestamp →  Created  (e.g. 2026-05-19T15:22:05.765+03:00)
3. Compute digest:
       PasswordDigest = Base64( SHA1( nonce_bytes + created_utf8 + password_utf8 ) )
4. Embed Nonce, Created, and PasswordDigest into the SOAP Header
5. POST text/xml to the NIRA WSDL endpoint
6. Parse XML response → return clean JSON
```

No external SOAP libraries are used — only Python's built-in `hashlib`, `secrets`,
`base64`, and `xml.etree.ElementTree`.

---

## How UCC Login + Verify Works

```
1. POST /refugees/api/login/   { username, password }
                               ← { token: "..." }
2. POST /refugees/api/validate/ { individualId, sex, yearOfBirth, fingerprint }
   Authorization: Bearer <token>
                               ← { result: "Match" }
```

A new token is obtained for every verification request. The fingerprint field is a
base64-encoded WSQ image (50–200 KB) and is passed through to UCC exactly as received.
The raw fingerprint is **never** written to logs — only its byte length is recorded.

---

## Running Locally

```bash
# 1. Create and activate virtual environment
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # Linux / macOS

# 2. Install dependencies
pip install -r requirements.txt

# 3. Start the server
uvicorn app.main:app --host 0.0.0.0 --port 8000 --timeout-keep-alive 60 --reload
```

Visit **http://localhost:8000/docs** for interactive Swagger docs.

---

## Running with Docker

```bash
# Build
docker build -t middleware-api .

# Run (mounts your .env file)
docker run -p 8000:8000 --env-file .env middleware-api
```

### docker-compose example

```yaml
version: "3.9"
services:
  middleware-api:
    build: .
    ports:
      - "8000:8000"
    env_file:
      - .env
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
```

---

## curl Examples

### NIRA — National ID Verification

```bash
curl -X POST http://localhost:8000/api/nira/verify \
  -H "Content-Type: application/json" \
  -d '{
    "nationalId":   "CM9900910UKVUL",
    "dateOfBirth":  "11/11/1999",
    "documentId":   "022815224",
    "givenNames":   "",
    "otherNames":   "?",
    "surname":      ""
  }'
```

**Success response:**
```json
{
  "success": true,
  "data": {
    "transaction_status": "Ok",
    "matching_status": false,
    "card_status": "Valid",
    "password_days_left": "11",
    "execution_cost": "0.0"
  }
}
```

---

### UCC — Refugee Biometric Verification

```bash
curl -X POST http://localhost:8000/api/refugee/verify \
  -H "Content-Type: application/json" \
  -d '{
    "individualId":  "PCS-00077251",
    "sex":           "Male",
    "yearOfBirth":   1987,
    "fingerprint":   "/6D/qAB6TklT..."
  }'
```

> **Note:** The `fingerprint` value is a full base64 WSQ image — typically 50–200 KB.
> The truncated example above is for illustration only.

**Success response:**
```json
{
  "success": true,
  "data": {
    "result": "Match"
  }
}
```

---

## Error Response Format

All errors return a consistent JSON envelope regardless of where they originate:

```json
{
  "success": false,
  "error": true,
  "message": "NIRA timed out after 60 seconds",
  "status_code": 504,
  "path": "/api/nira/verify"
}
```

| Status | Meaning |
|--------|---------|
| `400` | Invalid or missing request fields |
| `403` | Client IP not in whitelist |
| `502` | NIRA or UCC returned an error |
| `504` | NIRA or UCC timed out |
| `500` | Unexpected internal error |

---

## IP Whitelisting

NIRA and Refugee have **completely separate** IP policies.
Being allowed for NIRA does **not** grant access to the Refugee endpoint.

### NIRA — individual IP list

```env
NIRA_ALLOWED_IPS=10.20.20.1,10.20.20.4
```

| IP | Server | Status |
|----|--------|--------|
| `10.20.20.1` | Production app server | Active |
| `10.20.20.4` | Test app server | Pre-configured, not yet live |

### Refugee — CIDR subnet

```env
REFUGEE_ALLOWED_SUBNETS=192.168.168.10/29
```

The `/29` subnet covers `192.168.168.8` – `192.168.168.15` (8 addresses).
Two app servers will be assigned IPs from this block.
CIDR checking uses Python's built-in `ipaddress` module — no external libraries.

### Dev / empty list behaviour

If a whitelist variable is left empty, the endpoint logs a warning and allows
all IPs. **Never deploy to production with empty whitelists.**

### 403 response

```json
{
  "success": false,
  "error": true,
  "message": "Access denied. IP 10.x.x.x is not authorised for this service.",
  "status_code": 403,
  "path": "/api/nira/verify"
}
```

---

## Log Format

Every log line is a single JSON object:

```json
{
  "timestamp": "2026-05-19T15:22:05.765+03:00",
  "level": "INFO",
  "message": "NIRA verification completed",
  "module": "nira_service",
  "function": "verify_person",
  "line": 193,
  "service": "nira",
  "nationalId": "CM9900910UKVUL",
  "transaction_status": "Ok",
  "matching_status": false,
  "card_status": "Valid",
  "duration_ms": 312.4
}
```

Fingerprint data is **never** logged. Only its presence and byte length appear:
```json
{ "fingerprint": "[PRESENT, 143872 bytes]" }
```
