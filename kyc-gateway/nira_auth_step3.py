"""
Step 3: POST /nira/auth — NIRA National ID authentication.

Client-side crypto required (cannot be done with curl alone):
  1. thumbprint      = SHA-256 of NIRA cert (DER), lowercase hex
  2. requestSessionKey = AES session key, RSA-OAEP encrypted to NIRA cert public key
  3. requestHMAC     = AES-GCM encrypted UPPERCASE SHA-256 hex digest of inner request
  4. request         = AES-GCM encrypted biometric + demographic payload
  5. Signature       = detached JWS over the request body

Run on the server:
  python3 nira_auth_step3.py <token> <nin> <dob> <surname> <given_names>

Files needed in the same directory:
  nira-cert.pem   — NIRA encryption certificate from GET /nira/certificate response
  partner-key.pem — Partner private key (BEGIN PRIVATE KEY) for JWS signing (optional)

Dependencies: cryptography pyjwt requests
"""

import sys
import json
import base64
import hashlib
import os
import uuid
from datetime import datetime, timezone

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.x509 import load_pem_x509_certificate
import jwt
import requests


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def load_file(path: str) -> str:
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def compute_thumbprint(cert_pem: str) -> str:
    """SHA-256 of the DER-encoded certificate, lowercase hex."""
    cert = load_pem_x509_certificate(cert_pem.encode("utf-8"))
    der = cert.public_bytes(serialization.Encoding.DER)
    return hashlib.sha256(der).hexdigest()


def encrypt_session_key(session_key: bytes, cert_pem: str) -> str:
    """RSA-OAEP (SHA-256) encrypt the AES session key to NIRA cert public key."""
    cert = load_pem_x509_certificate(cert_pem.encode("utf-8"))
    public_key = cert.public_key()
    encrypted = public_key.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return b64url_encode(encrypted)


def aes_gcm_encrypt(plaintext: bytes, key: bytes) -> str:
    """AES-256-GCM encrypt, returns base64url(nonce + ciphertext + tag)."""
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext, None)
    return b64url_encode(nonce + ct)


def build_inner_request(transaction_id: str, nin: str, dob: str,
                        surname: str, given_names: str) -> dict:
    """Build the inner (plaintext) NIRA AUTH request."""
    return {
        "id": "mosip.identity.auth",
        "version": "1.0",
        "transactionID": transaction_id,
        "requestTime": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
        "env": "Pre-Production",
        "domainUri": "https://api-internal-preprod.nsis.nira.go.ug",
        "individualId": nin.lower() + "@nin",
        "individualIdType": "HANDLE",
        "consentObtained": True,
        "demographic": {
            "surname": surname,
            "givenName": given_names,
            "dateOfBirth": dob,
            "nin": nin.upper(),
        },
    }


def make_jws(payload: bytes, private_key_pem: str) -> str:
    """Create a detached JWS (RS256) over the payload."""
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode("utf-8"), password=None
    )
    token = jwt.encode(
        {},
        payload,
        algorithm="RS256",
        key=private_key,
        headers={"typ": "JWT", "cty": "json"},
    )
    return token


def main():
    if len(sys.argv) < 6:
        print("Usage: python3 nira_auth_step3.py <token> <nin> <dob> <surname> <given_names>")
        print("Example: python3 nira_auth_step3.py <JWT> CM702356039748 11/06/1970 SSONKO KEVIN")
        sys.exit(1)

    token = sys.argv[1]
    nin = sys.argv[2]
    dob = sys.argv[3]
    surname = sys.argv[4]
    given_names = sys.argv[5]

    # NIRA credentials from hamiltel.properties
    misp_license_key = "bkWwgkd0mW2GLNF9gSMUJNYFdp75D7zaQoteGa0w3u4d3Qt0qY"
    partner_id = "hamiltel"
    partner_api_key = "266950"
    vendor_api_key = "1774eb6283f6202ed9b9d7705583a731c7d03ad8ca2fedd26d7f7413539ee547"

    # ---- Step A: Load NIRA certificate from file ----
    if not os.path.exists("nira-cert.pem"):
        print("ERROR: nira-cert.pem not found. Save the Step 2 certificate PEM to nira-cert.pem")
        sys.exit(1)
    niracert_pem = load_file("nira-cert.pem")
    print(f"Loaded NIRA certificate from nira-cert.pem")

    # ---- Step B: Compute thumbprint ----
    thumbprint = compute_thumbprint(niracert_pem)
    print(f"Thumbprint: {thumbprint}")

    # ---- Step C: Generate AES session key ----
    session_key = os.urandom(32)  # AES-256
    request_session_key = encrypt_session_key(session_key, niracert_pem)
    print(f"requestSessionKey (RSA-OAEP encrypted): {request_session_key[:40]}...")

    # ---- Step D: Build inner request ----
    transaction_id = str(uuid.uuid4().int)[:10]
    inner_request = build_inner_request(transaction_id, nin, dob, surname, given_names)
    inner_request_json = json.dumps(inner_request, separators=(",", ":")).encode("utf-8")
    print(f"Inner request: {inner_request_json[:200]}...")

    # ---- Step E: Compute requestHMAC ----
    digest = hashlib.sha256(inner_request_json).hexdigest().upper()
    request_hmac = aes_gcm_encrypt(digest.encode("utf-8"), session_key)
    print(f"requestHMAC (AES-GCM of uppercase SHA-256): {request_hmac[:40]}...")

    # ---- Step F: Compute encrypted request field ----
    request_field = aes_gcm_encrypt(inner_request_json, session_key)
    print(f"request (AES-GCM encrypted payload): {request_field[:40]}...")

    # ---- Step G: Build outer request body ----
    outer_body = {
        "id": "mosip.identity.auth",
        "version": "1.0",
        "transactionID": transaction_id,
        "requestTime": inner_request["requestTime"],
        "env": "Pre-Production",
        "domainUri": "https://api-internal-preprod.nsis.nira.go.ug",
        "individualId": nin.lower() + "@nin",
        "individualIdType": "HANDLE",
        "consentObtained": True,
        "thumbprint": thumbprint,
        "requestSessionKey": request_session_key,
        "requestHMAC": request_hmac,
        "request": request_field,
    }
    outer_body_json = json.dumps(outer_body, separators=(",", ":")).encode("utf-8")
    print(f"Outer body size: {len(outer_body_json)} bytes")

    # ---- Step H: Create JWS signature ----
    signature = None
    if os.path.exists("partner-key.pem"):
        partner_private_key_pem = load_file("partner-key.pem")
        signature = make_jws(outer_body_json, partner_private_key_pem)
        print(f"JWS Signature: {signature[:40]}...")
    else:
        print("WARNING: partner-key.pem not found — skipping Signature header (NIRA may reject)")

    # ---- Step I: POST /nira/auth ----
    headers = {
        "X-API-Key": vendor_api_key,
        "X-MISP-License-Key": misp_license_key,
        "X-Partner-ID": partner_id,
        "X-Partner-API-Key": partner_api_key,
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    if signature:
        headers["Signature"] = signature

    url = "http://10.33.33.30:8001/nira/auth"
    print(f"\nPOST {url}")
    resp = requests.post(url, headers=headers, content=outer_body_json, timeout=60)
    print(f"Status: {resp.status_code}")
    print(f"Headers: {dict(resp.headers)}")
    print(f"Body: {resp.text}")


if __name__ == "__main__":
    main()
