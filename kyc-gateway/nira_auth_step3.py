"""
Step 3: POST /nira/auth — NIRA National ID authentication.

Client-side crypto required (cannot be done with curl alone):
  1. thumbprint      = SHA-256 of NIRA cert (DER), lowercase hex
  2. requestSessionKey = AES session key, RSA-OAEP encrypted to NIRA cert public key
  3. requestHMAC     = AES-GCM encrypted UPPERCASE SHA-256 hex digest of inner request
  4. request         = AES-GCM encrypted biometric + demographic payload
  5. Signature       = detached JWS over the request body

Run on the server:
  python3 nira_auth_step3.py <token> <nin> <dob> <surname> <given_names> \
      --cert nira-cert.pem --key partner-key.pem --blocks blocks.json

Files needed:
  nira-cert.pem   — NIRA encryption certificate from GET /nira/certificate response
  partner-key.pem — Partner private key (BEGIN PRIVATE KEY) for JWS signing
  blocks.json     — Biometric blocks from MOSIP SBI capture (optional)

Environment:
  UCC_BASE_URL — sets domainUri in the request body (default:
                 https://api-internal-preprod.nsis.nira.go.ug)

Dependencies: cryptography requests
"""

import sys
import json
import base64
import hashlib
import os
import uuid
import argparse
from datetime import datetime, timezone

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.x509 import load_pem_x509_certificate
import requests


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def load_file(path: str) -> str:
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def load_json_file(path: str):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


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
                        surname: str, given_names: str, blocks=None) -> dict:
    """Build the inner (plaintext) NIRA AUTH request.

    Includes the MOSIP SBI-signed biometric blocks when provided, so the
    fingerprint is captured within the ~30-second freshness window.

    `domainUri` uses the UCC_BASE_URL env var (default NIRA base URL).
    """
    domain_uri = os.environ.get("UCC_BASE_URL",
                                "https://api-internal-preprod.nsis.nira.go.ug")
    request = {
        "id": "mosip.identity.auth",
        "version": "1.0",
        "transactionID": transaction_id,
        "requestTime": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
        "env": "Pre-Production",
        "domainUri": domain_uri,
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
    if blocks:
        request["biometric"] = {
            "biometric_type": "FINGERPRINT",
            "format": "MOSIP_SBI_SIGNED",
            "blocks": blocks,
        }
    return request


def make_jws(payload: bytes, private_key_pem: str) -> str:
    """Create a standard JWS compact serialization (RS256).

    Returns: base64url(header).base64url(payload).base64url(signature)
    """
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode("utf-8"), password=None
    )
    header = {"alg": "RS256", "typ": "JWT", "cty": "json"}
    header_b64 = b64url_encode(
        json.dumps(header, separators=(",", ":")).encode("utf-8")
    )
    payload_b64 = b64url_encode(payload)
    signing_input = (header_b64 + "." + payload_b64).encode("ascii")
    signature = private_key.sign(
        signing_input, padding.PKCS1v15(), hashes.SHA256()
    )
    sig_b64 = b64url_encode(signature)
    return header_b64 + "." + payload_b64 + "." + sig_b64


def main():
    parser = argparse.ArgumentParser(
        description="NIRA Step 3: POST /nira/auth with client-side crypto"
    )
    parser.add_argument("token", help="Step 1 JWT bearer token")
    parser.add_argument("nin", help="National ID number (e.g. CM702356039748)")
    parser.add_argument("dob", help="Date of birth (e.g. 11/06/1970)")
    parser.add_argument("surname", help="Surname (e.g. SSONKO)")
    parser.add_argument("given_names", help="Given names (e.g. KEVIN)")
    parser.add_argument("--cert", default="nira-cert.pem",
                        help="Path to NIRA certificate PEM (default: nira-cert.pem)")
    parser.add_argument("--key", default="partner-key.pem",
                        help="Path to partner private key PEM (default: partner-key.pem)")
    parser.add_argument("--blocks", default="blocks.json",
                        help="Path to MOSIP SBI blocks JSON (default: blocks.json)")
    args = parser.parse_args()

    token = args.token
    nin = args.nin
    dob = args.dob
    surname = args.surname
    given_names = args.given_names

    # NIRA credentials from hamiltel.properties
    misp_license_key = "bkWwgkd0mW2GLNF9gSMUJNYFdp75D7zaQoteGa0w3u4d3Qt0qY"
    partner_id = "hamiltel"
    partner_api_key = "266950"
    vendor_api_key = "1774eb6283f6202ed9b9d7705583a731c7d03ad8ca2fedd26d7f7413539ee547"

    # ---- Step A: Load NIRA certificate from file ----
    if not os.path.exists(args.cert):
        print(f"ERROR: {args.cert} not found. Save the Step 2 certificate PEM there.")
        sys.exit(1)
    niracert_pem = load_file(args.cert)
    print(f"Loaded NIRA certificate from {args.cert}")

    # ---- Step B: Compute thumbprint ----
    thumbprint = compute_thumbprint(niracert_pem)
    print(f"Thumbprint: {thumbprint}")

    # ---- Step C: Generate AES session key ----
    session_key = os.urandom(32)  # AES-256
    request_session_key = encrypt_session_key(session_key, niracert_pem)
    print(f"requestSessionKey (RSA-OAEP encrypted): {request_session_key[:40]}...")

    # ---- Step D: Load biometric blocks (fingerprint capture) ----
    blocks = None
    if os.path.exists(args.blocks):
        blocks = load_json_file(args.blocks)
        print(f"Loaded {len(blocks)} biometric block(s) from {args.blocks}")
    else:
        print(f"WARNING: {args.blocks} not found — proceeding without biometric "
              f"(NIRA may reject due to 30-second freshness window)")

    # ---- Step E: Build inner request ----
    transaction_id = str(uuid.uuid4().int)[:10]
    inner_request = build_inner_request(transaction_id, nin, dob, surname,
                                        given_names, blocks=blocks)
    inner_request_json = json.dumps(inner_request, separators=(",", ":")).encode("utf-8")
    print(f"Inner request: {inner_request_json[:300]}...")

    # ---- Step F: Compute requestHMAC ----
    digest = hashlib.sha256(inner_request_json).hexdigest().upper()
    request_hmac = aes_gcm_encrypt(digest.encode("utf-8"), session_key)
    print(f"requestHMAC (AES-GCM of uppercase SHA-256): {request_hmac[:40]}...")

    # ---- Step G: Compute encrypted request field ----
    request_field = aes_gcm_encrypt(inner_request_json, session_key)
    print(f"request (AES-GCM encrypted payload): {request_field[:40]}...")

    # ---- Step H: Build outer request body ----
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

    # ---- Step I: Create JWS signature ----
    signature = None
    if os.path.exists(args.key):
        partner_private_key_pem = load_file(args.key)
        signature = make_jws(outer_body_json, partner_private_key_pem)
        print(f"JWS Signature: {signature[:40]}...")
    else:
        print(f"WARNING: {args.key} not found — skipping Signature header "
              f"(NIRA may reject)")

    # ---- Step J: POST /nira/auth ----
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
    resp = requests.post(url, headers=headers, data=outer_body_json, timeout=60)
    print(f"Status: {resp.status_code}")
    print(f"Headers: {dict(resp.headers)}")
    print(f"Body: {resp.text}")


if __name__ == "__main__":
    main()
