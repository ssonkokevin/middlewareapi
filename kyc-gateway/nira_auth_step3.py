"""
Step 3: POST /nira/auth — NIRA National ID authentication.

Client-side crypto required (per NIRA Auth Partner API Guide v1.0):
  1. thumbprint      = SHA-256 of NIRA cert (DER), Base64URL without padding
  2. requestSessionKey = AES session key, RSA-OAEP encrypted to NIRA cert public key
  3. requestHMAC     = AES-GCM encrypted UPPERCASE SHA-256 hex digest of inner request
  4. request         = AES-GCM encrypted timestamp + signed biometric blocks
                     Layout: ciphertext || gcm_tag || nonce (nonce at END)
  5. Signature       = detached JWS (RS256) over request body
                     Format: base64url(header)..base64url(signature)
                     Header: {"alg":"RS256","x5c":["<std Base64 DER partner cert>"]}

Run on the server:
  python3 nira_auth_step3.py <token> <nin> \
      --cert nira-cert.pem --key partner-key.pem --partner-cert partner-cert.pem \
      --blocks blocks.json

Files needed:
  nira-cert.pem     — NIRA encryption certificate from GET /nira/certificate response
  partner-key.pem   — Partner private key (BEGIN PRIVATE KEY) for JWS signing
  partner-cert.pem  — Partner certificate PEM (for JWS x5c header)
  blocks.json       — Signed biometric blocks from MOSIP SBI capture (required)

Environment:
  DOMAIN_URI — domainUri in the request body (default:
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

GCM_NONCE_SIZE = 16


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def load_file(path: str) -> str:
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def load_json_file(path: str):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def extract_block_metadata(blocks) -> tuple:
    """Decode the first Mosip block's JWT data field to extract
    transactionId and env for binding with the outer request.

    blocks may be a list of blocks or a dict with a "biometrics" key.

    Returns: (transaction_id, env) or (None, None)
    """
    if isinstance(blocks, dict):
        block_list = blocks.get("biometrics", [])
    elif isinstance(blocks, list):
        block_list = blocks
    else:
        return None, None

    if not block_list:
        return None, None

    block = block_list[0]
    data_jwt = block.get("data", "")
    parts = data_jwt.split(".")
    if len(parts) < 2:
        return None, None
    payload_b64 = parts[1] + "=="
    payload = json.loads(base64.urlsafe_b64decode(payload_b64))
    return payload.get("transactionId"), payload.get("env")


def compute_thumbprint(cert_pem: str) -> str:
    """SHA-256 of the DER-encoded certificate, Base64URL without padding (43 chars)."""
    cert = load_pem_x509_certificate(cert_pem.encode("utf-8"))
    der = cert.public_bytes(serialization.Encoding.DER)
    return base64.urlsafe_b64encode(hashlib.sha256(der).digest()).rstrip(b"=").decode("ascii")


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
    """AES-256-GCM encrypt per NIRA spec sections 11.2 / 11.4.

    Layout: ciphertext || gcm_tag || nonce (nonce at END — not beginning).
    Base64URL-encode without padding.
    """
    aesgcm = AESGCM(key)
    nonce = os.urandom(GCM_NONCE_SIZE)
    ct_and_tag = aesgcm.encrypt(nonce, plaintext, None)  # ciphertext || tag
    request_bytes = ct_and_tag + nonce  # ciphertext || tag || nonce
    return b64url_encode(request_bytes)


def aes_gcm_decrypt(encoded: str, key: bytes) -> bytes:
    """Reverse of aes_gcm_encrypt: base64url-decode, split ciphertext||tag||nonce."""
    raw = base64.urlsafe_b64decode(encoded + "==")
    nonce = raw[-GCM_NONCE_SIZE:]
    ct_and_tag = raw[:-GCM_NONCE_SIZE]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct_and_tag, None)


def round_trip_self_test(session_key: bytes) -> bool:
    """Verify AES-GCM round-trip and the NIRA 16-byte nonce layout."""
    test = b'{"test":"round-trip"}'
    enc = aes_gcm_encrypt(test, session_key)
    raw = base64.urlsafe_b64decode(enc + "==")
    if len(raw) != len(test) + 16 + GCM_NONCE_SIZE:
        return False
    return aes_gcm_decrypt(enc, session_key) == test


def build_inner_request(transaction_id: str, nin: str, dob: str,
                        surname: str, given_names: str, blocks,
                        domain_uri: str, env: str, timestamp: str) -> dict:
    """Build the inner (plaintext) NIRA AUTH request per spec section 8.

    Structure: { "timestamp", "biometrics" } plus identity/demographic fields.
    """
    biometric_blocks = (
        blocks.get("biometrics", []) if isinstance(blocks, dict) else blocks
    )
    if not isinstance(biometric_blocks, list) or not biometric_blocks:
        raise ValueError("NIRA AUTH requires at least one signed biometric block")
    return {
        "id": "mosip.identity.auth",
        "version": "1.0",
        "transactionID": transaction_id,
        "timestamp": timestamp,
        "env": env,
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
        "requestedAuth": {
            "otp": False,
            "demo": False,
            "bio": True,
        },
        "biometric": {
            "biometric_type": "FINGERPRINT",
            "format": "MOSIP_SBI_SIGNED",
            "blocks": biometric_blocks,
        },
    }


def make_jws(payload: bytes, private_key_pem: str, partner_cert_pem: str) -> str:
    """Create a detached JWS (RS256) per NIRA spec section 11.5.

    Header: {"alg":"RS256","x5c":["<standard Base64 DER partner cert>"]}
    Signing input: base64url(header) + "." + base64url(request body)
    Signature: RSASSA-PKCS1-v1_5 / SHA-256
    Output: base64url(header)..base64url(signature)  (detached, empty payload)
    """
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode("utf-8"), password=None
    )

    # Partner certificate DER -> standard Base64 with padding for x5c
    partner_cert = load_pem_x509_certificate(partner_cert_pem.encode("utf-8"))
    cert_der = partner_cert.public_bytes(serialization.Encoding.DER)
    cert_b64_standard = base64.b64encode(cert_der).decode("ascii")

    header = {"alg": "RS256", "x5c": [cert_b64_standard]}
    header_b64 = b64url_encode(
        json.dumps(header, separators=(",", ":")).encode("utf-8")
    )
    payload_b64 = b64url_encode(payload)
    signing_input = (header_b64 + "." + payload_b64).encode("ascii")
    signature = private_key.sign(
        signing_input, padding.PKCS1v15(), hashes.SHA256()
    )
    sig_b64 = b64url_encode(signature)
    return header_b64 + ".." + sig_b64


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
    parser.add_argument("--partner-cert", default="partner-cert.pem",
                        help="Path to partner certificate PEM for JWS x5c (default: partner-cert.pem)")
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

    # domainUri for the NIRA auth request (DOMAIN_URI env var)
    domain_uri = os.environ.get("DOMAIN_URI",
                                "https://api-internal-preprod.nsis.nira.go.ug")

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

    # Self-test: verify AES-GCM encrypt/decrypt round-trips before sending
    self_test_ok = round_trip_self_test(session_key)
    print(f"AES-GCM round-trip self-test: {'PASS' if self_test_ok else 'FAIL'}")
    if not self_test_ok:
        raise RuntimeError("AES-GCM self-test failed; refusing to send AUTH request")

    # ---- Step D: Load biometric blocks (fingerprint capture) ----
    blocks = None
    block_transaction_id = None
    block_env = None
    if os.path.exists(args.blocks):
        blocks = load_json_file(args.blocks)
        block_count = (
            len(blocks.get("biometrics", []))
            if isinstance(blocks, dict)
            else len(blocks)
        )
        print(f"Loaded {block_count} biometric block(s) from {args.blocks}")
        block_transaction_id, block_env = extract_block_metadata(blocks)
        if block_transaction_id:
            print(f"Block transactionId: {block_transaction_id}")
        if block_env:
            print(f"Block env: {block_env}")
    else:
        print(f"ERROR: {args.blocks} not found — a signed biometric block is required")
        sys.exit(1)

    # ---- Step E: Build inner request ----
    transaction_id = block_transaction_id or str(uuid.uuid4().int)[:10]
    env = block_env or "Pre-Production"
    request_time = datetime.now(timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%S.%f"
    )[:-3] + "Z"
    inner_request = build_inner_request(transaction_id, nin, dob, surname,
                                        given_names, blocks, domain_uri, env,
                                        request_time)
    inner_request_json = json.dumps(inner_request, separators=(",", ":")).encode("utf-8")
    print(f"Inner request size: {len(inner_request_json)} bytes")

    # ---- Step F: Compute requestHMAC ----
    digest = hashlib.sha256(inner_request_json).hexdigest().upper()
    request_hmac = aes_gcm_encrypt(digest.encode("utf-8"), session_key)
    print(f"requestHMAC (AES-GCM of uppercase SHA-256): {request_hmac}")
    print(f"requestHMAC length: {len(request_hmac)} chars")

    # ---- Step G: Compute encrypted request field ----
    request_field = aes_gcm_encrypt(inner_request_json, session_key)
    print(f"request (AES-GCM encrypted payload): {request_field}")
    print(f"request length: {len(request_field)} chars")

    # ---- Step H: Build outer request body ----
    outer_body = {
        "id": "mosip.identity.auth",
        "version": "1.0",
        "transactionID": transaction_id,
        "requestTime": request_time,
        "env": env,
        "domainUri": domain_uri,
        "individualId": nin.lower() + "@nin",
        "individualIdType": "HANDLE",
        "consentObtained": True,
        "requestedAuth": inner_request["requestedAuth"],
        "thumbprint": thumbprint,
        "requestSessionKey": request_session_key,
        "requestHMAC": request_hmac,
        "request": request_field,
    }
    outer_body_json = json.dumps(outer_body, separators=(",", ":")).encode("utf-8")
    print(f"Outer body size: {len(outer_body_json)} bytes")

    # ---- Step I: Create JWS signature ----
    signature = None
    if os.path.exists(args.key) and os.path.exists(args.partner_cert):
        partner_private_key_pem = load_file(args.key)
        partner_cert_pem = load_file(args.partner_cert)
        signature = make_jws(outer_body_json, partner_private_key_pem,
                             partner_cert_pem)
        print(f"JWS Signature (detached): {signature[:40]}...")
    else:
        missing = []
        if not os.path.exists(args.key):
            missing.append(args.key)
        if not os.path.exists(args.partner_cert):
            missing.append(args.partner_cert)
        print(f"WARNING: {', '.join(missing)} not found — skipping Signature header "
              f"(NIRA may reject with IDA-MPA-001)")

    # ---- Step J: POST /nira/auth ----
    headers = {
        "X-API-Key": vendor_api_key,
        "X-MISP-License-Key": misp_license_key,
        "X-Partner-ID": partner_id,
        "X-Partner-API-Key": partner_api_key,
        "Authorization": f"Authorization={token}",
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
