#!/usr/bin/env python3
"""
Test script for POST /nira/legacy endpoint.
Generates SOAP envelope with WS-Security UsernameToken (PasswordDigest)
for verifying old national ID cards via NIRA TPI.
"""

import base64
import hashlib
import secrets
import sys
from datetime import datetime, timezone, timedelta

# ============================================================
# CONFIGURATION — UPDATE WITH YOUR DETAILS
# ============================================================
NIRA_TPI_USERNAME = "Hamiltel@TPI"
NIRA_TPI_PASSWORD = "5ty7!GJU"

# Your National ID details (from your images)
NATIONAL_ID = "CM9903610CN5AK"      # 14-char NIN
DOCUMENT_ID = "020841233"            # 9-digit card number (OLD card only)
GIVEN_NAMES = "KEVIN"                # Given names
OTHER_NAMES = ""                     # Other names (optional, empty if none)
SURNAME = "SSONKO"                   # Surname
DATE_OF_BIRTH = "11/04/1999"         # DD/MM/YYYY format

# Gateway endpoint
GATEWAY_URL = "http://10.33.33.30:8001/nira/legacy"
VENDOR_API_KEY = "1774eb6283f6202ed9b9d7705583a731c7d03ad8ca2fedd26d7f7413539ee547"
# ============================================================


# EAT timezone (UTC+3)
EAT = timezone(timedelta(hours=3))


def generate_wsse_token(username: str, password: str) -> dict:
    """
    Generate WS-Security UsernameToken with PasswordDigest.
    Digest = Base64(SHA1(nonce + created + SHA1(password)))
    """
    # 16 random bytes for nonce
    nonce_bytes = secrets.token_bytes(16)
    nonce_b64 = base64.b64encode(nonce_bytes).decode("utf-8")

    # Created timestamp in EAT with milliseconds
    now = datetime.now(EAT)
    ms = f"{now.microsecond // 1000:03d}"
    # For WSSE Created element: with colon in timezone (+03:00)
    created = now.strftime("%Y-%m-%dT%H:%M:%S.") + ms + "+03:00"
    # For digest calculation: without colon in timezone (+0300) per NIRA spec
    created_for_digest = now.strftime("%Y-%m-%dT%H:%M:%S.") + ms + "+0300"

    # PasswordDigest = Base64(SHA1(nonce + created + SHA1(password)))
    sha1_password = hashlib.sha1(password.encode("utf-8")).digest()
    created_bytes = created_for_digest.encode("utf-8")
    raw_digest = hashlib.sha1(nonce_bytes + created_bytes + sha1_password).digest()
    digest_b64 = base64.b64encode(raw_digest).decode("utf-8")

    return {
        "username": username,
        "digest": digest_b64,
        "nonce": nonce_b64,
        "created": created,
    }


def build_soap_envelope(token: dict) -> str:
    """Build the complete SOAP 1.1 envelope for verifyPersonInformation."""
    return f'''<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
                   xmlns:fac="http://facade.server.pilatus.thirdparty.tidis.muehlbauer.de/"
                   xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
  <soapenv:Header>
    <wsse:UsernameToken>
      <wsse:Username>{token["username"]}</wsse:Username>
      <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">{token["digest"]}</wsse:Password>
      <wsse:Nonce>{token["nonce"]}</wsse:Nonce>
      <wsse:Created>{token["created"]}</wsse:Created>
    </wsse:UsernameToken>
  </soapenv:Header>
  <soapenv:Body>
    <fac:verifyPersonInformation>
      <request>
        <dateOfBirth>{DATE_OF_BIRTH}</dateOfBirth>
        <documentId>{DOCUMENT_ID}</documentId>
        <givenNames>{GIVEN_NAMES}</givenNames>
        <nationalId>{NATIONAL_ID}</nationalId>
        <otherNames>{OTHER_NAMES}</otherNames>
        <surname>{SURNAME}</surname>
      </request>
    </fac:verifyPersonInformation>
  </soapenv:Body>
</soapenv:Envelope>'''


def main():
    print("=" * 60)
    print("NIRA Legacy TPI Test - verifyPersonInformation")
    print("=" * 60)
    print(f"Gateway URL: {GATEWAY_URL}")
    print(f"Vendor API Key: {VENDOR_API_KEY[:16]}...")
    print(f"NIRA TPI Username: {NIRA_TPI_USERNAME}")
    print(f"National ID: {NATIONAL_ID}")
    print(f"Document ID (9-digit): {DOCUMENT_ID}")
    print(f"Names: {GIVEN_NAMES} {SURNAME}")
    print(f"DOB: {DATE_OF_BIRTH}")
    print()

    # Generate WS-Security token
    token = generate_wsse_token(NIRA_TPI_USERNAME, NIRA_TPI_PASSWORD)
    print("Generated WS-Security token:")
    print(f"  Nonce: {token['nonce']}")
    print(f"  Created: {token['created']}")
    print(f"  Digest: {token['digest']}")
    print()

    # Build SOAP envelope
    soap_body = build_soap_envelope(token)
    print("SOAP Request Body:")
    print(soap_body)
    print()

    # Save to file for curl testing
    with open("soap_request.xml", "w", encoding="utf-8") as f:
        f.write(soap_body)
    print("Saved SOAP request to: soap_request.xml")
    print()

    # Try to send request if httpx available
    try:
        import httpx
    except ImportError:
        print("httpx not installed. Install with: pip install httpx")
        print()
        print("Run manually with curl:")
        print(f'''curl -X POST {GATEWAY_URL} \\
  -H "X-API-Key: {VENDOR_API_KEY}" \\
  -H "Content-Type: text/xml; charset=utf-8" \\
  -H "SOAPAction: \"\"" \\
  -d @soap_request.xml''')
        return

    # Send request
    print("Sending request to gateway...")
    try:
        with httpx.Client(timeout=60.0, verify=False) as client:
            response = client.post(
                GATEWAY_URL,
                content=soap_body.encode("utf-8"),
                headers={
                    "X-API-Key": VENDOR_API_KEY,
                    "Content-Type": "text/xml; charset=utf-8",
                    "SOAPAction": '""',
                },
            )

        print(f"Response Status: {response.status_code}")
        print(f"Response Headers:")
        for k, v in response.headers.items():
            print(f"  {k}: {v}")
        print()
        print("Response Body:")
        print(response.text)

        # Check for verification reference
        if response.status_code == 200:
            x_vref = response.headers.get("x-verification-reference")
            if x_vref:
                print(f"\n✅ SUCCESS! X-Verification-Reference: {x_vref}")
            else:
                print("\n⚠️  HTTP 200 but no X-Verification-Reference header")
                print("Check response body for matchingStatus/cardStatus")

    except httpx.ConnectError as e:
        print(f"❌ Connection failed: {e}")
        print("Is the gateway running at http://10.33.33.30:8001?")
    except httpx.TimeoutException:
        print("❌ Request timed out")
    except Exception as e:
        print(f"❌ Error: {e}")


if __name__ == "__main__":
    main()