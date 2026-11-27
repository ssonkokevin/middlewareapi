#!/usr/bin/env python3
"""
Generates a ready-to-use curl command for testing POST /nira/legacy
Run this script, then copy-paste the output curl command to your server.
"""

import base64
import hashlib
import secrets
from datetime import datetime, timezone, timedelta

# ============================================================
# CONFIGURATION
# ============================================================
NIRA_TPI_USERNAME = "Hamiltel@TPI"
NIRA_TPI_PASSWORD = "5ty7!GJU"

# National ID details
NATIONAL_ID = "CM9903610CN5AK"
DOCUMENT_ID = "020841233"
GIVEN_NAMES = "KEVIN"
OTHER_NAMES = ""
SURNAME = "SSONKO"
DATE_OF_BIRTH = "11/04/1999"

GATEWAY_URL = "http://10.33.33.30:8001/nira/legacy"
VENDOR_API_KEY = "1774eb6283f6202ed9b9d7705583a731c7d03ad8ca2fedd26d7f7413539ee547"
# ============================================================

EAT = timezone(timedelta(hours=3))


def generate_wsse_token(username: str, password: str) -> dict:
    nonce_bytes = secrets.token_bytes(16)
    nonce_b64 = base64.b64encode(nonce_bytes).decode("utf-8")

    now = datetime.now(EAT)
    ms = f"{now.microsecond // 1000:03d}"
    created = now.strftime("%Y-%m-%dT%H:%M:%S.") + ms + "+03:00"
    created_for_digest = now.strftime("%Y-%m-%dT%H:%M:%S.") + ms + "+0300"

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
    token = generate_wsse_token(NIRA_TPI_USERNAME, NIRA_TPI_PASSWORD)
    soap_body = build_soap_envelope(token)

    # Escape for curl -d (replace " with \", newlines with nothing)
    soap_escaped = soap_body.replace('"', '\\"').replace('\n', '')

    curl_cmd = f'''curl -X POST "{GATEWAY_URL}" \\
  -H "X-API-Key: {VENDOR_API_KEY}" \\
  -H "Content-Type: text/xml; charset=utf-8" \\
  -H "SOAPAction: \\"\\"" \\
  -d "{soap_escaped}"'''

    print("=" * 70)
    print("COPY-PASTE THIS CURL COMMAND TO YOUR SERVER:")
    print("=" * 70)
    print()
    print(curl_cmd)
    print()
    print("=" * 70)
    print()
    print("WS-Security details (for reference):")
    print(f"  Username: {token['username']}")
    print(f"  Nonce: {token['nonce']}")
    print(f"  Created: {token['created']}")
    print(f"  Digest: {token['digest']}")
    print()
    print("SOAP saved to: soap_request.xml")

    with open("soap_request.xml", "w", encoding="utf-8") as f:
        f.write(soap_body)


if __name__ == "__main__":
    main()