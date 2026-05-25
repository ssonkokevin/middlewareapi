"""
NIRA service — Uganda National ID verification via SOAP/XML with WS-Security.

Protocol details:
  - Endpoint : SOAP 1.1 over HTTP (internal network, self-signed cert)
  - Auth     : WS-Security UsernameToken with PasswordDigest
  - Digest   : Base64( SHA1( nonce_bytes + created_bytes + password_bytes ) )
  - Timezone : EAT (UTC+3) for the Created timestamp
"""

import base64
import hashlib
import logging
import secrets
import xml.etree.ElementTree as ET
from datetime import datetime, timezone, timedelta
from typing import Dict, Any

import httpx

from app.core.config import settings

logger = logging.getLogger("middleware")

# EAT timezone offset (UTC+3)
_EAT = timezone(timedelta(hours=3))

# XML namespace map used when parsing the NIRA response
_NS = {
    "soap": "http://schemas.xmlsoap.org/soap/envelope/",
    "ns2":  "http://facade.server.pilatus.thirdparty.tidis.muehlbauer.de/",
}


class NiraService:
    """Handles all communication with the NIRA SOAP endpoint."""

    # ------------------------------------------------------------------ private helpers

    def _make_security_header(self, password: str) -> Dict[str, str]:
        """
        Generate a fresh WS-Security token for every request.

        Args:
            password: The NIRA WS-Security password for this environment.

        Returns a dict with three keys:
            nonce_b64   – Base64-encoded random nonce (16 bytes)
            created     – ISO-8601 timestamp in EAT (e.g. 2026-05-19T15:22:05.765+03:00)
            digest      – Base64( SHA1( nonce_bytes + created_utf8 + SHA1(password) ) )
        """
        # 16 cryptographically random bytes, new for every call
        nonce_bytes: bytes = secrets.token_bytes(16)

        # Created timestamp in EAT with millisecond precision
        now = datetime.now(_EAT)
        created: str = now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}+03:00"

        # PasswordDigest = Base64( SHA1( nonce + created + SHA1(password) ) )
        # Per NIRA spec NB: pre-hash password first, then concatenate as bytes
        sha1_password: bytes = hashlib.sha1(password.encode("utf-8")).digest()
        created_bytes: bytes = created.encode("utf-8")
        raw_digest: bytes = hashlib.sha1(nonce_bytes + created_bytes + sha1_password).digest()

        nonce_b64: str = base64.b64encode(nonce_bytes).decode("utf-8")
        digest_b64: str = base64.b64encode(raw_digest).decode("utf-8")

        logger.debug(
            "Generated WS-Security token",
            extra={"service": "nira", "created": created},
        )

        return {
            "nonce_b64": nonce_b64,
            "created": created,
            "digest": digest_b64,
        }

    def _build_soap_envelope(
        self,
        national_id: str,
        date_of_birth: str,
        document_id: str,
        given_names: str,
        other_names: str,
        surname: str,
        username: str,
        password: str,
    ) -> str:
        """
        Build the complete SOAP XML envelope that matches the real NIRA log format.

        Args:
            national_id   : e.g. "CM9900910UKVUL"
            date_of_birth : DD/MM/YYYY format, e.g. "11/11/1999"
            document_id   : e.g. "022815224" (optional, send empty string if unknown)
            given_names   : first / given names (optional)
            other_names   : middle names, send "?" when unknown
            surname       : family name (optional)
            username      : NIRA WS-Security username for this environment
            password      : NIRA WS-Security password for this environment

        Returns:
            UTF-8 XML string ready to POST.
        """
        token = self._make_security_header(password)

        envelope = f"""<soapenv:Envelope \
xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" \
xmlns:fac="http://facade.server.pilatus.thirdparty.tidis.muehlbauer.de/" \
xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
  <soapenv:Header>
    <wsse:UsernameToken>
      <wsse:Username>{username}</wsse:Username>
      <wsse:Password Type="PasswordDigest">{token["digest"]}</wsse:Password>
      <wsse:Nonce>{token["nonce_b64"]}</wsse:Nonce>
      <wsse:Created>{token["created"]}</wsse:Created>
    </wsse:UsernameToken>
  </soapenv:Header>
  <soapenv:Body>
    <fac:verifyPersonInformation>
      <request>
        <dateOfBirth>{date_of_birth}</dateOfBirth>
        <documentId>{document_id}</documentId>
        <givenNames>{given_names}</givenNames>
        <nationalId>{national_id}</nationalId>
        <otherNames>{other_names}</otherNames>
        <surname>{surname}</surname>
      </request>
    </fac:verifyPersonInformation>
  </soapenv:Body>
</soapenv:Envelope>"""

        return envelope

    def _parse_response(self, xml_text: str) -> Dict[str, Any]:
        """
        Parse the NIRA SOAP XML response into a clean Python dict.

        Expected XML structure (abbreviated):
            <soap:Envelope>
              <soap:Body>
                <ns2:verifyPersonInformationResponse>
                  <return>
                    <transactionStatus>
                      <transactionStatus>Ok</transactionStatus>
                      <passwordDaysLeft>11</passwordDaysLeft>
                      <executionCost>0.0</executionCost>
                    </transactionStatus>
                    <matchingStatus>false</matchingStatus>
                    <cardStatus>Valid</cardStatus>
                  </return>
                </ns2:verifyPersonInformationResponse>
              </soap:Body>
            </soap:Envelope>
        """
        root = ET.fromstring(xml_text)

        body = root.find("soap:Body", _NS)
        if body is None:
            raise ValueError("NIRA response missing <soap:Body>")

        # Walk to <return> regardless of exact ns2 prefix in response
        response_el = None
        for child in body:
            return_el = child.find("return")
            if return_el is not None:
                response_el = return_el
                break

        if response_el is None:
            raise ValueError("NIRA response missing <return> element")

        # Extract transactionStatus block
        tx_status_el = response_el.find("transactionStatus")
        transaction_status = ""
        password_days_left = ""
        execution_cost = ""

        if tx_status_el is not None:
            tx_inner = tx_status_el.find("transactionStatus")
            transaction_status = tx_inner.text if tx_inner is not None else ""

            pdays = tx_status_el.find("passwordDaysLeft")
            password_days_left = pdays.text if pdays is not None else ""

            cost = tx_status_el.find("executionCost")
            execution_cost = cost.text if cost is not None else ""

        matching_el = response_el.find("matchingStatus")
        matching_status_raw = matching_el.text if matching_el is not None else "false"
        matching_status: bool = matching_status_raw.strip().lower() == "true"

        card_el = response_el.find("cardStatus")
        card_status = card_el.text if card_el is not None else ""

        return {
            "transaction_status": transaction_status,
            "matching_status": matching_status,
            "card_status": card_status,
            "password_days_left": password_days_left,
            "execution_cost": execution_cost,
        }

    # ------------------------------------------------------------------ public API

    async def verify_person(
        self,
        national_id: str,
        date_of_birth: str,
        document_id: str = "",
        given_names: str = "",
        other_names: str = "?",
        surname: str = "",
        url: str = None,
        username: str = None,
        password: str = None,
        environment: str = "production",
    ) -> Dict[str, Any]:
        """
        Verify a person's National ID against the NIRA SOAP endpoint.

        Args:
            national_id   : Uganda National ID number (required)
            date_of_birth : DD/MM/YYYY (required)
            document_id   : Physical card document number (optional)
            given_names   : First / given names (optional)
            other_names   : Middle names; defaults to "?" when unknown
            surname       : Family / last name (optional)
            url           : NIRA SOAP endpoint URL for this environment
            username      : WS-Security username for this environment
            password      : WS-Security password for this environment
            environment   : "production" or "test" (used only for logging)

        Returns:
            dict with keys: transaction_status, matching_status, card_status,
                            password_days_left, execution_cost

        Raises:
            Exception: wraps timeout, connection, HTTP, or parse errors
        """
        start_time = datetime.now(_EAT)

        logger.info(
            "Calling NIRA SOAP endpoint",
            extra={
                "service": "nira",
                "environment": environment,
                "url": url,
                "nationalId": national_id,
                "dateOfBirth": date_of_birth,
            },
        )

        soap_body = self._build_soap_envelope(
            national_id=national_id,
            date_of_birth=date_of_birth,
            document_id=document_id,
            given_names=given_names,
            other_names=other_names,
            surname=surname,
            username=username,
            password=password,
        )

        headers = {
            "Content-Type": "text/xml; charset=utf-8",
            "SOAPAction": '""',
            "User-Agent": "Middleware-API-Gateway/1.0.0",
        }

        try:
            # verify=False — NIRA uses a self-signed internal certificate
            # timeout=30 s: NIRA is on the local network and responds quickly
            async with httpx.AsyncClient(
                timeout=30, verify=False
            ) as client:
                response = await client.post(url, content=soap_body.encode("utf-8"), headers=headers)

            duration_ms = round(
                (datetime.now(_EAT) - start_time).total_seconds() * 1000, 2
            )

            logger.info(
                "NIRA HTTP response received",
                extra={
                    "service": "nira",
                    "environment": environment,
                    "status_code": response.status_code,
                    "duration_ms": duration_ms,
                    "nationalId": national_id,
                },
            )

            if response.status_code != 200:
                raise Exception(
                    f"NIRA returned HTTP {response.status_code}: {response.text[:300]}"
                )

            parsed = self._parse_response(response.text)

            logger.info(
                "NIRA verification completed",
                extra={
                    "service": "nira",
                    "environment": environment,
                    "nationalId": national_id,
                    "transaction_status": parsed["transaction_status"],
                    "matching_status": parsed["matching_status"],
                    "card_status": parsed["card_status"],
                    "duration_ms": duration_ms,
                },
            )

            return parsed

        except httpx.TimeoutException:
            duration_ms = round(
                (datetime.now(_EAT) - start_time).total_seconds() * 1000, 2
            )
            logger.error(
                "NIRA request timed out",
                extra={
                    "service": "nira",
                    "environment": environment,
                    "nationalId": national_id,
                    "timeout_s": 30,
                    "duration_ms": duration_ms,
                },
            )
            raise Exception("NIRA timed out after 30 seconds")

        except httpx.RequestError as exc:
            duration_ms = round(
                (datetime.now(_EAT) - start_time).total_seconds() * 1000, 2
            )
            logger.error(
                "NIRA connection error",
                extra={
                    "service": "nira",
                    "environment": environment,
                    "nationalId": national_id,
                    "error": str(exc),
                    "duration_ms": duration_ms,
                },
            )
            raise Exception(f"NIRA connection error: {exc}")

        except ET.ParseError as exc:
            logger.error(
                "Failed to parse NIRA XML response",
                extra={"service": "nira", "environment": environment, "nationalId": national_id, "error": str(exc)},
            )
            raise Exception(f"NIRA returned invalid XML: {exc}")

        except Exception:
            raise


# Application-wide singleton
nira_service = NiraService()
