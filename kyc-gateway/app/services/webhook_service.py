"""
Outbound batch-completion webhook delivery (BATCH COMPLETION WEBHOOK in the
spec). This gateway plays UCC's role, so it SIGNS and SENDS this
notification — it does not receive/verify one.

Delivery semantics per the spec:
  - fired once a batch reaches `completed` or `failed`
  - operator endpoint must answer 2xx within KYC_WEBHOOK_TIMEOUT_SECONDS
  - non-2xx, connection error, or timeout is retried with increasing
    backoff, up to KYC_WEBHOOK_MAX_RETRIES attempts total
  - if no KYC_WEBHOOK_URL is configured, no notification is sent — this is
    a supported configuration, not an error

Signing: HMAC-SHA256 over the raw JSON body, keyed on KYC_WEBHOOK_SECRET,
sent as `X-KYC-Signature: sha256=<hex digest>`.
"""

import hashlib
import hmac
import json
import logging
import time

import httpx

from app.core.config import settings
from app.schemas.kyc import BatchCompletedEvent

logger = logging.getLogger("kyc_gateway")


def _sign(body: bytes) -> str:
    digest = hmac.new(settings.KYC_WEBHOOK_SECRET.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def send_batch_completed(event: BatchCompletedEvent) -> None:
    if not settings.KYC_WEBHOOK_URL:
        return  # no URL registered — supported, not an error

    if not settings.KYC_WEBHOOK_SECRET:
        logger.warning(
            "KYC_WEBHOOK_URL is set but KYC_WEBHOOK_SECRET is not — refusing to send "
            "an unsigned webhook (per spec, an unsecured webhook URL is a "
            "misconfiguration, not a supported setup)."
        )
        return

    body = json.dumps(event.model_dump(mode="json"), separators=(",", ":")).encode("utf-8")
    headers = {"Content-Type": "application/json", "X-KYC-Signature": _sign(body)}

    delay = 1.0
    for attempt in range(1, settings.KYC_WEBHOOK_MAX_RETRIES + 1):
        try:
            response = httpx.post(
                settings.KYC_WEBHOOK_URL, content=body, headers=headers,
                timeout=settings.KYC_WEBHOOK_TIMEOUT_SECONDS,
            )
            if 200 <= response.status_code < 300:
                return
            logger.warning(
                f"Webhook delivery attempt {attempt} got HTTP {response.status_code}; "
                f"job_id={event.job_id}"
            )
        except httpx.HTTPError as exc:
            logger.warning(f"Webhook delivery attempt {attempt} failed: {exc}; job_id={event.job_id}")

        if attempt < settings.KYC_WEBHOOK_MAX_RETRIES:
            time.sleep(delay)
            delay *= 2

    logger.error(
        f"Webhook delivery abandoned after {settings.KYC_WEBHOOK_MAX_RETRIES} attempts; "
        f"job_id={event.job_id}"
    )
