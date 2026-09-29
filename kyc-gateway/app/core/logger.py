"""
Structured JSON logging for the KYC Verification API gateway.

Fingerprint/biometric template data must NEVER be written to logs — callers
should log only presence/byte-length of biometric fields, never the raw value.
"""

import json
import logging
import sys
from datetime import datetime, timezone, timedelta

_EAT = timezone(timedelta(hours=3))


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": datetime.now(_EAT).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+03:00",
            "level": record.levelname,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }
        # Include any extra fields attached via `extra={...}`
        reserved = set(logging.LogRecord("", 0, "", 0, "", (), None).__dict__.keys())
        for key, value in record.__dict__.items():
            if key not in reserved and key not in payload:
                payload[key] = value
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def setup_logging(level: int = logging.INFO) -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)
