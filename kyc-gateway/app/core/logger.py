"""
Detailed structured logging for the KYC Verification API gateway.

Logs in format similar to:
2026-10-25 08:44:25.248 +03:00 [INF] HTTP POST /path responded 200 in 146.9364 ms

Captures detailed request/response information for API calls.
"""

import json
import logging
import sys
from datetime import datetime, timezone, timedelta

_EAT = timezone(timedelta(hours=3))


class DetailedFormatter(logging.Formatter):
    LEVEL_MAP = {
        'DEBUG': 'DBG',
        'INFO': 'INF',
        'WARNING': 'WRN',
        'ERROR': 'ERR',
        'CRITICAL': 'CRT',
    }
    
    def format(self, record: logging.LogRecord) -> str:
        now = datetime.now(_EAT)
        timestamp = now.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] + " +03:00"
        level = self.LEVEL_MAP.get(record.levelname, record.levelname[:3].upper())
        
        # If message is already formatted in our custom style, use it as-is
        msg = record.getMessage()
        
        # For extra detailed logs, check if it's a structured log
        if hasattr(record, 'detailed') and record.detailed:
            return f"{timestamp} [{level}] {msg}"
        
        return f"{timestamp} [{level}] {msg}"


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
            if key not in reserved and key not in payload and not key.startswith('_'):
                payload[key] = value
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def setup_logging(level: int = logging.INFO, use_json: bool = False) -> None:
    handler = logging.StreamHandler(sys.stdout)
    if use_json:
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(DetailedFormatter())
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)
    
    # Also configure uvicorn loggers
    for logger_name in ['uvicorn', 'uvicorn.access', 'uvicorn.error', 'fastapi']:
        log = logging.getLogger(logger_name)
        log.handlers.clear()
        log.addHandler(handler)
        log.propagate = False
