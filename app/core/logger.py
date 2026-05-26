"""
Logging configuration for the middleware API gateway.
Provides structured JSON logging for all requests, responses, and external API calls.
Includes daily rotating file logs for persistent storage.
"""

import logging
import json
import os
from datetime import datetime, timezone, timedelta
from typing import Optional
from logging.handlers import TimedRotatingFileHandler
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware

# EAT timezone (UTC+3) — consistent with service layer timestamps
_EAT = timezone(timedelta(hours=3))


class TextFormatter(logging.Formatter):
    """Emits logs in the format: 2026-05-26 10:28:34.228 +03:00 [INF] message"""
    
    LEVEL_MAP = {
        "DEBUG": "DBG",
        "INFO": "INF",
        "WARNING": "WRN",
        "ERROR": "ERR",
        "CRITICAL": "CRT"
    }
    
    def format(self, record: logging.LogRecord) -> str:
        # Get timestamp with milliseconds
        now = datetime.now(_EAT)
        timestamp = now.strftime("%Y-%m-%d %H:%M:%S.") + f"{now.microsecond // 1000:03d} +03:00"
        
        # Map level to 3-letter abbreviation
        level_abbr = self.LEVEL_MAP.get(record.levelname, record.levelname[:3])
        
        # Get the message
        message = record.getMessage()
        
        return f"{timestamp} [{level_abbr}] {message}"


class LoggingMiddleware(BaseHTTPMiddleware):
    """Logs every HTTP request and its response status + duration."""

    async def dispatch(self, request: Request, call_next):
        start_time = datetime.now(_EAT)
        logger = logging.getLogger("middleware")

        # Safely resolve client IP — request.client can be None behind some proxies
        client_ip: str = "unknown"
        if request.headers.get("x-forwarded-for"):
            client_ip = request.headers["x-forwarded-for"].split(",")[0].strip()
        elif request.headers.get("x-real-ip"):
            client_ip = request.headers["x-real-ip"].strip()
        elif request.client is not None:
            client_ip = request.client.host

        logger.info(f"HTTP {request.method} {request.url.path}")

        response = await call_next(request)

        duration_ms = round(
            (datetime.now(_EAT) - start_time).total_seconds() * 1000, 4
        )

        logger.info(f"HTTP {request.method} {request.url.path} responded {response.status_code} in {duration_ms} ms")

        return response


def setup_logging(debug: bool = False) -> None:
    """Configure root logger with text output to both console and daily rotating files."""
    log_level = logging.DEBUG if debug else logging.INFO

    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)

    # Remove any handlers added by uvicorn or previous calls
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # Console handler for development/monitoring
    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level)
    console_handler.setFormatter(TextFormatter())
    root_logger.addHandler(console_handler)

    # Daily rotating file handler for persistent logs
    logs_dir = os.path.join(os.getcwd(), "logs")
    os.makedirs(logs_dir, exist_ok=True)
    
    file_handler = TimedRotatingFileHandler(
        filename=os.path.join(logs_dir, "middleware.log"),
        when="midnight",
        interval=1,
        backupCount=30,  # Keep 30 days of logs
        encoding="utf-8"
    )
    file_handler.setLevel(log_level)
    file_handler.setFormatter(TextFormatter())
    file_handler.suffix = "%Y-%m-%d"  # Daily files: middleware.log.2026-05-26
    root_logger.addHandler(file_handler)

    # Quieten noisy third-party loggers
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.error").setLevel(logging.INFO)
