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


class JSONFormatter(logging.Formatter):
    """Emits every log record as a single-line JSON object."""

    # Fields added by the logging machinery that we do not want to repeat
    _SKIP = frozenset({
        "args", "created", "exc_info", "exc_text", "filename",
        "levelno", "lineno", "message", "module", "msecs",
        "msg", "name", "pathname", "process", "processName",
        "relativeCreated", "stack_info", "taskName", "thread", "threadName",
    })

    def format(self, record: logging.LogRecord) -> str:
        record.getMessage()  # merges args into msg

        log_entry = {
            "timestamp": datetime.now(_EAT).strftime("%Y-%m-%dT%H:%M:%S.") +
                         f"{datetime.now(_EAT).microsecond // 1000:03d}+03:00",
            "level": record.levelname,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        # Attach any extra= fields passed by the caller
        for key, value in record.__dict__.items():
            if key not in self._SKIP and not key.startswith("_"):
                log_entry[key] = value

        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_entry, default=str)


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

        logger.info(
            "Incoming request",
            extra={
                "method": request.method,
                "path": request.url.path,
                "client_ip": client_ip,
                "user_agent": request.headers.get("user-agent", ""),
            },
        )

        response = await call_next(request)

        duration_ms = round(
            (datetime.now(_EAT) - start_time).total_seconds() * 1000, 2
        )

        logger.info(
            "Request completed",
            extra={
                "method": request.method,
                "path": request.url.path,
                "status_code": response.status_code,
                "duration_ms": duration_ms,
                "client_ip": client_ip,
            },
        )

        return response


def setup_logging(debug: bool = False) -> None:
    """Configure root logger with JSON output to both console and daily rotating files."""
    log_level = logging.DEBUG if debug else logging.INFO

    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)

    # Remove any handlers added by uvicorn or previous calls
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # Console handler for development/monitoring
    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level)
    console_handler.setFormatter(JSONFormatter())
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
    file_handler.setFormatter(JSONFormatter())
    file_handler.suffix = "%Y-%m-%d"  # Daily files: middleware.log.2026-05-26
    root_logger.addHandler(file_handler)

    # Quieten noisy third-party loggers
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.error").setLevel(logging.INFO)
