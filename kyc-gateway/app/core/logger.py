"""
Detailed structured logging for the KYC Verification API gateway.

Logs in format similar to:
2026-10-25 08:44:25.248 +03:00 [INF] HTTP POST /path responded 200 in 146.9364 ms

Writes daily date-stamped log files to /app/logs/kyc-gateway-YYYYMMDD.txt
which can be tailed or viewed with less/cat. Rotates at midnight and keeps
the last 30 days.
"""

import glob
import json
import logging
import os
import sys
from datetime import datetime, timezone, timedelta

_EAT = timezone(timedelta(hours=3))

# Ensure logs directory exists inside the container
_LOGS_DIR = "/app/logs"
os.makedirs(_LOGS_DIR, exist_ok=True)


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
        msg = record.getMessage()

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
        reserved = set(logging.LogRecord("", 0, "", 0, "", (), None).__dict__.keys())
        for key, value in record.__dict__.items():
            if key not in reserved and key not in payload and not key.startswith('_'):
                payload[key] = value
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


class DateStampedFileHandler(logging.FileHandler):
    """
    FileHandler that writes to a date-stamped filename (kyc-gateway-YYYYMMDD.txt)
    and rotates automatically at midnight. Keeps the last backup_count days.
    """

    def __init__(self, logs_dir: str, prefix: str = "kyc-gateway",
                 suffix: str = ".txt", encoding: str = "utf-8",
                 backup_count: int = 30):
        self._logs_dir = logs_dir
        self._prefix = prefix
        self._suffix = suffix
        self._encoding = encoding
        self._backup_count = backup_count
        self._current_date = self._today()
        filename = self._filename_for(self._current_date)
        super().__init__(filename, encoding=encoding)

    def _today(self) -> str:
        return datetime.now(_EAT).strftime("%Y%m%d")

    def _filename_for(self, date_str: str) -> str:
        return os.path.join(self._logs_dir, f"{self._prefix}-{date_str}{self._suffix}")

    def _rotate(self) -> None:
        today = self._today()
        if today != self._current_date:
            self.close()
            self._current_date = today
            self.baseFilename = self._filename_for(today)
            self._open()
            self._cleanup()

    def _cleanup(self) -> None:
        pattern = os.path.join(self._logs_dir, f"{self._prefix}-*{self._suffix}")
        files = sorted(glob.glob(pattern))
        if len(files) > self._backup_count:
            for f in files[:-self._backup_count]:
                try:
                    os.remove(f)
                except OSError:
                    pass

    def emit(self, record: logging.LogRecord) -> None:
        self._rotate()
        super().emit(record)


def setup_logging(level: int = logging.INFO, use_json: bool = False) -> None:
    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(level)

    # --- Console (stdout) handler ---
    console_handler = logging.StreamHandler(sys.stdout)
    if use_json:
        console_handler.setFormatter(JsonFormatter())
    else:
        console_handler.setFormatter(DetailedFormatter())
    root.addHandler(console_handler)

    # --- Daily date-stamped file handler ---
    # Writes to /app/logs/kyc-gateway-YYYYMMDD.txt, rotates at midnight,
    # keeps last 30 days. Can be tailed in real time: tail -f kyc-gateway-YYYYMMDD.txt
    file_handler = DateStampedFileHandler(
        logs_dir=_LOGS_DIR,
        prefix="kyc-gateway",
        suffix=".txt",
        encoding="utf-8",
        backup_count=30,
    )
    if use_json:
        file_handler.setFormatter(JsonFormatter())
    else:
        file_handler.setFormatter(DetailedFormatter())
    root.addHandler(file_handler)

    # Also configure uvicorn loggers
    for logger_name in ['uvicorn', 'uvicorn.access', 'uvicorn.error', 'fastapi']:
        log = logging.getLogger(logger_name)
        log.handlers.clear()
        log.addHandler(console_handler)
        log.addHandler(file_handler)
        log.propagate = False
