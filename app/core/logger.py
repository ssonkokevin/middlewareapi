"""
Logging configuration for the middleware API gateway.
Provides structured logging matching production KYC app format.
"""

import logging
import os
from logging.handlers import RotatingFileHandler

# Remap level names to match production format
logging.addLevelName(logging.INFO, "INF")
logging.addLevelName(logging.WARNING, "WRN")
logging.addLevelName(logging.ERROR, "ERR")
logging.addLevelName(logging.DEBUG, "DBG")


def setup_logging() -> None:
    """Configure logging with exact production format and rotating file handler."""
    from app.core.config import settings
    
    # Set log level based on DEBUG setting
    log_level = logging.DEBUG if settings.DEBUG else logging.INFO
    
    # Create logs directory if it doesn't exist
    logs_dir = os.path.join(os.getcwd(), "logs")
    os.makedirs(logs_dir, exist_ok=True)
    
    # Define the exact format matching production
    formatter = logging.Formatter(
        fmt="%(asctime)s.%(msecs)03d +03:00 [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    
    # Get root logger and set level
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    
    # Remove any existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level)
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)
    
    # Rotating file handler
    file_handler = RotatingFileHandler(
        filename=os.path.join(logs_dir, "middleware.log"),
        maxBytes=10 * 1024 * 1024,  # 10MB
        backupCount=5,
        encoding="utf-8"
    )
    file_handler.setLevel(log_level)
    file_handler.setFormatter(formatter)
    root_logger.addHandler(file_handler)
    
    # Suppress noisy third-party loggers
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("watchfiles").setLevel(logging.WARNING)
