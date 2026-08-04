"""
Logger utility for Embedded Runtime Security Monitor (ERSM).
Provides structured logging across the application.
"""

import logging
import os
import sys

def setup_logger(name: str = "ERSM", log_level: str = "INFO") -> logging.Logger:
    """
    Configures and returns a standard logger for ERSM components.
    """
    logger = logging.getLogger(name)
    level = getattr(logging, log_level.upper(), logging.INFO)
    logger.setLevel(level)

    if not logger.handlers:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(level)
        formatter = logging.Formatter(
            "[%(asctime)s] [%(levelname)s] [%(name)s]: %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%SZ"
        )
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

    return logger
