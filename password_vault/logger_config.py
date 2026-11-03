"""Application logging configuration."""

import logging
from pathlib import Path


def configure_logging(log_path: str | Path = "vault.log") -> logging.Logger:
    """Configure console and file activity logging without secret data."""
    logging.basicConfig(
        filename=log_path,
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))

    root_logger = logging.getLogger()
    if not any(
        isinstance(handler, logging.StreamHandler)
        and not isinstance(handler, logging.FileHandler)
        for handler in root_logger.handlers
    ):
        root_logger.addHandler(console_handler)
    return logging.getLogger("password_vault")
