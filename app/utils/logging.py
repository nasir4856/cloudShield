import logging
from logging.handlers import RotatingFileHandler

from flask import Flask


def _handler(path: str, level: int) -> RotatingFileHandler:
    handler = RotatingFileHandler(
        path,
        maxBytes=1_000_000,
        backupCount=5,
        encoding="utf-8",
    )
    handler.setLevel(level)
    handler.setFormatter(
        logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    )
    return handler


def configure_logging(app: Flask) -> None:
    log_dir = app.config["LOG_DIR"]
    log_dir.mkdir(parents=True, exist_ok=True)

    app.logger.setLevel(logging.INFO)
    app.logger.addHandler(_handler(str(app.config["APP_LOG_FILE"]), logging.INFO))
    app.logger.addHandler(_handler(str(app.config["ERROR_LOG_FILE"]), logging.ERROR))

    security_logger = logging.getLogger("cloudshield.security")
    security_logger.setLevel(logging.INFO)
    security_logger.propagate = False
    if not security_logger.handlers:
        security_logger.addHandler(
            _handler(str(app.config["SECURITY_LOG_FILE"]), logging.INFO)
        )

