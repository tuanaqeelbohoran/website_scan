"""config/logging_config.py — Structured JSON logging with a separate audit handler."""
import logging.config
from config.settings import settings

LOGGING: dict = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "json": {
            "()": "pythonjsonlogger.jsonlogger.JsonFormatter",
            "format": "%(asctime)s %(name)s %(levelname)s %(message)s",
        },
        "plain": {
            "format": "%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "plain",
            "stream": "ext://sys.stdout",
        },
        "audit_file": {
            "class": "logging.handlers.WatchedFileHandler",
            "formatter": "json",
            "filename": settings.AUDIT_LOG_PATH,
            "mode": "a",
            "encoding": "utf-8",
        },
    },
    "root": {
        "level": settings.LOG_LEVEL,
        "handlers": ["console"],
    },
    "loggers": {
        "webscan.audit": {
            "level": "INFO",
            "handlers": ["audit_file", "console"],
            "propagate": False,
        },
        "webscan.checks": {
            "level": "WARNING",
            "handlers": ["console"],
            "propagate": False,
        },
    },
}


def configure_logging() -> None:
    logging.config.dictConfig(LOGGING)
