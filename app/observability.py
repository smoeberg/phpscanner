"""Small, dependency-free JSON logging helpers for API and worker processes."""
from __future__ import annotations

import json
import logging
import os
import sys
from datetime import datetime, timezone


class JsonLogFormatter(logging.Formatter):
    """Render one structured JSON object per log record."""

    _FIELDS = (
        "event", "request_id", "method", "path", "status_code",
        "duration_ms", "job_id", "attempt",
    )

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": datetime.fromtimestamp(record.created, timezone.utc).isoformat(),
            "level": record.levelname.lower(),
            "logger": record.name,
            "message": record.getMessage(),
        }
        for field in self._FIELDS:
            value = getattr(record, field, None)
            if value is not None:
                payload[field] = value
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))


def configure_logger(name: str) -> logging.Logger:
    """Configure a dedicated JSON logger without replacing host/test handlers."""
    logger = logging.getLogger(name)
    logger.setLevel(os.getenv("LOG_LEVEL", "INFO").upper())
    logger.propagate = False
    if not any(getattr(handler, "_scanner_json_handler", False) for handler in logger.handlers):
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(JsonLogFormatter())
        handler._scanner_json_handler = True
        logger.addHandler(handler)
    return logger
