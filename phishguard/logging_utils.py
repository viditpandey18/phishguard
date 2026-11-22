"""Structured JSON logging with PII redaction.

Policy: the application logs *metadata only* (scan id, input type, label,
score, latency). Redaction is a second line of defence in case content
ever leaks into a log message or exception string.
"""

from __future__ import annotations

import json
import logging
import re
import sys
from datetime import datetime, timezone

_REDACTIONS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"[\w.+-]+@[\w-]+(\.[\w-]+)*"), "<EMAIL/UPI>"),  # emails and UPI ids (name@okaxis)
    (re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b"), "<PAN>"),
    (re.compile(r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}\b"), "<AADHAAR/CARD>"),
    (re.compile(r"\b(?:\d[\s-]?){13,19}\b"), "<CARD>"),
    (re.compile(r"(?<!\d)(?:\+?\d{1,3}[\s-]?)?[6-9]\d{4}[\s-]?\d{5}(?!\d)"), "<PHONE>"),
    (re.compile(r"(?<!\d)\+\d[\d\s-]{8,14}\d(?!\d)"), "<PHONE>"),
    (re.compile(r"\b\d{6,18}\b"), "<NUMBER>"),  # account numbers, OTPs
    (re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b"), "<IFSC>"),
]


def redact(text: str) -> str:
    for pattern, repl in _REDACTIONS:
        text = pattern.sub(repl, text)
    return text


class RedactingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        try:
            msg = record.getMessage()
        except Exception:
            msg = str(record.msg)
        record.msg, record.args = redact(msg), None
        return True


_STD_ATTRS = set(vars(logging.LogRecord("x", 0, "", 0, "", None, None))) | {"message", "asctime"}


class JSONFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        for k, v in record.__dict__.items():
            if k not in _STD_ATTRS and not k.startswith("_"):
                payload[k] = redact(v) if isinstance(v, str) else v
        if record.exc_info:
            payload["exc_type"] = record.exc_info[0].__name__ if record.exc_info[0] else None
        return json.dumps(payload, default=str, ensure_ascii=False)


def configure_logging(level: str = "INFO", json_format: bool = True) -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.addFilter(RedactingFilter())
    handler.setFormatter(JSONFormatter() if json_format else logging.Formatter("%(levelname)s %(name)s %(message)s"))
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level.upper())
    # uvicorn's access log includes query strings; keep it but redacted via our handler
    for name in ("uvicorn", "uvicorn.access", "uvicorn.error"):
        logging.getLogger(name).handlers[:] = []
        logging.getLogger(name).propagate = True
