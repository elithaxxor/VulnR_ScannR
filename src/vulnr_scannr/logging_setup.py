"""Console + SQLite logging with secret redaction."""

from __future__ import annotations

import logging
import re
import sys

from vulnr_scannr.db import Database

LOGGER_NAME = "vulnr_scannr"

_REDACTIONS = [
    # NTLM LM:NT hash pairs
    (re.compile(r"\b[0-9A-Fa-f]{32}:[0-9A-Fa-f]{32}\b"), "[REDACTED-HASH]"),
    # user%password (samba style)
    (re.compile(r"\b([A-Za-z_][\w.\\/-]*)%(\S+)"), r"\1%[REDACTED]"),
    # password=..., pass: ..., SMBPass ...
    (re.compile(r"(?i)\b(pass(?:word)?|smbpass|pwd|secret|token)(\s*[=:]\s*|\s+)(\S+)"), r"\1\2[REDACTED]"),
]


def redact(text: str) -> str:
    for pattern, repl in _REDACTIONS:
        text = pattern.sub(repl, text)
    return text


class RedactingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = redact(record.getMessage())
        record.args = None
        return True


class SQLiteHandler(logging.Handler):
    def __init__(self, db: Database) -> None:
        super().__init__()
        self.db = db

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self.db.log(record.levelname, self.format(record))
        except Exception:  # noqa: BLE001  # pragma: no cover - never let logging crash the scan
            self.handleError(record)


def setup_logging(db: Database | None = None, verbose: bool = False, quiet: bool = False) -> logging.Logger:
    logger = logging.getLogger(LOGGER_NAME)
    for h in list(logger.handlers):
        logger.removeHandler(h)
    for f in list(logger.filters):
        logger.removeFilter(f)
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    logger.propagate = False
    logger.addFilter(RedactingFilter())

    console = logging.StreamHandler(sys.stderr)
    console.setLevel(logging.WARNING if quiet else (logging.DEBUG if verbose else logging.INFO))
    console.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
    logger.addHandler(console)

    if db is not None:
        handler = SQLiteHandler(db)
        handler.setLevel(logging.INFO)
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(handler)
    return logger
