"""Structured logging setup for qjsync.

By default logs are emitted as one JSON object per line (timestamp, level,
logger, message, plus any structured extras attached via ``logger.info(...,
extra={...})``) so that a downstream collector can index the per-run summary and
per-detection events without brittle regex parsing. A concise human-readable
``console`` formatter is available for interactive use.

The config's ``logging`` block (:class:`qjsync.config.schema.LoggingConfig`)
drives this via :func:`setup_logging`; :func:`get_logger` is the thin accessor
the rest of the package uses.
"""

from __future__ import annotations

import datetime as _dt
import json
import logging
import sys
from typing import Any

# Attributes present on every stdlib LogRecord; anything else is treated as a
# caller-supplied structured extra and folded into the JSON payload.
_RESERVED_RECORD_ATTRS = frozenset(
    logging.makeLogRecord({}).__dict__
) | {"message", "asctime", "taskName"}

_CONSOLE_FORMAT = "%(asctime)s %(levelname)-8s %(name)s: %(message)s"
_CONSOLE_DATEFMT = "%Y-%m-%d %H:%M:%S"


class JsonFormatter(logging.Formatter):
    """Render a log record as a single-line JSON object.

    Emits ``timestamp`` (UTC, ISO-8601), ``level``, ``logger`` and ``message``,
    appends any structured extras passed via ``extra={...}``, and includes an
    ``exc_info`` traceback string when one is attached.
    """

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": _dt.datetime.fromtimestamp(
                record.created, tz=_dt.UTC
            ).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for key, value in record.__dict__.items():
            if key not in _RESERVED_RECORD_ATTRS and not key.startswith("_"):
                payload[key] = value
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def setup_logging(level: str = "INFO", fmt: str = "json") -> None:
    """Configure the root logger for the process.

    :param level: a stdlib level name (e.g. ``"INFO"``, ``"DEBUG"``); unknown
        names fall back to ``INFO``.
    :param fmt: ``"json"`` for structured JSON lines, anything else for the
        concise console formatter.

    Idempotent: existing handlers on the root logger are removed first so that a
    second call (e.g. across CLI commands) does not duplicate output.
    """
    root = logging.getLogger()
    for handler in list(root.handlers):
        root.removeHandler(handler)

    handler = logging.StreamHandler(stream=sys.stderr)
    formatter: logging.Formatter
    if fmt == "json":
        formatter = JsonFormatter()
    else:
        formatter = logging.Formatter(fmt=_CONSOLE_FORMAT, datefmt=_CONSOLE_DATEFMT)
    handler.setFormatter(formatter)
    root.addHandler(handler)

    resolved = logging.getLevelName(level.upper())
    root.setLevel(resolved if isinstance(resolved, int) else logging.INFO)


def get_logger(name: str) -> logging.Logger:
    """Return the named logger (use ``__name__`` at the call site)."""
    return logging.getLogger(name)
