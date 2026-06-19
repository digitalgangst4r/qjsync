"""Tests for :mod:`qjsync.logging`.

Verifies that ``setup_logging`` wires the root logger, that ``get_logger``
returns the named logger, and that the JSON format emits one parseable JSON
object per record (with structured extras folded in).
"""

from __future__ import annotations

import json
import logging
from typing import Any

import pytest

from qjsync.logging import JsonFormatter, get_logger, setup_logging


def _make_record(message: str, **extra: Any) -> logging.LogRecord:
    record = logging.LogRecord(
        name="qjsync.test",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg=message,
        args=(),
        exc_info=None,
    )
    for key, value in extra.items():
        setattr(record, key, value)
    return record


def test_get_logger_returns_named_logger() -> None:
    logger = get_logger("qjsync.somewhere")
    assert isinstance(logger, logging.Logger)
    assert logger.name == "qjsync.somewhere"


def test_setup_logging_sets_level_and_single_handler() -> None:
    setup_logging(level="DEBUG", fmt="json")
    root = logging.getLogger()
    assert root.level == logging.DEBUG
    assert len(root.handlers) == 1
    assert isinstance(root.handlers[0].formatter, JsonFormatter)


def test_setup_logging_is_idempotent() -> None:
    setup_logging(level="INFO", fmt="json")
    setup_logging(level="INFO", fmt="console")
    root = logging.getLogger()
    # A second call replaces handlers rather than appending.
    assert len(root.handlers) == 1
    assert not isinstance(root.handlers[0].formatter, JsonFormatter)


def test_setup_logging_unknown_level_falls_back_to_info() -> None:
    setup_logging(level="NOTALEVEL", fmt="json")
    assert logging.getLogger().level == logging.INFO


def test_json_formatter_emits_parseable_json() -> None:
    formatter = JsonFormatter()
    line = formatter.format(_make_record("hello world", primary_key="1:200:none"))
    payload = json.loads(line)  # must be valid JSON
    assert payload["level"] == "INFO"
    assert payload["logger"] == "qjsync.test"
    assert payload["message"] == "hello world"
    assert payload["primary_key"] == "1:200:none"  # structured extra folded in
    assert "timestamp" in payload


def test_json_formatter_captures_record_via_caplog(
    caplog: pytest.LogCaptureFixture,
) -> None:
    # Note: we do NOT call setup_logging here — it would strip pytest's own
    # capture handler off the root logger. We let caplog capture the record and
    # then run the JSON formatter over it.
    logger = get_logger("qjsync.capture")
    with caplog.at_level(logging.INFO, logger="qjsync.capture"):
        logger.info("synced", extra={"created_count": 3})
    record = next(r for r in caplog.records if r.name == "qjsync.capture")
    payload = json.loads(JsonFormatter().format(record))
    assert payload["message"] == "synced"
    assert payload["created_count"] == 3
