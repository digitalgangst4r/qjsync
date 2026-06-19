"""The operator registry the rules engine evaluates leaf conditions with.

A leaf condition is ``OPERATORS[op](signal_value, rule_value)`` where
``signal_value`` comes from :meth:`MergedVulnerability.signal_context` (and may be
absent/``None``) and ``rule_value`` is the literal from ``rules.yml``. Keeping the
operators in a flat dict — rather than an ``eval``'d expression — is the
documented design (see config/schema.py): no arbitrary code execution, trivially
testable, and a new operator is a single entry here mirrored by
``config.schema.Operator``.

**None-safety is the contract.** A missing signal evaluates to ``None`` (via
``dict.get``) and *must never raise*. Concretely:

* numeric comparisons (``> >= < <=``) against a ``None`` signal return ``False``;
* ``in`` / ``not_in`` test membership of the signal *within* the rule value
  (a list or string), so a ``None`` signal is simply not a member;
* ``contains`` / ``not_contains`` test the rule value *within* the signal value
  (works for lists and strings), so a ``None`` signal contains nothing;
* ``exists`` is ``True`` iff the signal value is not ``None``;
* ``matches`` runs ``re.search(str(rule_value), str(signal))`` and is ``False`` on
  a ``None`` signal.

This means a leaf over an unknown/missing signal cleanly *fails* (returns
``False``) instead of erroring mid-sync.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any


def _eq(signal: Any, value: Any) -> bool:
    return bool(signal == value)


def _ne(signal: Any, value: Any) -> bool:
    return bool(signal != value)


def _gt(signal: Any, value: Any) -> bool:
    if signal is None or value is None:
        return False
    try:
        return bool(signal > value)
    except TypeError:
        return False


def _ge(signal: Any, value: Any) -> bool:
    if signal is None or value is None:
        return False
    try:
        return bool(signal >= value)
    except TypeError:
        return False


def _lt(signal: Any, value: Any) -> bool:
    if signal is None or value is None:
        return False
    try:
        return bool(signal < value)
    except TypeError:
        return False


def _le(signal: Any, value: Any) -> bool:
    if signal is None or value is None:
        return False
    try:
        return bool(signal <= value)
    except TypeError:
        return False


def _in(signal: Any, value: Any) -> bool:
    """``signal`` is a member of ``value`` (a list/str). ``None`` is never a member."""
    if value is None:
        return False
    try:
        return signal in value
    except TypeError:
        return False


def _not_in(signal: Any, value: Any) -> bool:
    return not _in(signal, value)


def _contains(signal: Any, value: Any) -> bool:
    """``value`` is contained in ``signal`` (works for lists AND strings)."""
    if signal is None:
        return False
    try:
        return value in signal
    except TypeError:
        return False


def _not_contains(signal: Any, value: Any) -> bool:
    return not _contains(signal, value)


def _exists(signal: Any, value: Any) -> bool:
    """``True`` iff the signal value is present (not ``None``); ``value`` ignored."""
    return signal is not None


def _not_exists(signal: Any, value: Any) -> bool:
    return signal is None


def _matches(signal: Any, value: Any) -> bool:
    """Regex search of ``value`` within ``str(signal)``; ``False`` on a None signal."""
    if signal is None:
        return False
    return re.search(str(value), str(signal)) is not None


# Registry mirrored by ``qjsync.config.schema.Operator`` (validated at load time).
OPERATORS: dict[str, Callable[[Any, Any], bool]] = {
    "==": _eq,
    "!=": _ne,
    ">": _gt,
    ">=": _ge,
    "<": _lt,
    "<=": _le,
    "in": _in,
    "not_in": _not_in,
    "contains": _contains,
    "not_contains": _not_contains,
    "exists": _exists,
    "not_exists": _not_exists,
    "matches": _matches,
}


__all__ = ["OPERATORS"]
