"""Small :mod:`xml.etree.ElementTree` helpers shared by the Qualys readers.

Qualys XML is verbose and every numeric/boolean field arrives as text that may be
missing, empty, or malformed. These helpers centralise the "find a child element,
read its text, coerce it, tolerate absence" pattern so the detection and
KnowledgeBase parsers stay declarative and never raise on a missing optional
element.

All getters return ``None`` (rather than raising) when the element is absent or
the value cannot be coerced — the canonical model treats every Qualys field as
optional and simply omits it downstream.
"""

from __future__ import annotations

from collections.abc import Iterator
from xml.etree.ElementTree import Element


def text(el: Element | None, path: str) -> str | None:
    """Return the stripped text of ``el.find(path)``, or ``None`` if absent/empty.

    ``path`` may be ``"."`` to read the element's own text. Whitespace-only text
    is treated as empty (``None``).
    """
    if el is None:
        return None
    found = el if path == "." else el.find(path)
    if found is None or found.text is None:
        return None
    value = found.text.strip()
    return value or None


def intval(el: Element | None, path: str) -> int | None:
    """Read a child element as an ``int``, or ``None`` if absent/non-numeric."""
    raw = text(el, path)
    if raw is None:
        return None
    try:
        return int(raw)
    except ValueError:
        # Tolerate decimal-looking integers, e.g. "5.0".
        try:
            return int(float(raw))
        except ValueError:
            return None


def floatval(el: Element | None, path: str) -> float | None:
    """Read a child element as a ``float``, or ``None`` if absent/non-numeric."""
    raw = text(el, path)
    if raw is None:
        return None
    try:
        return float(raw)
    except ValueError:
        return None


def boolval(el: Element | None, path: str) -> bool | None:
    """Read a Qualys ``0``/``1`` flag as ``bool``, or ``None`` if absent/unknown.

    ``"1"`` -> ``True``, ``"0"`` -> ``False``; anything else (including a missing
    element) -> ``None`` so an unknown flag is never silently coerced to ``False``.
    """
    raw = text(el, path)
    if raw is None:
        return None
    if raw == "1":
        return True
    if raw == "0":
        return False
    return None


def find_all(el: Element | None, path: str) -> list[Element]:
    """Return every element matching ``path`` (empty list if ``el`` is ``None``)."""
    if el is None:
        return []
    return el.findall(path)


def texts(el: Element | None, path: str) -> list[str]:
    """Extract the stripped, non-empty text of every element matching ``path``.

    The workhorse list extractor: e.g. ``texts(host, "TAGS/TAG/NAME")`` yields the
    asset's tag names, ``texts(vuln, "CVE_LIST/CVE/ID")`` the CVE ids.
    """
    out: list[str] = []
    for child in find_all(el, path):
        if child.text is None:
            continue
        value = child.text.strip()
        if value:
            out.append(value)
    return out


def iter_elements(el: Element | None, path: str) -> Iterator[Element]:
    """Yield each element matching ``path`` (lazy companion to :func:`find_all`)."""
    yield from find_all(el, path)
