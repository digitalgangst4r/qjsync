"""Atlassian Document Format (ADF) builder for the issue description.

Jira Cloud REST v3 takes rich text as an ADF document (a JSON tree), not wiki
markup. :func:`build_description` assembles the issue body documented in
``docs/FIELD_MAPPING.md`` (§Description): a lead paragraph followed by the
*Environment*, *CVEs*, *Diagnosis*, *Consequence* and *Solution* sections. Every
section degrades gracefully — when its source (mostly the KnowledgeBase) is
missing, a neutral placeholder is emitted instead of crashing or dropping the
heading, so the description is always well-formed ADF.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # pragma: no cover - import only for type checkers
    from qjsync.models.canonical import MergedVulnerability

# ADF document version Jira Cloud expects at the root of a doc node.
_ADF_VERSION = 1
# Shown when a section has no source value, keeping the doc well-formed.
_MISSING = "None"

# Jira Cloud rejects a text field value over jira.text.field.character.limit
# (default 32767 chars) with HTTP 400 CONTENT_LIMIT_EXCEEDED. Qualys `Results`
# (raw scan output) routinely exceeds this, so every text-bearing field is
# truncated below the limit with a margin. The description is one field too, so
# each long section is bounded so their sum stays safely under the limit.
FIELD_CHAR_LIMIT = 32767
_SAFE_FIELD_CHARS = 32000  # margin under the hard limit (ADF overhead + the note)
_SECTION_CHARS = 9000  # per long section in the description (diag/cons/sol)
_MAX_CVES = 150  # cap the CVE bullet list so a huge list can't blow the limit
_TRUNC_NOTE = " […truncated by qjsync: exceeds Jira's 32767-char field limit]"


def truncate_field_text(s: str, limit: int = _SAFE_FIELD_CHARS) -> str:
    """Trim ``s`` to ``limit`` chars (with a visible note) so a single Jira text
    field never exceeds the 32767-char limit (CONTENT_LIMIT_EXCEEDED)."""
    if len(s) <= limit:
        return s
    return s[: max(0, limit - len(_TRUNC_NOTE))] + _TRUNC_NOTE


def _text_node(text: str) -> dict[str, Any]:
    """An ADF inline text node."""
    return {"type": "text", "text": text}


def _paragraph(text: str) -> dict[str, Any]:
    """An ADF paragraph wrapping a single text node."""
    return {"type": "paragraph", "content": [_text_node(text)]}


def text_to_adf(s: str) -> list[dict[str, Any]]:
    """Split ``s`` into ADF paragraph nodes (one per non-empty line).

    Multi-line KnowledgeBase fields (Diagnosis/Consequence/Solution) carry their
    own line breaks; each becomes its own paragraph so the rendered description
    keeps that structure. Empty input degrades to a single placeholder paragraph
    so a section heading is never left dangling.
    """
    lines = [line.strip() for line in s.splitlines()]
    paragraphs = [_paragraph(line) for line in lines if line]
    if not paragraphs:
        return [_paragraph(_MISSING)]
    return paragraphs


def _heading(text: str, *, level: int = 3) -> dict[str, Any]:
    """An ADF heading node."""
    return {
        "type": "heading",
        "attrs": {"level": level},
        "content": [_text_node(text)],
    }


def _bullet_list(items: list[str]) -> dict[str, Any]:
    """An ADF bullet list, one paragraph-bearing list item per string."""
    return {
        "type": "bulletList",
        "content": [
            {"type": "listItem", "content": [_paragraph(item)]} for item in items
        ],
    }


def _section(heading: str, body: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """A heading-3 followed by its body nodes."""
    return [_heading(heading), *body]


def _environment_items(merged: MergedVulnerability) -> list[str]:
    """Bullet strings for the Environment section, skipping absent attributes."""
    asset = merged.asset
    items: list[str] = []
    if asset.os:
        items.append(f"OS: {asset.os}")
    ip_parts = [p for p in (asset.ip, asset.ipv6) if p]
    if ip_parts:
        items.append("IP / IPv6: " + " / ".join(ip_parts))
    if asset.dns:
        items.append(f"DNS: {asset.dns}")
    if asset.netbios:
        items.append(f"NetBIOS: {asset.netbios}")
    if asset.tracking_method:
        items.append(f"Tracking Method: {asset.tracking_method}")
    return items


def build_description(merged: MergedVulnerability) -> dict[str, Any]:
    """Build the ADF issue description for a merged vulnerability.

    Layout (``docs/FIELD_MAPPING.md`` §Description):

    1. Lead paragraph — host + vulnerability one-liner.
    2. **Environment** — OS / IP / IPv6 / DNS / NetBIOS / Tracking Method bullets.
    3. **CVEs** — KB CVE list (or "None").
    4. **Diagnosis** — KB ``DIAGNOSIS``.
    5. **Consequence** — KB ``CONSEQUENCE``.
    6. **Solution** — KB ``SOLUTION``.

    Each section degrades to a "None" placeholder when its KB source is missing.
    """
    asset = merged.asset
    kb = merged.kb

    ip = asset.ip or _MISSING
    dns = asset.dns or _MISSING
    lead = (
        f"Host details: IP {ip} DNS name : {dns} "
        f"Vulnerability details: {merged.title}"
    )

    content: list[dict[str, Any]] = [_paragraph(lead)]

    # Environment.
    env_items = _environment_items(merged)
    env_body = [_bullet_list(env_items)] if env_items else [_paragraph(_MISSING)]
    content += _section("Environment", env_body)

    # CVEs (capped — a huge list could otherwise blow the field limit).
    cve_list = list(kb.cve_list) if kb else []
    if len(cve_list) > _MAX_CVES:
        extra = len(cve_list) - _MAX_CVES
        cve_list = cve_list[:_MAX_CVES] + [f"… (+{extra} more)"]
    cve_body = [_bullet_list(cve_list)] if cve_list else [_paragraph(_MISSING)]
    content += _section("CVEs", cve_body)

    # Diagnosis / Consequence / Solution (multi-line KB text). Each long section is
    # bounded so the assembled description stays under the 32767-char field limit.
    diagnosis = truncate_field_text((kb.diagnosis if kb else None) or "", _SECTION_CHARS)
    content += _section("Diagnosis", text_to_adf(diagnosis))

    consequence = truncate_field_text((kb.consequence if kb else None) or "", _SECTION_CHARS)
    content += _section("Consequence", text_to_adf(consequence))

    solution = truncate_field_text((kb.solution if kb else None) or "", _SECTION_CHARS)
    content += _section("Solution", text_to_adf(solution))

    return {"version": _ADF_VERSION, "type": "doc", "content": content}


__all__ = ["FIELD_CHAR_LIMIT", "build_description", "text_to_adf", "truncate_field_text"]
