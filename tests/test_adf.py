"""Tests for the ADF description builder (:mod:`qjsync.jira.adf`).

Cover the documented layout (lead paragraph + the five heading-3 sections) and
graceful degradation when KnowledgeBase enrichment is missing.
"""

from __future__ import annotations

from typing import Any

from qjsync.jira.adf import build_description, text_to_adf
from qjsync.models.canonical import Asset, Detection, KbVuln, MergedVulnerability


def _headings(doc: dict[str, Any]) -> list[str]:
    return [
        node["content"][0]["text"]
        for node in doc["content"]
        if node["type"] == "heading"
    ]


def _section_body(doc: dict[str, Any], heading: str) -> list[dict[str, Any]]:
    """Nodes between the given heading and the next heading."""
    content = doc["content"]
    out: list[dict[str, Any]] = []
    collecting = False
    for node in content:
        if node["type"] == "heading":
            if collecting:
                break
            collecting = node["content"][0]["text"] == heading
            continue
        if collecting:
            out.append(node)
    return out


def _full_merged() -> MergedVulnerability:
    return MergedVulnerability(
        asset=Asset(
            host_id=42,
            ip="10.0.0.5",
            ipv6="fe80::1",
            dns="web01.example.com",
            netbios="WEB01",
            os="Ubuntu 22.04",
            tracking_method="AGENT",
        ),
        detection=Detection(qid=105413, severity=5),
        kb=KbVuln(
            qid=105413,
            title="OpenSSL Heap Overflow",
            cve_list=["CVE-2022-3602", "CVE-2022-3786"],
            diagnosis="A buffer overflow.\nSecond diagnosis line.",
            consequence="Remote code execution.",
            solution="Upgrade OpenSSL.",
        ),
    )


def test_text_to_adf_splits_lines_into_paragraphs() -> None:
    nodes = text_to_adf("first line\nsecond line")
    assert [n["type"] for n in nodes] == ["paragraph", "paragraph"]
    assert nodes[0]["content"][0]["text"] == "first line"
    assert nodes[1]["content"][0]["text"] == "second line"


def test_text_to_adf_empty_degrades_to_placeholder() -> None:
    nodes = text_to_adf("")
    assert len(nodes) == 1
    assert nodes[0]["content"][0]["text"] == "None"


def test_build_description_structure_and_lead() -> None:
    doc = build_description(_full_merged())

    assert doc["type"] == "doc"
    assert doc["version"] == 1

    # Lead paragraph is first and carries the documented one-liner.
    lead = doc["content"][0]
    assert lead["type"] == "paragraph"
    lead_text = lead["content"][0]["text"]
    assert lead_text == (
        "Host details: IP 10.0.0.5 DNS name : web01.example.com "
        "Vulnerability details: 105413 - OpenSSL Heap Overflow"
    )

    # All five documented sections present, in order.
    assert _headings(doc) == [
        "Environment",
        "CVEs",
        "Diagnosis",
        "Consequence",
        "Solution",
    ]


def test_build_description_environment_bullets() -> None:
    doc = build_description(_full_merged())
    body = _section_body(doc, "Environment")
    assert body[0]["type"] == "bulletList"
    items = [
        item["content"][0]["content"][0]["text"]
        for item in body[0]["content"]
    ]
    assert "OS: Ubuntu 22.04" in items
    assert "IP / IPv6: 10.0.0.5 / fe80::1" in items
    assert "DNS: web01.example.com" in items
    assert "NetBIOS: WEB01" in items
    assert "Tracking Method: AGENT" in items


def test_build_description_cves_listed() -> None:
    doc = build_description(_full_merged())
    body = _section_body(doc, "CVEs")
    assert body[0]["type"] == "bulletList"
    cves = [item["content"][0]["content"][0]["text"] for item in body[0]["content"]]
    assert cves == ["CVE-2022-3602", "CVE-2022-3786"]


def test_build_description_multiline_diagnosis() -> None:
    doc = build_description(_full_merged())
    body = _section_body(doc, "Diagnosis")
    assert [n["content"][0]["text"] for n in body] == [
        "A buffer overflow.",
        "Second diagnosis line.",
    ]


def test_build_description_graceful_without_kb() -> None:
    """No KB: every KB-sourced section degrades to a 'None' placeholder."""
    merged = MergedVulnerability(
        asset=Asset(host_id=1),
        detection=Detection(qid=999),
        kb=None,
    )
    doc = build_description(merged)

    # Still a well-formed doc with all five headings.
    assert _headings(doc) == [
        "Environment",
        "CVEs",
        "Diagnosis",
        "Consequence",
        "Solution",
    ]

    # Lead paragraph uses the 'None' placeholders for missing IP/DNS.
    lead_text = doc["content"][0]["content"][0]["text"]
    assert "IP None" in lead_text
    assert "DNS name : None" in lead_text
    assert "999 - Unknown vulnerability" in lead_text

    # Environment has no attributes -> placeholder paragraph.
    env = _section_body(doc, "Environment")
    assert env[0]["type"] == "paragraph"
    assert env[0]["content"][0]["text"] == "None"

    for heading in ("CVEs", "Diagnosis", "Consequence", "Solution"):
        body = _section_body(doc, heading)
        assert body[0]["content"][0]["text"] == "None"
