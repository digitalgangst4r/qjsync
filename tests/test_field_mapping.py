"""Tests for the Qualys -> Jira field mapper (:mod:`qjsync.jira.mapper`).

Cover the full mapping (every custom field present with the discovered id),
omission of None sources, Yes/No coercion, the connector-written Primary Key,
and the derived patch-routing label.
"""

from __future__ import annotations

import logging

from qjsync.config.schema import JiraConfig, QjsyncConfig
from qjsync.jira.mapper import IssueMapper
from qjsync.models.canonical import (
    Asset,
    Detection,
    DetectionStatus,
    EvaluationResult,
    JiraPriority,
    KbVuln,
    MergedVulnerability,
    RuleAction,
)

# Every human field name the mapper may emit -> a stable fake customfield id.
_FIELD_NAMES = [
    "Host ID", "Asset ID", "IP", "IPV6", "Tracking Method", "OS",
    "Last Scan Datetime", "Last VM Scanned Date", "Asset Tag", "QID", "QDS",
    "Port", "Severity", "Vuln Type", "Patchable", "PCI Flag", "Vuln Category",
    "Published Datetime", "CVSS Base", "CVSS Temporal", "Detection Status",
    "CVSS V3 Base", "CVSS V3 Temporal", "Last Service Modification Datetime",
    "CVEs", "Diagnosis", "Consequence", "Solution", "Primary Key",
    "TruRisk Score", "Asset Criticality Score", "Last VM Scanned Duration",
    "Network ID", "DNS", "QG Host ID", "Netbios", "Unique Value ID", "SSL",
    "Results", "First Found Datetime", "Last Found Datetime", "Times Found",
    "Last Test Datetime", "Last Update Datetime", "Last Fixed Datetime",
    "Is Ignored", "Is Disabled", "Last Processed Datetime", "Protocol",
]


def _field_ids() -> dict[str, str]:
    return {name: f"customfield_{10000 + i}" for i, name in enumerate(_FIELD_NAMES)}


def _config(**jira_overrides: object) -> QjsyncConfig:
    # The mapper only reads config.jira; prioritization defaults are fine here.
    return QjsyncConfig(
        jira=JiraConfig(project="SEC", **jira_overrides),  # type: ignore[arg-type]
    )


def _full_merged() -> MergedVulnerability:
    return MergedVulnerability(
        asset=Asset(
            host_id=42,
            asset_id=7,
            ip="10.0.0.5",
            ipv6="fe80::1",
            tracking_method="AGENT",
            os="Ubuntu 22.04",
            dns="web01.example.com",
            netbios="WEB01",
            qg_hostid="abc-123",
            network_id=3,
            last_scan_datetime="2026-06-01T00:00:00Z",
            last_vm_scanned_date="2026-06-01T00:00:00Z",
            last_vm_scanned_duration=120,
            asset_tags=["Internet Facing Assets", "ACS-4"],
            asset_criticality_score=4,
        ),
        detection=Detection(
            qid=105413,
            port=443,
            protocol="tcp",
            ssl=1,
            severity=5,
            status=DetectionStatus.ACTIVE,
            vuln_type="Confirmed",
            results="vulnerable",
            qds=88,
            unique_vuln_id=999001,
            is_ignored=0,
            is_disabled=0,
            first_found_datetime="2026-01-01T00:00:00Z",
            last_found_datetime="2026-06-01T00:00:00Z",
            times_found=12,
            last_test_datetime="2026-06-01T00:00:00Z",
            last_update_datetime="2026-06-01T00:00:00Z",
            last_fixed_datetime="2026-05-01T00:00:00Z",
            last_processed_datetime="2026-06-01T00:00:00Z",
        ),
        kb=KbVuln(
            qid=105413,
            title="OpenSSL Heap Overflow",
            category="General Remote Services",
            published_datetime="2022-11-01T00:00:00Z",
            last_service_modification_datetime="2023-01-01T00:00:00Z",
            patchable=True,
            pci_flag=False,
            cvss_base=7.5,
            cvss_temporal=6.9,
            cvss_v3_base=9.8,
            cvss_v3_temporal=9.1,
            diagnosis="A buffer overflow.",
            consequence="RCE.",
            solution="Upgrade.",
            cve_list=["CVE-2022-3602", "CVE-2022-3786"],
        ),
    )


def _evaluation(
    labels: list[str] | None = None, component: str | None = None
) -> EvaluationResult:
    return EvaluationResult(
        action=RuleAction.CREATE,
        matched_rule="default",
        priority=JiraPriority.HIGH,
        project="SEC",
        issue_type="Host Vulnerability",
        component=component,
        labels=labels or [],
    )


def test_routing_component_emitted_only_when_set() -> None:
    mapper = IssueMapper(_field_ids(), _config())
    # No routing component -> no `components` key (Jira would reject an empty one).
    assert "components" not in mapper.build_fields(_full_merged(), _evaluation(), "pk")
    # A routing rule that set a component -> components payload by name.
    routed = mapper.build_fields(_full_merged(), _evaluation(component="Cloud Platform"), "pk")
    assert routed["components"] == [{"name": "Cloud Platform"}]


def test_full_mapping_present_with_correct_ids() -> None:
    ids = _field_ids()
    mapper = IssueMapper(ids, _config())
    fields = mapper.build_fields(_full_merged(), _evaluation(), "42:105413:443")

    # Standard fields.
    assert fields["summary"] == "105413 - OpenSSL Heap Overflow"
    assert fields["project"] == {"key": "SEC"}
    assert fields["issuetype"] == {"name": "Host Vulnerability"}
    assert fields["priority"] == {"name": "High"}
    assert fields["description"]["type"] == "doc"

    # Numbers stay numbers, looked up by name -> id.
    assert fields[ids["Host ID"]] == 42
    assert fields[ids["QID"]] == 105413
    assert fields[ids["QDS"]] == 88
    assert fields[ids["Severity"]] == 5
    assert fields[ids["CVSS Base"]] == 7.5
    assert fields[ids["CVSS V3 Base"]] == 9.8
    assert fields[ids["Asset Criticality Score"]] == 4
    assert fields[ids["Unique Value ID"]] == 999001

    # Text fields.
    assert fields[ids["IP"]] == "10.0.0.5"
    assert fields[ids["Detection Status"]] == "Active"
    assert fields[ids["Vuln Category"]] == "General Remote Services"

    # Dates as text (raw Qualys string).
    assert fields[ids["First Found Datetime"]] == "2026-01-01T00:00:00Z"

    # Multi-line (textarea) fields are ADF documents in Jira API v3, not plain
    # strings (a live create 400s otherwise). CVEs joined one paragraph per CVE.
    cves = fields[ids["CVEs"]]
    assert cves["type"] == "doc" and cves["version"] == 1
    para_texts = [
        node["content"][0]["text"] for node in cves["content"] if node.get("content")
    ]
    assert para_texts == ["CVE-2022-3602", "CVE-2022-3786"]

    # Asset Tag as a sanitised labels list.
    assert fields[ids["Asset Tag"]] == ["Internet_Facing_Assets", "ACS-4"]


def test_yes_no_conversion() -> None:
    ids = _field_ids()
    mapper = IssueMapper(ids, _config())
    fields = mapper.build_fields(_full_merged(), _evaluation(), "pk")
    assert fields[ids["Patchable"]] == "Yes"
    assert fields[ids["PCI Flag"]] == "No"


def test_primary_key_written() -> None:
    ids = _field_ids()
    mapper = IssueMapper(ids, _config())
    fields = mapper.build_fields(_full_merged(), _evaluation(), "42:105413:443")
    assert fields[ids["Primary Key"]] == "42:105413:443"


def test_trurisk_omitted_no_source() -> None:
    ids = _field_ids()
    mapper = IssueMapper(ids, _config())
    fields = mapper.build_fields(_full_merged(), _evaluation(), "pk")
    assert ids["TruRisk Score"] not in fields


def test_none_sources_omitted() -> None:
    ids = _field_ids()
    mapper = IssueMapper(ids, _config())
    merged = MergedVulnerability(
        asset=Asset(host_id=1),  # ip/os/dns/... all None
        detection=Detection(qid=2, status=DetectionStatus.NEW),
        kb=None,
    )
    fields = mapper.build_fields(merged, _evaluation(), "1:2:none")

    # Present: required + non-None sources.
    assert fields[ids["Host ID"]] == 1
    assert fields[ids["QID"]] == 2
    assert fields[ids["Detection Status"]] == "New"
    assert fields[ids["Primary Key"]] == "1:2:none"

    # Omitted: None sources and KB fields with no KB.
    for absent in ("IP", "OS", "DNS", "Port", "QDS", "CVSS Base", "Patchable",
                   "PCI Flag", "Diagnosis", "Asset Tag", "Asset Criticality Score"):
        assert ids[absent] not in fields


def test_derived_patch_routing_label_needs_mitigation() -> None:
    ids = _field_ids()
    mapper = IssueMapper(ids, _config())
    merged = _full_merged()
    assert merged.kb is not None
    merged.kb.patchable = False  # not patchable -> mitigation lane
    fields = mapper.build_fields(merged, _evaluation(labels=["rule-label"]), "pk")
    assert "needs-mitigation" in fields["labels"]
    assert "auto-patch" not in fields["labels"]
    assert "rule-label" in fields["labels"]


def test_derived_patch_routing_label_auto_patch() -> None:
    ids = _field_ids()
    mapper = IssueMapper(ids, _config())
    fields = mapper.build_fields(_full_merged(), _evaluation(), "pk")  # patchable True
    assert "auto-patch" in fields["labels"]
    assert "needs-mitigation" not in fields["labels"]


def test_derived_patch_routing_unknown_adds_nothing() -> None:
    ids = _field_ids()
    mapper = IssueMapper(ids, _config())
    merged = _full_merged()
    assert merged.kb is not None
    merged.kb.patchable = None  # unknown -> no patch label
    fields = mapper.build_fields(merged, _evaluation(), "pk")
    assert "auto-patch" not in fields["labels"]
    assert "needs-mitigation" not in fields["labels"]


def test_derive_patch_routing_disabled() -> None:
    ids = _field_ids()
    mapper = IssueMapper(ids, _config(derive_patch_routing=False))
    fields = mapper.build_fields(_full_merged(), _evaluation(), "pk")
    assert "auto-patch" not in fields["labels"]


def test_oversized_text_field_is_truncated() -> None:
    # Qualys `Results` can exceed Jira's 32767-char field limit; the mapper must
    # truncate it (else HTTP 400 CONTENT_LIMIT_EXCEEDED — a fatal, non-retryable
    # error, as verified against live Jira: 32767 OK, 32768 rejected).
    ids = _field_ids()
    merged = _full_merged()
    merged.detection.results = "A" * 40000
    fields = IssueMapper(ids, _config()).build_fields(merged, _evaluation(), "pk")
    doc = fields[ids["Results"]]
    total = sum(len(n["content"][0]["text"]) for n in doc["content"] if n.get("content"))
    assert total <= 32767
    assert "truncated by qjsync" in doc["content"][-1]["content"][0]["text"]


def test_most_critical_rti_added_as_label() -> None:
    ids = _field_ids()
    merged = _full_merged()
    # Exploit_Public outranks Denial_of_Service/No_Patch -> it is the surfaced label.
    merged.detection.rtis = ["Denial_of_Service", "Exploit_Public", "No_Patch"]
    fields = IssueMapper(ids, _config()).build_fields(merged, _evaluation(), "pk")
    assert "Exploit_Public" in fields["labels"]


def test_missing_field_name_skipped_with_warning(caplog: object) -> None:
    # Drop a couple of names from the discovered set: they must be skipped, logged.
    ids = _field_ids()
    del ids["QDS"]
    mapper = IssueMapper(ids, _config())
    with caplog.at_level(logging.WARNING):  # type: ignore[attr-defined]
        fields = mapper.build_fields(_full_merged(), _evaluation(), "pk")
    # No crash; the missing field simply isn't in the payload.
    assert all(not v == 88 for v in fields.values())
    assert any("QDS" in rec.message for rec in caplog.records)  # type: ignore[attr-defined]
