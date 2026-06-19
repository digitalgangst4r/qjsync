"""Tests for ``sources.qualys.knowledgebase.fetch_kb`` against the real-structure
KB fixture."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from qjsync.models.canonical import KbVuln
from qjsync.sources.qualys.knowledgebase import fetch_kb

_FIXTURE = Path(__file__).parent / "fixtures" / "kb_sample.xml"


class _OnePageClient:
    def __init__(self, body: bytes) -> None:
        self._body = body
        self.calls: list[dict[str, Any]] = []

    def post(self, endpoint: str, params: dict[str, Any]) -> bytes:
        self.calls.append({"endpoint": endpoint, "params": dict(params)})
        return self._body

    def get(self, endpoint: str, params: dict[str, Any]) -> bytes:  # pragma: no cover
        return self.post(endpoint, params)


def _vulns(qids: Any = None) -> tuple[dict[int, KbVuln], _OnePageClient]:
    client = _OnePageClient(_FIXTURE.read_bytes())
    out = {v.qid: v for v in fetch_kb(client, qids=qids)}
    return out, client


def test_parses_both_vulns() -> None:
    vulns, _ = _vulns()
    assert set(vulns) == {105413, 38170}


def test_qid_38170_has_cves_and_cvss_v3() -> None:
    vulns, _ = _vulns()
    v = vulns[38170]
    assert v.cve_list == ["CVE-2016-2183", "CVE-2014-3566"]
    assert v.cvss_v3_base == 7.5
    assert v.cvss_v3_temporal == 6.5
    assert v.cvss_base == 7.4
    assert v.patchable is True
    assert v.pci_flag is False
    assert v.category == "General Remote Services"


def test_qid_105413_non_patchable_with_threat_intel_rtis() -> None:
    vulns, _ = _vulns()
    v = vulns[105413]
    assert v.patchable is False
    assert v.pci_flag is True
    # THREAT_INTELLIGENCE/THREAT_INTEL texts become rtis.
    assert "High_Lateral_Movement" in v.rtis
    assert "No_Patch" in v.rtis
    # CVSS v3 absent on this QID -> stays None; v2 present.
    assert v.cvss_v3_base is None
    assert v.cvss_base == 10.0
    assert v.cve_list == []  # no CVEs
    assert v.title is not None and "JDK" in v.title


def test_request_params_action_list_details_all() -> None:
    _vulns_map, client = _vulns()
    params = client.calls[0]["params"]
    assert params["action"] == "list"
    assert params["details"] == "All"
    assert "ids" not in params  # full pull


def test_ids_param_when_qids_given() -> None:
    _vulns_map, client = _vulns(qids=[38170, 105413])
    params = client.calls[0]["params"]
    # ids is the sorted comma list of requested QIDs.
    assert params["ids"] == "38170,105413"


def test_empty_qids_yields_nothing_without_call() -> None:
    client = _OnePageClient(_FIXTURE.read_bytes())
    assert list(fetch_kb(client, qids=[])) == []
    assert client.calls == []
