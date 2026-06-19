"""Tests for ``sources.qualys.detection.iter_detections`` against the real-structure
HLD fixture."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

from qjsync.config.schema import QualysQueryConfig
from qjsync.models.canonical import Asset, Detection, DetectionStatus
from qjsync.sources.qualys.detection import iter_detections

_FIXTURE = Path(__file__).parent / "fixtures" / "hld_sample.xml"


class _OnePageClient:
    """A QualysClient stand-in that returns one fixed body and records calls."""

    def __init__(self, body: bytes) -> None:
        self._body = body
        self.calls: list[dict[str, Any]] = []

    def post(self, endpoint: str, params: dict[str, Any]) -> bytes:
        self.calls.append({"endpoint": endpoint, "params": dict(params)})
        return self._body

    def get(self, endpoint: str, params: dict[str, Any]) -> bytes:  # pragma: no cover
        return self.post(endpoint, params)


def _pairs(
    *, acs_pattern: str | None = None, since: str | None = None
) -> tuple[list[tuple[Asset, Detection]], _OnePageClient]:
    client = _OnePageClient(_FIXTURE.read_bytes())
    query = QualysQueryConfig()
    result = list(
        iter_detections(client, query, since=since, acs_pattern=acs_pattern)
    )
    return result, client


def _by_host(pairs: list[tuple[Asset, Detection]]) -> dict[int, list[tuple[Asset, Detection]]]:
    out: dict[int, list[tuple[Asset, Detection]]] = {}
    for asset, det in pairs:
        out.setdefault(asset.host_id, []).append((asset, det))
    return out


def test_parses_all_detections() -> None:
    pairs, _ = _pairs()
    # Host A has 2 detections, host B has 1.
    assert len(pairs) == 3
    by_host = _by_host(pairs)
    assert set(by_host) == {1000001, 1000002}


def test_host_a_portless_detection_rtis_from_qds_factors() -> None:
    pairs, _ = _pairs(acs_pattern=r"ACS-(\d)")
    by_host = _by_host(pairs)
    host_a = by_host[1000001]

    # Find QID 105413: port-less, Active, exploit RTI.
    det_105413 = next(det for _asset, det in host_a if det.qid == 105413)
    assert det_105413.port is None  # port-less
    assert det_105413.status is DetectionStatus.ACTIVE
    assert "Exploit_Public" in det_105413.rtis
    assert "Remote_Code_Execution" in det_105413.rtis
    # raw QDS_FACTORS captured by name
    assert det_105413.qds_factors["CVSS"] == "9.3"
    assert det_105413.qds == 60


def test_host_a_acs_is_max_over_tags() -> None:
    pairs, _ = _pairs(acs_pattern=r"ACS-(\d)")
    by_host = _by_host(pairs)
    asset_a = by_host[1000001][0][0]
    # Host A carries ACS-2 and ACS-4 -> MAX == 4.
    assert asset_a.asset_criticality_score == 4
    assert "Internet Facing Assets" in asset_a.asset_tags


def test_acs_none_when_pattern_absent() -> None:
    pairs, _ = _pairs(acs_pattern=None)
    by_host = _by_host(pairs)
    assert by_host[1000001][0][0].asset_criticality_score is None


def test_host_a_second_detection_is_fixed() -> None:
    pairs, _ = _pairs()
    by_host = _by_host(pairs)
    host_a = by_host[1000001]
    det_38170 = next(det for _asset, det in host_a if det.qid == 38170)
    assert det_38170.status is DetectionStatus.FIXED
    assert det_38170.port == 443
    assert det_38170.protocol == "tcp"


def test_host_b_tracking_method_is_ip() -> None:
    pairs, _ = _pairs()
    by_host = _by_host(pairs)
    asset_b = by_host[1000002][0][0]
    assert asset_b.tracking_method == "IP"
    assert asset_b.netbios == "HOSTB"
    assert asset_b.last_vm_scanned_date == "2026-05-20T02:00:00Z"


def test_params_include_action_list_and_never_show_trurisk() -> None:
    _pairs_list, client = _pairs(since="2026-06-19T00:00:00Z")
    params = client.calls[0]["params"]
    assert params["action"] == "list"
    assert params["show_qds"] == 1
    assert params["show_qds_factors"] == 1
    assert params["show_tags"] == 1
    # The managed `since` is injected as vm_scan_since.
    assert params["vm_scan_since"] == "2026-06-19T00:00:00Z"
    # HLD 2.0 rejects show_trurisk -> it must NEVER be sent.
    assert "show_trurisk" not in params


def test_since_overrides_static_vm_scan_since() -> None:
    client = _OnePageClient(_FIXTURE.read_bytes())
    query = QualysQueryConfig(vm_scan_since="2020-01-01T00:00:00Z")
    list(iter_detections(client, query, since="2026-06-19T00:00:00Z"))
    assert client.calls[0]["params"]["vm_scan_since"] == "2026-06-19T00:00:00Z"


def test_static_vm_scan_since_used_when_no_managed_window() -> None:
    client = _OnePageClient(_FIXTURE.read_bytes())
    query = QualysQueryConfig(vm_scan_since="2020-01-01T00:00:00Z")
    list(iter_detections(client, query, since=None))
    assert client.calls[0]["params"]["vm_scan_since"] == "2020-01-01T00:00:00Z"


def test_extra_params_merged() -> None:
    client = _OnePageClient(_FIXTURE.read_bytes())
    query = QualysQueryConfig(extra={"custom_flag": "1"})
    list(iter_detections(client, query))
    assert client.calls[0]["params"]["custom_flag"] == "1"


def test_iter_detections_is_lazy() -> None:
    """The generator yields pairs incrementally rather than buffering everything."""
    client = _OnePageClient(_FIXTURE.read_bytes())
    gen: Iterator[tuple[Asset, Detection]] = iter_detections(client, QualysQueryConfig())
    first = next(gen)
    assert isinstance(first[0], Asset)
    assert isinstance(first[1], Detection)
