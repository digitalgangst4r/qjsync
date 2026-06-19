"""Unit tests for the purge classifier (sync/purge.py).

Exercises the tracking-method-aware gate that protects the network-scanned estate
from false purge: agent assets go stale on consecutive misses; network assets go
stale only when overdue beyond their own (slower) scan cycle. Also covers the
mode+success eligibility gate (only a successful full run may infer purge).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from qjsync.config.schema import PurgeConfig
from qjsync.state.models import (
    DetectionState,
    SyncMode,
    SyncRun,
    SyncRunStatus,
)
from qjsync.sync.purge import classify_missing, is_purge_eligible

_DT_FMT = "%Y-%m-%dT%H:%M:%SZ"
_NOW = datetime(2026, 6, 19, 12, 0, 0, tzinfo=UTC)


def _qualys_dt(days_ago: int) -> str:
    return (_NOW - timedelta(days=days_ago)).strftime(_DT_FMT)


def _state(
    *,
    tracking_method: str | None = "AGENT",
    consecutive_misses: int = 0,
    last_vm_scanned_date: str | None = None,
) -> DetectionState:
    return DetectionState(
        primary_key="1:2:none",
        host_id=1,
        qid=2,
        port="none",
        tracking_method=tracking_method,
        consecutive_misses=consecutive_misses,
        last_vm_scanned_date=last_vm_scanned_date,
    )


# --------------------------------------------------------------------------- #
# is_purge_eligible — mode + success gate
# --------------------------------------------------------------------------- #
def test_purge_eligible_only_for_successful_full() -> None:
    assert is_purge_eligible(SyncRun(mode=SyncMode.FULL, status=SyncRunStatus.SUCCESS))
    assert not is_purge_eligible(SyncRun(mode=SyncMode.FULL, status=SyncRunStatus.FAILED))
    assert not is_purge_eligible(SyncRun(mode=SyncMode.FULL, status=SyncRunStatus.RUNNING))
    assert not is_purge_eligible(
        SyncRun(mode=SyncMode.INCREMENTAL, status=SyncRunStatus.SUCCESS)
    )


# --------------------------------------------------------------------------- #
# Agent-tracked: grace-syncs gate
# --------------------------------------------------------------------------- #
def test_agent_keep_below_grace() -> None:
    cfg = PurgeConfig(agent_grace_syncs=2)
    assert classify_missing(_state(consecutive_misses=1), cfg, now=_NOW) == "keep"


def test_agent_stale_at_grace() -> None:
    cfg = PurgeConfig(agent_grace_syncs=2)
    assert classify_missing(_state(consecutive_misses=2), cfg, now=_NOW) == "stale"


def test_agent_stale_above_grace() -> None:
    cfg = PurgeConfig(agent_grace_syncs=2)
    assert classify_missing(_state(consecutive_misses=5), cfg, now=_NOW) == "stale"


def test_agent_match_is_case_insensitive_substring() -> None:
    cfg = PurgeConfig(agent_grace_syncs=1)
    # Real Qualys values include "QAGENT"/"AGENT"; substring + upper handles both.
    st = _state(tracking_method="qagent", consecutive_misses=1)
    assert classify_missing(st, cfg, now=_NOW) == "stale"


def test_agent_ignores_scan_age() -> None:
    # An agent asset is decided by misses, not last scan date.
    cfg = PurgeConfig(agent_grace_syncs=2)
    st = _state(consecutive_misses=0, last_vm_scanned_date=_qualys_dt(days_ago=999))
    assert classify_missing(st, cfg, now=_NOW) == "keep"


# --------------------------------------------------------------------------- #
# Network-scanned: scan-age gate (NOT mere absence)
# --------------------------------------------------------------------------- #
def test_network_keep_when_recently_scanned() -> None:
    cfg = PurgeConfig(network_scan_grace_days=30)
    st = _state(
        tracking_method="IP",
        consecutive_misses=99,  # many misses are irrelevant for network assets
        last_vm_scanned_date=_qualys_dt(days_ago=10),
    )
    assert classify_missing(st, cfg, now=_NOW) == "keep"


def test_network_stale_when_overdue() -> None:
    cfg = PurgeConfig(network_scan_grace_days=30)
    st = _state(
        tracking_method="DNS",
        consecutive_misses=1,
        last_vm_scanned_date=_qualys_dt(days_ago=45),
    )
    assert classify_missing(st, cfg, now=_NOW) == "stale"


def test_network_keep_at_exact_boundary() -> None:
    # "older than" -> equal to the grace window is still keep.
    cfg = PurgeConfig(network_scan_grace_days=30)
    st = _state(tracking_method="IP", last_vm_scanned_date=_qualys_dt(days_ago=30))
    assert classify_missing(st, cfg, now=_NOW) == "keep"


def test_network_keep_when_scan_date_unknown() -> None:
    # No trustworthy last-scan date -> never purge a network asset on absence.
    cfg = PurgeConfig(network_scan_grace_days=30)
    st = _state(tracking_method="IP", last_vm_scanned_date=None)
    assert classify_missing(st, cfg, now=_NOW) == "keep"


def test_network_keep_when_scan_date_unparseable() -> None:
    cfg = PurgeConfig(network_scan_grace_days=30)
    st = _state(tracking_method="NETBIOS", last_vm_scanned_date="not-a-date")
    assert classify_missing(st, cfg, now=_NOW) == "keep"


def test_none_tracking_method_treated_as_network() -> None:
    # Unknown tracking method falls into the conservative network branch.
    cfg = PurgeConfig(network_scan_grace_days=30)
    st = _state(tracking_method=None, last_vm_scanned_date=None)
    assert classify_missing(st, cfg, now=_NOW) == "keep"
