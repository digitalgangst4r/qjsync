"""Purge classification — telling *purge* (not remediation) apart from *fixed*.

A detection that simply **disappears** from a full Host List Detection result,
without ever being reported ``STATUS=Fixed``, is a *purge* (asset decommissioned,
removed, or aged out by Qualys retention) — not a remediation. Closing it as
"Fixed" would be a dangerous lie, so it gets its own resolution/closure reason.

This module decides *whether* a missing-from-a-full-run detection has been absent
long enough to be considered stale. It is **tracking-method aware** so the ~10%
network-scanned estate is not false-purged just for falling outside a single
appliance scan window. See docs/LIFECYCLE.md and docs/ARCHITECTURE.md.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal

from qjsync.config.schema import PurgeConfig
from qjsync.state.models import DetectionState, SyncMode, SyncRun, SyncRunStatus

# Qualys datetime format used across HLD/KB, e.g. "2024-10-15T13:45:02Z".
_QUALYS_DT_FMT = "%Y-%m-%dT%H:%M:%SZ"

PurgeDecision = Literal["stale", "keep"]


def is_purge_eligible(run: SyncRun) -> bool:
    """Whether ``run`` may infer purge at all.

    Only a **successful full** run can mark anything stale. An incremental run
    deliberately skips the purge pass (the 4h delta would look like mass
    disappearance), and a failed/partial run is untrustworthy for absence
    inference. This is the mode+success gate from the lifecycle contract.
    """
    return run.mode is SyncMode.FULL and run.status is SyncRunStatus.SUCCESS


def _parse_qualys_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.strptime(value, _QUALYS_DT_FMT).replace(tzinfo=UTC)
    except (ValueError, TypeError):
        return None


def _is_agent_tracked(state: DetectionState) -> bool:
    """True when the asset is Cloud-Agent tracked (``tracking_method`` ~ AGENT)."""
    method = state.tracking_method or ""
    return "AGENT" in method.upper()


def classify_missing(
    state: DetectionState,
    cfg: PurgeConfig,
    *,
    now: datetime | None = None,
) -> PurgeDecision:
    """Classify a detection that was *missing* from this full run.

    Returns ``"stale"`` only when the absence is trustworthy for the asset's
    tracking method, otherwise ``"keep"`` (give it more time — prefer a lingering
    issue over a wrongly "resolved" one):

    * **Agent-tracked** (``tracking_method`` contains "AGENT", ~4h cadence): a
      sustained absence is a strong purge/decommission signal, so it becomes
      stale once ``consecutive_misses >= cfg.agent_grace_syncs``.
    * **Network-scanned** (any non-agent method, slower appliance cadence):
      absence from a run is *expected* when the appliance simply has not scanned
      the asset yet. It becomes stale only once ``last_vm_scanned_date`` is older
      than ``cfg.network_scan_grace_days`` — i.e. the asset is overdue beyond its
      own (slower) cycle, not merely missing from one run. An unknown/unparseable
      last-scan date is treated conservatively as **keep**.

    This is invoked only on a purge-eligible run (see :func:`is_purge_eligible`);
    the mode+success gate is enforced by the caller.
    """
    now = now or datetime.now(UTC)

    if _is_agent_tracked(state):
        misses = state.consecutive_misses or 0
        return "stale" if misses >= cfg.agent_grace_syncs else "keep"

    # Network-scanned: gate on scan-age, not mere absence.
    last_scanned = _parse_qualys_dt(state.last_vm_scanned_date)
    if last_scanned is None:
        # No trustworthy last-scan date -> do not purge a network asset on absence.
        return "keep"
    age_days = (now - last_scanned).days
    return "stale" if age_days > cfg.network_scan_grace_days else "keep"
