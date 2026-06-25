"""LocalSink — writes the lifecycle into the ``dash.issues`` work-layer instead of Jira.

No HTTP, no rate limit: every orchestrator call becomes a small Postgres write in the same database
(public = qjsync's truth, dash = the team's work). The orchestrator's invariants are untouched —
LocalSink only changes *where* state is written and read:

* create/update mirror the qjsync-owned columns only (never the team's workflow/assignee/sticky).
* transition maps fixed/stale/reopen onto ``lifecycle_state`` (+ closed/purged stamps), separate
  from the team workflow (the dash auto-moves workflow to Concluído on closed_fixed via a trigger).
* get_issue returns the team-set ``sticky_resolution`` so the orchestrator's sticky/no-surprise
  logic keeps working — now the human sets it in the dash, not in Jira.
* create is idempotent on ``primary_key`` (re-create reconciles to the existing issue).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import insert, select, update

from qjsync.sink.contract import (
    SINK_INSERT_COLUMNS,
    SINK_UPDATE_COLUMNS,
    issue_events,
    issues,
)
from qjsync.state.db import session_scope

if TYPE_CHECKING:
    from sqlalchemy.orm import Session, sessionmaker

    from qjsync.config.schema import QjsyncConfig
    from qjsync.models.canonical import EvaluationResult, MergedVulnerability

_QUALYS_DT_FMT = "%Y-%m-%dT%H:%M:%SZ"
_PK_FIELD = "primary_key"


def _now() -> datetime:
    return datetime.now(UTC)


def _parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.strptime(value, _QUALYS_DT_FMT).replace(tzinfo=UTC)
    except (ValueError, TypeError):
        return None


def _adf_text(body_adf: dict[str, Any]) -> str:
    try:
        return str(body_adf["content"][0]["content"][0]["text"])
    except (KeyError, IndexError, TypeError):
        return ""


class LocalFieldBuilder:
    """Emits a dict keyed by ``dash.issues`` column names (the qjsync-owned/mirrored fields)."""

    def build_fields(
        self, merged: MergedVulnerability, evaluation: EvaluationResult, primary_key: str
    ) -> dict[str, Any]:
        s = merged.signal_context()
        priority = evaluation.priority.value if evaluation.priority else None
        return {
            _PK_FIELD: primary_key,
            "qid": merged.detection.qid,
            "title": merged.title,
            "qds": s.get("qds"),
            "severity": s.get("severity"),
            "cvss_v3_base": s.get("cvss_v3_base"),
            "epss": s.get("epss"),
            "cve_list": s.get("cve_list") or [],
            "host_id": merged.asset.host_id,
            "os": s.get("os"),
            "tracking_method": s.get("tracking_method"),
            "network_id": s.get("network_id"),
            "pci_flag": s.get("pci_flag"),
            "has_exploit": s.get("has_exploit"),
            "actively_attacked": s.get("actively_attacked"),
            "ransomware": s.get("ransomware"),
            "wormable": s.get("wormable"),
            "qualys_status": s.get("status"),
            "asset_tags": s.get("asset_tags") or [],
            "priority": priority,
            "band": priority,  # the band-shift prioritisation output (qjsync has no separate band)
            "labels": list(evaluation.labels),
            "first_found_at": _parse_dt(merged.detection.first_found_datetime),
        }


class LocalSink:
    """Implements :class:`~qjsync.sink.base.IssueSink` over the ``dash.issues`` work-layer."""

    def __init__(self, session_factory: sessionmaker[Session], config: QjsyncConfig) -> None:
        self._sf = session_factory
        self._jira = config.jira  # reused only for transition/resolution names

    # --- reads -----------------------------------------------------------------------------------
    def find_issue_by_primary_key(self, primary_key: str) -> dict[str, Any] | None:
        with session_scope(self._sf) as s:
            row = s.execute(
                select(issues.c.local_key).where(issues.c.primary_key == primary_key)
            ).first()
        return {"key": row.local_key} if row else None

    def get_issue(self, issue_key: str) -> dict[str, Any]:
        with session_scope(self._sf) as s:
            row = s.execute(
                select(issues.c.sticky_resolution, issues.c.labels).where(
                    issues.c.local_key == issue_key
                )
            ).first()
        if row is None:
            return {"fields": {}}
        fields: dict[str, Any] = {"labels": row.labels or []}
        if row.sticky_resolution:
            fields["resolution"] = {"name": row.sticky_resolution}
        return {"fields": fields}

    # --- writes ----------------------------------------------------------------------------------
    def create_issue(self, fields: dict[str, Any]) -> dict[str, Any]:
        pk = fields.get(_PK_FIELD)
        now = _now()
        with session_scope(self._sf) as s:
            # Idempotency: never create a second issue for the same detection.
            existing = s.execute(
                select(issues.c.local_key).where(issues.c.primary_key == pk)
            ).first()
            if existing is not None:
                return {"key": existing.local_key}
            values = {k: fields[k] for k in SINK_INSERT_COLUMNS if k in fields}
            values.update(lifecycle_state="open", created_at=now, updated_at=now)
            result = s.execute(insert(issues).values(**values))
            issue_id = int(result.inserted_primary_key[0])
            key = f"QJ-{issue_id}"
            s.execute(update(issues).where(issues.c.id == issue_id).values(local_key=key))
            s.execute(
                insert(issue_events).values(
                    issue_id=issue_id, author="qjsync", kind="opened", created_at=now
                )
            )
        return {"key": key}

    def update_issue(self, issue_key: str, fields: dict[str, Any]) -> None:
        now = _now()
        values = {k: fields[k] for k in SINK_UPDATE_COLUMNS if k in fields}
        values["updated_at"] = now
        with session_scope(self._sf) as s:
            cur = s.execute(
                select(issues.c.id, issues.c.band).where(issues.c.local_key == issue_key)
            ).first()
            if cur is None:
                return
            s.execute(update(issues).where(issues.c.local_key == issue_key).values(**values))
            new_band = values.get("band")
            # Only a genuine *re*-prioritisation (band actually changed from a known prior value)
            # is timeline-worthy — not the first time a band is set.
            if new_band is not None and cur.band is not None and new_band != cur.band:
                s.execute(
                    insert(issue_events).values(
                        issue_id=cur.id, author="qjsync", kind="reprioritised",
                        body=f"{cur.band} → {new_band}", created_at=now,
                    )
                )

    def transition_issue(
        self, issue_key: str, name: str, *, resolution: str | None = None
    ) -> None:
        now = _now()
        if resolution == self._jira.resolution_stale:
            values = {"lifecycle_state": "closed_stale", "closed_at": now, "purged_at": now}
            kind = "closed_stale"
        elif resolution == self._jira.resolution_fixed:
            values = {"lifecycle_state": "closed_fixed", "closed_at": now, "purged_at": None}
            kind = "closed_fixed"
        elif name == self._jira.reopen_transition:
            values = {"lifecycle_state": "reopened", "closed_at": None, "purged_at": None}
            kind = "reopened"
        else:
            values, kind = {}, "transition"
        values["updated_at"] = now
        with session_scope(self._sf) as s:
            row = s.execute(select(issues.c.id).where(issues.c.local_key == issue_key)).first()
            if row is None:
                return
            s.execute(update(issues).where(issues.c.local_key == issue_key).values(**values))
            s.execute(
                insert(issue_events).values(
                    issue_id=row.id, author="qjsync", kind=kind, created_at=now
                )
            )

    def add_comment(self, issue_key: str, body_adf: dict[str, Any]) -> None:
        now = _now()
        with session_scope(self._sf) as s:
            row = s.execute(select(issues.c.id).where(issues.c.local_key == issue_key)).first()
            if row is None:
                return
            s.execute(
                insert(issue_events).values(
                    issue_id=row.id,
                    author="qjsync",
                    kind="comment",
                    body=_adf_text(body_adf),
                    created_at=now,
                )
            )
