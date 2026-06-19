"""PostgreSQL-backed state.

Postgres is the *only* runtime dependency for state (no Redis). It holds:

* :class:`~qjsync.state.models.SyncRun` — one row per sync cycle (for purge safety).
* :class:`~qjsync.state.models.DetectionState` — primary_key -> Jira issue mapping
  plus the snapshot needed to detect change / fixed / purge.
* :class:`~qjsync.state.models.KbEntry` — cached KnowledgeBase, keyed by QID.
* :class:`~qjsync.state.models.Job` — the durable work queue (FOR UPDATE SKIP LOCKED).
"""

from __future__ import annotations

from qjsync.state.models import (
    Base,
    ClosureReason,
    DetectionState,
    Job,
    JobStatus,
    KbEntry,
    SyncMode,
    SyncRun,
    SyncRunStatus,
)

__all__ = [
    "Base",
    "ClosureReason",
    "DetectionState",
    "Job",
    "JobStatus",
    "KbEntry",
    "SyncMode",
    "SyncRun",
    "SyncRunStatus",
]
