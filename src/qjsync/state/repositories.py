"""Repositories over the state tables.

Each repository is bound to a single :class:`~sqlalchemy.orm.Session` (handed in
by :func:`qjsync.state.db.session_scope`) and exposes the small, intention-named
operations the orchestrator and workers need. They never commit — the caller's
``session_scope`` owns transaction boundaries — so a unit of work stays atomic.

Keeping the SQL here (and out of the orchestrator) is what makes the lifecycle
unit-testable against in-memory SQLite without a live Postgres.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from qjsync.models.canonical import KbVuln, MergedVulnerability
from qjsync.state.models import (
    ClosureReason,
    DetectionState,
    Job,
    JobStatus,
    KbEntry,
    SyncMode,
    SyncRun,
    SyncRunStatus,
)


def _utcnow() -> datetime:
    return datetime.now(UTC)


class SyncRunRepo:
    """Lifecycle of :class:`SyncRun` rows — one per ``sync`` invocation.

    The two ``last_successful_*`` lookups encode a contract distinction: purge
    gating needs the last successful **full** run, while the incremental window
    start needs the last successful run of **any** mode.
    """

    def __init__(self, session: Session) -> None:
        self.session = session

    def start(self, mode: SyncMode) -> SyncRun:
        """Open a new run in ``RUNNING`` state and flush so it gets an id."""
        run = SyncRun(mode=mode, status=SyncRunStatus.RUNNING)
        self.session.add(run)
        self.session.flush()  # assign run.id for use as last_seen_run this cycle
        return run

    def finish(self, run: SyncRun, status: SyncRunStatus, **counts: int) -> SyncRun:
        """Close ``run`` with ``status`` and the per-run summary counters.

        ``counts`` keys mirror :class:`SyncRun`'s counter columns (``evaluated``,
        ``created``, ``updated``, ``closed_fixed``, ``marked_stale``, ``reopened``,
        ``skipped``); ``notes`` (a dict) is also accepted. Unknown keys are ignored
        so a caller passing an extra count never crashes a finishing run.
        """
        run.status = status
        run.finished_at = _utcnow()
        allowed = {
            "evaluated",
            "created",
            "updated",
            "closed_fixed",
            "marked_stale",
            "reopened",
            "skipped",
            "notes",
        }
        for key, value in counts.items():
            if key in allowed:
                setattr(run, key, value)
        self.session.flush()
        return run

    def last_successful_full(self) -> SyncRun | None:
        """Most recent successful **full** run — the purge-gating reference."""
        stmt = (
            select(SyncRun)
            .where(SyncRun.status == SyncRunStatus.SUCCESS, SyncRun.mode == SyncMode.FULL)
            .order_by(SyncRun.started_at.desc(), SyncRun.id.desc())
            .limit(1)
        )
        return self.session.scalars(stmt).first()

    def last_successful_any(self) -> SyncRun | None:
        """Most recent successful run of **any** mode — the incremental window start."""
        stmt = (
            select(SyncRun)
            .where(SyncRun.status == SyncRunStatus.SUCCESS)
            .order_by(SyncRun.started_at.desc(), SyncRun.id.desc())
            .limit(1)
        )
        return self.session.scalars(stmt).first()


class DetectionStateRepo:
    """The ``primary_key -> Jira issue`` mapping plus the per-detection snapshot."""

    def __init__(self, session: Session) -> None:
        self.session = session

    def get(self, pk: str) -> DetectionState | None:
        return self.session.get(DetectionState, pk)

    def upsert_seen(
        self,
        merged: MergedVulnerability,
        pk: str,
        run_id: int,
        *,
        issue_key: str | None = None,
        qualys_status: str | None = None,
        material_hash: str | None = None,
        tracking_method: str | None = None,
        last_vm_scanned_date: str | None = None,
        signals: dict[str, Any] | None = None,
    ) -> DetectionState:
        """Insert or update the row for ``pk`` as *seen this run*.

        On insert ``first_seen_run`` is stamped. On both insert and update
        ``last_seen_run`` is set to ``run_id`` and ``consecutive_misses`` is reset
        to 0 (the detection is present again). The identity columns (host/qid/port)
        come from ``merged``; optional Jira/Qualys snapshot fields override the row
        when provided (a ``None`` argument leaves an existing value untouched).
        """
        row = self.session.get(DetectionState, pk)
        if row is None:
            row = DetectionState(
                primary_key=pk,
                host_id=merged.asset.host_id,
                qid=merged.detection.qid,
                port=str(merged.detection.port) if merged.detection.port is not None else "none",
                unique_vuln_id=merged.detection.unique_vuln_id,
                first_seen_run=run_id,
            )
            self.session.add(row)

        # Always present-again bookkeeping.
        row.last_seen_run = run_id
        row.consecutive_misses = 0

        # Optional snapshot fields; only overwrite when a value is supplied.
        if issue_key is not None:
            row.jira_issue_key = issue_key
        if qualys_status is not None:
            row.qualys_status = qualys_status
        if material_hash is not None:
            row.material_hash = material_hash
        if tracking_method is not None:
            row.tracking_method = tracking_method
        if last_vm_scanned_date is not None:
            row.last_vm_scanned_date = last_vm_scanned_date
        if signals is not None:
            row.signals = signals

        self.session.flush()
        return row

    def mark_missed(self, run_id: int) -> list[DetectionState]:
        """Increment ``consecutive_misses`` on open rows not seen in ``run_id``.

        "Open" = has a Jira issue and is not yet closed. A row is *missed* when its
        ``last_seen_run`` is strictly less than the current ``run_id`` (it was not
        re-stamped by :meth:`upsert_seen` this cycle). Returns the affected rows so
        the purge pass can classify each one. Only meaningful on a full run.
        """
        stmt = select(DetectionState).where(
            DetectionState.jira_issue_key.is_not(None),
            DetectionState.closed_at.is_(None),
            DetectionState.last_seen_run.is_not(None),
            DetectionState.last_seen_run < run_id,
        )
        missed = list(self.session.scalars(stmt).all())
        for row in missed:
            row.consecutive_misses = (row.consecutive_misses or 0) + 1
        self.session.flush()
        return missed

    def iter_open(self) -> list[DetectionState]:
        """All open detections (mapped to an issue, not yet closed)."""
        stmt = select(DetectionState).where(
            DetectionState.jira_issue_key.is_not(None),
            DetectionState.closed_at.is_(None),
        )
        return list(self.session.scalars(stmt).all())

    def record_closed(
        self,
        pk: str,
        reason: ClosureReason,
        resolution: str,
        *,
        purged: bool = False,
    ) -> DetectionState | None:
        """Mark ``pk`` closed with ``reason``/``resolution``.

        ``reason=fixed`` is genuine remediation; ``reason=stale`` is a purge — in
        which case ``purged=True`` also stamps ``purged_at`` (the audit trail that
        this was *not* a fix). Returns the row, or None if it does not exist.
        """
        row = self.session.get(DetectionState, pk)
        if row is None:
            return None
        now = _utcnow()
        row.closed_at = now
        row.closed_reason = reason
        row.jira_resolution = resolution
        if purged:
            row.purged_at = now
        self.session.flush()
        return row

    def set_sticky(self, pk: str, resolution: str) -> DetectionState | None:
        """Flag ``pk`` as carrying a human-set sticky ``resolution`` (never overwritten)."""
        row = self.session.get(DetectionState, pk)
        if row is None:
            return None
        row.sticky = True
        row.jira_resolution = resolution
        self.session.flush()
        return row


class KbRepo:
    """Cache of KnowledgeBase entries, keyed by QID."""

    # KbVuln fields that map 1:1 onto KbEntry columns.
    _SCALAR_FIELDS = (
        "title",
        "category",
        "severity_level",
        "vuln_type",
        "patchable",
        "pci_flag",
        "cvss_base",
        "cvss_temporal",
        "cvss_v3_base",
        "cvss_v3_temporal",
        "published_datetime",
        "last_service_modification_datetime",
        "diagnosis",
        "consequence",
        "solution",
    )

    def __init__(self, session: Session) -> None:
        self.session = session

    def get(self, qid: int) -> KbEntry | None:
        return self.session.get(KbEntry, qid)

    def upsert_many(self, vulns: list[KbVuln]) -> int:
        """Insert or refresh ``vulns`` in the cache. Returns the count written."""
        count = 0
        for vuln in vulns:
            row = self.session.get(KbEntry, vuln.qid)
            if row is None:
                row = KbEntry(qid=vuln.qid)
                self.session.add(row)
            for field in self._SCALAR_FIELDS:
                setattr(row, field, getattr(vuln, field))
            row.cve_list = list(vuln.cve_list)
            row.rtis = list(vuln.rtis)
            row.raw = vuln.raw
            row.fetched_at = _utcnow()
            count += 1
        self.session.flush()
        return count

    def age_hours(self, qid: int) -> float | None:
        """Age of the cached entry for ``qid`` in hours, or None if not cached.

        Used by the source to decide whether the KB entry is stale and needs a
        re-fetch (``QualysConfig.kb_refresh_max_age_hours``).
        """
        row = self.session.get(KbEntry, qid)
        if row is None or row.fetched_at is None:
            return None
        fetched = row.fetched_at
        if fetched.tzinfo is None:
            # SQLite round-trips naive datetimes; assume UTC for the delta.
            fetched = fetched.replace(tzinfo=UTC)
        return (_utcnow() - fetched).total_seconds() / 3600.0

    @staticmethod
    def to_kbvuln(entry: KbEntry) -> KbVuln:
        """Rehydrate a cached :class:`KbEntry` into the canonical :class:`KbVuln`."""
        return KbVuln(
            qid=entry.qid,
            title=entry.title,
            category=entry.category,
            severity_level=entry.severity_level,
            vuln_type=entry.vuln_type,
            published_datetime=entry.published_datetime,
            last_service_modification_datetime=entry.last_service_modification_datetime,
            patchable=entry.patchable,
            pci_flag=entry.pci_flag,
            cvss_base=entry.cvss_base,
            cvss_temporal=entry.cvss_temporal,
            cvss_v3_base=entry.cvss_v3_base,
            cvss_v3_temporal=entry.cvss_v3_temporal,
            diagnosis=entry.diagnosis,
            consequence=entry.consequence,
            solution=entry.solution,
            cve_list=list(entry.cve_list or []),
            rtis=list(entry.rtis or []),
            raw=entry.raw or {},
        )


class JobQueue:
    """Durable work queue. Workers claim with ``FOR UPDATE SKIP LOCKED`` on Postgres."""

    def __init__(self, session: Session) -> None:
        self.session = session

    def enqueue(self, kind: str, payload: dict[str, Any], run_id: int | None = None) -> Job:
        """Add a ``PENDING`` job. ``kind`` e.g. ``upsert_issue`` / ``close_issue``."""
        job = Job(kind=kind, payload=payload, run_id=run_id, status=JobStatus.PENDING)
        self.session.add(job)
        self.session.flush()
        return job

    def claim_batch(self, n: int) -> list[Job]:
        """Atomically claim up to ``n`` pending, available jobs.

        On PostgreSQL this uses ``FOR UPDATE SKIP LOCKED`` so concurrent workers
        never claim the same row and never block on each other. SQLite (tests) has
        no such lock, so the clause is omitted there — correctness under
        concurrency is a Postgres-only guarantee.
        """
        stmt = (
            select(Job)
            .where(Job.status == JobStatus.PENDING, Job.available_at <= _utcnow())
            .order_by(Job.available_at, Job.id)
            .limit(n)
        )
        if self.session.bind is not None and self.session.bind.dialect.name == "postgresql":
            stmt = stmt.with_for_update(skip_locked=True)
        jobs = list(self.session.scalars(stmt).all())
        now = _utcnow()
        for job in jobs:
            job.status = JobStatus.IN_PROGRESS
            job.attempts = (job.attempts or 0) + 1
            job.locked_at = now
        self.session.flush()
        return jobs

    def complete(self, job: Job) -> Job:
        """Mark ``job`` done."""
        job.status = JobStatus.DONE
        job.locked_at = None
        self.session.flush()
        return job

    def fail(self, job: Job, err: str) -> Job:
        """Mark ``job`` failed and record ``err``."""
        job.status = JobStatus.FAILED
        job.last_error = err
        job.locked_at = None
        self.session.flush()
        return job
