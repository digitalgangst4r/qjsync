"""SQLAlchemy 2.0 ORM models — the durable state contract.

Alembic owns the migrations; these classes are the source of truth they target.
JSONB columns keep the raw signals/payloads so we can re-evaluate or debug a
historical decision without re-fetching from Qualys.
"""

from __future__ import annotations

import enum
from datetime import datetime

from sqlalchemy import (
    JSON,
    BigInteger,
    DateTime,
    Index,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy import (
    Enum as SAEnum,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

# Portable JSON: real JSONB on PostgreSQL (production), plain JSON elsewhere
# (e.g. SQLite in unit tests) so repositories are testable without a live DB.
JSONColumn = JSON().with_variant(JSONB(), "postgresql")


class Base(DeclarativeBase):
    pass


class SyncRunStatus(str, enum.Enum):
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"


class SyncMode(str, enum.Enum):
    """How a sync was scoped.

    * ``incremental`` — a delta scoped to a connector-managed ``vm_scan_since``
      window (aligned to the 4h Cloud Agent cadence). Creates/updates/closes-by-
      Fixed/reopens, but **never** runs the purge pass.
    * ``full`` — the whole set per the user's query (weekly reconciliation, or the
      slowest network-scan cadence). The **only** mode that may mark a detection
      stale (purge).
    """

    INCREMENTAL = "incremental"
    FULL = "full"


class ClosureReason(str, enum.Enum):
    """Why an issue was closed by the connector — the Fixed/Purge distinction."""

    FIXED = "fixed"  # Qualys reported STATUS=Fixed -> genuine remediation
    STALE = "stale"  # detection disappeared without Fixed -> purge, NOT remediation


class JobStatus(str, enum.Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    DONE = "done"
    FAILED = "failed"


class SyncRun(Base):
    """One sync cycle. ``completeness`` gates purge inference (PurgeConfig)."""

    __tablename__ = "sync_runs"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[SyncRunStatus] = mapped_column(
        SAEnum(SyncRunStatus, name="sync_run_status"), default=SyncRunStatus.RUNNING
    )
    mode: Mapped[SyncMode] = mapped_column(
        SAEnum(SyncMode, name="sync_mode"), default=SyncMode.INCREMENTAL, index=True
    )
    # Per-run summary counters.
    evaluated: Mapped[int] = mapped_column(Integer, default=0)
    created: Mapped[int] = mapped_column(Integer, default=0)
    updated: Mapped[int] = mapped_column(Integer, default=0)
    closed_fixed: Mapped[int] = mapped_column(Integer, default=0)
    marked_stale: Mapped[int] = mapped_column(Integer, default=0)
    reopened: Mapped[int] = mapped_column(Integer, default=0)
    skipped: Mapped[int] = mapped_column(Integer, default=0)
    notes: Mapped[dict | None] = mapped_column(JSONColumn, nullable=True)


class DetectionState(Base):
    """Per-detection state: the dedup mapping plus the snapshot for diffing."""

    __tablename__ = "detection_state"

    primary_key: Mapped[str] = mapped_column(String(255), primary_key=True)

    host_id: Mapped[int] = mapped_column(BigInteger, index=True)
    qid: Mapped[int] = mapped_column(Integer, index=True)
    port: Mapped[str] = mapped_column(String(32))  # normalised (sentinel for port-less)
    unique_vuln_id: Mapped[int | None] = mapped_column(BigInteger, nullable=True)

    # Jira linkage.
    jira_issue_key: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    jira_status: Mapped[str | None] = mapped_column(String(128), nullable=True)
    jira_resolution: Mapped[str | None] = mapped_column(String(128), nullable=True)

    # Qualys-side snapshot.
    qualys_status: Mapped[str | None] = mapped_column(String(32), nullable=True)
    # Tracking method (AGENT vs IP/DNS/NETBIOS) and last network/agent scan date
    # are persisted so the purge classifier can protect non-agent (network-scan)
    # assets from false-purge — see sync.purge.classify_missing.
    tracking_method: Mapped[str | None] = mapped_column(String(32), nullable=True)
    last_vm_scanned_date: Mapped[str | None] = mapped_column(String(32), nullable=True)
    # Hash over MATERIAL fields only (telemetry excluded). A change here is what
    # triggers a Jira write — see qjsync.models.canonical.MATERIAL_SIGNAL_KEYS.
    material_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    signals: Mapped[dict | None] = mapped_column(JSONColumn, nullable=True)

    # Lifecycle bookkeeping.
    first_seen_run: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    last_seen_run: Mapped[int | None] = mapped_column(BigInteger, nullable=True, index=True)
    consecutive_misses: Mapped[int] = mapped_column(Integer, default=0)
    issue_created_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    closed_reason: Mapped[ClosureReason | None] = mapped_column(
        SAEnum(ClosureReason, name="closure_reason"), nullable=True
    )
    purged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    sticky: Mapped[bool] = mapped_column(default=False)  # human set a sticky resolution

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    __table_args__ = (Index("ix_detection_state_open", "jira_issue_key", "closed_at"),)


class KbEntry(Base):
    """Cached KnowledgeBase entry, keyed by QID."""

    __tablename__ = "kb_cache"

    qid: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str | None] = mapped_column(Text, nullable=True)
    category: Mapped[str | None] = mapped_column(String(255), nullable=True)
    severity_level: Mapped[int | None] = mapped_column(Integer, nullable=True)
    vuln_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    patchable: Mapped[bool | None] = mapped_column(nullable=True)
    pci_flag: Mapped[bool | None] = mapped_column(nullable=True)
    cvss_base: Mapped[float | None] = mapped_column(nullable=True)
    cvss_temporal: Mapped[float | None] = mapped_column(nullable=True)
    cvss_v3_base: Mapped[float | None] = mapped_column(nullable=True)
    cvss_v3_temporal: Mapped[float | None] = mapped_column(nullable=True)
    published_datetime: Mapped[str | None] = mapped_column(String(32), nullable=True)
    last_service_modification_datetime: Mapped[str | None] = mapped_column(
        String(32), nullable=True
    )
    diagnosis: Mapped[str | None] = mapped_column(Text, nullable=True)
    consequence: Mapped[str | None] = mapped_column(Text, nullable=True)
    solution: Mapped[str | None] = mapped_column(Text, nullable=True)
    cve_list: Mapped[list | None] = mapped_column(JSONColumn, nullable=True)
    rtis: Mapped[list | None] = mapped_column(JSONColumn, nullable=True)
    raw: Mapped[dict | None] = mapped_column(JSONColumn, nullable=True)
    fetched_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class Job(Base):
    """Durable work queue. Workers claim rows with FOR UPDATE SKIP LOCKED."""

    __tablename__ = "jobs"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    run_id: Mapped[int | None] = mapped_column(BigInteger, nullable=True, index=True)
    kind: Mapped[str] = mapped_column(String(64))  # e.g. "upsert_issue", "close_issue"
    payload: Mapped[dict] = mapped_column(JSONColumn)
    status: Mapped[JobStatus] = mapped_column(
        SAEnum(JobStatus, name="job_status"), default=JobStatus.PENDING, index=True
    )
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    locked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    available_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
