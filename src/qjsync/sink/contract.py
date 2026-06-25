"""The qjsync↔dash boundary contract: the ``dash.issues`` / ``dash.issue_events`` columns the
LocalSink writes.

The **dash** owns the DDL for these tables (Alembic migrations + the column-level grants that
physically stop qjsync from touching the team's workflow columns, and the trigger that auto-moves a
team's workflow to "Concluído" when lifecycle becomes ``closed_fixed``). qjsync only declares — via
SQLAlchemy Core, without importing the dash's ORM — the subset of columns it is allowed to write,
exactly mirroring how the dash declares read-only Core contracts for qjsync's tables. Keep the two
in lock-step; this module is the single source of truth on the qjsync side.

Ownership (enforced in Postgres by grants — see the dash migration):

* qjsync (LocalSink) writes:  mirrored vuln fields, ``priority``/``band``/``labels``,
  ``lifecycle_state``, the lifecycle timestamps, ``first_found_at``. Reads ``sticky_resolution``.
* dash (team UI) writes:      ``workflow_status``, ``assignee_id``, ``sticky_resolution`` (+ reason),
  ``due_date``, human comments/events.
"""

from __future__ import annotations

from sqlalchemy import (
    BigInteger,
    Boolean,
    Column,
    DateTime,
    Integer,
    MetaData,
    Numeric,
    String,
    Table,
    Text,
)
from sqlalchemy.types import JSON

DASH_SCHEMA = "dash"

# JSONB on PostgreSQL, plain JSON on SQLite (tests) — matches both sides' variant convention.
try:  # keep importable without the postgres dialect present
    from sqlalchemy.dialects.postgresql import JSONB

    _JSON = JSON().with_variant(JSONB(), "postgresql")
except Exception:  # pragma: no cover
    _JSON = JSON()

_metadata = MetaData(schema=DASH_SCHEMA)

issues = Table(
    "issues",
    _metadata,
    Column("id", BigInteger, primary_key=True, autoincrement=True),
    Column("local_key", String(32)),  # "QJ-<id>", set by the sink after insert
    Column("primary_key", String(255), unique=True),  # logical FK -> public.detection_state
    # --- qjsync-owned: mirrored vuln fields (hot fields only; heavy text via JOIN to kb_cache) ---
    Column("qid", Integer),
    Column("title", Text),
    Column("qds", Integer),
    Column("severity", Integer),
    Column("cvss_v3_base", Numeric),
    Column("epss", Numeric),
    Column("cve_list", _JSON),
    Column("host_id", BigInteger),
    Column("os", String),
    Column("tracking_method", String(32)),
    Column("network_id", Integer),
    Column("pci_flag", Boolean),
    Column("has_exploit", Boolean),
    Column("actively_attacked", Boolean),
    Column("ransomware", Boolean),
    Column("wormable", Boolean),
    Column("qualys_status", String(32)),
    Column("asset_tags", _JSON),  # the Qualys asset tags — the dash scopes visibility by team off these
    # --- qjsync-owned: derived prioritisation (NOT in detection_state; must be mirrored) ---
    Column("priority", String(32)),
    Column("band", String(32)),
    Column("labels", _JSON),
    # --- qjsync-owned: lifecycle (separate from the team workflow) ---
    Column("lifecycle_state", String(16)),  # open | closed_fixed | closed_stale | reopened
    Column("first_found_at", DateTime(timezone=True)),  # SLA clock start
    Column("closed_at", DateTime(timezone=True)),
    Column("purged_at", DateTime(timezone=True)),
    # --- dash-owned (qjsync only READS sticky_resolution; never writes these) ---
    Column("workflow_status", String(32)),
    Column("assignee_id", BigInteger),
    Column("sticky_resolution", String(128)),
    Column("sticky_reason", Text),
    Column("due_date", DateTime(timezone=True)),
    Column("created_at", DateTime(timezone=True)),
    Column("updated_at", DateTime(timezone=True)),
)

issue_events = Table(
    "issue_events",
    _metadata,
    Column("id", BigInteger, primary_key=True, autoincrement=True),
    Column("issue_id", BigInteger),  # FK -> dash.issues.id
    Column("author", String(128)),  # "qjsync" / "system" for sink events
    Column("kind", String(32)),  # opened | updated | closed_fixed | closed_stale | reopened | comment
    Column("body", Text),
    Column("payload", _JSON),
    Column("created_at", DateTime(timezone=True)),
)

# Columns the sink may set on INSERT (workflow_status/assignee/etc. take their DB defaults).
SINK_INSERT_COLUMNS: tuple[str, ...] = (
    "primary_key", "qid", "title", "qds", "severity", "cvss_v3_base", "epss", "cve_list",
    "host_id", "os", "tracking_method", "network_id", "pci_flag", "has_exploit",
    "actively_attacked", "ransomware", "wormable", "qualys_status", "asset_tags", "priority", "band", "labels",
    "lifecycle_state", "first_found_at",
)

# Columns the sink may set on UPDATE — the qjsync-owned set ONLY (never workflow/assignee/sticky).
SINK_UPDATE_COLUMNS: tuple[str, ...] = (
    "qid", "title", "qds", "severity", "cvss_v3_base", "epss", "cve_list", "host_id", "os",
    "tracking_method", "network_id", "pci_flag", "has_exploit", "actively_attacked", "ransomware",
    "wormable", "qualys_status", "asset_tags", "priority", "band", "labels", "lifecycle_state",
    "first_found_at", "closed_at", "purged_at",
)
