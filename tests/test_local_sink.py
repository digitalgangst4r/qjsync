"""LocalSink lifecycle tests — the qjsync↔dash boundary, on in-memory SQLite.

A fake source drives the real orchestrator with a real LocalSink writing to the dash.issues /
dash.issue_events contract tables (in an attached `dash` schema). Proves LocalSink preserves the
orchestrator's invariants exactly, just writing locally instead of to Jira:
create, fixed-close, purge→stale (never fixed), sticky respected, telemetry no-write, idempotency.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest
from sqlalchemy import BigInteger, create_engine, event, func, select, update
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from qjsync.config.schema import (
    PrimaryKeyConfig,
    PrioritizationConfig,
    PurgeConfig,
    QjsyncConfig,
    QualysConfig,
)
from qjsync.models.canonical import (
    Asset,
    Detection,
    DetectionStatus,
    KbVuln,
    MergedVulnerability,
)
from qjsync.sink.contract import issue_events, issues
from qjsync.sink.contract import _metadata as dash_meta
from qjsync.sink.local import LocalFieldBuilder, LocalSink
from qjsync.state.db import create_all
from qjsync.state.models import SyncMode
from qjsync.state.repositories import DetectionStateRepo
from qjsync.sync.orchestrator import SyncOrchestrator


@compiles(BigInteger, "sqlite")
def _bigint_as_integer_on_sqlite(element: BigInteger, compiler: object, **kw: object) -> str:
    return "INTEGER"  # so BigInteger PKs autoincrement on SQLite


class FakeSource:
    name = "vm"

    def __init__(self, batch: list[MergedVulnerability]) -> None:
        self.batch = batch

    def iter_merged(self, *, since: str | None = None) -> Iterator[MergedVulnerability]:
        yield from self.batch

    def refresh_knowledgebase(self) -> int:
        return 0


def _merged(
    *,
    host_id: int = 100,
    qid: int = 38739,
    qds: int = 90,
    status: DetectionStatus = DetectionStatus.ACTIVE,
    tracking: str = "AGENT",
) -> MergedVulnerability:
    return MergedVulnerability(
        asset=Asset(host_id=host_id, tracking_method=tracking, last_vm_scanned_date="2026-06-19T00:00:00Z"),
        detection=Detection(
            qid=qid, port=443, qds=qds, status=status, first_found_datetime="2026-01-01T00:00:00Z"
        ),
        kb=KbVuln(qid=qid, title="Test Vuln", cvss_base=7.5),
    )


def _cfg(*, agent_grace_syncs: int = 2) -> QjsyncConfig:
    return QjsyncConfig(
        sink="local",
        qualys=QualysConfig(),
        purge=PurgeConfig(agent_grace_syncs=agent_grace_syncs, network_scan_grace_days=30),
        primary_key=PrimaryKeyConfig(),
        prioritization=PrioritizationConfig(),
    )


@pytest.fixture
def factory() -> sessionmaker[Session]:
    engine = create_engine(
        "sqlite://", future=True, connect_args={"check_same_thread": False}, poolclass=StaticPool
    )

    @event.listens_for(engine, "connect")
    def _attach(dbapi_conn, _record):  # noqa: ANN001
        cur = dbapi_conn.cursor()
        cur.execute("ATTACH DATABASE ':memory:' AS dash")
        cur.close()

    create_all(engine)  # qjsync tables (main)
    dash_meta.create_all(engine)  # dash.issues + dash.issue_events (attached 'dash')
    return sessionmaker(bind=engine, expire_on_commit=False, future=True, class_=Session)


def _orch(source: FakeSource, factory: sessionmaker[Session], cfg: QjsyncConfig) -> SyncOrchestrator:
    from qjsync.rules.engine import RulesEngine

    return SyncOrchestrator(
        source, RulesEngine(cfg), LocalSink(factory, cfg), factory, cfg, mapper=LocalFieldBuilder()
    )


def _issue(factory: sessionmaker[Session], pk: str) -> dict[str, Any] | None:
    with factory() as s:
        row = s.execute(select(issues).where(issues.c.primary_key == pk)).mappings().first()
    return dict(row) if row else None


def _events(factory: sessionmaker[Session], issue_id: int) -> list[dict]:
    with factory() as s:
        return [dict(r) for r in s.execute(
            select(issue_events).where(issue_events.c.issue_id == issue_id)
        ).mappings()]


def _state(factory: sessionmaker[Session], pk: str):
    with factory() as s:
        return DetectionStateRepo(s).get(pk)


def test_local_create_writes_issue(factory: sessionmaker[Session]) -> None:
    cfg = _cfg()
    m = _merged(qds=90)
    summary = _orch(FakeSource([m]), factory, cfg).run(mode=SyncMode.FULL)

    assert summary.created == 1
    iss = _issue(factory, m.primary_key())
    assert iss is not None
    assert iss["lifecycle_state"] == "open"
    assert iss["local_key"].startswith("QJ-")
    assert iss["qid"] == m.detection.qid
    assert iss["title"] == m.title
    assert iss["priority"] is not None  # band-shift prioritisation mirrored
    assert iss["first_found_at"] is not None  # SLA clock start
    # detection_state (qjsync) links to the local key
    assert _state(factory, m.primary_key()).jira_issue_key == iss["local_key"]
    # timeline has an 'opened' event authored by qjsync
    assert any(e["kind"] == "opened" and e["author"] == "qjsync" for e in _events(factory, iss["id"]))


def test_local_fixed_closes_lifecycle(factory: sessionmaker[Session]) -> None:
    cfg = _cfg()
    m = _merged(qds=90, status=DetectionStatus.ACTIVE)
    _orch(FakeSource([m]), factory, cfg).run(mode=SyncMode.FULL)
    summary = _orch(
        FakeSource([_merged(qds=90, status=DetectionStatus.FIXED)]), factory, cfg
    ).run(mode=SyncMode.FULL)

    assert summary.closed_fixed == 1
    iss = _issue(factory, m.primary_key())
    assert iss["lifecycle_state"] == "closed_fixed"
    assert iss["closed_at"] is not None
    assert iss["purged_at"] is None


def test_local_purge_closes_stale_never_fixed(factory: sessionmaker[Session]) -> None:
    cfg = _cfg(agent_grace_syncs=1)
    m = _merged(qds=90, tracking="AGENT")
    _orch(FakeSource([m]), factory, cfg).run(mode=SyncMode.FULL)
    summary = _orch(FakeSource([]), factory, cfg).run(mode=SyncMode.FULL)  # absent → purge

    assert summary.marked_stale == 1
    iss = _issue(factory, m.primary_key())
    assert iss["lifecycle_state"] == "closed_stale"  # NOT closed_fixed — purge ≠ remediation
    assert iss["purged_at"] is not None


def test_local_sticky_resolution_respected(factory: sessionmaker[Session]) -> None:
    cfg = _cfg()
    m = _merged(qds=90, status=DetectionStatus.ACTIVE)
    _orch(FakeSource([m]), factory, cfg).run(mode=SyncMode.FULL)

    # The team sets a sticky resolution in the dash (simulated UI write to the dash-owned column).
    with factory() as s:
        s.execute(
            update(issues).where(issues.c.primary_key == m.primary_key()).values(
                sticky_resolution="Won't Fix"
            )
        )
        s.commit()

    # qjsync now sees STATUS=Fixed but must NOT close — the human resolution is sticky.
    summary = _orch(
        FakeSource([_merged(qds=90, status=DetectionStatus.FIXED)]), factory, cfg
    ).run(mode=SyncMode.FULL)

    assert summary.closed_fixed == 0
    assert _issue(factory, m.primary_key())["lifecycle_state"] == "open"  # untouched
    assert _state(factory, m.primary_key()).sticky is True


def test_local_telemetry_no_write_no_event_and_idempotent(factory: sessionmaker[Session]) -> None:
    cfg = _cfg()
    m = _merged(qds=90, status=DetectionStatus.ACTIVE)
    _orch(FakeSource([m]), factory, cfg).run(mode=SyncMode.FULL)
    iss = _issue(factory, m.primary_key())
    events_before = len(_events(factory, iss["id"]))

    # Identical material on the next run → telemetry-only → no update_issue, no new timeline event.
    summary = _orch(
        FakeSource([_merged(qds=90, status=DetectionStatus.ACTIVE)]), factory, cfg
    ).run(mode=SyncMode.FULL)

    assert summary.telemetry >= 1
    assert summary.updated == 0
    assert len(_events(factory, iss["id"])) == events_before  # no timeline noise
    with factory() as s:  # still exactly one issue (idempotent on primary_key)
        assert s.execute(select(func.count()).select_from(issues)).scalar_one() == 1
