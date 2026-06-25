"""Lifecycle tests for the sync orchestrator against in-memory SQLite.

No live APIs: a fake source yields canonical :class:`MergedVulnerability` objects,
a fake Jira client records every write, and the real state repositories run on
SQLite. The rules engine is the real one when its module is present, otherwise a
small local evaluator with the same first-match-wins ``evaluate`` contract — both
satisfy :class:`~qjsync.sync.orchestrator.RulesEngineLike`.

Covers: create on match, skip on non-match, material vs telemetry update,
Fixed->close, reopen on return, stale on full only (never incremental), sticky
resolution never overwritten, and dry_run writing nothing.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest
from sqlalchemy import BigInteger
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import Session, sessionmaker

from qjsync.config.schema import (
    JiraConfig,
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
from qjsync.state.db import create_all, make_engine, make_session_factory
from qjsync.state.models import ClosureReason, DetectionState, SyncMode, SyncRun, SyncRunStatus
from qjsync.state.repositories import DetectionStateRepo, SyncRunRepo
from qjsync.sync.orchestrator import SyncOrchestrator


# SQLite only autoincrements INTEGER PRIMARY KEY; render BigInteger as INTEGER so
# sync_runs.id / jobs.id autoincrement in tests. Test-local; frozen models untouched.
@compiles(BigInteger, "sqlite")
def _bigint_as_integer_on_sqlite(element: BigInteger, compiler: object, **kw: object) -> str:
    return "INTEGER"


# --------------------------------------------------------------------------- #
# Test doubles
# --------------------------------------------------------------------------- #
class FakeJira:
    """Records Jira writes; serves canned issue reads for non-surprise checks."""

    def __init__(self) -> None:
        self.created: list[dict[str, Any]] = []
        self.updated: list[tuple[str, dict[str, Any]]] = []
        self.transitions: list[tuple[str, str, str | None]] = []
        self.comments: list[tuple[str, dict[str, Any]]] = []
        self.by_primary_key: dict[str, dict[str, Any]] = {}
        # issue_key -> issue dict ({"fields": {...}}) for get_issue.
        self.issues: dict[str, dict[str, Any]] = {}
        self._next = 1

    # --- writes ---
    def create_issue(self, fields: dict[str, Any]) -> dict[str, Any]:
        key = f"SEC-{self._next}"
        self._next += 1
        self.created.append(fields)
        self.issues[key] = {"key": key, "fields": dict(fields)}
        return {"key": key}

    def update_issue(self, issue_key: str, fields: dict[str, Any]) -> None:
        self.updated.append((issue_key, fields))
        self.issues.setdefault(issue_key, {"key": issue_key, "fields": {}})
        self.issues[issue_key]["fields"].update(fields)

    def transition_issue(
        self, issue_key: str, name: str, *, resolution: str | None = None
    ) -> None:
        self.transitions.append((issue_key, name, resolution))
        if resolution is not None:
            issue = self.issues.setdefault(issue_key, {"key": issue_key, "fields": {}})
            issue["fields"]["resolution"] = {"name": resolution}

    def add_comment(self, issue_key: str, body_adf: dict[str, Any]) -> None:
        self.comments.append((issue_key, body_adf))

    # --- reads ---
    def find_issue_by_primary_key(self, primary_key: str) -> dict[str, Any] | None:
        return self.by_primary_key.get(primary_key)

    def get_issue(self, issue_key: str) -> dict[str, Any]:
        return self.issues.get(issue_key, {"key": issue_key, "fields": {}})

    def set_resolution(self, issue_key: str, resolution: str | None) -> None:
        issue = self.issues.setdefault(issue_key, {"key": issue_key, "fields": {}})
        if resolution is None:
            issue["fields"].pop("resolution", None)
        else:
            issue["fields"]["resolution"] = {"name": resolution}


class FakeSource:
    """A source double yielding a fixed batch of merged vulnerabilities."""

    name = "vm"

    def __init__(self, batch: list[MergedVulnerability]) -> None:
        self.batch = batch
        self.since_seen: list[str | None] = []

    def iter_merged(self, *, since: str | None = None) -> Iterator[MergedVulnerability]:
        self.since_seen.append(since)
        yield from self.batch

    def refresh_knowledgebase(self) -> int:
        return 0


def _make_engine() -> Any:
    """The real band-shift RulesEngine over the test config."""
    from qjsync.rules.engine import RulesEngine

    return RulesEngine(_CONFIG)


# --------------------------------------------------------------------------- #
# Config + fixtures
# --------------------------------------------------------------------------- #
_CONFIG = QjsyncConfig(
    jira=JiraConfig(project="SEC"),
    qualys=QualysConfig(),
    purge=PurgeConfig(agent_grace_syncs=2, network_scan_grace_days=30),
    primary_key=PrimaryKeyConfig(),
    # Default band-shift model: qds>=90 Highest / >=70 High / >=50 Medium; below -> skip.
    prioritization=PrioritizationConfig(),
)


@pytest.fixture
def session_factory() -> sessionmaker[Session]:
    engine = make_engine("sqlite+pysqlite:///:memory:")
    create_all(engine)
    return make_session_factory(engine)


def _merged(
    *,
    host_id: int = 100,
    qid: int = 38739,
    port: int | None = 443,
    qds: int | None = 90,
    status: DetectionStatus = DetectionStatus.ACTIVE,
    tracking_method: str = "AGENT",
    last_vm_scanned_date: str | None = "2026-06-19T00:00:00Z",
    cvss_base: float | None = 7.5,
) -> MergedVulnerability:
    return MergedVulnerability(
        asset=Asset(
            host_id=host_id,
            tracking_method=tracking_method,
            last_vm_scanned_date=last_vm_scanned_date,
        ),
        detection=Detection(qid=qid, port=port, qds=qds, status=status),
        kb=KbVuln(qid=qid, title="Test", cvss_base=cvss_base),
    )


def _orch(source: FakeSource, jira: FakeJira, factory: sessionmaker[Session]) -> SyncOrchestrator:
    return SyncOrchestrator(source, _make_engine(), jira, factory, _CONFIG)


def _state(factory: sessionmaker[Session], pk: str) -> DetectionState | None:
    with factory() as s:
        return DetectionStateRepo(s).get(pk)


# --------------------------------------------------------------------------- #
# create / skip
# --------------------------------------------------------------------------- #
def test_create_on_match(session_factory: sessionmaker[Session]) -> None:
    merged = _merged(qds=90)
    jira = FakeJira()
    source = FakeSource([merged])
    summary = _orch(source, jira, session_factory).run(mode=SyncMode.FULL)

    assert summary.created == 1
    assert len(jira.created) == 1
    fields = jira.created[0]
    # Primary Key is written; the managed label is present.
    assert fields[_CONFIG.jira.primary_key_field] == merged.primary_key()
    assert _CONFIG.jira.managed_label in fields["labels"]

    row = _state(session_factory, merged.primary_key())
    assert row is not None
    assert row.jira_issue_key == "SEC-1"
    assert row.material_hash == merged.material_hash()


def _comment_text(body: dict[str, Any]) -> str:
    return body["content"][0]["content"][0]["text"]


def test_create_posts_open_comment(session_factory: sessionmaker[Session]) -> None:
    jira = FakeJira()
    _orch(FakeSource([_merged(qds=90)]), jira, session_factory).run(mode=SyncMode.FULL)
    assert len(jira.comments) == 1
    text = _comment_text(jira.comments[0][1])
    assert "encontrada no Qualys" in text and "Abrindo Ticket" in text


def test_fixed_posts_close_comment(session_factory: sessionmaker[Session]) -> None:
    jira = FakeJira()
    _orch(FakeSource([_merged(qds=90, status=DetectionStatus.ACTIVE)]), jira, session_factory).run(
        mode=SyncMode.FULL
    )
    jira.comments.clear()
    _orch(FakeSource([_merged(qds=90, status=DetectionStatus.FIXED)]), jira, session_factory).run(
        mode=SyncMode.FULL
    )
    assert any("Fechando ticket" in _comment_text(b) for _, b in jira.comments)


def test_skip_on_non_match(session_factory: sessionmaker[Session]) -> None:
    merged = _merged(qds=10)  # below the rule threshold
    jira = FakeJira()
    summary = _orch(FakeSource([merged]), jira, session_factory).run(mode=SyncMode.FULL)

    assert summary.created == 0
    assert summary.skipped == 1
    assert jira.created == []
    # State is recorded even though no issue was created.
    row = _state(session_factory, merged.primary_key())
    assert row is not None
    assert row.jira_issue_key is None


# --------------------------------------------------------------------------- #
# material vs telemetry update
# --------------------------------------------------------------------------- #
def test_material_change_triggers_update(session_factory: sessionmaker[Session]) -> None:
    jira = FakeJira()
    first = _merged(qds=90)
    _orch(FakeSource([first]), jira, session_factory).run(mode=SyncMode.FULL)
    assert len(jira.created) == 1

    # QDS (material) moves -> exactly one PUT.
    second = _merged(qds=95)
    summary = _orch(FakeSource([second]), jira, session_factory).run(mode=SyncMode.FULL)
    assert summary.updated == 1
    assert len(jira.updated) == 1
    row = _state(session_factory, second.primary_key())
    assert row is not None
    assert row.material_hash == second.material_hash()


def test_telemetry_only_change_no_jira_write(session_factory: sessionmaker[Session]) -> None:
    jira = FakeJira()
    first = _merged(qds=90, last_vm_scanned_date="2026-06-19T00:00:00Z")
    _orch(FakeSource([first]), jira, session_factory).run(mode=SyncMode.FULL)
    jira.updated.clear()

    # Only telemetry (scan date) changes; material hash is identical.
    second = _merged(qds=90, last_vm_scanned_date="2026-06-19T04:00:00Z")
    assert second.material_hash() == first.material_hash()
    summary = _orch(FakeSource([second]), jira, session_factory).run(mode=SyncMode.FULL)

    assert summary.updated == 0
    assert summary.telemetry == 1
    assert jira.updated == []  # snapshot only, no Jira write
    row = _state(session_factory, second.primary_key())
    assert row is not None
    assert row.last_vm_scanned_date == "2026-06-19T04:00:00Z"


# --------------------------------------------------------------------------- #
# Fixed -> close
# --------------------------------------------------------------------------- #
def test_fixed_closes_issue(session_factory: sessionmaker[Session]) -> None:
    jira = FakeJira()
    active = _merged(qds=90, status=DetectionStatus.ACTIVE)
    _orch(FakeSource([active]), jira, session_factory).run(mode=SyncMode.FULL)
    key = jira.created and "SEC-1"

    fixed = _merged(qds=90, status=DetectionStatus.FIXED)
    summary = _orch(FakeSource([fixed]), jira, session_factory).run(mode=SyncMode.FULL)

    assert summary.closed_fixed == 1
    assert (key, _CONFIG.jira.done_transition, _CONFIG.jira.resolution_fixed) in jira.transitions
    row = _state(session_factory, fixed.primary_key())
    assert row is not None
    assert row.closed_reason is ClosureReason.FIXED
    assert row.purged_at is None  # a fix is not a purge


# --------------------------------------------------------------------------- #
# reopen on return
# --------------------------------------------------------------------------- #
def test_reopen_after_fixed_then_active(session_factory: sessionmaker[Session]) -> None:
    jira = FakeJira()
    pk = _merged().primary_key()
    _orch(FakeSource([_merged(status=DetectionStatus.ACTIVE)]), jira, session_factory).run(
        mode=SyncMode.FULL
    )
    _orch(FakeSource([_merged(status=DetectionStatus.FIXED)]), jira, session_factory).run(
        mode=SyncMode.FULL
    )
    # Clear resolution so the reopened issue is not seen as sticky.
    jira.set_resolution("SEC-1", None)

    summary = _orch(
        FakeSource([_merged(status=DetectionStatus.REOPENED)]), jira, session_factory
    ).run(mode=SyncMode.FULL)

    assert summary.reopened == 1
    assert ("SEC-1", _CONFIG.jira.reopen_transition, None) in jira.transitions
    row = _state(session_factory, pk)
    assert row is not None
    assert row.closed_at is None  # lifecycle re-opened


# --------------------------------------------------------------------------- #
# stale only on full
# --------------------------------------------------------------------------- #
def test_stale_only_on_full_after_grace(session_factory: sessionmaker[Session]) -> None:
    jira = FakeJira()
    merged = _merged(tracking_method="AGENT")
    pk = merged.primary_key()
    # Create the issue on a full run.
    _orch(FakeSource([merged]), jira, session_factory).run(mode=SyncMode.FULL)

    # Two subsequent full runs where the detection is ABSENT -> 2 misses -> stale.
    _orch(FakeSource([]), jira, session_factory).run(mode=SyncMode.FULL)  # miss 1
    summary = _orch(FakeSource([]), jira, session_factory).run(mode=SyncMode.FULL)  # miss 2

    assert summary.marked_stale == 1
    row = _state(session_factory, pk)
    assert row is not None
    assert row.closed_reason is ClosureReason.STALE
    assert row.purged_at is not None
    # Closed via stale resolution, with the stale label applied.
    assert any(
        t == ("SEC-1", _CONFIG.jira.done_transition, _CONFIG.jira.resolution_stale)
        for t in jira.transitions
    )
    label_update = [u for u in jira.updated if _CONFIG.jira.stale_label in u[1].get("labels", [])]
    assert label_update


def test_incremental_never_marks_stale(session_factory: sessionmaker[Session]) -> None:
    jira = FakeJira()
    merged = _merged(tracking_method="AGENT")
    pk = merged.primary_key()
    _orch(FakeSource([merged]), jira, session_factory).run(mode=SyncMode.FULL)

    # Many incremental runs with the detection absent must never purge.
    for _ in range(5):
        summary = _orch(FakeSource([]), jira, session_factory).run(mode=SyncMode.INCREMENTAL)
        assert summary.marked_stale == 0

    row = _state(session_factory, pk)
    assert row is not None
    assert row.closed_at is None  # still open


def test_partial_full_does_not_overpurge_network(
    session_factory: sessionmaker[Session],
) -> None:
    # A network asset recently scanned must NOT go stale just for being absent.
    jira = FakeJira()
    net = _merged(
        host_id=200, qid=111, tracking_method="IP", last_vm_scanned_date="2026-06-18T00:00:00Z"
    )
    pk = net.primary_key()
    _orch(FakeSource([net]), jira, session_factory).run(mode=SyncMode.FULL)

    # Absent across full runs, but recently scanned -> kept (not stale).
    for _ in range(3):
        summary = _orch(FakeSource([]), jira, session_factory).run(mode=SyncMode.FULL)
        assert summary.marked_stale == 0

    row = _state(session_factory, pk)
    assert row is not None
    assert row.closed_at is None


# --------------------------------------------------------------------------- #
# sticky resolution
# --------------------------------------------------------------------------- #
def test_sticky_resolution_not_overwritten(session_factory: sessionmaker[Session]) -> None:
    jira = FakeJira()
    merged = _merged(qds=90)
    pk = merged.primary_key()
    _orch(FakeSource([merged]), jira, session_factory).run(mode=SyncMode.FULL)
    # A human marks the issue Risk Accepted.
    jira.set_resolution("SEC-1", "Risk Accepted")
    jira.updated.clear()
    jira.transitions.clear()

    # A material change would normally PUT; sticky must suppress the write.
    changed = _merged(qds=99)
    summary = _orch(FakeSource([changed]), jira, session_factory).run(mode=SyncMode.FULL)

    assert summary.updated == 0
    assert jira.updated == []
    row = _state(session_factory, pk)
    assert row is not None
    assert row.sticky is True
    assert row.jira_resolution == "Risk Accepted"


def test_sticky_not_purged(session_factory: sessionmaker[Session]) -> None:
    jira = FakeJira()
    merged = _merged(tracking_method="AGENT")
    pk = merged.primary_key()
    _orch(FakeSource([merged]), jira, session_factory).run(mode=SyncMode.FULL)
    jira.set_resolution("SEC-1", "Won't Do")

    _orch(FakeSource([]), jira, session_factory).run(mode=SyncMode.FULL)
    summary = _orch(FakeSource([]), jira, session_factory).run(mode=SyncMode.FULL)

    assert summary.marked_stale == 0
    row = _state(session_factory, pk)
    assert row is not None
    assert row.closed_reason is None  # sticky issue left alone
    assert row.sticky is True


# --------------------------------------------------------------------------- #
# dry run
# --------------------------------------------------------------------------- #
def test_dry_run_writes_nothing(session_factory: sessionmaker[Session]) -> None:
    jira = FakeJira()
    merged = _merged(qds=90)
    summary = _orch(FakeSource([merged]), jira, session_factory).run(
        dry_run=True, mode=SyncMode.FULL
    )

    # Would-create is counted, but no Jira write happened.
    assert summary.created == 1
    assert jira.created == []
    assert jira.updated == []
    assert jira.transitions == []
    # State is still snapshotted (reads/DB only), but with no issue key.
    row = _state(session_factory, merged.primary_key())
    assert row is not None
    assert row.jira_issue_key is None


def test_dry_run_would_mark_stale_without_writing(
    session_factory: sessionmaker[Session],
) -> None:
    jira = FakeJira()
    merged = _merged(tracking_method="AGENT")
    pk = merged.primary_key()
    _orch(FakeSource([merged]), jira, session_factory).run(mode=SyncMode.FULL)
    jira.transitions.clear()

    # Two absences accrue misses; the second is a dry run that should only report.
    _orch(FakeSource([]), jira, session_factory).run(mode=SyncMode.FULL)
    summary = _orch(FakeSource([]), jira, session_factory).run(dry_run=True, mode=SyncMode.FULL)

    assert summary.marked_stale == 1
    assert jira.transitions == []  # no real close in a dry run
    row = _state(session_factory, pk)
    assert row is not None
    assert row.closed_at is None  # not actually purged


# --------------------------------------------------------------------------- #
# incremental window
# --------------------------------------------------------------------------- #
def test_incremental_computes_since_from_last_success(
    session_factory: sessionmaker[Session],
) -> None:
    # Seed a prior successful run so the incremental window has a basis.
    with session_factory() as s:
        repo = SyncRunRepo(s)
        prior = repo.start(SyncMode.FULL)
        repo.finish(prior, SyncRunStatus.SUCCESS)
        s.commit()

    jira = FakeJira()
    source = FakeSource([_merged(qds=90)])
    _orch(source, jira, session_factory).run(mode=SyncMode.INCREMENTAL)

    # A since window was computed and passed to the source.
    assert source.since_seen[0] is not None
    assert source.since_seen[0].endswith("Z")


def test_first_incremental_has_no_window(session_factory: sessionmaker[Session]) -> None:
    jira = FakeJira()
    source = FakeSource([_merged(qds=90)])
    _orch(source, jira, session_factory).run(mode=SyncMode.INCREMENTAL)
    # No prior success -> behaves as a bounded full (no managed window).
    assert source.since_seen[0] is None


def test_full_run_passes_no_window(session_factory: sessionmaker[Session]) -> None:
    with session_factory() as s:
        repo = SyncRunRepo(s)
        prior = repo.start(SyncMode.FULL)
        repo.finish(prior, SyncRunStatus.SUCCESS)
        s.commit()

    jira = FakeJira()
    source = FakeSource([_merged(qds=90)])
    _orch(source, jira, session_factory).run(mode=SyncMode.FULL)
    assert source.since_seen[0] is None  # full injects no managed window


# --------------------------------------------------------------------------- #
# run row + failure
# --------------------------------------------------------------------------- #
def test_run_row_finishes_success_with_counts(
    session_factory: sessionmaker[Session],
) -> None:
    jira = FakeJira()
    _orch(FakeSource([_merged(qds=90)]), jira, session_factory).run(mode=SyncMode.FULL)
    with session_factory() as s:
        run = SyncRunRepo(s).last_successful_full()
        assert run is not None
        assert run.status is SyncRunStatus.SUCCESS
        assert run.created == 1
        assert run.evaluated == 1


def test_run_marked_failed_on_source_error(
    session_factory: sessionmaker[Session],
) -> None:
    class Boom(FakeSource):
        def iter_merged(self, *, since: str | None = None) -> Iterator[MergedVulnerability]:
            raise RuntimeError("fetch incomplete")

    jira = FakeJira()
    orch = _orch(Boom([]), jira, session_factory)
    with pytest.raises(RuntimeError):
        orch.run(mode=SyncMode.FULL)

    # The run is recorded FAILED, so neither purge nor the window trusts it.
    with session_factory() as s:
        from sqlalchemy import select

        run = s.scalars(select(SyncRun)).first()
        assert run is not None
        assert run.status is SyncRunStatus.FAILED


# --------------------------------------------------------------------------- #
# dashboard-only mode (jira.enabled = false): full lifecycle, zero Jira calls
# --------------------------------------------------------------------------- #
def _no_jira_config(*, agent_grace_syncs: int = 1) -> QjsyncConfig:
    return QjsyncConfig(
        jira=JiraConfig(enabled=False),  # no project required when disabled
        qualys=QualysConfig(),
        purge=PurgeConfig(agent_grace_syncs=agent_grace_syncs, network_scan_grace_days=30),
        primary_key=PrimaryKeyConfig(),
        prioritization=PrioritizationConfig(),
    )


def _null_orch(
    source: FakeSource, factory: sessionmaker[Session], config: QjsyncConfig
) -> SyncOrchestrator:
    from qjsync.jira.null import NullFieldBuilder, NullJiraClient
    from qjsync.rules.engine import RulesEngine

    return SyncOrchestrator(
        source, RulesEngine(config), NullJiraClient(), factory, config, mapper=NullFieldBuilder()
    )


def test_dashboard_only_create_uses_local_marker(session_factory: sessionmaker[Session]) -> None:
    from qjsync.jira.null import local_issue_key

    cfg = _no_jira_config()
    merged = _merged(qds=90, status=DetectionStatus.ACTIVE)
    summary = _null_orch(FakeSource([merged]), session_factory, cfg).run(mode=SyncMode.FULL)

    assert summary.created == 1
    row = _state(session_factory, merged.primary_key())
    assert row is not None
    assert row.closed_at is None  # open
    # The "issue key" is a deterministic local marker — never a real Jira key.
    assert row.jira_issue_key == local_issue_key(merged.primary_key())
    assert row.jira_issue_key.startswith("LOCAL-")


def test_dashboard_only_fixed_closes_in_state(session_factory: sessionmaker[Session]) -> None:
    cfg = _no_jira_config()
    merged = _merged(qds=90, status=DetectionStatus.ACTIVE)
    _null_orch(FakeSource([merged]), session_factory, cfg).run(mode=SyncMode.FULL)

    summary = _null_orch(
        FakeSource([_merged(qds=90, status=DetectionStatus.FIXED)]), session_factory, cfg
    ).run(mode=SyncMode.FULL)

    assert summary.closed_fixed == 1
    row = _state(session_factory, merged.primary_key())
    assert row is not None
    assert row.closed_at is not None
    assert row.closed_reason is ClosureReason.FIXED


def test_dashboard_only_stale_purge_in_state(session_factory: sessionmaker[Session]) -> None:
    # agent_grace_syncs=1: present once, then absent on a full run -> stale (purge).
    cfg = _no_jira_config(agent_grace_syncs=1)
    merged = _merged(qds=90, status=DetectionStatus.ACTIVE, tracking_method="AGENT")
    _null_orch(FakeSource([merged]), session_factory, cfg).run(mode=SyncMode.FULL)

    summary = _null_orch(FakeSource([]), session_factory, cfg).run(mode=SyncMode.FULL)

    assert summary.marked_stale == 1
    row = _state(session_factory, merged.primary_key())
    assert row is not None
    assert row.closed_reason is ClosureReason.STALE
    assert row.purged_at is not None  # the durable "this was NOT a fix" marker


def test_jira_disabled_config_allows_missing_project() -> None:
    cfg = QjsyncConfig(jira=JiraConfig(enabled=False))
    assert cfg.jira.enabled is False
    assert cfg.jira.project == ""


def test_jira_enabled_requires_project() -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        JiraConfig(enabled=True, project="")
