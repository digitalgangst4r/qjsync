"""Unit tests for the state repositories against in-memory SQLite.

These exercise the lifecycle bookkeeping the orchestrator relies on without any
live database: SQLite is created fresh per test via ``create_all``. The
``FOR UPDATE SKIP LOCKED`` path is Postgres-only, so the queue tests assert the
claim semantics (status/attempts) rather than concurrency.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from sqlalchemy import BigInteger
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import Session, sessionmaker

from qjsync.models.canonical import (
    Asset,
    Detection,
    DetectionStatus,
    KbVuln,
    MergedVulnerability,
)
from qjsync.state.db import create_all, make_engine, make_session_factory
from qjsync.state.models import ClosureReason, JobStatus, SyncMode, SyncRunStatus
from qjsync.state.repositories import (
    DetectionStateRepo,
    JobQueue,
    KbRepo,
    SyncRunRepo,
)


# SQLite only autoincrements an ``INTEGER PRIMARY KEY``; a ``BIGINT`` PK (used for
# sync_runs.id / jobs.id in production Postgres) silently stays NULL. Render
# BigInteger as INTEGER on SQLite *for the tests only* so autoincrement PKs work.
# This is test-local and does not touch the frozen ORM models.
@compiles(BigInteger, "sqlite")
def _bigint_as_integer_on_sqlite(element: BigInteger, compiler: object, **kw: object) -> str:
    return "INTEGER"


@pytest.fixture
def session_factory() -> sessionmaker[Session]:
    engine = make_engine("sqlite+pysqlite:///:memory:")
    create_all(engine)
    return make_session_factory(engine)


@pytest.fixture
def session(session_factory: sessionmaker[Session]) -> Iterator[Session]:
    sess = session_factory()
    try:
        yield sess
    finally:
        sess.rollback()
        sess.close()


def _merged(
    *,
    host_id: int = 100,
    qid: int = 38739,
    port: int | None = 443,
    unique_vuln_id: int | None = 9001,
    status: DetectionStatus = DetectionStatus.ACTIVE,
    tracking_method: str = "AGENT",
) -> MergedVulnerability:
    return MergedVulnerability(
        asset=Asset(host_id=host_id, tracking_method=tracking_method),
        detection=Detection(qid=qid, port=port, unique_vuln_id=unique_vuln_id, status=status),
        kb=None,
    )


def _kbvuln(qid: int = 38739) -> KbVuln:
    return KbVuln(
        qid=qid,
        title="Test vuln",
        category="Security Policy",
        severity_level=4,
        vuln_type="Vulnerability",
        patchable=True,
        pci_flag=False,
        cvss_base=7.5,
        cvss_v3_base=8.1,
        cve_list=["CVE-2024-0001", "CVE-2024-0002"],
        rtis=["Exploit_Public"],
        raw={"QID": qid},
    )


# --------------------------------------------------------------------------- #
# SyncRunRepo
# --------------------------------------------------------------------------- #
def test_start_assigns_id_and_running_status(session: Session) -> None:
    repo = SyncRunRepo(session)
    run = repo.start(SyncMode.INCREMENTAL)
    assert run.id is not None
    assert run.status is SyncRunStatus.RUNNING
    assert run.mode is SyncMode.INCREMENTAL


def test_finish_sets_status_and_counts(session: Session) -> None:
    repo = SyncRunRepo(session)
    run = repo.start(SyncMode.FULL)
    repo.finish(run, SyncRunStatus.SUCCESS, created=3, updated=1, skipped=5, bogus=99)
    assert run.status is SyncRunStatus.SUCCESS
    assert run.finished_at is not None
    assert run.created == 3
    assert run.updated == 1
    assert run.skipped == 5
    # Unknown counter keys are ignored, not crashed on.
    assert not hasattr(run, "bogus")


def test_last_successful_full_vs_any_mode_filter(session: Session) -> None:
    repo = SyncRunRepo(session)

    # A successful incremental, then a successful full, then a failed full.
    inc = repo.start(SyncMode.INCREMENTAL)
    repo.finish(inc, SyncRunStatus.SUCCESS)
    full = repo.start(SyncMode.FULL)
    repo.finish(full, SyncRunStatus.SUCCESS)
    failed_full = repo.start(SyncMode.FULL)
    repo.finish(failed_full, SyncRunStatus.FAILED)
    latest_inc = repo.start(SyncMode.INCREMENTAL)
    repo.finish(latest_inc, SyncRunStatus.SUCCESS)

    # last_successful_full filters mode==FULL and status==SUCCESS -> the full run.
    lf = repo.last_successful_full()
    assert lf is not None
    assert lf.id == full.id

    # last_successful_any ignores mode -> the most recent successful (incremental).
    la = repo.last_successful_any()
    assert la is not None
    assert la.id == latest_inc.id


def test_last_successful_none_when_no_success(session: Session) -> None:
    repo = SyncRunRepo(session)
    run = repo.start(SyncMode.FULL)
    repo.finish(run, SyncRunStatus.FAILED)
    assert repo.last_successful_full() is None
    assert repo.last_successful_any() is None


# --------------------------------------------------------------------------- #
# DetectionStateRepo
# --------------------------------------------------------------------------- #
def test_upsert_seen_insert_then_update(session: Session) -> None:
    repo = DetectionStateRepo(session)
    merged = _merged()
    pk = merged.primary_key()

    row = repo.upsert_seen(
        merged, pk, run_id=1, issue_key="SEC-1", qualys_status="Active", material_hash="h1"
    )
    assert row.first_seen_run == 1
    assert row.last_seen_run == 1
    assert row.consecutive_misses == 0
    assert row.jira_issue_key == "SEC-1"
    assert row.host_id == 100
    assert row.qid == 38739
    assert row.port == "443"

    # Re-seen in a later run: first_seen_run stays, last_seen_run advances.
    row2 = repo.upsert_seen(merged, pk, run_id=5, material_hash="h2")
    assert row2.primary_key == row.primary_key
    assert row2.first_seen_run == 1
    assert row2.last_seen_run == 5
    assert row2.consecutive_misses == 0
    assert row2.material_hash == "h2"
    # None args do not clobber an existing value.
    assert row2.jira_issue_key == "SEC-1"


def test_upsert_seen_portless_sentinel(session: Session) -> None:
    repo = DetectionStateRepo(session)
    merged = _merged(port=None)
    pk = merged.primary_key()
    row = repo.upsert_seen(merged, pk, run_id=1)
    assert row.port == "none"
    assert pk.endswith(":none")


def test_upsert_seen_resets_misses(session: Session) -> None:
    repo = DetectionStateRepo(session)
    merged = _merged()
    pk = merged.primary_key()
    row = repo.upsert_seen(merged, pk, run_id=1, issue_key="SEC-1")
    row.consecutive_misses = 3
    session.flush()
    row2 = repo.upsert_seen(merged, pk, run_id=2)
    assert row2.consecutive_misses == 0


def test_mark_missed_increments_and_returns(session: Session) -> None:
    repo = DetectionStateRepo(session)

    seen_again = _merged(host_id=1, qid=10, port=80)
    missed = _merged(host_id=2, qid=20, port=81)
    no_issue = _merged(host_id=3, qid=30, port=82)

    pk_seen = seen_again.primary_key()
    pk_missed = missed.primary_key()
    pk_noissue = no_issue.primary_key()

    # All three created at run 1 with issues (except no_issue, which has no issue).
    repo.upsert_seen(seen_again, pk_seen, run_id=1, issue_key="SEC-1")
    repo.upsert_seen(missed, pk_missed, run_id=1, issue_key="SEC-2")
    repo.upsert_seen(no_issue, pk_noissue, run_id=1)  # no issue key

    # Run 2: only seen_again is re-stamped.
    repo.upsert_seen(seen_again, pk_seen, run_id=2)

    result = repo.mark_missed(run_id=2)
    pks = {r.primary_key for r in result}
    # Only the open (issue-bearing) row not seen in run 2 is missed.
    assert pks == {pk_missed}
    assert result[0].consecutive_misses == 1

    # Run 3: seen_again is re-stamped again; missed is still absent and
    # increments a second time.
    repo.upsert_seen(seen_again, pk_seen, run_id=3)
    result2 = repo.mark_missed(run_id=3)
    assert {r.primary_key for r in result2} == {pk_missed}
    assert result2[0].consecutive_misses == 2


def test_mark_missed_ignores_closed_rows(session: Session) -> None:
    repo = DetectionStateRepo(session)
    merged = _merged()
    pk = merged.primary_key()
    repo.upsert_seen(merged, pk, run_id=1, issue_key="SEC-1")
    repo.record_closed(pk, ClosureReason.FIXED, "Fixed")

    assert repo.mark_missed(run_id=2) == []


def test_iter_open(session: Session) -> None:
    repo = DetectionStateRepo(session)
    open_m = _merged(host_id=1, qid=10, port=80)
    closed_m = _merged(host_id=2, qid=20, port=81)
    noissue_m = _merged(host_id=3, qid=30, port=82)

    repo.upsert_seen(open_m, open_m.primary_key(), run_id=1, issue_key="SEC-1")
    repo.upsert_seen(closed_m, closed_m.primary_key(), run_id=1, issue_key="SEC-2")
    repo.upsert_seen(noissue_m, noissue_m.primary_key(), run_id=1)
    repo.record_closed(closed_m.primary_key(), ClosureReason.FIXED, "Fixed")

    open_rows = repo.iter_open()
    assert {r.primary_key for r in open_rows} == {open_m.primary_key()}


def test_record_closed_fixed_vs_stale(session: Session) -> None:
    repo = DetectionStateRepo(session)
    fixed_m = _merged(host_id=1, qid=10, port=80)
    stale_m = _merged(host_id=2, qid=20, port=81)
    repo.upsert_seen(fixed_m, fixed_m.primary_key(), run_id=1, issue_key="SEC-1")
    repo.upsert_seen(stale_m, stale_m.primary_key(), run_id=1, issue_key="SEC-2")

    fixed_row = repo.record_closed(fixed_m.primary_key(), ClosureReason.FIXED, "Fixed")
    assert fixed_row is not None
    assert fixed_row.closed_reason is ClosureReason.FIXED
    assert fixed_row.jira_resolution == "Fixed"
    assert fixed_row.closed_at is not None
    assert fixed_row.purged_at is None  # a fix is not a purge

    stale_row = repo.record_closed(
        stale_m.primary_key(), ClosureReason.STALE, "Stale - asset/detection purged", purged=True
    )
    assert stale_row is not None
    assert stale_row.closed_reason is ClosureReason.STALE
    assert stale_row.purged_at is not None  # purge stamps the audit timestamp


def test_record_closed_missing_returns_none(session: Session) -> None:
    repo = DetectionStateRepo(session)
    assert repo.record_closed("999:999:none", ClosureReason.FIXED, "Fixed") is None


def test_set_sticky(session: Session) -> None:
    repo = DetectionStateRepo(session)
    merged = _merged()
    pk = merged.primary_key()
    repo.upsert_seen(merged, pk, run_id=1, issue_key="SEC-1")
    row = repo.set_sticky(pk, "Risk Accepted")
    assert row is not None
    assert row.sticky is True
    assert row.jira_resolution == "Risk Accepted"
    assert repo.set_sticky("nope:0:none", "Won't Do") is None


# --------------------------------------------------------------------------- #
# KbRepo
# --------------------------------------------------------------------------- #
def test_kb_upsert_and_get_roundtrip(session: Session) -> None:
    repo = KbRepo(session)
    written = repo.upsert_many([_kbvuln(1), _kbvuln(2)])
    assert written == 2

    entry = repo.get(1)
    assert entry is not None
    assert entry.title == "Test vuln"
    assert entry.cvss_base == 7.5
    assert entry.cve_list == ["CVE-2024-0001", "CVE-2024-0002"]
    assert entry.rtis == ["Exploit_Public"]

    # Rehydration to canonical KbVuln preserves the lists/scalars.
    vuln = KbRepo.to_kbvuln(entry)
    assert isinstance(vuln, KbVuln)
    assert vuln.qid == 1
    assert vuln.cve_list == ["CVE-2024-0001", "CVE-2024-0002"]
    assert vuln.patchable is True


def test_kb_upsert_updates_existing(session: Session) -> None:
    repo = KbRepo(session)
    repo.upsert_many([_kbvuln(1)])
    updated = _kbvuln(1)
    updated.title = "Changed title"
    updated.cvss_base = 9.9
    repo.upsert_many([updated])

    entry = repo.get(1)
    assert entry is not None
    assert entry.title == "Changed title"
    assert entry.cvss_base == 9.9


def test_kb_age_hours(session: Session) -> None:
    repo = KbRepo(session)
    assert repo.age_hours(1) is None  # not cached yet
    repo.upsert_many([_kbvuln(1)])
    age = repo.age_hours(1)
    assert age is not None
    assert age < 1.0  # just written


# --------------------------------------------------------------------------- #
# JobQueue
# --------------------------------------------------------------------------- #
def test_job_enqueue_claim_complete(session: Session) -> None:
    queue = JobQueue(session)
    j1 = queue.enqueue("upsert_issue", {"pk": "1:2:none"}, run_id=7)
    queue.enqueue("close_issue", {"pk": "3:4:none"})
    assert j1.status is JobStatus.PENDING
    assert j1.run_id == 7

    claimed = queue.claim_batch(10)
    assert len(claimed) == 2
    assert all(j.status is JobStatus.IN_PROGRESS for j in claimed)
    assert all(j.attempts == 1 for j in claimed)
    assert all(j.locked_at is not None for j in claimed)

    # Claimed jobs are no longer pending, so a second claim returns nothing.
    assert queue.claim_batch(10) == []

    queue.complete(j1)
    assert j1.status is JobStatus.DONE
    assert j1.locked_at is None


def test_job_claim_batch_respects_limit(session: Session) -> None:
    queue = JobQueue(session)
    for i in range(5):
        queue.enqueue("upsert_issue", {"i": i})
    claimed = queue.claim_batch(2)
    assert len(claimed) == 2
    # The remaining three are still claimable.
    assert len(queue.claim_batch(10)) == 3


def test_job_fail_records_error(session: Session) -> None:
    queue = JobQueue(session)
    queue.enqueue("upsert_issue", {"pk": "1:2:none"})
    (claimed,) = queue.claim_batch(1)
    queue.fail(claimed, "boom: 500 from Jira")
    assert claimed.status is JobStatus.FAILED
    assert claimed.last_error == "boom: 500 from Jira"
    assert claimed.locked_at is None
