"""Unit tests for :class:`~qjsync.sources.qualys.source.VmSource`.

These exercise the source's two real responsibilities — KB enrichment with a
reused cache, and ACS pass-through — without any live Qualys API. The lower-level
readers (``iter_detections`` / ``fetch_kb``) are owned by sibling modules built in
the same wave; here they are stubbed so this module is self-contained and tests
only the merge/cache logic that lives in ``source.py``.

The stubs are registered in ``sys.modules`` *before* importing ``source`` so the
real readers need not be present on disk for this suite to run; tests then
monkeypatch the stub callables per-case. The DB cache is real, on in-memory
SQLite.
"""

from __future__ import annotations

import sys
import types
from collections.abc import Callable, Iterator
from typing import Any

import pytest
from sqlalchemy import BigInteger
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import Session, sessionmaker

# --- Stub the sibling reader modules before importing the source under test. ---
# source.py does `import qjsync.sources.qualys.detection` (and .knowledgebase); the
# real implementations land in the same wave. Pre-seeding sys.modules lets this
# test file stand alone and gives us a stable object to monkeypatch.
_detection_stub = types.ModuleType("qjsync.sources.qualys.detection")
_knowledgebase_stub = types.ModuleType("qjsync.sources.qualys.knowledgebase")


def _unconfigured_iter_detections(*_args: Any, **_kwargs: Any) -> Iterator[Any]:
    raise AssertionError("iter_detections stub not configured for this test")


def _unconfigured_fetch_kb(*_args: Any, **_kwargs: Any) -> Iterator[Any]:
    raise AssertionError("fetch_kb stub not configured for this test")


_detection_stub.iter_detections = _unconfigured_iter_detections  # type: ignore[attr-defined]
_knowledgebase_stub.fetch_kb = _unconfigured_fetch_kb  # type: ignore[attr-defined]
# Force the stubs into sys.modules even if the real reader modules were already
# imported (e.g. by another test module collected earlier in the same session):
# `source` is (re)imported below and must bind to these stubs, not the real ones.
# We also overwrite the parent package's attributes, because `source`'s
# ``import qjsync.sources.qualys.detection as detection_mod`` resolves via the
# package attribute, not just ``sys.modules``.
import qjsync.sources.qualys as _qualys_pkg  # noqa: E402

sys.modules["qjsync.sources.qualys.detection"] = _detection_stub
sys.modules["qjsync.sources.qualys.knowledgebase"] = _knowledgebase_stub
_qualys_pkg.detection = _detection_stub  # type: ignore[attr-defined]
_qualys_pkg.knowledgebase = _knowledgebase_stub  # type: ignore[attr-defined]
sys.modules.pop("qjsync.sources.qualys.source", None)

from qjsync.config.schema import JiraConfig, QjsyncConfig  # noqa: E402
from qjsync.models.canonical import (  # noqa: E402
    Asset,
    Detection,
    DetectionStatus,
    KbVuln,
)
from qjsync.sources.qualys import source as source_mod  # noqa: E402
from qjsync.state.db import create_all, make_engine, make_session_factory  # noqa: E402
from qjsync.state.models import KbEntry  # noqa: E402
from qjsync.state.repositories import KbRepo  # noqa: E402

VmSource = source_mod.VmSource


# SQLite only autoincrements an INTEGER PRIMARY KEY; render BigInteger as INTEGER
# on SQLite for the tests so the state tables behave. Test-local; frozen models
# are untouched. (Mirrors the workaround in test_repositories.py.)
@compiles(BigInteger, "sqlite")
def _bigint_as_integer_on_sqlite(element: BigInteger, compiler: object, **kw: object) -> str:
    return "INTEGER"


# --------------------------------------------------------------------- fixtures
@pytest.fixture
def session_factory() -> sessionmaker[Session]:
    engine = make_engine("sqlite+pysqlite:///:memory:")
    create_all(engine)
    return make_session_factory(engine)


@pytest.fixture
def config() -> QjsyncConfig:
    """A minimal valid config; ACS pattern off and a 24h KB max age by default.

    VmSource only reads ``config.qualys``; prioritization defaults are irrelevant.
    """
    return QjsyncConfig(jira=JiraConfig(project="SEC"))


@pytest.fixture(autouse=True)
def _reset_stubs() -> Iterator[None]:
    """Restore the stub callables to their unconfigured defaults after each test."""
    yield
    _detection_stub.iter_detections = _unconfigured_iter_detections  # type: ignore[attr-defined]
    _knowledgebase_stub.fetch_kb = _unconfigured_fetch_kb  # type: ignore[attr-defined]


# ----------------------------------------------------------------------- helpers
def _asset(host_id: int = 1000001, *, tracking: str = "AGENT", acs: int | None = None) -> Asset:
    return Asset(host_id=host_id, tracking_method=tracking, asset_criticality_score=acs)


def _detection(
    qid: int,
    *,
    port: int | None = None,
    status: DetectionStatus = DetectionStatus.ACTIVE,
) -> Detection:
    return Detection(qid=qid, port=port, severity=5, status=status)


def _kbvuln(qid: int, *, title: str = "Sample KB", cvss_base: float = 9.8) -> KbVuln:
    return KbVuln(qid=qid, title=title, cvss_base=cvss_base, patchable=True, pci_flag=False)


def _set_iter_detections(pairs: list[tuple[Asset, Detection]]) -> None:
    def fake(*_args: Any, **_kwargs: Any) -> Iterator[tuple[Asset, Detection]]:
        yield from pairs

    _detection_stub.iter_detections = fake  # type: ignore[attr-defined]


def _set_fetch_kb(fn: Callable[..., Iterator[KbVuln]]) -> None:
    _knowledgebase_stub.fetch_kb = fn  # type: ignore[attr-defined]


# ------------------------------------------------------------------------- tests
def test_iter_merged_enriches_from_kb(
    session_factory: sessionmaker[Session], config: QjsyncConfig
) -> None:
    """A detection with no cached KB triggers a per-QID fetch and carries the KB."""
    asset = _asset()
    det = _detection(105413)
    _set_iter_detections([(asset, det)])

    fetch_calls: list[list[int] | None] = []

    def fetch(_client: Any, qids: list[int] | None = None) -> Iterator[KbVuln]:
        fetch_calls.append(qids)
        assert qids == [105413]
        yield _kbvuln(105413, title="JDK EOL", cvss_base=10.0)

    _set_fetch_kb(fetch)

    src = VmSource(client=object(), session_factory=session_factory, config=config)
    merged = list(src.iter_merged(since=None))

    assert len(merged) == 1
    m = merged[0]
    assert m.kb is not None
    assert m.kb.qid == 105413
    assert m.kb.title == "JDK EOL"
    assert m.signal_context()["cvss_base"] == 10.0
    assert fetch_calls == [[105413]]


def test_kb_cache_is_reused_across_detections(
    session_factory: sessionmaker[Session], config: QjsyncConfig
) -> None:
    """Two detections of the same QID fetch the KB once (in-run memo)."""
    pairs = [
        (_asset(1000001), _detection(105413, port=None)),
        (_asset(1000002), _detection(105413, port=443)),
    ]
    _set_iter_detections(pairs)

    calls = {"n": 0}

    def fetch(_client: Any, qids: list[int] | None = None) -> Iterator[KbVuln]:
        calls["n"] += 1
        yield _kbvuln(105413)

    _set_fetch_kb(fetch)

    src = VmSource(client=object(), session_factory=session_factory, config=config)
    merged = list(src.iter_merged())

    assert len(merged) == 2
    assert all(m.kb is not None and m.kb.qid == 105413 for m in merged)
    assert calls["n"] == 1  # second detection reused the resolved KB


def test_kb_cache_reused_across_calls_when_fresh(
    session_factory: sessionmaker[Session], config: QjsyncConfig
) -> None:
    """A fresh DB-cached entry is reused on a later iter_merged without re-fetching."""
    _set_iter_detections([(_asset(), _detection(105413))])

    calls = {"n": 0}

    def fetch(_client: Any, qids: list[int] | None = None) -> Iterator[KbVuln]:
        calls["n"] += 1
        yield _kbvuln(105413)

    _set_fetch_kb(fetch)

    src = VmSource(client=object(), session_factory=session_factory, config=config)

    list(src.iter_merged())  # warms the DB cache
    assert calls["n"] == 1

    # Second run, same QID, new in-process memo: should hit the DB cache, not fetch.
    list(src.iter_merged())
    assert calls["n"] == 1


def test_stale_cache_triggers_refetch(
    session_factory: sessionmaker[Session], config: QjsyncConfig
) -> None:
    """An entry older than kb_refresh_max_age_hours is re-fetched."""
    config.qualys.kb_refresh_max_age_hours = 0  # everything cached is immediately stale
    _set_iter_detections([(_asset(), _detection(105413))])

    calls = {"n": 0}

    def fetch(_client: Any, qids: list[int] | None = None) -> Iterator[KbVuln]:
        calls["n"] += 1
        yield _kbvuln(105413, title=f"refetch-{calls['n']}")

    _set_fetch_kb(fetch)

    src = VmSource(client=object(), session_factory=session_factory, config=config)

    m1 = list(src.iter_merged())[0]
    m2 = list(src.iter_merged())[0]

    assert calls["n"] == 2  # stale each time -> re-fetched
    assert m1.kb is not None and m1.kb.title == "refetch-1"
    assert m2.kb is not None and m2.kb.title == "refetch-2"


def test_kb_miss_yields_none_enrichment(
    session_factory: sessionmaker[Session], config: QjsyncConfig
) -> None:
    """A QID the KnowledgeBase has no row for merges with kb=None (no crash)."""
    _set_iter_detections([(_asset(), _detection(99999))])

    def fetch(_client: Any, qids: list[int] | None = None) -> Iterator[KbVuln]:
        return iter(())  # empty: KB has nothing for this QID

    _set_fetch_kb(fetch)

    src = VmSource(client=object(), session_factory=session_factory, config=config)
    merged = list(src.iter_merged())

    assert len(merged) == 1
    assert merged[0].kb is None


def test_acs_passed_through_to_iter_detections(
    session_factory: sessionmaker[Session], config: QjsyncConfig
) -> None:
    """The configured ACS tag pattern is forwarded to iter_detections, and an asset
    that already carries a derived ACS surfaces it on the merged signal."""
    config.qualys.asset_criticality_tag_pattern = r"(?i)ACS-(\d)"

    captured: dict[str, Any] = {}

    def fake_iter(
        client: Any,
        query: Any,
        *,
        since: str | None = None,
        acs_pattern: str | None = None,
    ) -> Iterator[tuple[Asset, Detection]]:
        captured["since"] = since
        captured["acs_pattern"] = acs_pattern
        captured["query_is_config"] = query is config.qualys.query
        yield (_asset(acs=4), _detection(105413))

    _detection_stub.iter_detections = fake_iter  # type: ignore[attr-defined]
    _set_fetch_kb(lambda _c, qids=None: iter([_kbvuln(105413)]))

    src = VmSource(client=object(), session_factory=session_factory, config=config)
    merged = list(src.iter_merged(since="2026-06-19T00:00:00Z"))

    assert captured["acs_pattern"] == r"(?i)ACS-(\d)"
    assert captured["since"] == "2026-06-19T00:00:00Z"
    assert captured["query_is_config"] is True  # query.vm_scan_since precedence stays in detection
    assert merged[0].signal_context()["asset_criticality"] == 4


def test_incomplete_fetch_propagates(
    session_factory: sessionmaker[Session], config: QjsyncConfig
) -> None:
    """If the detection reader raises on an incomplete fetch, iter_merged re-raises
    (purge safety: never yield a partial set silently)."""

    def boom(*_args: Any, **_kwargs: Any) -> Iterator[tuple[Asset, Detection]]:
        yield (_asset(), _detection(105413))
        raise RuntimeError("HLD fetch truncated / incomplete")

    _detection_stub.iter_detections = boom  # type: ignore[attr-defined]
    _set_fetch_kb(lambda _c, qids=None: iter([_kbvuln(105413)]))

    src = VmSource(client=object(), session_factory=session_factory, config=config)
    with pytest.raises(RuntimeError, match="incomplete"):
        list(src.iter_merged())


def test_refresh_knowledgebase_upserts_all(
    session_factory: sessionmaker[Session], config: QjsyncConfig
) -> None:
    """refresh_knowledgebase pulls the whole KB (qids=None) and returns the count."""
    captured: dict[str, Any] = {}

    def fetch(_client: Any, qids: list[int] | None = None) -> Iterator[KbVuln]:
        captured["qids"] = qids
        yield _kbvuln(105413)
        yield _kbvuln(38170)

    _set_fetch_kb(fetch)

    src = VmSource(client=object(), session_factory=session_factory, config=config)
    written = src.refresh_knowledgebase()

    assert written == 2
    assert captured["qids"] is None  # full refresh

    # The entries are actually persisted and readable via the cache.
    with session_factory() as session:
        repo = KbRepo(session)
        assert isinstance(repo.get(105413), KbEntry)
        assert isinstance(repo.get(38170), KbEntry)
