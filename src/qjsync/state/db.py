"""Engine / session plumbing for the PostgreSQL state store.

Thin wrappers over SQLAlchemy 2.0 so the rest of the codebase (and the tests)
never touch engine construction directly. Production runs PostgreSQL via psycopg3
(``postgresql+psycopg://``); the unit tests run in-memory SQLite — the ORM models
use a portable ``JSON``/``JSONB`` variant so both work unchanged.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker

from qjsync.state.models import Base


def make_engine(url: str, *, echo: bool = False) -> Engine:
    """Create a SQLAlchemy :class:`Engine` for ``url``.

    ``url`` is a standard SQLAlchemy URL, e.g.
    ``postgresql+psycopg://qjsync:qjsync@localhost:5432/qjsync`` in production or
    ``sqlite+pysqlite:///:memory:`` in tests.
    """
    return create_engine(url, echo=echo, future=True)


def make_session_factory(engine: Engine) -> sessionmaker[Session]:
    """Return a :class:`sessionmaker` bound to ``engine``.

    ``expire_on_commit=False`` keeps returned ORM objects usable after the
    enclosing :func:`session_scope` commits, so callers can read counters off a
    finished :class:`~qjsync.state.models.SyncRun` without a re-query.
    """
    return sessionmaker(bind=engine, expire_on_commit=False, future=True)


@contextmanager
def session_scope(factory: sessionmaker[Session]) -> Iterator[Session]:
    """Provide a transactional scope around a series of operations.

    Commits on success, rolls back on any exception, and always closes the
    session. Per-detection work in the orchestrator runs inside one of these so an
    interrupted sync leaves no half-written row.
    """
    session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def create_all(engine: Engine) -> None:
    """Create every table defined on :class:`~qjsync.state.models.Base`.

    Alembic owns production schema; this is for tests and ``init-db`` bootstrap.
    """
    Base.metadata.create_all(engine)


def drop_all(engine: Engine) -> None:
    """Drop every table defined on :class:`~qjsync.state.models.Base` (tests/teardown)."""
    Base.metadata.drop_all(engine)
