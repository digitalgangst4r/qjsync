"""The source-module interface that makes qjsync multi-source.

A source module knows how to (a) stream the *current* set of canonical merged
vulnerabilities for a sync, and (b) enrich from its KnowledgeBase. The
orchestrator never imports a concrete source; it is handed one that satisfies
this protocol. Adding WAS/Container later = implementing this once more.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterator

from qjsync.models.canonical import MergedVulnerability


class SourceModule(ABC):
    """Abstract base for a vulnerability source (VM, WAS, Container, ...)."""

    #: short stable id, e.g. "vm" — used in logs and (optionally) the primary key.
    name: str = "base"

    @abstractmethod
    def iter_merged(self, *, since: str | None = None) -> Iterator[MergedVulnerability]:
        """Yield every merged vulnerability in scope for this sync.

        ``since`` is the connector-managed ``vm_scan_since`` for an *incremental*
        run; it overrides any static date filter in the source's query. Pass None
        for a *full* run, which scans the user's whole query scope.

        Implementations must handle their own pagination and KB enrichment, and
        must raise on an incomplete fetch rather than silently yielding a partial
        set — purge detection depends on a fetch being known-complete.
        """
        raise NotImplementedError

    @abstractmethod
    def refresh_knowledgebase(self) -> int:
        """Refresh the local KB cache for this source. Returns entries updated."""
        raise NotImplementedError
