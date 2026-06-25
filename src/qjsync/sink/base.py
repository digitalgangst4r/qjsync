"""The ``IssueSink`` interface — the exact, bounded surface the orchestrator uses.

Verified against the orchestrator: it calls precisely these six methods on its issue client and
nothing else (``discover_fields`` is a build-time concern handled in the CLI; ``list_transitions``
and ``close`` are internal to the Jira client). Any sink that implements these six can carry the
full lifecycle (create / material-update / fixed-close / stale-close / reopen / sticky) unchanged.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class IssueSink(Protocol):
    def find_issue_by_primary_key(self, primary_key: str) -> dict[str, Any] | None: ...

    def create_issue(self, fields: dict[str, Any]) -> dict[str, Any]:
        """Create an issue; return at least ``{"key": <issue key>}``."""

    def update_issue(self, issue_key: str, fields: dict[str, Any]) -> None: ...

    def get_issue(self, issue_key: str) -> dict[str, Any]:
        """Return the issue as ``{"fields": {"resolution": {...}|absent, "labels": [...]}}``."""

    def transition_issue(
        self, issue_key: str, name: str, *, resolution: str | None = None
    ) -> None: ...

    def add_comment(self, issue_key: str, body_adf: dict[str, Any]) -> None: ...
