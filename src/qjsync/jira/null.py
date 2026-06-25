"""No-op Jira sink for dashboard-only mode (``jira.enabled: false``).

When Jira is disabled, the sync orchestrator still runs its full lifecycle — opening,
closing-as-fixed, reopening and marking-stale detections in the PostgreSQL state store —
but every Jira REST call is replaced by these no-ops. No network request is made and no Jira
credentials are required; the ``qjsync-dash`` service reads the resulting state directly.

The orchestrator keys "this detection has an open ticket" off a non-null ``jira_issue_key``, so
:meth:`NullJiraClient.create_issue` mints a deterministic local id (``LOCAL-<hash>``) instead of a
real Jira key. That id is only an internal lifecycle marker — it points at nothing in Jira.
"""

from __future__ import annotations

import hashlib
from typing import Any

# Key under which NullFieldBuilder smuggles the detection's primary key to the sink, so
# create_issue can mint a stable per-detection local id without a real Jira round-trip.
_PK_FIELD = "_qjsync_primary_key"


def local_issue_key(primary_key: str) -> str:
    """A deterministic, stable, <=64-char local marker for a detection's lifecycle row."""
    digest = hashlib.sha1(primary_key.encode("utf-8")).hexdigest()[:12]
    return f"LOCAL-{digest}"


class NullFieldBuilder:
    """A field builder that does no Jira mapping — only carries the primary key to the sink."""

    def build_fields(
        self,
        merged: Any,
        evaluation: Any,
        primary_key: str,
    ) -> dict[str, Any]:
        return {_PK_FIELD: primary_key}


class NullJiraClient:
    """Satisfies the orchestrator's ``JiraClientLike`` without touching Jira."""

    def discover_fields(self) -> dict[str, str]:
        return {}

    def find_issue_by_primary_key(self, primary_key: str) -> dict[str, Any] | None:
        # No external Jira to search — always "no existing issue", so creation proceeds locally.
        return None

    def create_issue(self, fields: dict[str, Any]) -> dict[str, Any]:
        primary_key = str(fields.get(_PK_FIELD, ""))
        return {"key": local_issue_key(primary_key)}

    def update_issue(self, issue_key: str, fields: dict[str, Any]) -> None:
        return None

    def get_issue(self, issue_key: str) -> dict[str, Any]:
        # Shaped like Jira's REST response so resolution/label reads return "nothing set".
        return {"fields": {}}

    def transition_issue(
        self, issue_key: str, name: str, *, resolution: str | None = None
    ) -> None:
        return None

    def add_comment(self, issue_key: str, body_adf: dict[str, Any]) -> None:
        return None

    def close(self) -> None:
        return None


__all__ = ["NullFieldBuilder", "NullJiraClient", "local_issue_key"]
