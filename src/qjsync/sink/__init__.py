"""Issue sinks — where the sync lifecycle writes issue state.

The orchestrator talks to a small :class:`~qjsync.sink.base.IssueSink` (6 methods); the concrete
sink is chosen by ``config.sink``:

* ``jira``  → :class:`~qjsync.jira.client.JiraClient` (writes Jira Cloud over HTTP).
* ``local`` → :class:`~qjsync.sink.local.LocalSink` (writes the ``dash.issues`` work-layer in the
  same Postgres — no HTTP, no rate limit; qjsync-dash is the human surface).
* ``none``  → :class:`~qjsync.jira.null.NullJiraClient` (no-op; dashboard-only via a read of state).
"""

from .base import IssueSink

__all__ = ["IssueSink"]
