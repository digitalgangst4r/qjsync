"""Pluggable vulnerability *source modules*.

Only VM/VMDR is implemented today, but the orchestrator depends solely on the
:class:`~qjsync.sources.base.SourceModule` interface so WAS and Container can be
added later as new modules without touching the rules engine, Jira layer, or
state store.
"""

from __future__ import annotations

from qjsync.sources.base import SourceModule

__all__ = ["SourceModule"]
