"""Per-run summary counters and the one-line log emitted at the end of a sync.

The orchestrator accumulates a :class:`RunSummary` as it works and hands its
counter keys to :meth:`qjsync.state.repositories.SyncRunRepo.finish`. In a
``--dry-run`` the same counters are filled with *would-do* numbers (no Jira
writes happen), so a dry run reads exactly like a real one minus the side
effects.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass

from qjsync.state.models import SyncMode

# Counter keys understood by SyncRunRepo.finish (mirrors SyncRun's columns). Kept
# here so finish_counts() only ever forwards persistable keys.
_PERSISTED_COUNTERS: tuple[str, ...] = (
    "evaluated",
    "created",
    "updated",
    "closed_fixed",
    "marked_stale",
    "reopened",
    "skipped",
)


@dataclass
class RunSummary:
    """Outcome counters for a single orchestrator run.

    ``mode``/``dry_run`` are descriptive; the remaining fields are the counters
    that also land on the :class:`~qjsync.state.models.SyncRun` row. ``telemetry``
    counts detections whose only change was telemetry (snapshot-only, no Jira
    write) — surfaced in the log line but not a persisted column.
    """

    mode: SyncMode
    dry_run: bool = False

    evaluated: int = 0
    created: int = 0
    updated: int = 0
    closed_fixed: int = 0
    marked_stale: int = 0
    reopened: int = 0
    skipped: int = 0
    telemetry: int = 0
    classified_low: int = 0  # band < materialize threshold: classified, not ticketed

    def finish_counts(self) -> dict[str, int]:
        """The subset of counters persisted onto the SyncRun row."""
        data = asdict(self)
        return {k: int(data[k]) for k in _PERSISTED_COUNTERS}

    def log_line(self) -> str:
        """A compact, single-line summary for structured logs.

        Includes the mode and a ``would-`` prefix on the action counters when this
        was a dry run, so an operator can tell a rehearsal from a real sync at a
        glance.
        """
        verb = "would_" if self.dry_run else ""
        return (
            f"sync mode={self.mode.value} dry_run={self.dry_run} "
            f"evaluated={self.evaluated} "
            f"{verb}created={self.created} "
            f"{verb}updated={self.updated} "
            f"{verb}closed_fixed={self.closed_fixed} "
            f"{verb}reopened={self.reopened} "
            f"{verb}marked_stale={self.marked_stale} "
            f"skipped={self.skipped} "
            f"classified_low={self.classified_low} "
            f"telemetry_only={self.telemetry}"
        )
