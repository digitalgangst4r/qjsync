"""The sync orchestrator — the lifecycle heart of qjsync.

It pulls the canonical stream from a :class:`~qjsync.sources.base.SourceModule`,
runs each merged vulnerability through the rules engine, and reconciles Jira and
the Postgres state store per the algorithm in docs/ARCHITECTURE.md (§"The sync
algorithm"). Two structural rules from the contract are enforced here:

* **Sync modes.** ``incremental`` computes a managed ``vm_scan_since`` window
  from the last successful sync and **skips the purge pass**; ``full`` injects no
  window and **runs purge** — it is the only mode that may mark a detection stale.
* **Material vs telemetry.** An existing open issue is re-PUT only when its
  ``material_hash`` changed; a telemetry-only change updates the Postgres snapshot
  only, never Jira.

Downstream collaborators (rules engine, Jira client, field mapper) are consumed
through small structural :class:`typing.Protocol` interfaces so this module — and
its tests — never hard-depend on those concrete classes. The real
``qjsync.jira.mapper.IssueMapper`` is used automatically when present; a fake one
can be injected for unit tests.

v1 takes the **direct-write** path: each detection is reconciled inline within a
per-detection transaction. The durable ``jobs`` queue exists for a future async
worker; wiring the orchestrator onto it is a drop-in change that does not alter
this lifecycle.
"""

from __future__ import annotations

import importlib
import logging
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from qjsync.config.schema import QjsyncConfig
from qjsync.models.canonical import EvaluationResult, MergedVulnerability
from qjsync.state.db import session_scope
from qjsync.state.models import (
    ClosureReason,
    DetectionState,
    SyncMode,
    SyncRun,
    SyncRunStatus,
)
from qjsync.state.repositories import DetectionStateRepo, SyncRunRepo
from qjsync.sync.purge import classify_missing, is_purge_eligible
from qjsync.sync.summary import RunSummary

if TYPE_CHECKING:
    from sqlalchemy.orm import Session, sessionmaker

    from qjsync.sources.base import SourceModule

logger = logging.getLogger("qjsync.sync")

# Qualys datetime format the managed window is rendered in (matches HLD/KB).
_QUALYS_DT_FMT = "%Y-%m-%dT%H:%M:%SZ"


@runtime_checkable
class RulesEngineLike(Protocol):
    """Just the slice of the rules engine the orchestrator calls."""

    def evaluate(self, merged: MergedVulnerability) -> EvaluationResult: ...


@runtime_checkable
class JiraClientLike(Protocol):
    """The Jira REST operations the lifecycle needs (see jira/client.py).

    ``create_issue`` returns the created issue (at minimum ``{"key": ...}``);
    ``get_issue`` returns the issue as Jira's REST v3 shape (``{"fields": {...}}``).
    ``transition_issue`` moves the issue by transition *name*, optionally setting a
    resolution name in the same transition.
    """

    def find_issue_by_primary_key(self, primary_key: str) -> dict[str, Any] | None: ...
    def create_issue(self, fields: dict[str, Any]) -> dict[str, Any]: ...
    def update_issue(self, issue_key: str, fields: dict[str, Any]) -> None: ...
    def get_issue(self, issue_key: str) -> dict[str, Any]: ...
    def transition_issue(
        self, issue_key: str, name: str, *, resolution: str | None = None
    ) -> None: ...
    def add_comment(self, issue_key: str, body_adf: dict[str, Any]) -> None: ...


def _comment_adf(text: str) -> dict[str, Any]:
    """Wrap a plain message in a minimal ADF document for a Jira comment."""
    return {
        "type": "doc",
        "version": 1,
        "content": [{"type": "paragraph", "content": [{"type": "text", "text": text}]}],
    }


@runtime_checkable
class FieldBuilderLike(Protocol):
    """The mapper slice the orchestrator needs (see jira/mapper.py::IssueMapper)."""

    def build_fields(
        self,
        merged: MergedVulnerability,
        evaluation: EvaluationResult,
        primary_key: str,
    ) -> dict[str, Any]: ...


def _resolve_mapper(config: QjsyncConfig, mapper: FieldBuilderLike | None) -> FieldBuilderLike:
    """Return an injected mapper, else the real IssueMapper, else a minimal fallback.

    The real mapper lives in a sibling module written in parallel; importing it
    lazily keeps this module importable on its own and lets tests inject a fake.
    """
    if mapper is not None:
        return mapper
    try:  # pragma: no cover - exercised once the jira module lands
        # Dynamic import so this module type-checks and imports cleanly before the
        # sibling jira/mapper.py (written in parallel) exists.
        module = importlib.import_module("qjsync.jira.mapper")
        issue_mapper_cls = module.IssueMapper
        built: FieldBuilderLike = issue_mapper_cls(config.jira)
        return built
    except Exception:  # noqa: BLE001 - any import/construction failure -> fallback
        return _FallbackFieldBuilder(config)


class _FallbackFieldBuilder:
    """Minimal, contract-shaped field builder used until jira/mapper.py exists.

    Emits the standard fields plus the Primary Key and managed/rule labels. The
    real :class:`~qjsync.jira.mapper.IssueMapper` supersedes it (FIELD_MAPPING.md);
    this only keeps the orchestrator self-contained and unit-testable.
    """

    def __init__(self, config: QjsyncConfig) -> None:
        self._jira = config.jira

    def build_fields(
        self,
        merged: MergedVulnerability,
        evaluation: EvaluationResult,
        primary_key: str,
    ) -> dict[str, Any]:
        labels = [self._jira.managed_label, *evaluation.labels]
        fields: dict[str, Any] = {
            "project": {"key": evaluation.project or self._jira.project},
            "issuetype": {"name": evaluation.issue_type or self._jira.issue_type},
            "summary": merged.title,
            "labels": labels,
            self._jira.primary_key_field: primary_key,
        }
        if evaluation.priority is not None:
            fields["priority"] = {"name": evaluation.priority.value}
        return fields


class SyncOrchestrator:
    """Reconcile a source's detections into Jira + the state store."""

    def __init__(
        self,
        source: SourceModule,
        engine: RulesEngineLike,
        jira: JiraClientLike,
        session_factory: sessionmaker[Session],
        config: QjsyncConfig,
        *,
        mapper: FieldBuilderLike | None = None,
    ) -> None:
        """``engine`` is the rules engine; ``jira`` the Jira REST client.

        ``mapper`` is optional — the real :class:`IssueMapper` is used when its
        module is available, otherwise a minimal built-in builder.
        """
        self.source = source
        self.engine = engine
        self.jira = jira
        self.session_factory = session_factory
        self.config = config
        self.mapper = _resolve_mapper(config, mapper)

    # ------------------------------------------------------------------ #
    # public entrypoint
    # ------------------------------------------------------------------ #
    def run(
        self, dry_run: bool = False, *, mode: SyncMode | str = "incremental",
        run_notes: dict | None = None,
    ) -> RunSummary:
        """Execute one sync cycle and return its :class:`RunSummary`.

        ``mode`` selects incremental (managed window, no purge) or full (whole
        scope, purge). ``dry_run`` performs all reads but no Jira writes and
        reports *would-do* counts. Steps mirror docs/ARCHITECTURE.md. ``run_notes``
        is stamped onto the run (e.g. rules origin/hash) for pipeline observability;
        the active ``sink`` is always recorded.
        """
        mode = SyncMode(mode) if not isinstance(mode, SyncMode) else mode
        summary = RunSummary(mode=mode, dry_run=dry_run)
        self._run_notes = {**(run_notes or {}), "sink": self.config.sink, "dry_run": dry_run}

        # Step 1 — start the run and compute the (incremental) window.
        with session_scope(self.session_factory) as session:
            run = SyncRunRepo(session).start(mode)
            run_id = run.id
            since = self._compute_since(session, mode)

        # Step 2 — per detection. Each detection is its own transaction so an
        # interruption leaves no half-written row and a re-run reconciles.
        try:
            for merged in self.source.iter_merged(since=since):
                with session_scope(self.session_factory) as session:
                    self._process_detection(session, run_id, merged, summary, dry_run)
        except Exception:
            # Mark the run failed so neither purge gating nor the incremental
            # window trusts a partial fetch, then re-raise.
            self._finish_run(run_id, SyncRunStatus.FAILED, summary)
            raise

        # Step 3 — purge pass (FULL mode only, on an otherwise successful run).
        if mode is SyncMode.FULL:
            with session_scope(self.session_factory) as session:
                self._purge_pass(session, run_id, summary, dry_run)

        # Step 5 — finish.
        self._finish_run(run_id, SyncRunStatus.SUCCESS, summary)
        logger.info(summary.log_line())
        return summary

    # ------------------------------------------------------------------ #
    # step 1 helpers
    # ------------------------------------------------------------------ #
    def _compute_since(self, session: Session, mode: SyncMode) -> str | None:
        """Managed ``vm_scan_since`` for incremental; None for full.

        Incremental computes ``last_successful_any().started_at - overlap`` so
        edge detections near the window boundary are not missed. With no prior
        successful run, returns None (the first incremental behaves as a bounded
        full of the query scope). Full injects no window (static YAML value wins).
        """
        if mode is SyncMode.FULL:
            return None
        last = SyncRunRepo(session).last_successful_any()
        if last is None or last.started_at is None:
            return None
        overlap = timedelta(minutes=self.config.qualys.incremental_overlap_minutes)
        window_start = last.started_at - overlap
        return window_start.strftime(_QUALYS_DT_FMT)

    # ------------------------------------------------------------------ #
    # step 2 — per detection
    # ------------------------------------------------------------------ #
    def _process_detection(
        self,
        session: Session,
        run_id: int,
        merged: MergedVulnerability,
        summary: RunSummary,
        dry_run: bool,
    ) -> None:
        states = DetectionStateRepo(session)
        pk = merged.primary_key(
            port_sentinel=self.config.primary_key.port_sentinel,
            include_unique_vuln_id=self.config.primary_key.include_unique_vuln_id,
        )
        material_hash = merged.material_hash()
        evaluation = self.engine.evaluate(merged)
        state = states.get(pk)
        qualys_status = merged.detection.status.value if merged.detection.status else None

        summary.evaluated += 1

        open_issue_key = self._open_issue_key(state)

        # --- Qualys STATUS=Fixed -> remediation (close as Done/Fixed) ----------
        if merged.detection.status is not None and merged.detection.status.value == "Fixed":
            sticky = (
                open_issue_key is not None
                and self._is_sticky(session, states, pk, open_issue_key)
            )
            if open_issue_key is not None and not sticky:
                summary.closed_fixed += 1
                if not dry_run:
                    self.jira.transition_issue(
                        open_issue_key,
                        self.config.jira.done_transition,
                        resolution=self.config.jira.resolution_fixed,
                    )
                    states.record_closed(
                        pk, ClosureReason.FIXED, self.config.jira.resolution_fixed
                    )
                    self._lifecycle_comment(
                        open_issue_key, "Fechando ticket",
                        merged.detection.last_fixed_datetime or self._today(), "Fixed",
                    )
            self._snapshot(states, merged, pk, run_id, material_hash, qualys_status, open_issue_key)
            return

        # --- STATUS Active / New / Re-Opened -----------------------------------
        # A row with a Jira issue that is already closed but whose detection is now
        # active again is a *return* (reopen / reevaluate), not a fresh create.
        if state is not None and state.jira_issue_key is not None and state.closed_at is not None:
            self._handle_returned(
                session, states, merged, evaluation, pk, run_id, material_hash,
                qualys_status, state, summary, dry_run,
            )
            return

        if open_issue_key is None:
            self._handle_no_issue(
                states, merged, evaluation, pk, run_id, material_hash, qualys_status,
                summary, dry_run,
            )
            return

        # Open issue + active detection: non-surprise read, then material/telemetry.
        if self._is_sticky(session, states, pk, open_issue_key):
            self._snapshot(states, merged, pk, run_id, material_hash, qualys_status, open_issue_key)
            return

        if not evaluation.should_create:
            # Drift: open issue whose detection now evaluates to skip.
            self._handle_drift(
                states, merged, pk, run_id, material_hash, qualys_status,
                open_issue_key, summary,
            )
            return

        if state is not None and state.material_hash == material_hash:
            # Telemetry-only change -> update the snapshot, never Jira.
            summary.telemetry += 1
            self._snapshot(states, merged, pk, run_id, material_hash, qualys_status, open_issue_key)
            return

        # Material change -> one idempotent PUT carrying material + telemetry.
        summary.updated += 1
        if not dry_run:
            fields = self.mapper.build_fields(merged, evaluation, pk)
            self.jira.update_issue(open_issue_key, fields)
        self._snapshot(states, merged, pk, run_id, material_hash, qualys_status, open_issue_key)

    def _handle_no_issue(
        self,
        states: DetectionStateRepo,
        merged: MergedVulnerability,
        evaluation: EvaluationResult,
        pk: str,
        run_id: int,
        material_hash: str,
        qualys_status: str | None,
        summary: RunSummary,
        dry_run: bool,
    ) -> None:
        """No open issue yet: create when materialised, else record state only.

        A band below the materialise threshold (e.g. Low) is *classified* — its
        state is recorded so a later promotion to Medium+ creates the ticket — but
        no Jira issue is created now (Lever D-narrow).
        """
        if not evaluation.should_create:
            if evaluation.priority is not None:
                summary.classified_low += 1  # classified (e.g. Low) but not ticketed
            else:
                summary.skipped += 1
            self._snapshot(states, merged, pk, run_id, material_hash, qualys_status, None)
            return

        # Idempotency: a prior issue may already carry the Primary Key.
        existing = None if dry_run else self.jira.find_issue_by_primary_key(pk)
        summary.created += 1
        issue_key: str | None = None
        if not dry_run:
            if existing is not None:
                issue_key = self._issue_key(existing)
                fields = self.mapper.build_fields(merged, evaluation, pk)
                self.jira.update_issue(issue_key, fields)
            else:
                fields = self.mapper.build_fields(merged, evaluation, pk)
                created = self.jira.create_issue(fields)
                issue_key = self._issue_key(created)
                self._lifecycle_comment(
                    issue_key, "Abrindo Ticket", self._today(),
                    merged.detection.status.value if merged.detection.status else None,
                )
        self._snapshot(states, merged, pk, run_id, material_hash, qualys_status, issue_key)

    def _handle_returned(
        self,
        session: Session,
        states: DetectionStateRepo,
        merged: MergedVulnerability,
        evaluation: EvaluationResult,
        pk: str,
        run_id: int,
        material_hash: str,
        qualys_status: str | None,
        state: DetectionState,
        summary: RunSummary,
        dry_run: bool,
    ) -> None:
        """A previously-closed issue whose detection is active again.

        * Closed by **fixed** and now Active/Re-Opened -> reopen (unless sticky).
        * Closed by **stale** (purge) -> governed by ``purge.reevaluate_on_return``
          (default: treat as a fresh evaluation -> reopen if it should_create).
        """
        issue_key = state.jira_issue_key
        if issue_key is None:
            return

        if self._is_sticky(session, states, pk, issue_key):
            self._snapshot(states, merged, pk, run_id, material_hash, qualys_status, issue_key)
            return

        closed_by_stale = state.closed_reason is ClosureReason.STALE
        if closed_by_stale and not self.config.purge.reevaluate_on_return:
            # Purged detections are not auto-reopened when this is disabled.
            self._snapshot(states, merged, pk, run_id, material_hash, qualys_status, issue_key)
            return

        if closed_by_stale and not evaluation.should_create:
            # Fresh evaluation says skip -> leave the purged issue closed.
            summary.skipped += 1
            self._snapshot(states, merged, pk, run_id, material_hash, qualys_status, issue_key)
            return

        summary.reopened += 1
        if not dry_run:
            self.jira.transition_issue(issue_key, self.config.jira.reopen_transition)
            fields = self.mapper.build_fields(merged, evaluation, pk)
            self.jira.update_issue(issue_key, fields)
            # Clear the closed bookkeeping by re-opening the row's lifecycle.
            self._reopen_state(states, pk)
            self._lifecycle_comment(
                issue_key, "Reabrindo ticket", self._today(),
                merged.detection.status.value if merged.detection.status else None,
            )
        self._snapshot(states, merged, pk, run_id, material_hash, qualys_status, issue_key)

    def _handle_drift(
        self,
        states: DetectionStateRepo,
        merged: MergedVulnerability,
        pk: str,
        run_id: int,
        material_hash: str,
        qualys_status: str | None,
        issue_key: str,
        summary: RunSummary,
    ) -> None:
        """Open issue whose detection dropped below threshold (rule -> skip).

        Default ``DriftConfig.below_threshold == keep_open``: we do not flap
        issues open/closed on score fluctuation, so only the snapshot is refreshed.
        ``close``/``downgrade`` are reserved for a future iteration; until then
        they degrade to keep_open (the conservative choice).
        """
        summary.skipped += 1
        self._snapshot(states, merged, pk, run_id, material_hash, qualys_status, issue_key)

    # ------------------------------------------------------------------ #
    # lifecycle comments
    # ------------------------------------------------------------------ #
    def _lifecycle_comment(
        self, issue_key: str, verb: str, date_str: str, status: str | None
    ) -> None:
        """Post the open/close/reopen lifecycle comment on the issue (best-effort)."""
        msg = (
            f"Vulnerabilidade com status {status or 'desconhecido'} encontrada no "
            f"Qualys. {verb} em {date_str}."
        )
        self.jira.add_comment(issue_key, _comment_adf(msg))

    @staticmethod
    def _today() -> str:
        return datetime.now(UTC).strftime("%Y-%m-%d")

    # ------------------------------------------------------------------ #
    # step 3 — purge pass
    # ------------------------------------------------------------------ #
    def _purge_pass(
        self,
        session: Session,
        run_id: int,
        summary: RunSummary,
        dry_run: bool,
    ) -> None:
        """Mark stale the open detections missing from this full run.

        Guarded by :func:`is_purge_eligible` (full + success). Each missed,
        open detection is classified by :func:`classify_missing`; a ``stale``
        verdict adds the stale label, sets the stale resolution, and stamps
        ``closed_reason=stale`` + ``purged_at``. Never closed as fixed; never
        auto-reopened. A sticky resolution is never overwritten.
        """
        # Build a provisional success-shaped run object purely for the eligibility
        # gate (the row is still RUNNING in the DB at this point).
        gate = SyncRun(id=run_id, mode=SyncMode.FULL, status=SyncRunStatus.SUCCESS)
        if not is_purge_eligible(gate):
            return

        states = DetectionStateRepo(session)
        missed = states.mark_missed(run_id)
        for state in missed:
            issue_key = state.jira_issue_key
            if issue_key is None:
                continue
            if self._is_sticky(session, states, state.primary_key, issue_key):
                continue
            if classify_missing(state, self.config.purge) != "stale":
                continue
            summary.marked_stale += 1
            if not dry_run:
                self.jira.transition_issue(
                    issue_key,
                    self.config.jira.done_transition,
                    resolution=self.config.jira.resolution_stale,
                )
                self.jira.update_issue(
                    issue_key, {"labels": self._stale_labels(state)}
                )
                states.record_closed(
                    state.primary_key,
                    ClosureReason.STALE,
                    self.config.jira.resolution_stale,
                    purged=True,
                )

    def _stale_labels(self, state: DetectionState) -> list[str]:
        existing = self._existing_labels(state)
        labels = list(existing)
        for required in (self.config.jira.managed_label, self.config.jira.stale_label):
            if required not in labels:
                labels.append(required)
        return labels

    def _existing_labels(self, state: DetectionState) -> list[str]:
        if not state.jira_issue_key:
            return []
        try:
            issue = self.jira.get_issue(state.jira_issue_key)
        except Exception:  # noqa: BLE001 - missing issue -> no prior labels
            return []
        raw = (issue.get("fields") or {}).get("labels") or []
        return [str(label) for label in raw]

    # ------------------------------------------------------------------ #
    # non-surprise + snapshot helpers
    # ------------------------------------------------------------------ #
    def _is_sticky(
        self,
        session: Session,
        states: DetectionStateRepo,
        pk: str,
        issue_key: str,
    ) -> bool:
        """Non-surprise: never overwrite a human-set sticky resolution.

        Reads current Jira state; if the issue carries a resolution in
        ``jira.sticky_resolutions``, flags the row ``sticky`` and reports True so
        the caller leaves it alone.
        """
        resolution = self._current_resolution(issue_key)
        if resolution is not None and resolution in self.config.jira.sticky_resolutions:
            states.set_sticky(pk, resolution)
            return True
        return False

    def _current_resolution(self, issue_key: str) -> str | None:
        try:
            issue = self.jira.get_issue(issue_key)
        except Exception:  # noqa: BLE001 - treat an unreadable issue as non-sticky
            return None
        fields = issue.get("fields") or {}
        resolution = fields.get("resolution")
        if isinstance(resolution, dict):
            name = resolution.get("name")
            return str(name) if name is not None else None
        return None

    def _snapshot(
        self,
        states: DetectionStateRepo,
        merged: MergedVulnerability,
        pk: str,
        run_id: int,
        material_hash: str,
        qualys_status: str | None,
        issue_key: str | None,
    ) -> None:
        """Persist the per-detection snapshot and stamp ``last_seen_run``."""
        states.upsert_seen(
            merged,
            pk,
            run_id,
            issue_key=issue_key,
            qualys_status=qualys_status,
            material_hash=material_hash,
            tracking_method=merged.asset.tracking_method,
            last_vm_scanned_date=merged.asset.last_vm_scanned_date,
            signals=merged.signal_context(),
        )

    def _reopen_state(self, states: DetectionStateRepo, pk: str) -> None:
        """Clear the closed bookkeeping on a row whose issue we just reopened."""
        row = states.get(pk)
        if row is None:
            return
        row.closed_at = None
        row.closed_reason = None
        row.purged_at = None
        states.session.flush()

    @staticmethod
    def _issue_key(issue: dict[str, Any]) -> str:
        return str(issue["key"])

    @staticmethod
    def _open_issue_key(state: DetectionState | None) -> str | None:
        """The issue key iff the row is mapped and not closed."""
        if state is None or state.jira_issue_key is None or state.closed_at is not None:
            return None
        return state.jira_issue_key

    # ------------------------------------------------------------------ #
    # finish
    # ------------------------------------------------------------------ #
    def _finish_run(self, run_id: int, status: SyncRunStatus, summary: RunSummary) -> None:
        with session_scope(self.session_factory) as session:
            run = session.get(SyncRun, run_id)
            if run is None:  # pragma: no cover - run always exists here
                return
            notes = getattr(self, "_run_notes", None) or None
            SyncRunRepo(session).finish(run, status, **summary.finish_counts(), notes=notes)


__all__ = [
    "FieldBuilderLike",
    "JiraClientLike",
    "RulesEngineLike",
    "SyncOrchestrator",
]
