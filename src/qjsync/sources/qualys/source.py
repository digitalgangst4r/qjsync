"""The VM/VMDR source module.

:class:`VmSource` is the only concrete :class:`~qjsync.sources.base.SourceModule`
today. It glues together the three lower-level Qualys helpers — the HTTP client,
the Host List Detection reader (:func:`~qjsync.sources.qualys.detection.iter_detections`)
and the KnowledgeBase reader (:func:`~qjsync.sources.qualys.knowledgebase.fetch_kb`) —
and turns their output into the canonical :class:`MergedVulnerability` the rest of
the connector speaks.

Two responsibilities live here and nowhere else:

* **KB enrichment with a cache.** Every detection carries a QID; the KB entry for
  that QID is fetched once, cached in Postgres (:class:`~qjsync.state.repositories.KbRepo`),
  and re-used for every other detection of the same QID in the same run and across
  runs until it ages past ``QualysConfig.kb_refresh_max_age_hours``. A network
  estate has tens of thousands of detections over a few thousand distinct QIDs, so
  the cache is what keeps a sync from re-pulling the KnowledgeBase per detection.
* **Fetch completeness.** Purge detection (the full-mode pass) trusts that a fetch
  either returned the whole scope or raised. We never silently yield a partial set:
  the underlying readers raise on a truncated/incomplete fetch and we let that
  propagate out of :meth:`iter_merged`.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import TYPE_CHECKING

from sqlalchemy.orm import Session, sessionmaker

import qjsync.sources.qualys.detection as detection_mod
import qjsync.sources.qualys.knowledgebase as knowledgebase_mod
from qjsync.config.schema import QjsyncConfig
from qjsync.models.canonical import Asset, Detection, KbVuln, MergedVulnerability
from qjsync.sources.base import SourceModule
from qjsync.state.db import session_scope
from qjsync.state.repositories import KbRepo

if TYPE_CHECKING:
    from qjsync.sources.qualys.client import QualysClient


class VmSource(SourceModule):
    """Stream canonical merged vulnerabilities from a Qualys VMDR subscription.

    The orchestrator only ever sees the :class:`SourceModule` interface; this class
    owns the Qualys-specific details (query params, KB cache, fetch completeness).
    """

    name = "vm"

    #: detections buffered before resolving their distinct QIDs' KB in one batch.
    _KB_BATCH = 200

    def __init__(
        self,
        client: QualysClient,
        session_factory: sessionmaker[Session],
        config: QjsyncConfig,
    ) -> None:
        self.client = client
        self.session_factory = session_factory
        self.config = config

    # ------------------------------------------------------------------ public
    def iter_merged(self, *, since: str | None = None) -> Iterator[MergedVulnerability]:
        """Yield every in-scope detection enriched with its asset and KB entry.

        ``since`` is the connector-managed ``vm_scan_since`` for an incremental run
        (``None`` for a full run); it is passed straight through to
        :func:`iter_detections`, which lets it override the static
        ``query.vm_scan_since`` floor.

        KB entries are pulled from the local cache and only re-fetched on a miss or
        when the cached copy is older than ``QualysConfig.kb_refresh_max_age_hours``.
        The cache is consulted/updated through a short-lived session per QID so the
        long-running detection stream never holds a single transaction open.

        Raises whatever the underlying readers raise on an incomplete fetch — the
        purge pass depends on a fetch being known-complete, so a partial set must
        surface as an error rather than a truncated stream.
        """
        qcfg = self.config.qualys
        # Per-run, in-process memo so we don't re-open a DB session (or re-fetch) for
        # a QID we've already resolved this stream; the DB cache is the cross-run layer.
        kb_seen: dict[int, KbVuln | None] = {}

        detections = detection_mod.iter_detections(
            self.client,
            qcfg.query,
            since=since,
            acs_pattern=qcfg.asset_criticality_tag_pattern,
        )
        # Buffer detections and resolve each chunk's distinct QIDs with ONE batched
        # KB fetch (ids=comma-list) instead of a call per QID. At scale (tens of
        # thousands of detections over a few thousand QIDs) per-QID calls are the
        # bottleneck; batching collapses a chunk's misses into a single request.
        buffer: list[tuple[Asset, Detection]] = []
        for asset, det in detections:
            buffer.append((asset, det))
            if len(buffer) >= self._KB_BATCH:
                yield from self._drain(buffer, kb_seen)
                buffer = []
        yield from self._drain(buffer, kb_seen)

    def refresh_knowledgebase(self) -> int:
        """Force a full refresh of the local KB cache. Returns entries written.

        Used by the ``kb-refresh`` CLI command and as an explicit warm-up. Pulls the
        entire KnowledgeBase (``qids=None``) and upserts every entry, resetting each
        entry's ``fetched_at`` so the age-based refresh in :meth:`iter_merged` starts
        from now.
        """
        vulns = list(knowledgebase_mod.fetch_kb(self.client, qids=None))
        with session_scope(self.session_factory) as session:
            return KbRepo(session).upsert_many(vulns)

    # ----------------------------------------------------------------- internal
    def _drain(
        self,
        buffer: list[tuple[Asset, Detection]],
        kb_seen: dict[int, KbVuln | None],
    ) -> Iterator[MergedVulnerability]:
        """Resolve the buffer's distinct QIDs (one batched KB fetch) then yield."""
        if not buffer:
            return
        self._batch_resolve_kb([det.qid for _, det in buffer], kb_seen)
        for asset, det in buffer:
            yield MergedVulnerability(asset=asset, detection=det, kb=kb_seen.get(det.qid))

    def _batch_resolve_kb(self, qids: list[int], kb_seen: dict[int, KbVuln | None]) -> None:
        """Populate ``kb_seen`` for every QID not already resolved, using one
        batched ``fetch_kb`` for all QIDs that miss/are stale in the cache."""
        need = sorted({q for q in qids if q not in kb_seen})
        if not need:
            return
        max_age = self.config.qualys.kb_refresh_max_age_hours
        with session_scope(self.session_factory) as session:
            repo = KbRepo(session)
            missing: list[int] = []
            for qid in need:
                age = repo.age_hours(qid)
                if age is not None and age <= max_age:
                    cached = repo.get(qid)
                    if cached is not None:
                        kb_seen[qid] = KbRepo.to_kbvuln(cached)
                        continue
                missing.append(qid)
            if not missing:
                return
            fetched = list(knowledgebase_mod.fetch_kb(self.client, qids=missing))
            if fetched:
                repo.upsert_many(fetched)
            by_qid = {v.qid: v for v in fetched}
            for qid in missing:
                if qid in by_qid:
                    kb_seen[qid] = by_qid[qid]
                else:
                    cached = repo.get(qid)
                    kb_seen[qid] = KbRepo.to_kbvuln(cached) if cached is not None else None

    def _resolve_kb(self, qid: int) -> KbVuln | None:
        """Return the cached KB entry for ``qid``, refreshing on miss/stale.

        On a cache miss, or when the cached entry is older than the configured max
        age, fetch just this QID from the KnowledgeBase and upsert it. Returns
        ``None`` when the KnowledgeBase has no entry for the QID (some QIDs — e.g.
        information-gathered — legitimately lack a KB row); enrichment is optional.
        """
        max_age = self.config.qualys.kb_refresh_max_age_hours
        with session_scope(self.session_factory) as session:
            repo = KbRepo(session)
            age = repo.age_hours(qid)
            if age is not None and age <= max_age:
                cached = repo.get(qid)
                if cached is not None:
                    return KbRepo.to_kbvuln(cached)
            # Miss or stale -> refresh just this QID.
            fetched = list(knowledgebase_mod.fetch_kb(self.client, qids=[qid]))
            if fetched:
                repo.upsert_many(fetched)
                # Prefer the freshly fetched entry for this QID.
                for vuln in fetched:
                    if vuln.qid == qid:
                        return vuln
            # Nothing returned: fall back to a stale cached copy if we have one,
            # otherwise no enrichment.
            cached = repo.get(qid)
            return KbRepo.to_kbvuln(cached) if cached is not None else None
