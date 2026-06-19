"""Qualys VMDR source: HTTP client, Host List Detection / KnowledgeBase readers,
and the :class:`~qjsync.sources.qualys.source.VmSource` that merges them into the
canonical model.
"""

from __future__ import annotations

from qjsync.sources.qualys.client import QualysClient
from qjsync.sources.qualys.detection import iter_detections
from qjsync.sources.qualys.knowledgebase import fetch_kb

__all__ = ["QualysClient", "fetch_kb", "iter_detections"]
