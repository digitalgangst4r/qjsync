"""qjsync — a transparent connector between Qualys VMDR and Jira Cloud.

Synchronises Qualys vulnerability detections into Jira issues, gated by a
configurable prioritisation engine, enriched from the Qualys KnowledgeBase,
with first-class handling of the detection lifecycle (fixed / re-opened) and
asset/detection *purge* (which is explicitly NOT remediation).

Public version string only; see :mod:`qjsync.cli` for the entry point.
"""

from __future__ import annotations

__version__ = "0.1.0"

__all__ = ["__version__"]
