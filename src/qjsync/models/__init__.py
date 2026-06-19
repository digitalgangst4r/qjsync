"""Canonical, source-agnostic domain model for qjsync.

These types are deliberately decoupled from the raw Qualys/Jira API payloads.
Source modules (VM today; WAS/Container later) are responsible for translating
their raw responses into these objects. Everything downstream — the rules
engine, the Jira mapper, the state store — speaks *only* this vocabulary.
"""

from __future__ import annotations

from qjsync.models.canonical import (
    Asset,
    Detection,
    DetectionStatus,
    EvaluationResult,
    JiraPriority,
    KbVuln,
    MergedVulnerability,
    RuleAction,
)
from qjsync.models.identity import compute_primary_key

__all__ = [
    "Asset",
    "Detection",
    "DetectionStatus",
    "EvaluationResult",
    "JiraPriority",
    "KbVuln",
    "MergedVulnerability",
    "RuleAction",
    "compute_primary_key",
]
