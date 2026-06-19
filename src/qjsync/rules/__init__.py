"""The prioritisation engine.

Detections only reach Jira because a rule said so. This package owns the decision:

* :mod:`qjsync.rules.operators` — the None-safe operator registry that backs each
  leaf condition (mirrored by ``config.schema.Operator``).
* :mod:`qjsync.rules.engine` — :class:`RulesEngine`, which walks the ordered rule
  list (first match wins) and emits an
  :class:`~qjsync.models.canonical.EvaluationResult` (or the implicit ``skip``).
"""

from __future__ import annotations

from qjsync.rules.engine import RulesEngine
from qjsync.rules.operators import OPERATORS

__all__ = ["OPERATORS", "RulesEngine"]
