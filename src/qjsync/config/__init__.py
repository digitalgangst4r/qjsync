"""Configuration: declarative rules (YAML) + secrets (environment).

Two strictly separated concerns:

* :mod:`qjsync.config.schema` — the versionable, non-secret ``rules.yml``
  (Qualys query, prioritisation rules, lifecycle behaviour). Validated with
  pydantic so a bad config fails loudly at startup, never mid-sync.
* :mod:`qjsync.config.settings` — secrets pulled from the environment
  (Qualys/Jira credentials, database URL). **Never** placed in ``rules.yml``.
"""

from __future__ import annotations

from qjsync.config.schema import (
    Condition,
    DriftConfig,
    JiraConfig,
    Modifier,
    PrimaryKeyConfig,
    PrioritizationConfig,
    PurgeConfig,
    QdsBands,
    QjsyncConfig,
    QualysConfig,
)
from qjsync.config.settings import Secrets

__all__ = [
    "Condition",
    "DriftConfig",
    "JiraConfig",
    "Modifier",
    "PrimaryKeyConfig",
    "PrioritizationConfig",
    "PurgeConfig",
    "QdsBands",
    "QjsyncConfig",
    "QualysConfig",
    "Secrets",
]
