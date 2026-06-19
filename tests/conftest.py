"""Shared pytest fixtures.

Other test modules rely on ``sample_config_dict`` / ``sample_config`` existing
here, so this stays intentionally small: the *minimal* mapping the schema
accepts (a Jira project + one ``create`` rule with a priority) and its parsed
:class:`QjsyncConfig`.
"""

from __future__ import annotations

from typing import Any

import pytest

from qjsync.config.schema import QjsyncConfig


@pytest.fixture()
def sample_config_dict() -> dict[str, Any]:
    """A minimal, valid ``rules.yml`` body as a plain dict.

    The only hard requirement is ``jira.project``; the band-shift ``prioritization``
    defaults to QDS bands 90/70/50. Here we include one modifier and a skip filter
    so fixtures exercise the mechanism.
    """
    return {
        "version": 1,
        "jira": {"project": "QVULN"},
        "prioritization": {
            "qds_bands": {"highest": 90, "high": 70, "medium": 50},
            "skip_when": {"signal": "vuln_type", "op": "==", "value": "Information"},
            "modifiers": [
                {
                    "name": "internet-facing",
                    "when": {
                        "signal": "asset_tags",
                        "op": "contains",
                        "value": "Internet Facing Assets",
                    },
                    "shift": 1,
                    "label": "internet-facing",
                }
            ],
        },
    }


@pytest.fixture()
def sample_config(sample_config_dict: dict[str, Any]) -> QjsyncConfig:
    """The parsed :class:`QjsyncConfig` for :func:`sample_config_dict`."""
    return QjsyncConfig.model_validate(sample_config_dict)
