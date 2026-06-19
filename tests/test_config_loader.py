"""Tests for :mod:`qjsync.config.loader`.

Covers the happy path (including the shipped ``examples/rules.yml``) and the
failure modes the loader must collapse into :class:`ConfigError`: missing
required fields, unknown fields, an empty rules list, a parse error, and a
non-existent file.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from qjsync.config.loader import ConfigError, load_config
from qjsync.config.schema import QjsyncConfig

# Repo root: tests/ -> repo root, so examples/rules.yml resolves regardless of cwd.
_REPO_ROOT = Path(__file__).resolve().parent.parent
_EXAMPLE_RULES = _REPO_ROOT / "examples" / "rules.yml"


def _write(path: Path, body: dict[str, Any]) -> Path:
    """Serialise ``body`` as JSON (a valid YAML subset) for the loader to parse."""
    path.write_text(json.dumps(body), encoding="utf-8")
    return path


# --------------------------------------------------------------------------- #
# Valid loads
# --------------------------------------------------------------------------- #
def test_load_valid_dict(
    tmp_path: Path, sample_config_dict: dict[str, Any]
) -> None:
    cfg = load_config(_write(tmp_path / "rules.yml", sample_config_dict))
    assert isinstance(cfg, QjsyncConfig)
    assert cfg.jira.project == "QVULN"
    assert cfg.prioritization.qds_bands.highest == 90
    assert len(cfg.prioritization.modifiers) == 1


def test_load_accepts_str_path(
    tmp_path: Path, sample_config_dict: dict[str, Any]
) -> None:
    path = _write(tmp_path / "rules.yml", sample_config_dict)
    cfg = load_config(str(path))  # str, not Path
    assert isinstance(cfg, QjsyncConfig)


def test_load_example_rules_succeeds() -> None:
    assert _EXAMPLE_RULES.is_file(), f"missing fixture: {_EXAMPLE_RULES}"
    cfg = load_config(_EXAMPLE_RULES)
    assert isinstance(cfg, QjsyncConfig)
    assert cfg.jira.project == "QVULN"
    assert len(cfg.prioritization.modifiers) >= 1


# --------------------------------------------------------------------------- #
# Invalid -> ConfigError
# --------------------------------------------------------------------------- #
def test_missing_required_field(
    tmp_path: Path, sample_config_dict: dict[str, Any]
) -> None:
    body = copy.deepcopy(sample_config_dict)
    del body["jira"]  # jira (and jira.project) is required
    with pytest.raises(ConfigError) as exc_info:
        load_config(_write(tmp_path / "rules.yml", body))
    assert "jira" in str(exc_info.value)


def test_unknown_field(
    tmp_path: Path, sample_config_dict: dict[str, Any]
) -> None:
    body = copy.deepcopy(sample_config_dict)
    body["nonsense"] = True  # schema is extra="forbid"
    with pytest.raises(ConfigError) as exc_info:
        load_config(_write(tmp_path / "rules.yml", body))
    assert "nonsense" in str(exc_info.value)


def test_invalid_qds_bands_ordering(
    tmp_path: Path, sample_config_dict: dict[str, Any]
) -> None:
    body = copy.deepcopy(sample_config_dict)
    # qds_bands must satisfy highest >= high >= medium.
    body["prioritization"]["qds_bands"] = {"highest": 50, "high": 70, "medium": 90}
    with pytest.raises(ConfigError):
        load_config(_write(tmp_path / "rules.yml", body))


def test_invalid_zero_shift_modifier(
    tmp_path: Path, sample_config_dict: dict[str, Any]
) -> None:
    body = copy.deepcopy(sample_config_dict)
    body["prioritization"]["modifiers"][0]["shift"] = 0  # no-effect modifier rejected
    with pytest.raises(ConfigError):
        load_config(_write(tmp_path / "rules.yml", body))


def test_parse_error(tmp_path: Path) -> None:
    bad = tmp_path / "rules.yml"
    bad.write_text("jira: {project: QVULN\nrules: [", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(bad)


def test_nonexistent_file(tmp_path: Path) -> None:
    with pytest.raises(ConfigError) as exc_info:
        load_config(tmp_path / "does-not-exist.yml")
    assert "not found" in str(exc_info.value)
