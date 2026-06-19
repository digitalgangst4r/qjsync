"""Unit tests for the Typer CLI.

These tests never touch the network or a real database: the heavy wiring is
replaced via ``monkeypatch`` (``qjsync.cli._build_orchestrator`` and
``qjsync.cli._configure_logging``), and ``validate-config`` is exercised against
the real pydantic schema through a lightweight in-process loader stub. Secrets
are controlled by clearing the relevant environment variables so the "secrets
missing" paths are deterministic.
"""

from __future__ import annotations

import sys
import types
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
import yaml
from pydantic import ValidationError
from typer.testing import CliRunner

import qjsync.cli as cli
from qjsync.config.schema import QjsyncConfig
from qjsync.state.models import SyncMode
from qjsync.sync.summary import RunSummary

runner = CliRunner()

# Secret env vars the CLI reads; cleared so "missing secrets" tests are stable.
_SECRET_ENV = (
    "QUALYS_USERNAME",
    "QUALYS_PASSWORD",
    "QUALYS_API_URL",
    "JIRA_BASE_URL",
    "JIRA_EMAIL",
    "JIRA_API_TOKEN",
    "QJSYNC_DATABASE_URL",
)

# A minimal-but-valid rules.yml body (the schema requires jira.project; the
# band-shift prioritisation has sensible defaults — one modifier shown).
_VALID_CONFIG: dict[str, Any] = {
    "version": 1,
    "jira": {"project": "QVULN"},
    "prioritization": {
        "qds_bands": {"highest": 90, "high": 70, "medium": 50},
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


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #
@pytest.fixture()
def no_secrets(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Guarantee no Qualys/Jira secrets are visible to the process."""
    for var in _SECRET_ENV:
        monkeypatch.delenv(var, raising=False)
    # Run from an empty dir so a stray ./.env can't supply secrets.
    monkeypatch.chdir(tmp_path)


@pytest.fixture()
def fake_loader(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Install an in-process ``qjsync.config.loader`` backed by the real schema.

    The real loader module is written by another wave; this stub lets the CLI's
    ``validate-config`` exercise its actual import + error-handling code path
    against the authoritative pydantic schema without depending on that file.
    """
    module = types.ModuleType("qjsync.config.loader")

    class ConfigError(Exception):
        """Raised when ``rules.yml`` is malformed or fails schema validation."""

    def load_config(path: Any) -> QjsyncConfig:
        text = Path(path).read_text(encoding="utf-8")
        try:
            data = yaml.safe_load(text) or {}
            return QjsyncConfig.model_validate(data)
        except (ValidationError, yaml.YAMLError) as exc:
            raise ConfigError(str(exc)) from exc

    module.ConfigError = ConfigError  # type: ignore[attr-defined]
    module.load_config = load_config  # type: ignore[attr-defined]

    saved = sys.modules.get("qjsync.config.loader")
    sys.modules["qjsync.config.loader"] = module
    try:
        yield
    finally:
        if saved is not None:
            sys.modules["qjsync.config.loader"] = saved
        else:
            del sys.modules["qjsync.config.loader"]


def _write_config(path: Path, body: dict[str, Any]) -> Path:
    path.write_text(yaml.safe_dump(body), encoding="utf-8")
    return path


class _FakeSource:
    def __init__(self) -> None:
        self.refreshed = 0

    def refresh_knowledgebase(self) -> int:
        self.refreshed = 7
        return 7


class _FakeOrchestrator:
    """Records how it was invoked so tests can assert mode/dry_run plumbing."""

    def __init__(self) -> None:
        self.source = _FakeSource()
        self.run_calls: list[tuple[bool, SyncMode]] = []

    def run(self, dry_run: bool = False, *, mode: SyncMode = SyncMode.INCREMENTAL) -> RunSummary:
        self.run_calls.append((dry_run, mode))
        return RunSummary(mode=mode, dry_run=dry_run, evaluated=3, created=1, skipped=2)


@pytest.fixture()
def fake_orchestrator(monkeypatch: pytest.MonkeyPatch) -> _FakeOrchestrator:
    """Replace the heavy wiring + logging so no network/DB/log setup happens."""
    orch = _FakeOrchestrator()
    monkeypatch.setattr(cli, "_build_orchestrator", lambda secrets, config: orch)
    monkeypatch.setattr(cli, "_configure_logging", lambda config: None)
    return orch


@pytest.fixture()
def with_secrets(monkeypatch: pytest.MonkeyPatch) -> None:
    """Provide a complete, syntactically valid set of secrets via the env."""
    monkeypatch.setenv("QUALYS_USERNAME", "u")
    monkeypatch.setenv("QUALYS_PASSWORD", "p")
    monkeypatch.setenv("QUALYS_API_URL", "https://qualysapi.example.com")
    monkeypatch.setenv("JIRA_BASE_URL", "https://x.atlassian.net")
    monkeypatch.setenv("JIRA_EMAIL", "you@example.com")
    monkeypatch.setenv("JIRA_API_TOKEN", "token")
    monkeypatch.setenv("QJSYNC_DATABASE_URL", "sqlite+pysqlite:///:memory:")


# --------------------------------------------------------------------------- #
# validate-config
# --------------------------------------------------------------------------- #
def test_validate_config_valid(fake_loader: None, tmp_path: Path) -> None:
    cfg = _write_config(tmp_path / "rules.yml", _VALID_CONFIG)
    result = runner.invoke(cli.app, ["validate-config", "-c", str(cfg)])
    assert result.exit_code == 0, result.output
    assert "OK" in result.output
    assert "modifiers=1" in result.output


def test_validate_config_invalid(fake_loader: None, tmp_path: Path) -> None:
    bad = dict(_VALID_CONFIG)
    bad["nonsense_key"] = True  # schema is extra="forbid"
    cfg = _write_config(tmp_path / "rules.yml", bad)
    result = runner.invoke(cli.app, ["validate-config", "-c", str(cfg)])
    assert result.exit_code == 2
    assert "Invalid config" in result.output


def test_validate_config_missing_file(fake_loader: None, tmp_path: Path) -> None:
    result = runner.invoke(cli.app, ["validate-config", "-c", str(tmp_path / "nope.yml")])
    assert result.exit_code == 2
    assert "not found" in result.output


# --------------------------------------------------------------------------- #
# sync / dry-run
# --------------------------------------------------------------------------- #
def test_sync_default_mode_incremental(
    fake_loader: None,
    fake_orchestrator: _FakeOrchestrator,
    with_secrets: None,
    tmp_path: Path,
) -> None:
    cfg = _write_config(tmp_path / "rules.yml", _VALID_CONFIG)
    result = runner.invoke(cli.app, ["sync", "-c", str(cfg)])
    assert result.exit_code == 0, result.output
    assert fake_orchestrator.run_calls == [(False, SyncMode.INCREMENTAL)]
    assert "mode=incremental" in result.output
    assert "evaluated=3" in result.output


def test_sync_full_dry_run(
    fake_loader: None,
    fake_orchestrator: _FakeOrchestrator,
    with_secrets: None,
    tmp_path: Path,
) -> None:
    cfg = _write_config(tmp_path / "rules.yml", _VALID_CONFIG)
    result = runner.invoke(cli.app, ["sync", "-c", str(cfg), "--mode", "full", "--dry-run"])
    assert result.exit_code == 0, result.output
    assert fake_orchestrator.run_calls == [(True, SyncMode.FULL)]
    assert "dry_run=True" in result.output
    assert "would_created=1" in result.output


def test_dry_run_alias_sets_dry_run(
    fake_loader: None,
    fake_orchestrator: _FakeOrchestrator,
    with_secrets: None,
    tmp_path: Path,
) -> None:
    cfg = _write_config(tmp_path / "rules.yml", _VALID_CONFIG)
    result = runner.invoke(cli.app, ["dry-run", "-c", str(cfg), "--mode", "full"])
    assert result.exit_code == 0, result.output
    assert fake_orchestrator.run_calls == [(True, SyncMode.FULL)]


def test_sync_missing_secrets_fails_cleanly(
    fake_loader: None,
    no_secrets: None,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    # Logging stub so we exercise the secrets check, not real log setup.
    monkeypatch.setattr(cli, "_configure_logging", lambda config: None)
    # _build_orchestrator must never be reached when secrets are absent.
    monkeypatch.setattr(
        cli,
        "_build_orchestrator",
        lambda secrets, config: pytest.fail("orchestrator built without secrets"),
    )
    cfg = _write_config(tmp_path / "rules.yml", _VALID_CONFIG)
    result = runner.invoke(cli.app, ["sync", "-c", str(cfg)])
    assert result.exit_code == 2
    assert "Missing or invalid secrets" in result.output


# --------------------------------------------------------------------------- #
# kb-refresh
# --------------------------------------------------------------------------- #
def test_kb_refresh_reports_count(
    fake_loader: None,
    fake_orchestrator: _FakeOrchestrator,
    with_secrets: None,
    tmp_path: Path,
) -> None:
    cfg = _write_config(tmp_path / "rules.yml", _VALID_CONFIG)
    result = runner.invoke(cli.app, ["kb-refresh", "-c", str(cfg)])
    assert result.exit_code == 0, result.output
    assert "7 entries updated" in result.output
    assert fake_orchestrator.source.refreshed == 7


def test_kb_refresh_missing_secrets_fails_cleanly(
    fake_loader: None,
    no_secrets: None,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(cli, "_configure_logging", lambda config: None)
    monkeypatch.setattr(
        cli,
        "_build_orchestrator",
        lambda secrets, config: pytest.fail("orchestrator built without secrets"),
    )
    cfg = _write_config(tmp_path / "rules.yml", _VALID_CONFIG)
    result = runner.invoke(cli.app, ["kb-refresh", "-c", str(cfg)])
    assert result.exit_code == 2
    assert "Missing or invalid secrets" in result.output


# --------------------------------------------------------------------------- #
# init-db
# --------------------------------------------------------------------------- #
def test_init_db_creates_schema(
    no_secrets: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Point at an in-memory sqlite DB; create_all must run against it.
    monkeypatch.setenv("QUALYS_USERNAME", "u")
    monkeypatch.setenv("QUALYS_PASSWORD", "p")
    monkeypatch.setenv("QUALYS_API_URL", "https://qualysapi.example.com")
    monkeypatch.setenv("JIRA_BASE_URL", "https://x.atlassian.net")
    monkeypatch.setenv("JIRA_EMAIL", "you@example.com")
    monkeypatch.setenv("JIRA_API_TOKEN", "token")
    monkeypatch.setenv("QJSYNC_DATABASE_URL", "sqlite+pysqlite:///:memory:")

    result = runner.invoke(cli.app, ["init-db"])
    assert result.exit_code == 0, result.output
    assert "Schema created" in result.output


def test_init_db_missing_secrets_fails_cleanly(no_secrets: None) -> None:
    result = runner.invoke(cli.app, ["init-db"])
    assert result.exit_code == 2
    assert "Missing or invalid secrets" in result.output
