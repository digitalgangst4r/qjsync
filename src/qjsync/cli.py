"""The ``qjsync`` command-line interface.

A thin Typer wrapper that wires the pieces together and stays out of the way:
secrets come from the environment (:class:`~qjsync.config.settings.Secrets`),
non-secret config from ``rules.yml`` (:func:`~qjsync.config.loader.load_config`),
and the heavy collaborators — Qualys client/source, rules engine, Jira client —
are assembled into a :class:`~qjsync.sync.orchestrator.SyncOrchestrator` whose
:meth:`run` does the actual work.

Commands::

    qjsync validate-config -c rules.yml      # parse + validate, never touches network
    qjsync init-db                           # create the state schema (uses QJSYNC_DATABASE_URL)
    qjsync kb-refresh -c rules.yml           # refresh the local KnowledgeBase cache
    qjsync sync -c rules.yml [--mode ...] [--dry-run]
    qjsync dry-run -c rules.yml [--mode ...] # alias for `sync --dry-run`

The downstream modules (``config.loader``, ``logging``, ``sources.qualys``,
``rules.engine``, ``jira``, ``sync.orchestrator``) are imported lazily inside the
command bodies so that ``import qjsync.cli`` is cheap and side-effect free, and so
the test-suite can mock the orchestrator wiring without any of those modules
performing network or database I/O.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import typer

from qjsync.config.schema import QjsyncConfig
from qjsync.config.settings import Secrets
from qjsync.state.models import SyncMode

if TYPE_CHECKING:  # pragma: no cover - import only for type checkers
    from qjsync.sync.orchestrator import SyncOrchestrator
    from qjsync.sync.summary import RunSummary

app = typer.Typer(
    name="qjsync",
    help="Sync Qualys VMDR detections into Jira Cloud.",
    no_args_is_help=True,
    add_completion=False,
)

# Reusable Typer option for the config path; ``-c`` everywhere for muscle memory.
_CONFIG_OPTION = typer.Option(
    Path("rules.yml"),
    "--config",
    "-c",
    help="Path to rules.yml (non-secret config).",
    exists=False,  # we raise a friendly error ourselves, not Typer's generic one
)

# ``sync`` and ``dry-run`` share this; the value maps 1:1 onto SyncMode.
_MODE_OPTION = typer.Option(
    SyncMode.INCREMENTAL,
    "--mode",
    help="Sync scope: 'incremental' (delta, default) or 'full' (reconciliation + purge).",
    case_sensitive=False,
)


# --------------------------------------------------------------------------- #
# Internal helpers (kept small + individually mockable in tests)
# --------------------------------------------------------------------------- #
def _load_secrets() -> Secrets:
    """Load secrets from the environment, or exit with a clear message.

    A missing/blank credential is the single most common misconfiguration, so we
    translate pydantic's validation error into a short, actionable line and a
    non-zero exit code rather than dumping a traceback.
    """
    try:
        return Secrets()  # values are supplied from the environment / .env
    except Exception as exc:  # pydantic ValidationError (and friends)
        typer.secho(
            "Missing or invalid secrets. Set QUALYS_USERNAME, QUALYS_PASSWORD, "
            "QUALYS_API_URL, JIRA_BASE_URL, JIRA_EMAIL and JIRA_API_TOKEN "
            "(in the environment or a .env file).",
            fg=typer.colors.RED,
            err=True,
        )
        typer.secho(f"  details: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2) from exc


def _load_config(path: Path) -> QjsyncConfig:
    """Load + validate ``rules.yml``, or exit with a clear message."""
    from qjsync.config.loader import ConfigError, load_config

    try:
        return load_config(path)
    except FileNotFoundError as exc:
        typer.secho(f"Config file not found: {path}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2) from exc
    except ConfigError as exc:
        typer.secho(f"Invalid config ({path}):", fg=typer.colors.RED, err=True)
        typer.secho(f"  {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2) from exc


def _configure_logging(config: QjsyncConfig) -> None:
    """Initialise structured logging from the config's logging block."""
    from qjsync.logging import setup_logging

    setup_logging(level=config.logging.level, fmt=config.logging.format)


def _build_orchestrator(
    secrets: Secrets,
    config: QjsyncConfig,
) -> SyncOrchestrator:
    """Wire Qualys -> source -> rules -> Jira -> orchestrator.

    Isolated in one place so the whole heavy chain can be replaced with a stub in
    tests by monkeypatching ``qjsync.cli._build_orchestrator``; no network or DB
    connection is opened until a command actually calls ``.run()``.
    """
    from qjsync.jira.auth import BasicAuthProvider
    from qjsync.jira.client import JiraClient
    from qjsync.jira.mapper import IssueMapper
    from qjsync.rules.engine import RulesEngine
    from qjsync.sources.qualys.client import QualysClient
    from qjsync.sources.qualys.source import VmSource
    from qjsync.state.db import make_engine, make_session_factory
    from qjsync.sync.orchestrator import SyncOrchestrator

    qualys_client = QualysClient(
        secrets.qualys_api_url,
        secrets.qualys_username,
        secrets.qualys_password,
        requests_per_second=config.qualys.requests_per_second,
        max_concurrency=config.qualys.max_concurrency,
    )

    engine = make_engine(secrets.database_url)
    session_factory = make_session_factory(engine)

    source = VmSource(qualys_client, session_factory, config)
    rules_engine = RulesEngine(config)

    auth = BasicAuthProvider(secrets.jira_email, secrets.jira_api_token)
    jira_client = JiraClient(
        secrets.jira_base_url,
        auth,
        requests_per_second=config.jira.requests_per_second,
    )

    # Discover custom-field ids by name (live GET /rest/api/3/field) and wire the
    # real IssueMapper so issues carry the full FIELD_MAPPING field set rather than
    # the orchestrator's minimal fallback builder.
    field_ids = jira_client.discover_fields()
    mapper = IssueMapper(field_ids, config)

    return SyncOrchestrator(
        source, rules_engine, jira_client, session_factory, config, mapper=mapper
    )


def _print_summary(summary: RunSummary) -> None:
    """Print the per-run summary line to stdout for the operator."""
    typer.echo(summary.log_line())


# --------------------------------------------------------------------------- #
# Commands
# --------------------------------------------------------------------------- #
@app.command("validate-config")
def validate_config(config_path: Path = _CONFIG_OPTION) -> None:
    """Parse and validate ``rules.yml`` without touching Qualys, Jira or the DB."""
    config = _load_config(config_path)
    p = config.prioritization
    typer.secho(
        f"OK: {config_path} is valid "
        f"(version={config.version}, qds_bands={p.qds_bands.highest}/{p.qds_bands.high}/"
        f"{p.qds_bands.medium}, modifiers={len(p.modifiers)}, "
        f"jira_project={config.jira.project}).",
        fg=typer.colors.GREEN,
    )


@app.command("init-db")
def init_db() -> None:
    """Create the state-store schema from the ORM models.

    Uses ``QJSYNC_DATABASE_URL`` from the environment. Alembic owns production
    migrations; this is the convenience bootstrap described in the architecture.
    """
    from qjsync.state.db import create_all, make_engine

    secrets = _load_secrets()
    engine = make_engine(secrets.database_url)
    create_all(engine)
    typer.secho(f"Schema created on {engine.url}.", fg=typer.colors.GREEN)


@app.command("kb-refresh")
def kb_refresh(config_path: Path = _CONFIG_OPTION) -> None:
    """Refresh the local KnowledgeBase cache from Qualys."""
    config = _load_config(config_path)
    _configure_logging(config)
    secrets = _load_secrets()
    orchestrator = _build_orchestrator(secrets, config)
    updated = orchestrator.source.refresh_knowledgebase()
    typer.secho(f"KnowledgeBase refreshed: {updated} entries updated.", fg=typer.colors.GREEN)


@app.command("sync")
def sync(
    config_path: Path = _CONFIG_OPTION,
    mode: SyncMode = _MODE_OPTION,
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Read everything, write nothing to Jira; report would-do counts.",
    ),
) -> None:
    """Run a sync (incremental by default; ``--mode full`` adds the purge pass)."""
    _run_sync(config_path, mode, dry_run=dry_run)


@app.command("dry-run")
def dry_run(
    config_path: Path = _CONFIG_OPTION,
    mode: SyncMode = _MODE_OPTION,
) -> None:
    """Alias for ``sync --dry-run`` (honours ``--mode``)."""
    _run_sync(config_path, mode, dry_run=True)


def _run_sync(config_path: Path, mode: SyncMode, *, dry_run: bool) -> None:
    """Shared body for ``sync`` and ``dry-run``."""
    config = _load_config(config_path)
    _configure_logging(config)
    secrets = _load_secrets()
    orchestrator = _build_orchestrator(secrets, config)
    summary = orchestrator.run(dry_run, mode=mode)
    _print_summary(summary)


def main() -> None:
    """Console-script entry point (see ``[project.scripts]`` in pyproject)."""
    app()


if __name__ == "__main__":  # pragma: no cover
    main()
