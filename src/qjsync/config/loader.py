"""Load and validate the non-secret ``rules.yml`` into a :class:`QjsyncConfig`.

The loader is deliberately thin: it reads the file, parses it with PyYAML
(``safe_load`` — JSON is a YAML subset, so the same parser handles both
``.yml``/``.yaml`` and ``.json``), and hands the resulting mapping to the
authoritative pydantic schema. Every failure mode is surfaced as a single
:class:`ConfigError` carrying a human-readable message (including the pydantic
detail), so callers — chiefly :mod:`qjsync.cli` — can present one clean line to
the operator instead of a traceback.

Secrets never live here; they come from the environment via
:class:`qjsync.config.settings.Secrets`.
"""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import ValidationError

from qjsync.config.schema import QjsyncConfig


class ConfigError(Exception):
    """Raised when ``rules.yml`` cannot be read, parsed, or validated.

    The message is intended to be shown directly to an operator; for schema
    failures it embeds the pydantic validation detail.
    """


def load_config(path: str | Path) -> QjsyncConfig:
    """Parse and validate a qjsync config file into a :class:`QjsyncConfig`.

    YAML and JSON are both accepted (JSON is valid YAML). Any problem — the file
    not existing, a parse error, or a schema validation failure — is raised as a
    :class:`ConfigError` with a clear, single-line-friendly message.
    """
    config_path = Path(path)
    try:
        text = config_path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise ConfigError(f"config file not found: {config_path}") from exc
    except OSError as exc:
        raise ConfigError(f"could not read config file {config_path}: {exc}") from exc

    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ConfigError(f"could not parse config file {config_path}: {exc}") from exc

    if data is None:
        raise ConfigError(f"config file {config_path} is empty")
    if not isinstance(data, dict):
        raise ConfigError(
            f"config file {config_path} must contain a mapping at the top level, "
            f"got {type(data).__name__}"
        )

    try:
        return QjsyncConfig.model_validate(data)
    except ValidationError as exc:
        raise ConfigError(f"invalid config {config_path}:\n{exc}") from exc
