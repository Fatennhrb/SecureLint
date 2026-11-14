"""Read a project's SecureLint settings from its ``pyproject.toml``.

The settings live in the file Python projects already have::

    [tool.securelint]
    exclude = ["tests/corpus", "docs/examples.py"]
    ignore = ["SL104"]

Settings make a scan look at less, so a mistake in them must never pass
unseen: an unknown setting, a wrong type or an unknown rule stops the scan
with an error instead of being skipped. A typo such as ``exlude`` would
otherwise turn a setting off without anyone noticing.
"""

import tomllib
from collections.abc import Collection
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from securelint.model import Confidence, Severity
from securelint.policy import Policy

_FILE_NAME = "pyproject.toml"
_KNOWN_SETTINGS = frozenset({"exclude", "ignore", "policy"})
_KNOWN_POLICY_SETTINGS = frozenset({"block-severity", "block-confidence"})


class ConfigError(Exception):
    """The settings cannot be used; the message says what to fix."""


@dataclass(frozen=True, slots=True)
class Config:
    """The settings of one project. The defaults change nothing."""

    source: Path | None = None
    """The file the settings were read from; ``None`` when there is none."""

    exclude: tuple[Path, ...] = ()
    """Files and directories to leave out, as full paths."""

    ignore: frozenset[str] = frozenset()
    """Ids of the rules that are turned off."""

    policy: Policy = field(default_factory=Policy)
    """Which findings block and which are warnings."""


def load_config(target: Path, known_rule_ids: Collection[str]) -> Config:
    """Return the settings that apply to a scan of ``target``.

    The file is looked for in the scanned directory, then in each
    directory above it, up to the top of the Git repository. The first
    ``pyproject.toml`` with a ``[tool.securelint]`` table is used.

    Raises ``ConfigError`` if that file cannot be read or its settings
    are not valid.
    """
    path = _find_settings_file(target)
    if path is None:
        return Config()
    table = _read_table(path)
    if table is None:
        return Config()

    unknown = sorted(set(table) - _KNOWN_SETTINGS)
    if unknown:
        raise ConfigError(
            f"{path}: unknown setting {unknown[0]!r} in [tool.securelint] "
            f"(known settings: {', '.join(sorted(_KNOWN_SETTINGS))})"
        )

    ignore = _strings(table, "ignore", path)
    for rule_id in ignore:
        if rule_id not in known_rule_ids:
            raise ConfigError(
                f"{path}: unknown rule {rule_id!r} in ignore "
                f"(known rules: {', '.join(sorted(known_rule_ids))})"
            )

    exclude = []
    for entry in _strings(table, "exclude", path):
        if Path(entry).is_absolute():
            raise ConfigError(
                f"{path}: exclude must hold paths relative to this file, not {entry!r}"
            )
        # Paths are written relative to the settings file, so they mean the
        # same thing wherever the scan is started from.
        exclude.append((path.parent / entry).resolve())

    return Config(
        source=path,
        exclude=tuple(exclude),
        ignore=frozenset(ignore),
        policy=_policy(table, path),
    )


def _policy(table: dict[str, Any], path: Path) -> Policy:
    """Read the ``[tool.securelint.policy]`` table; the defaults without one."""
    settings = table.get("policy", {})
    if not isinstance(settings, dict):
        raise ConfigError(f"{path}: [tool.securelint.policy] must be a table")
    unknown = sorted(set(settings) - _KNOWN_POLICY_SETTINGS)
    if unknown:
        raise ConfigError(
            f"{path}: unknown setting {unknown[0]!r} in [tool.securelint.policy] "
            f"(known settings: {', '.join(sorted(_KNOWN_POLICY_SETTINGS))})"
        )

    policy = Policy()
    severity = _level_name(
        settings, "block-severity", [level.name for level in Severity], path
    )
    if severity is not None:
        policy = replace(policy, block_severity=Severity[severity])
    confidence = _level_name(
        settings, "block-confidence", [level.name for level in Confidence], path
    )
    if confidence is not None:
        policy = replace(policy, block_confidence=Confidence[confidence])
    return policy


def _level_name(
    settings: dict[str, Any], name: str, levels: list[str], path: Path
) -> str | None:
    """Read a setting that must name a level, such as ``"high"``.

    Returns the level's name in capitals, or ``None`` when the setting is
    not written.
    """
    if name not in settings:
        return None
    value = settings[name]
    names = [level.lower() for level in levels]
    if not isinstance(value, str) or value not in names:
        choices = ", ".join(f'"{level}"' for level in names)
        raise ConfigError(f"{path}: {name} must be one of {choices}")
    return value.upper()


def _find_settings_file(target: Path) -> Path | None:
    """Return the nearest ``pyproject.toml`` that has SecureLint settings."""
    start = target.resolve()
    if not start.is_dir():
        start = start.parent
    for directory in (start, *start.parents):
        candidate = directory / _FILE_NAME
        if candidate.is_file() and _read_table(candidate) is not None:
            return candidate
        # The top of the repository is the top of the project. Settings
        # further up belong to something else and are not picked up.
        if (directory / ".git").exists():
            return None
    return None


def _read_table(path: Path) -> dict[str, Any] | None:
    """Return the ``[tool.securelint]`` table of a file, or None without one."""
    try:
        with path.open("rb") as file:
            document = tomllib.load(file)
    except OSError as error:
        raise ConfigError(f"{path}: cannot be read: {error}") from error
    except tomllib.TOMLDecodeError as error:
        raise ConfigError(f"{path}: not valid TOML: {error}") from error

    tool = document.get("tool")
    if not isinstance(tool, dict) or "securelint" not in tool:
        return None
    table = tool["securelint"]
    if not isinstance(table, dict):
        raise ConfigError(f"{path}: [tool.securelint] must be a table")
    return table


def _strings(table: dict[str, Any], name: str, path: Path) -> list[str]:
    """Return a setting that must be a list of non-empty strings."""
    value = table.get(name, [])
    if not isinstance(value, list) or not all(
        isinstance(item, str) and item for item in value
    ):
        raise ConfigError(
            f'{path}: {name} must be a list of names, such as {name} = ["..."]'
        )
    return value
