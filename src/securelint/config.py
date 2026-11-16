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

import re
import tomllib
from collections.abc import Collection
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from securelint.model import Confidence, Severity
from securelint.policy import Policy

_FILE_NAME = "pyproject.toml"
_KNOWN_SETTINGS = frozenset({"exclude", "ignore", "policy", "ai"})
_KNOWN_POLICY_SETTINGS = frozenset({"block-severity", "block-confidence"})
_KNOWN_AI_SETTINGS = frozenset({"provider", "model", "base-url", "api-key-env"})

PROVIDERS = ("anthropic", "openai-compatible")
"""The AI providers ``scan --explain`` can use."""

# Addresses on this machine: the only ones allowed without HTTPS.
_LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
_VARIABLE_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


class ConfigError(Exception):
    """The settings cannot be used; the message says what to fix."""


@dataclass(frozen=True, slots=True)
class AISettings:
    """Which AI explains findings, from ``[tool.securelint.ai]``."""

    provider: str
    """One of ``PROVIDERS``."""

    model: str
    """The provider's name for the model, e.g. ``claude-opus-5-5``."""

    base_url: str | None = None
    """Where an OpenAI-compatible service answers, e.g. ``http://localhost:11434/v1``."""

    api_key_env: str | None = None
    """The environment variable that holds the key. The key itself is never
    written in the settings file, which is usually committed."""


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

    ai: AISettings | None = None
    """The AI used by ``scan --explain``; ``None`` when none is set up."""


def ai_provider(target: Path) -> str | None:
    """Return the AI provider named in the settings for ``target``, if any.

    Only the name is read, and nothing is checked: the GitHub Action uses it
    to install a provider's package only when it is needed. The scan itself
    reads and checks every setting, and reports any mistake in them.
    """
    try:
        path = _find_settings_file(target)
        table = _read_table(path) if path is not None else None
    except ConfigError:
        return None
    settings = (table or {}).get("ai")
    provider = settings.get("provider") if isinstance(settings, dict) else None
    return provider if isinstance(provider, str) else None


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
        ai=_ai(table, path),
    )


def _ai(table: dict[str, Any], path: Path) -> AISettings | None:
    """Read the ``[tool.securelint.ai]`` table; ``None`` without one."""
    if "ai" not in table:
        return None
    settings = table["ai"]
    where = f"{path}: [tool.securelint.ai]"
    if not isinstance(settings, dict):
        raise ConfigError(f"{where} must be a table")
    if any("key" in name and name != "api-key-env" for name in settings):
        # The settings file is usually committed: a key in it is a leak.
        raise ConfigError(
            f"{where} must not hold a key; write the name of the environment "
            'variable that holds it instead, such as api-key-env = "ANTHROPIC_API_KEY"'
        )
    unknown = sorted(set(settings) - _KNOWN_AI_SETTINGS)
    if unknown:
        raise ConfigError(
            f"{where}: unknown setting {unknown[0]!r} "
            f"(known settings: {', '.join(sorted(_KNOWN_AI_SETTINGS))})"
        )

    provider = settings.get("provider")
    if provider not in PROVIDERS:
        choices = ", ".join(f'"{name}"' for name in PROVIDERS)
        raise ConfigError(f"{where}: provider must be one of {choices}")
    model = settings.get("model")
    if not isinstance(model, str) or not model.strip():
        raise ConfigError(f'{where}: model must name a model, such as model = "..."')

    base_url = settings.get("base-url")
    if provider == "openai-compatible":
        if base_url is None:
            raise ConfigError(f"{where}: an openai-compatible provider needs base-url")
        _check_base_url(base_url, where)
    elif base_url is not None:
        raise ConfigError(f"{where}: base-url is only for openai-compatible providers")

    api_key_env = settings.get("api-key-env")
    if api_key_env is not None and (
        not isinstance(api_key_env, str) or not _VARIABLE_NAME.fullmatch(api_key_env)
    ):
        raise ConfigError(
            f"{where}: api-key-env must be the name of an environment variable"
        )
    return AISettings(
        provider=provider,
        model=model.strip(),
        base_url=base_url,
        api_key_env=api_key_env,
    )


def _check_base_url(base_url: object, where: str) -> None:
    # Code is sent to this address: never in clear text over a network.
    if isinstance(base_url, str):
        parts = urlsplit(base_url)
        local = parts.hostname in _LOCAL_HOSTS
        secure = parts.scheme == "https" or (parts.scheme == "http" and local)
        no_login = not parts.username and not parts.password
        if secure and parts.hostname and no_login:
            return
    raise ConfigError(
        f"{where}: base-url must be an https:// address, or http:// on this "
        "machine (localhost), without a name or password in it"
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
