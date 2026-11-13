"""Tests for reading settings from pyproject.toml."""

from pathlib import Path

import pytest

from securelint.config import Config, ConfigError, load_config

RULES = ["SL101", "SL102", "SL103"]


def write_settings(directory: Path, text: str) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "pyproject.toml"
    path.write_text(text, encoding="utf-8")
    return path


def test_no_file_gives_the_defaults(tmp_path: Path) -> None:
    assert load_config(tmp_path, RULES) == Config()


def test_file_without_a_securelint_table_gives_the_defaults(tmp_path: Path) -> None:
    write_settings(tmp_path, '[project]\nname = "demo"\n\n[tool.ruff]\nsrc = ["src"]\n')

    assert load_config(tmp_path, RULES) == Config()


def test_empty_table_changes_nothing_but_is_recorded(tmp_path: Path) -> None:
    path = write_settings(tmp_path, "[tool.securelint]\n")

    assert load_config(tmp_path, RULES) == Config(source=path)


def test_reads_exclude_and_ignore(tmp_path: Path) -> None:
    path = write_settings(
        tmp_path,
        '[tool.securelint]\nexclude = ["tests/data", "old.py"]\nignore = ["SL102"]\n',
    )

    config = load_config(tmp_path, RULES)

    assert config.source == path
    assert config.exclude == (
        (tmp_path / "tests" / "data").resolve(),
        (tmp_path / "old.py").resolve(),
    )
    assert config.ignore == frozenset({"SL102"})


def test_file_is_found_in_a_directory_above(tmp_path: Path) -> None:
    path = write_settings(tmp_path, '[tool.securelint]\nexclude = ["build"]\n')
    deep = tmp_path / "src" / "pkg"
    deep.mkdir(parents=True)

    config = load_config(deep, RULES)

    assert config.source == path
    # Relative to the settings file, not to the directory being scanned.
    assert config.exclude == ((tmp_path / "build").resolve(),)


def test_file_is_found_when_a_single_file_is_scanned(tmp_path: Path) -> None:
    path = write_settings(tmp_path, '[tool.securelint]\nignore = ["SL101"]\n')
    script = tmp_path / "script.py"
    script.write_text("x = 1\n", encoding="utf-8")

    assert load_config(script, RULES).source == path


def test_the_nearest_file_with_settings_wins(tmp_path: Path) -> None:
    write_settings(tmp_path, '[tool.securelint]\nignore = ["SL101"]\n')
    # This one is nearer but says nothing about SecureLint.
    write_settings(tmp_path / "a", '[project]\nname = "inner"\n')
    nearest = write_settings(
        tmp_path / "a" / "b", '[tool.securelint]\nignore = ["SL102"]\n'
    )

    assert load_config(tmp_path / "a" / "b", RULES).source == nearest
    assert load_config(tmp_path / "a", RULES).ignore == frozenset({"SL101"})


def test_search_stops_at_the_top_of_the_repository(tmp_path: Path) -> None:
    write_settings(tmp_path, '[tool.securelint]\nignore = ["SL101"]\n')
    repository = tmp_path / "project"
    (repository / ".git").mkdir(parents=True)
    (repository / "src").mkdir()

    # Settings above the repository belong to something else.
    assert load_config(repository / "src", RULES) == Config()


def test_settings_at_the_top_of_the_repository_are_used(tmp_path: Path) -> None:
    repository = tmp_path / "project"
    (repository / ".git").mkdir(parents=True)
    (repository / "src").mkdir()
    path = write_settings(repository, '[tool.securelint]\nignore = ["SL101"]\n')

    assert load_config(repository / "src", RULES).source == path


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("[tool.securelint\n", "not valid TOML"),
        ('[tool]\nsecurelint = "on"\n', "[tool.securelint] must be a table"),
        # A typo must not silently turn a setting off.
        ('[tool.securelint]\nexlude = ["build"]\n', "unknown setting 'exlude'"),
        ('[tool.securelint]\nexclude = "build"\n', "exclude must be a list of names"),
        ("[tool.securelint]\nexclude = [1, 2]\n", "exclude must be a list of names"),
        ('[tool.securelint]\nexclude = [""]\n', "exclude must be a list of names"),
        ('[tool.securelint]\nignore = "SL101"\n', "ignore must be a list of names"),
        ('[tool.securelint]\nignore = ["SL999"]\n', "unknown rule 'SL999'"),
        ('[tool.securelint]\nignore = ["sl101"]\n', "unknown rule 'sl101'"),
    ],
)
def test_a_mistake_in_the_settings_is_an_error(
    tmp_path: Path, text: str, message: str
) -> None:
    path = write_settings(tmp_path, text)

    with pytest.raises(ConfigError) as error:
        load_config(tmp_path, RULES)

    assert message in str(error.value)
    assert str(path) in str(error.value)


def test_unknown_rule_error_lists_the_known_rules(tmp_path: Path) -> None:
    write_settings(tmp_path, '[tool.securelint]\nignore = ["SL999"]\n')

    with pytest.raises(ConfigError, match=r"known rules: SL101, SL102, SL103"):
        load_config(tmp_path, RULES)


def test_an_absolute_path_in_exclude_is_an_error(tmp_path: Path) -> None:
    absolute = (tmp_path / "build").resolve().as_posix()
    write_settings(tmp_path, f'[tool.securelint]\nexclude = ["{absolute}"]\n')

    with pytest.raises(ConfigError, match="relative to this file"):
        load_config(tmp_path, RULES)
