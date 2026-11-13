"""Tests for the settings changing what a scan does."""

import json
from pathlib import Path

import pytest

from securelint.cli import main
from securelint.discovery import discover

DANGEROUS = "eval(data)\n"


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def found(target: Path, *exclude: Path) -> list[str]:
    return [file.relative_path for file in discover(target, exclude)]


@pytest.fixture
def project(tmp_path: Path) -> Path:
    """A small project with dangerous code in three places."""
    write(tmp_path / "app.py", DANGEROUS)
    write(tmp_path / "old.py", DANGEROUS)
    write(tmp_path / "tests" / "data" / "sample.py", DANGEROUS)
    write(tmp_path / "tests" / "test_app.py", "x = 1\n")
    return tmp_path


def scanned_paths(capsys: pytest.CaptureFixture[str]) -> list[str]:
    document = json.loads(capsys.readouterr().out)
    return [finding["path"] for finding in document["findings"]]


def test_discover_leaves_out_an_excluded_directory(project: Path) -> None:
    excluded = (project / "tests" / "data").resolve()

    assert found(project, excluded) == ["app.py", "old.py", "tests/test_app.py"]


def test_discover_leaves_out_an_excluded_file(project: Path) -> None:
    excluded = (project / "old.py").resolve()

    assert found(project, excluded) == [
        "app.py",
        "tests/data/sample.py",
        "tests/test_app.py",
    ]


def test_discover_only_excludes_the_exact_path(project: Path) -> None:
    # "tests/dat" is not "tests/data", and "data" alone is not "tests/data".
    assert len(found(project, (project / "tests" / "dat").resolve())) == 4
    assert len(found(project, (project / "data").resolve())) == 4


def test_a_directory_asked_for_by_name_is_scanned(project: Path) -> None:
    excluded = (project / "tests" / "data").resolve()

    assert found(project / "tests" / "data", excluded) == ["sample.py"]
    # Also when the exclusion is higher up than the directory asked for.
    assert found(project / "tests" / "data", (project / "tests").resolve()) == [
        "sample.py"
    ]


def test_a_file_asked_for_by_name_is_scanned(project: Path) -> None:
    excluded = (project / "old.py").resolve()

    assert found(project / "old.py", excluded) == ["old.py"]


def test_scan_without_settings_reports_everything(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["scan", str(project), "--format", "json"]) == 1

    captured = capsys.readouterr()
    assert len(json.loads(captured.out)["findings"]) == 3
    assert captured.err == ""


def test_scan_leaves_out_what_the_settings_exclude(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    write(
        project / "pyproject.toml",
        '[tool.securelint]\nexclude = ["tests/data", "old.py"]\n',
    )

    assert main(["scan", str(project), "--format", "json"]) == 1

    assert scanned_paths(capsys) == ["app.py"]


def test_scan_says_which_settings_it_used(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    write(project / "pyproject.toml", '[tool.securelint]\nexclude = ["old.py"]\n')

    main(["scan", str(project)])

    assert (
        f"securelint: using settings from {project / 'pyproject.toml'}"
        in capsys.readouterr().err
    )


def test_scan_of_a_subdirectory_uses_the_settings_above_it(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    write(project / "pyproject.toml", '[tool.securelint]\nexclude = ["tests/data"]\n')

    assert main(["scan", str(project / "tests"), "--format", "json"]) == 0

    assert scanned_paths(capsys) == []


def test_scan_of_an_excluded_directory_by_name_reports_it(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    write(project / "pyproject.toml", '[tool.securelint]\nexclude = ["tests/data"]\n')

    assert main(["scan", str(project / "tests" / "data"), "--format", "json"]) == 1

    assert scanned_paths(capsys) == ["sample.py"]


def test_an_ignored_rule_is_not_run(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    write(project / "app.py", "eval(data)\nos.system(command)\n")
    write(
        project / "pyproject.toml",
        '[tool.securelint]\nexclude = ["old.py", "tests"]\nignore = ["SL101"]\n',
    )

    assert main(["scan", str(project), "--format", "json"]) == 1

    document = json.loads(capsys.readouterr().out)
    assert [finding["rule_id"] for finding in document["findings"]] == ["SL102"]


def test_ignoring_the_only_rule_that_matches_gives_a_clean_scan(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    write(project / "pyproject.toml", '[tool.securelint]\nignore = ["SL101"]\n')

    assert main(["scan", str(project)]) == 0
    assert "No problems found in 4 files." in capsys.readouterr().out


def test_a_mistake_in_the_settings_stops_the_scan(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    write(project / "pyproject.toml", '[tool.securelint]\nexlude = ["old.py"]\n')

    assert main(["scan", str(project)]) == 2

    captured = capsys.readouterr()
    # No report at all: a scan with half-understood settings proves nothing.
    assert captured.out == ""
    assert "securelint: error:" in captured.err
    assert "unknown setting 'exlude'" in captured.err


def test_an_unknown_rule_in_the_settings_stops_the_scan(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    write(project / "pyproject.toml", '[tool.securelint]\nignore = ["SL999"]\n')

    assert main(["scan", str(project)]) == 2
    assert "unknown rule 'SL999'" in capsys.readouterr().err
