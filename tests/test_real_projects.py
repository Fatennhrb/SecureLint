"""Tests for the script that lists findings on real projects."""

import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parent.parent / "benchmarks" / "real_projects.py"


def run(*folders: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 (Python itself, fixed arguments)
        [sys.executable, str(SCRIPT), *map(str, folders)],
        capture_output=True,
        text=True,
        check=False,
    )


def test_both_tools_are_listed_for_each_folder(tmp_path: Path) -> None:
    pytest.importorskip("bandit")
    (tmp_path / "app.py").write_text(
        'eval(data)\nif token == "keyword":\n    pass\n', encoding="utf-8"
    )

    completed = run(tmp_path)

    assert completed.returncode == 0, completed.stderr
    lines = completed.stdout.splitlines()
    assert lines[0].endswith("(1 files)")
    assert lines[1:3] == ["SecureLint: 1", "  app.py:1  SL101"]
    # Bandit also takes the comparison for a password, as it did 9 times in
    # Jinja (docs/real-projects.md); SecureLint does not.
    assert lines[3:] == [
        "Bandit (shared kinds): 2",
        "  app.py:1  SL101",
        "  app.py:2  SL104",
    ]


def test_a_missing_folder_is_refused(tmp_path: Path) -> None:
    completed = run(tmp_path / "missing")

    assert completed.returncode == 2
    assert "not a folder" in completed.stderr
