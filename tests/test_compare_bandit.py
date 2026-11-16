"""Tests for the SecureLint and Bandit comparison script."""

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

SCRIPT = Path(__file__).parent.parent / "benchmarks" / "compare_bandit.py"


def load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("compare_bandit", SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


compare = load()


def test_a_call_over_several_lines_is_one_statement(tmp_path: Path) -> None:
    path = tmp_path / "app.py"
    path.write_text(
        "import os\n"
        "cursor.execute(\n"
        '    "SELECT " + name,\n'
        ")\n"
        "def run():\n"
        "    os.system(x)\n",
        encoding="utf-8",
    )

    starts = compare.statement_starts(path)

    assert [starts[line] for line in (2, 3, 4)] == [2, 2, 2]
    # Inside a function, the innermost statement wins, not the def.
    assert starts[6] == 6


def test_cases_are_moved_to_the_start_of_their_statement(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        'subprocess.run(\n    "ls " + x,\n    shell=True,\n)\n', encoding="utf-8"
    )

    moved = compare.by_statement(tmp_path, [("app.py", 3, "SL102")])

    assert moved == {("app.py", 1, "SL102")}


def test_dangerous_lines_come_from_the_comments(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "eval(x)  # expect: SL101\n"
        "os.system(y)  # missed: SL102\n"
        "eval('1')  # false-alarm: SL101\n"
        "print('safe')\n",
        encoding="utf-8",
    )

    assert compare.dangerous_lines(tmp_path) == {
        ("app.py", 1, "SL101"),
        ("app.py", 2, "SL102"),
    }


def test_scoring() -> None:
    dangerous = {("a.py", 1, "SL101"), ("a.py", 2, "SL101"), ("a.py", 3, "SL102")}
    found = {("a.py", 1, "SL101"), ("a.py", 9, "SL101"), ("a.py", 3, "SL102")}

    assert compare.score(found, dangerous, "SL101") == (1, 1, 1)
    assert compare.score(found, dangerous, "SL102") == (1, 0, 0)


def fake_bandit(monkeypatch: pytest.MonkeyPatch, stdout: str) -> None:
    def run(*args: Any, **kwargs: Any) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(args, 1, stdout=stdout, stderr="")

    monkeypatch.setattr(compare.subprocess, "run", run)


def bandit_result(test_id: str, line: int, confidence: str = "HIGH") -> Any:
    return {
        "test_id": test_id,
        "test_name": "name",
        "filename": "corpus/app.py",
        "line_number": line,
        "issue_confidence": confidence,
    }


def test_bandit_checks_are_mapped_to_kinds(monkeypatch: pytest.MonkeyPatch) -> None:
    report = {
        "results": [
            bandit_result("B307", 1),
            bandit_result("B605", 2, confidence="LOW"),
            bandit_result("B404", 3),
        ]
    }
    fake_bandit(monkeypatch, json.dumps(report))

    cases, others = compare.bandit_cases(Path("corpus"))
    confident, _ = compare.bandit_cases(Path("corpus"), confident_only=True)

    assert cases == {("app.py", 1, "SL101"), ("app.py", 2, "SL102")}
    assert dict(others) == {"B404 name": 1}
    assert confident == {("app.py", 1, "SL101")}


def test_without_bandit_the_script_says_how_to_get_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_bandit(monkeypatch, "No module named bandit")

    with pytest.raises(SystemExit, match="cannot run Bandit"):
        compare.bandit_cases(Path("corpus"))


def test_the_published_numbers_are_still_true() -> None:
    # The same numbers are in the main README; keep them in step.
    pytest.importorskip("bandit")
    completed = subprocess.run(  # noqa: S603 (Python itself, fixed arguments)
        [sys.executable, str(SCRIPT)], capture_output=True, text=True, check=False
    )

    assert completed.returncode == 0, completed.stderr
    assert (
        "| **Total** | **63** | **54** | **9** | **4** | **49** | **14** | **21** |"
        in completed.stdout
    )
    assert "found 46, missed 17, false alarms 18." in completed.stdout
