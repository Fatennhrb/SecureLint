"""Tests for the command-line entry points."""

import ast
import json
import subprocess
import sys
from collections.abc import Iterable
from pathlib import Path

import pytest

from securelint import __version__, cli
from securelint.cli import main
from securelint.context import FileContext
from securelint.engine import Rule
from securelint.model import Confidence, Finding, Severity


class EvalRule(Rule):
    """A stand-in rule: reports every call to a function named ``eval``."""

    node_types = (ast.Call,)

    def check(self, node: ast.AST, context: FileContext) -> Iterable[Finding]:
        assert isinstance(node, ast.Call)
        if isinstance(node.func, ast.Name) and node.func.id == "eval":
            yield Finding(
                rule_id="T001",
                message="Call to eval().",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                path=context.path,
                line=node.lineno,
                column=node.col_offset + 1,
            )


@pytest.fixture
def eval_rule(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make the scan command run only ``EvalRule``.

    The command's own behaviour (output, exit codes) is then tested with a
    rule that never changes, whatever happens to the real rules.
    """
    monkeypatch.setattr(cli, "RULES", (EvalRule(),))


def test_version_flag_prints_version(capsys: pytest.CaptureFixture[str]) -> None:
    # argparse's "version" action prints the version, then raises SystemExit(0).
    with pytest.raises(SystemExit) as exc_info:
        main(["--version"])

    assert exc_info.value.code == 0
    assert capsys.readouterr().out.strip() == f"securelint {__version__}"


def test_no_arguments_prints_usage(capsys: pytest.CaptureFixture[str]) -> None:
    assert main([]) == 0
    assert "usage: securelint" in capsys.readouterr().out


def test_unknown_option_is_rejected(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["--no-such-option"])

    assert exc_info.value.code == 2
    assert "unrecognized arguments" in capsys.readouterr().err


def test_package_runs_as_a_module() -> None:
    # Starts a real `python -m securelint` process. This checks the wiring the
    # unit tests above can't: the installed package and its __main__.py.
    result = subprocess.run(
        [sys.executable, "-m", "securelint", "--version"],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0
    assert result.stdout.strip() == f"securelint {__version__}"


@pytest.mark.usefixtures("eval_rule")
def test_scan_clean_code_exits_0(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / "app.py").write_text("print('safe')\n", encoding="utf-8")

    assert main(["scan", str(tmp_path)]) == 0

    captured = capsys.readouterr()
    assert captured.out == "No problems found in 1 file.\n"
    assert captured.err == ""


@pytest.mark.usefixtures("eval_rule")
def test_scan_with_findings_exits_1(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / "app.py").write_text("x = 1\ny = eval(x)\n", encoding="utf-8")

    assert main(["scan", str(tmp_path)]) == 1

    assert capsys.readouterr().out.splitlines() == [
        "app.py:2:5  high      T001  Call to eval().",
        "",
        "1 problem found in 1 file (1 high).",
    ]


@pytest.mark.usefixtures("eval_rule")
def test_scan_missing_path_exits_2(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["scan", str(tmp_path / "does-not-exist")]) == 2

    captured = capsys.readouterr()
    assert captured.out == ""
    assert "securelint: error: no such file or directory" in captured.err


@pytest.mark.usefixtures("eval_rule")
def test_scan_with_an_unreadable_file_exits_2_even_with_findings(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / "broken.py").write_text("def oops(:\n", encoding="utf-8")
    (tmp_path / "found.py").write_text("eval(x)\n", encoding="utf-8")

    assert main(["scan", str(tmp_path)]) == 2

    captured = capsys.readouterr()
    assert "found.py:1:1" in captured.out
    assert "securelint: cannot scan broken.py:1:" in captured.err


@pytest.mark.usefixtures("eval_rule")
def test_scan_defaults_to_the_current_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    (tmp_path / "app.py").write_text("eval(x)\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    assert main(["scan"]) == 1
    assert "app.py:1:1" in capsys.readouterr().out


@pytest.mark.usefixtures("eval_rule")
def test_scan_a_single_file(tmp_path: Path) -> None:
    script = tmp_path / "script.py"
    script.write_text("eval(x)\n", encoding="utf-8")

    assert main(["scan", str(script)]) == 1


def test_scan_runs_the_real_rules(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # No fake rule here: this checks the real rules reach the command.
    (tmp_path / "app.py").write_text("result = eval(data)\n", encoding="utf-8")

    assert main(["scan", str(tmp_path)]) == 1
    assert "app.py:1:10  high      SL101  eval() runs" in capsys.readouterr().out


def test_scan_command_runs_as_a_real_process(tmp_path: Path) -> None:
    result = subprocess.run(
        [sys.executable, "-m", "securelint", "scan", "missing"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 2
    assert result.stdout == ""
    assert "no such file or directory" in result.stderr


@pytest.mark.usefixtures("eval_rule")
def test_scan_json_format_prints_a_json_document(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / "app.py").write_text("x = 1\ny = eval(x)\n", encoding="utf-8")

    assert main(["scan", str(tmp_path), "--format", "json"]) == 1

    captured = capsys.readouterr()
    document = json.loads(captured.out)
    assert document["summary"]["findings"] == 1
    assert document["findings"][0]["rule_id"] == "T001"
    assert (document["findings"][0]["line"], document["findings"][0]["column"]) == (
        2,
        5,
    )
    assert captured.err == ""


@pytest.mark.usefixtures("eval_rule")
def test_scan_json_format_keeps_the_exit_codes(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / "app.py").write_text("print('safe')\n", encoding="utf-8")
    assert main(["scan", str(tmp_path), "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["findings"] == []

    (tmp_path / "broken.py").write_text("def oops(:\n", encoding="utf-8")
    assert main(["scan", str(tmp_path), "--format", "json"]) == 2

    captured = capsys.readouterr()
    # Standard output is still one valid JSON document; the failure is in it
    # and also on standard error.
    assert json.loads(captured.out)["failures"][0]["path"] == "broken.py"
    assert "securelint: cannot scan broken.py:1:" in captured.err


def test_scan_unknown_format_is_rejected(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["scan", str(tmp_path), "--format", "xml"])

    assert exc_info.value.code == 2
    assert "invalid choice: 'xml'" in capsys.readouterr().err


@pytest.mark.usefixtures("eval_rule")
def test_scan_html_format_prints_a_page(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / "app.py").write_text("x = 1\ny = eval(x)\n", encoding="utf-8")

    assert main(["scan", str(tmp_path), "--format", "html"]) == 1

    captured = capsys.readouterr()
    assert captured.out.startswith("<!DOCTYPE html>")
    assert "Call to eval()." in captured.out
    assert captured.err == ""
